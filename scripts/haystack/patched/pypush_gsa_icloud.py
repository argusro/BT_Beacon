import time
import os

import urllib3
from getpass import getpass
import plistlib as plist
import json
import uuid
import pbkdf2
import requests
import hashlib
import hmac
import base64
import locale
import logging
import re
from datetime import datetime, timezone
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Hash import SHA256

from endpoint import mh_config

# Created here so that it is consistent
USER_ID = uuid.uuid4()
DEVICE_ID = uuid.uuid4()

# Response headers of the last GrandSlam request. The idmsa 2FA endpoints need
# X-Apple-ID-Session-Id and scnt from here (they are not in the body).
LAST_GSA_HEADERS = {}

# Configure SRP library for compatibility with Apple's implementation
srp.rfc5054_enable()
srp.no_username_in_x()

# Disable SSL Warning
urllib3.disable_warnings()

logger = logging.getLogger()


def icloud_login_mobileme(username='', password=''):
    print("")  # Sometimes no output
    if not username:
        username = input('Apple ID: ')
    if not password:
        password = getpass('Password: ')

    g = gsa_authenticate(username, password)
    pet = g["t"]["com.apple.gs.idms.pet"]["token"]
    adsid = g["adsid"]

    data = {
        "apple-id": username,
        "delegates": {"com.apple.mobileme": {}},
        "password": pet,
        "client-id": str(USER_ID),
    }
    data = plist.dumps(data)

    client_info, _ = anisette_client_identity()
    # Same platform prefix as the ADI, but with the AOSKit service suffix that
    # loginDelegates expects.
    platform_prefix = client_info.rsplit("<", 1)[0]
    aoskit = platform_prefix + "<com.apple.AOSKit/282 (com.apple.accountsd/113)>"

    client_infos = [
        aoskit,  # matches the provisioned platform (macOS backend -> macOS AOSKit)
        "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> "
        "<com.apple.AOSKit/282 (com.apple.accountsd/113)>",
        "<PC> <Windows;6.2(0,0);9200> <com.apple.AOSKit/282 (com.apple.accountsd/113)>",
    ]

    mobileme = {}
    for attempt, ci in enumerate(client_infos, start=1):
        headers = {
            "X-Apple-ADSID": adsid,
            "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
            "X-MMe-Client-Info": ci,
        }
        # loginDelegates wants the device/anisette headers too.
        headers.update(generate_anisette_headers())

        logger.info("Registering device after login (identity %d)", attempt)
        with requests.post(
                "https://setup.icloud.com/setup/iosbuddy/loginDelegates",
                auth=(username, pet),
                data=data,
                headers=headers,
                verify=False,
                timeout=60,
        ) as resp:
            resp.raise_for_status()
            mobileme = plist.loads(resp.content)

        delegate = mobileme.get("delegates", {}).get("com.apple.mobileme", {})
        status = delegate.get("status")
        logger.debug("loginDelegates -> status %s", status)
        if status == 0:
            break
        logger.warning("loginDelegates identity %d -> status %s (%s)",
                       attempt, status, delegate.get("status-message"))

    delegate = mobileme.get("delegates", {}).get("com.apple.mobileme", {})
    tokens = delegate.get("service-data", {}).get("tokens", {})
    if tokens:
        logger.info("tokens received: %s", ", ".join(sorted(tokens.keys())))

    logger.debug('Answer from icloud login')
    logger.debug(mobileme)
    return mobileme


def gsa_authenticate(username, password):
    # Password is None as we'll provide it later
    usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, a = usr.start_authentication()
    logger.info("Authentication request initialization")
    r = gsa_authenticated_request(
        {"A2k": a, "ps": ["s2k", "s2k_fo"], "u": username, "o": "init"})

    if r["sp"] not in ["s2k", "s2k_fo"]:
        logger.warning(f"This implementation only supports s2k and sk2_fo. Server returned {r['sp']}")
        return

    # Change the password out from under the SRP library, as we couldn't calculate it without the salt.
    usr.p = encrypt_password(password, r["s"], r["i"], r["sp"])

    m = usr.process_challenge(r["s"], r["B"])

    # Make sure we processed the challenge correctly
    if m is None:
        logger.error("Failed to process challenge")
        return
    logger.info("Authentication request completion")
    resp = gsa_authenticated_request(
        {"c": r["c"], "M1": m, "u": username, "o": "complete"})

    # Make sure that the server's session key matches our session key (and thus that they are not an imposter)
    if "M2" not in resp:
        logger.error("Error on authentication")
        logger.error(resp)
        return
    usr.verify_session(resp["M2"])
    if not usr.authenticated():
        logger.error("Failed to verify session")
        return

    spd = decrypt_cbc(usr, resp["spd"])
    # For some reason plistlib doesn't accept it without the header...
    PLISTHEADER = b"""\
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
"""
    spd = plist.loads(PLISTHEADER + spd)

    if "au" in resp["Status"] and resp["Status"]["au"] in ["trustedDeviceSecondaryAuth", "secondaryAuth"]:
        logger.info("2FA required, requesting SMS code. (No other 2FA-code will work!)")
        # Replace bytes with strings
        for k, v in spd.items():
            if isinstance(v, bytes):
                spd[k] = base64.b64encode(v).decode()
        sms_second_factor(spd["adsid"], spd["GsIdmsToken"])

        return gsa_authenticate(username, password)
    elif "au" in resp["Status"]:
        logger.error(f"Unknown auth value {r['Status']['au']}")
        return
    else:
        return spd


def gsa_authenticated_request(parameters):
    body = {
        "Header": {"Version": "1.0.1"},
        "Request": {"cpd": generate_cpd()},
    }
    body["Request"].update(parameters)

    client_info, user_agent = anisette_client_identity()

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": user_agent,
        "X-MMe-Client-Info": client_info,
    }

    with  requests.post(
            "https://gsa.apple.com/grandslam/GsService2",
            headers=headers,
            data=plist.dumps(body),
            verify=False,
            timeout=5,
    ) as resp:
        resp.raise_for_status()
        # scnt / X-Apple-ID-Session-Id live in the headers; 2FA needs them.
        LAST_GSA_HEADERS.clear()
        LAST_GSA_HEADERS.update({k.lower(): v for k, v in resp.headers.items()})

    response = f"HTTP-Code: {resp.status_code}\n{resp.text}"
    logger.debug(response)

    return plist.loads(resp.content)["Response"]


def generate_cpd():
    cpd = {
        # Many of these values are not strictly necessary, but may be tracked by Apple
        "bootstrap": True,  # All implementations set this to true
        "icscrec": True,  # Only AltServer sets this to true
        "pbe": False,  # All implementations explicitly set this to false
        "prkgen": True,  # I've also seen ckgen
        "svct": "iCloud",  # In certian circumstances, this can be 'iTunes' or 'iCloud'
    }

    cpd.update(generate_anisette_headers())
    return cpd


def anisette_client_identity():
    """Client identity matching the platform the Anisette backend provisioned.

    Apple ties SRP/2FA/iCloud calls to the ADI platform (changed ~12 Oct 2026):
    an Android ADI claiming to be a Mac gets -80045, a Windows ADI claiming to
    be a Mac gets -80044, and so on. macOS is also the only platform that gets a
    searchPartyToken (needed for Find My report fetching). So ask the Anisette
    v3 server what it actually provisioned instead of hardcoding one.
    """
    base = mh_config.getAnisetteServer().rstrip("/")
    try:
        with requests.get(base + "/v3/client_info", timeout=60) as response:
            response.raise_for_status()
            identity = response.json()
        return identity["client_info"], identity["user_agent"]
    except Exception as exc:  # noqa: BLE001 - fall back to the macos backend default
        logger.warning("could not read anisette client identity (%s)", exc)
        return (
            os.environ.get(
                "MH_CLIENT_INFO",
                "<MacBookPro16,2> <macOS;26.7.1;25G241> "
                "<com.apple.AuthKit/1 (com.apple.akd/1.0)>",
            ),
            os.environ.get("MH_USER_AGENT", "akd/1.0 CFNetwork/3860.100.1 Darwin/25.0.0"),
        )


def generate_anisette_headers():
    """Fetch the Anisette headers for the cpd payload.

    The whole server response is used (not just X-Apple-I-MD/MD-M) so that
    fields such as X-Apple-I-MD-RINFO match the provisioned identity; a stale
    hardcoded RINFO makes Apple reject the request. Identity belongs in the
    HTTP headers, not in the cpd, so those two keys are dropped here.
    """
    with requests.get(mh_config.getAnisetteServer(), timeout=30) as response:
        response.raise_for_status()
        headers = response.json()

    for key in ("User-Agent", "X-MMe-Client-Info"):
        headers.pop(key, None)
    return headers


def generate_meta_headers(serial="0", user_id=uuid.uuid4(), device_id=uuid.uuid4()):
    return {
        "X-Apple-I-Client-Time": datetime.now(timezone.utc).replace(microsecond=0).isoformat() + "Z",
        "X-Apple-I-TimeZone": str(datetime.now(timezone.utc).astimezone().tzinfo),
        "loc": locale.getdefaultlocale()[0] or "en_US",
        "X-Apple-Locale": locale.getdefaultlocale()[0] or "en_US",
        "X-Apple-I-MD-RINFO": "17106176",  # either 17106176 or 50660608
        "X-Apple-I-MD-LU": base64.b64encode(str(user_id).upper().encode()).decode(),
        "X-Mme-Device-Id": str(device_id).upper(),
        "X-Apple-I-SRL-NO": serial,  # Serial number
    }


def encrypt_password(password, salt, iterations, protocol):
    assert protocol in ["s2k", "s2k_fo"]
    p = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        p = p.hex().encode("utf-8")
    return pbkdf2.PBKDF2(p, salt, iterations, SHA256).read(32)


def create_session_key(usr, name):
    k = usr.get_session_key()
    if k is None:
        raise Exception("No session key")
    return hmac.new(k, name.encode(), hashlib.sha256).digest()


def decrypt_cbc(usr, data):
    extra_data_key = create_session_key(usr, "extra data key:")
    extra_data_iv = create_session_key(usr, "extra data iv:")
    # Get only the first 16 bytes of the iv
    extra_data_iv = extra_data_iv[:16]

    # Decrypt with AES CBC
    cipher = Cipher(algorithms.AES(extra_data_key), modes.CBC(extra_data_iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    # Remove PKCS#7 padding
    padder = padding.PKCS7(128).unpadder()
    return padder.update(data) + padder.finalize()


WAITING_TIME = 60


def sms_second_factor(dsid, idms_token):
    """Request and validate a 2FA code the way AltSign does.

    GSA-native flow (no idmsa involved): GET /auth/verify/trusteddevice pushes a
    code to the account's trusted devices, then GET
    /grandslam/GsService2/validate with a `security-code` header confirms it.

    The older pypush path via idmsa.apple.com/appleauth/* now needs an idmsa
    signin session (X-Apple-ID-Session-Id / scnt), which the GrandSlam SRP flow
    never returns, so it answers 401/403.
    """
    identity_token = base64.b64encode(
        (dsid + ":" + idms_token).encode()).decode()

    client_info, user_agent = anisette_client_identity()

    base = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "text/x-xml-plist",
        "Accept-Language": "en-us",
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Apple-Identity-Token": identity_token,
        "X-MMe-Client-Info": client_info,
    }
    base.update(generate_anisette_headers())

    # The ADI/identity pairing is what Apple checks, but the exact User-Agent
    # accepted by this endpoint varies, so try the matching one first.
    headers = None
    response = None
    for ua in (user_agent, "Xcode"):
        attempt = dict(base)
        attempt["User-Agent"] = ua
        response = requests.get("https://gsa.apple.com/auth/verify/trusteddevice",
                                headers=attempt, verify=False, timeout=30)
        logger.debug("verify/trusteddevice (UA=%s) -> %s", ua, response.status_code)
        if response.status_code == 200:
            headers = attempt
            break
    if headers is None:
        raise Exception("Could not request a 2FA code (HTTP %s)."
                        % (response.status_code if response is not None else "?"))

    logger.info("A 2FA code was sent to your trusted Apple devices "
                "(iPhone/iPad/Mac). Check for the notification.")
    for handler in logger.handlers:
        handler.flush()
    code = input("Enter the 2FA code shown on your trusted device: ").strip()

    headers["security-code"] = code
    resp = requests.get("https://gsa.apple.com/grandslam/GsService2/validate",
                        headers=headers, verify=False, timeout=30)
    resp.raise_for_status()

    try:
        data = plist.loads(resp.content)
    except Exception:  # noqa: BLE001
        data = {}
    status = data.get("Response", {}).get("Status", data)
    if not isinstance(status, dict):
        status = {}
    ec = status.get("ec", 0)
    if ec != 0:
        raise Exception("2FA failed: %s (ec %s)"
                        % (status.get("em", "unknown error"), ec))
    logger.info("2FA successful")


def request_code(headers,sms_id):
    # This will send the 2FA code to the user's phone over SMS
    # We don't care about the response, it's just some HTML with a form for entering the code
    # Easier to just use a text prompt
    logger.debug(headers)
    body = {"phoneNumber": {"id": sms_id}, "mode": "sms"}
    logger.info(f"Sending SMS via id {sms_id}")
    with requests.put(
            "https://idmsa.apple.com/appleauth/auth/verify/phone",
            json=body,
            headers=headers,
            verify=False,
            timeout=5
    ) as req:
        req.raise_for_status()
    code = input(f"Enter SMS 2FA code:")
    return code
