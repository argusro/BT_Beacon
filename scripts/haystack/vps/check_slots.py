import json
import urllib.request

keys = json.load(open("/keys/beacon_keys.json"))["keys"]
hashes = [k["hash_b64"] for k in keys[55:62]]
body = json.dumps({"ids": hashes, "days": 7}).encode()
req = urllib.request.Request(
    "http://endpoint:6176/", data=body,
    headers={"Content-Type": "application/json"},
)
r = json.load(urllib.request.urlopen(req, timeout=150))
print("rotated slots 56-62:", r.get("statusCode"), "->", len(r.get("results", [])), "reports")
for x in r.get("results", [])[:4]:
    print("  id", x["id"][:18], "statusCode", x.get("statusCode"))

allkeys = [k["hash_b64"] for k in keys]
body = json.dumps({"ids": allkeys, "days": 7}).encode()
req = urllib.request.Request(
    "http://endpoint:6176/", data=body,
    headers={"Content-Type": "application/json"},
)
r = json.load(urllib.request.urlopen(req, timeout=150))
print("all 96 slots       :", r.get("statusCode"), "->", len(r.get("results", [])), "reports")
