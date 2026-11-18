FROM christld/macless-haystack

WORKDIR /app

# Apple's Oct-2026 GrandSlam change: send the same client identity the Anisette
# server was provisioned with, otherwise logins get an HTML 503 at SRP init.
COPY patched/pypush_gsa_icloud.py /app/endpoint/register/pypush_gsa_icloud.py

# Apple now answers only the tail of a multi-id fetch when the request carries a
# startDate (see patch_endpoint.py). Drop it so one request can carry a whole
# key ring again; the endpoint still filters by --days locally.
COPY patch_endpoint.py /tmp/patch_endpoint.py
RUN python3 /tmp/patch_endpoint.py

# Skip ./endpoint/updateRepo: it fails to advance past the March 2026 commit and
# a `git pull` would fight the patched file.
ENTRYPOINT ["sh", "-c", "python -u endpoint/mh_endpoint.py"]
