FROM christld/macless-haystack

WORKDIR /app

# Apple's Oct-2026 GrandSlam change: send the same client identity the Anisette
# server was provisioned with, otherwise logins get an HTML 503 at SRP init.
COPY patched/pypush_gsa_icloud.py /app/endpoint/register/pypush_gsa_icloud.py

# Skip ./endpoint/updateRepo: it fails to advance past the March 2026 commit and
# a `git pull` would fight the patched file.
ENTRYPOINT ["sh", "-c", "python -u endpoint/mh_endpoint.py"]
