FROM python:3.12-slim

RUN pip install --no-cache-dir cryptography

WORKDIR /app

# Keep the repo layout inside the image so map_server.py's defaults
# (ROOT/scripts, ROOT/keys) resolve the same way as in a checkout.
COPY scripts/map_server.py scripts/decrypt_reports.py /app/scripts/
COPY scripts/web /app/scripts/web

EXPOSE 8080

# ENTRYPOINT so extra args (e.g. --endpoint, --keys-file) are appended, not
# replacing the interpreter.
ENTRYPOINT ["python", "-u", "/app/scripts/map_server.py"]
CMD ["--host", "0.0.0.0", "--port", "8080"]
