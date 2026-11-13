FROM python:3.12-slim

RUN pip install --no-cache-dir cryptography

WORKDIR /app
COPY scripts/map_server.py scripts/decrypt_reports.py /app/

EXPOSE 8080

# ENTRYPOINT so extra args (e.g. --endpoint, --key-file) are appended, not
# replacing the interpreter.
ENTRYPOINT ["python", "-u", "/app/map_server.py"]
CMD ["--host", "0.0.0.0", "--port", "8080"]
