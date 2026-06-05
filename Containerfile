FROM python:3.12-slim

WORKDIR /app

# Install dependencies (separate layer for better cache reuse)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY scanner_ingest/ ./scanner_ingest/
COPY web/            ./web/

# /data is mounted from the host — holds tokens.json and processed_files.log
VOLUME ["/data"]

ENV SYNACK_TOKEN_FILE=/data/tokens.json

EXPOSE 8080

CMD ["python", "-m", "uvicorn", "web.ingest_ui:app", "--host", "0.0.0.0", "--port", "8080"]
