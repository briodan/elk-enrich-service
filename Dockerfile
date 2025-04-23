FROM python:3.10-slim

# Install dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install supercronic for cron scheduling
RUN apt update && apt install -y curl && \
    curl -sSLo /usr/local/bin/supercronic https://github.com/aptible/supercronic/releases/latest/download/supercronic-linux-amd64 && \
    chmod +x /usr/local/bin/supercronic

# Add enrichment script and cron schedule
COPY enrich.py .
COPY crontab.txt .

CMD ["/usr/local/bin/supercronic", "/app/crontab.txt"]
