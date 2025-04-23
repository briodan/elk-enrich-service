FROM python:3.10-slim

WORKDIR /app

# Copy and install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install supercronic (lightweight cron runner)
RUN apt update && apt install -y curl && \
    curl -sSLo /usr/local/bin/supercronic https://github.com/aptible/supercronic/releases/latest/download/supercronic-linux-amd64 && \
    chmod +x /usr/local/bin/supercronic

# Add enrichment script and cron definition
COPY enrich.py .
COPY crontab.txt .

# Set up cron scheduler
CMD ["/usr/local/bin/supercronic", "/app/crontab.txt"]
