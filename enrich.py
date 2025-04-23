import os
import time
import csv
import json
import requests
import ipaddress
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

# === Environment Configuration ===
ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
INDEX_PATTERN = os.getenv("INDEX_PATTERN", "logs-*")
IP_FIELD = os.getenv("IP_FIELD", "dest_ip.keyword")
API_KEY = os.getenv("API_KEY")
OUTPUT_CSV = os.getenv("OUTPUT_CSV", "/data/whois.csv")
MAX_IPS = int(os.getenv("MAX_IPS", 10000))
RATE_LIMIT_SECONDS = float(os.getenv("RATE_LIMIT_SECONDS", 1.2))
CACHE_FILE = os.getenv("CACHE_FILE", "/data/ip_cache.json")
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("true", "1", "yes")
CRON_SCHEDULE = os.getenv("CRON_SCHEDULE", "*/5 * * * *")  # Default to every 5 minutes

# === Validate Required Environment Variables ===
if not API_KEY and not DRY_RUN:
    print("[ERROR] API_KEY is required unless DRY_RUN is enabled.")
    exit(1)

# === Elasticsearch Connection with Retry ===
es = None
for attempt in range(10):
    try:
        es = Elasticsearch(
            ES_HOST,
            verify_certs=False,
            request_timeout=30,
            retry_on_timeout=True,
            max_retries=3,
        )
        health = es.cluster.health()
        print(f"[INFO] Connected to Elasticsearch at {ES_HOST} — Cluster status: {health['status']}")
        break
    except Exception as e:
        print(f"[WAIT] Attempt {attempt + 1}/10: Elasticsearch not ready: {e}")
        time.sleep(10)
else:
    print("[ERROR] Failed to connect to Elasticsearch after 10 attempts.")
    exit(1)

# === Build Time-Bound Query (Past 24 Hours) ===
now = datetime.utcnow()
since = now - timedelta(hours=24)
query = {
    "size": 0,
    "query": {
        "range": {
            "@timestamp": {
                "gte": since.isoformat(),
                "lte": now.isoformat()
            }
        }
    },
    "aggs": {
        "unique_ips": {
            "terms": {
                "field": IP_FIELD,
                "size": MAX_IPS
            }
        }
    }
}

# === Fetch Unique IPs ===
try:
    response = es.search(index=INDEX_PATTERN, body=query)
    buckets = response.get("aggregations", {}).get("unique_ips", {}).get("buckets", [])
    raw_ips = [bucket["key"] for bucket in buckets]
    ip_list = []
    for ip in raw_ips:
        try:
            parsed = ipaddress.ip_address(ip)
            if not (parsed.is_private or parsed.is_loopback or parsed.is_reserved or parsed.is_link_local):
                ip_list.append(ip)
            else:
                print(f"[SKIP] Skipping private/reserved IP: {ip}")
        except ValueError:
            print(f"[WARN] Invalid IP skipped: {ip}")
    print(f"[INFO] Retrieved {len(ip_list)} public IPs out of {len(raw_ips)} total.")
except Exception as e:
    print(f"[ERROR] Failed to query Elasticsearch: {e}")
    exit(1)

# === Load Cache (if exists) ===
cache = {}
cache_expiry = timedelta(days=5)
if os.path.exists(CACHE_FILE):
    try:
        with open(CACHE_FILE, "r") as f:
            raw_cache = json.load(f)
            now_ts = datetime.utcnow().timestamp()
            for ip, record in raw_cache.items():
                if 'timestamp' in record and now_ts - record['timestamp'] <= cache_expiry.total_seconds():
                    cache[ip] = record
    except Exception as e:
        print(f"[WARN] Failed to load cache file: {e}")

# === Enrich IPs and Write CSV ===
try:
    with open(OUTPUT_CSV, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["ip", "abuse_score", "country", "isp"])

        for ip in ip_list:
            if ip in cache:
                print(f"[CACHE] Using cached result for {ip}")
                row = cache[ip]
            elif DRY_RUN:
                print(f"[DRY_RUN] Skipping enrichment for {ip}")
                row = {"abuse_score": "", "country": "", "isp": ""}
            else:
                try:
                    response = requests.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={
                            "Key": API_KEY,
                            "Accept": "application/json"
                        },
                        params={"ipAddress": ip, "maxAgeInDays": 90},
                        timeout=10
                    )
                    if response.status_code == 429:
                        retry_after = int(response.headers.get("Retry-After", RATE_LIMIT_SECONDS))
                        print(f"[RATE_LIMIT] Hit limit. Sleeping for {retry_after} seconds...")
                        time.sleep(retry_after)
                        continue
                    elif response.status_code != 200:
                        print(f"[WARN] API error for {ip}: {response.status_code} - {response.text}")
                        continue
                    data = response.json()["data"]
                    row = {
                        "abuse_score": data.get("abuseConfidenceScore", ""),
                        "country": data.get("countryCode", ""),
                        "isp": data.get("isp", ""),
                        "timestamp": datetime.utcnow().timestamp()
                    }
                    cache[ip] = row
                    print(f"[INFO] Enriched {ip}")
                except Exception as e:
                    print(f"[ERROR] Failed to enrich {ip}: {e}")
                    continue
                time.sleep(RATE_LIMIT_SECONDS)

            writer.writerow([ip, row.get("abuse_score", ""), row.get("country", ""), row.get("isp", "")])

    # Save updated cache
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except Exception as e:
        print(f"[WARN] Failed to save cache: {e}")

    print(f"[INFO] Enrichment complete. Data written to {OUTPUT_CSV}")
except Exception as e:
    print(f"[ERROR] Failed to write CSV: {e}")
    exit(1)
