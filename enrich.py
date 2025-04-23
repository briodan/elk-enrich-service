import os
import time
import csv
import requests
from elasticsearch import Elasticsearch
from elasticsearch import RequestsHttpConnection

# === Environment Configuration ===
ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
INDEX_PATTERN = os.getenv("INDEX_PATTERN", "logs-*")
IP_FIELD = os.getenv("IP_FIELD", "dst_ip.keyword")
API_KEY = os.getenv("API_KEY")
OUTPUT_CSV = os.getenv("OUTPUT_CSV", "/data/whois.csv")
MAX_IPS = int(os.getenv("MAX_IPS", 10000))
RATE_LIMIT_SECONDS = float(os.getenv("RATE_LIMIT_SECONDS", 1.2))

# === Check Required ENV ===
if not API_KEY:
    print("[ERROR] API_KEY not set in environment.")
    exit(1)

# === Connect to Elasticsearch with Retry ===
es = None
for attempt in range(10):
    try:
        es = Elasticsearch(
            ES_HOST,
            verify_certs=False,
            request_timeout=30,
            retry_on_timeout=True,
            max_retries=3
        )
        if es.ping():
            print(f"[INFO] Connected to Elasticsearch at {ES_HOST}")
            break
        else:
            raise Exception("Ping failed")
    except Exception as e:
        print(f"[WAIT] Attempt {attempt + 1}/10: Elasticsearch not ready: {e}")
        time.sleep(10)
else:
    print("[ERROR] Failed to connect to Elasticsearch after 10 attempts.")
    exit(1)

# === Query IPs from Elasticsearch ===
query = {
    "size": 0,
    "aggs": {
        "unique_ips": {
            "terms": {
                "field": IP_FIELD,
                "size": MAX_IPS
            }
        }
    }
}

try:
    response = es.search(index=INDEX_PATTERN, body=query)
    buckets = response.get("aggregations", {}).get("unique_ips", {}).get("buckets", [])
    ip_list = [bucket["key"] for bucket in buckets]
    print(f"[INFO] Retrieved {len(ip_list)} unique IPs.")
except Exception as e:
    print(f"[ERROR] Failed to query Elasticsearch: {e}")
    exit(1)

# === Enrich and Write CSV ===
try:
    with open(OUTPUT_CSV, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["ip", "abuse_score", "country", "isp"])

        for ip in ip_list:
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
                if response.status_code == 200:
                    data = response.json()["data"]
                    writer.writerow([
                        ip,
                        data.get("abuseConfidenceScore", ""),
                        data.get("countryCode", ""),
                        data.get("isp", "")
                    ])
                    print(f"[INFO] Enriched {ip}")  # ✅ LINE 92
                else:
                    print(f"[WARN] API error for {ip}: {response.status_code} - {response.text}")
            except Exception as e:
                print(f"[ERROR] Failed to enrich {ip}: {e}")
            time.sleep(RATE_LIMIT_SECONDS)

    print(f"[INFO] Enrichment complete. Data written to {OUTPUT_CSV}")
except Exception as e:
    print(f"[ERROR] Failed to write CSV: {e}")
    exit(1)
