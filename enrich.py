import os
import time
import csv
import requests
from elasticsearch import Elasticsearch

# === ENVIRONMENT CONFIG ===

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
INDEX_PATTERN = os.getenv("INDEX_PATTERN", "logs-*")
IP_FIELD = os.getenv("IP_FIELD", "dst_ip.keyword")
API_KEY = os.getenv("API_KEY")
OUTPUT_CSV = os.getenv("OUTPUT_CSV", "/data/whois.csv")
MAX_IPS = int(os.getenv("MAX_IPS", 10000))
RATE_LIMIT_SECONDS = float(os.getenv("RATE_LIMIT_SECONDS", 1.2))

# === CHECK FOR REQUIRED CONFIG ===

if not API_KEY:
    print("[ERROR] API_KEY not set.")
    exit(1)

# === ELASTIC CONNECTION (WITH RETRY) ===

print(f"[INFO] Connecting to Elasticsearch at {ES_HOST}...")

es = None
for attempt in range(10):
    try:
        es = Elasticsearch(ES_HOST)
        if es.ping():
            print("[INFO] Connected to Elasticsearch.")
            break
        else:
            raise Exception("Ping failed")
    except Exception as e:
        print(f"[WAIT] Elasticsearch not ready (attempt {attempt + 1}/10): {e}")
        time.sleep(10)
else:
    print("[ERROR] Failed to connect to Elasticsearch after 10 attempts.")
    exit(1)

# === AGGREGATE IPs ===

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
except Exception as e:
    print(f"[ERROR] Elasticsearch query failed: {e}")
    exit(1)

print(f"[INFO] Retrieved {len(ip_list)} unique IPs.")

# === ENRICH AND WRITE CSV ===

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
