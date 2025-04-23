import os
import time
import csv
import requests
from elasticsearch import Elasticsearch, exceptions as es_exceptions

# === CONFIGURATION ===

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
INDEX_PATTERN = os.getenv("INDEX_PATTERN", "logs-*")
IP_FIELD = os.getenv("IP_FIELD", "ip")
API_KEY = os.getenv("API_KEY")
OUTPUT_CSV = os.getenv("OUTPUT_CSV", "/data/whois.csv")
MAX_IPS = int(os.getenv("MAX_IPS", 10000))
RATE_LIMIT_SECONDS = float(os.getenv("RATE_LIMIT_SECONDS", 1.2))

# === VALIDATION ===

if not API_KEY:
    print("[ERROR] API_KEY not set. Exiting.")
    exit(1)

# === Connect to Elasticsearch ===

try:
    es = Elasticsearch(ES_HOST)
    if not es.ping():
        raise ValueError("Could not connect to Elasticsearch.")
except es_exceptions.ConnectionError as e:
    print(f"[ERROR] Elasticsearch connection failed: {e}")
    exit(1)

print(f"[INFO] Connected to Elasticsearch at {ES_HOST}")

# === Get Unique IPs ===

query = {
    "size": 0,
    "aggs": {
        "unique_ips": {
            "terms": {
                "field": f"{IP_FIELD}.keyword",
                "size": MAX_IPS
            }
        }
    }
}

print(f"[INFO] Querying Elasticsearch index: {INDEX_PATTERN}")
try:
    resp = es.search(index=INDEX_PATTERN, body=query)
    ip_buckets = resp.get("aggregations", {}).get("unique_ips", {}).get("buckets", [])
    ip_list = [bucket["key"] for bucket in ip_buckets]
except Exception as e:
    print(f"[ERROR] Failed to query Elasticsearch: {e}")
    exit(1)

print(f"[INFO] Retrieved {len(ip_list)} unique IPs")

# === Enrich and Write CSV ===

with open(OUTPUT_CSV, "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["ip", "abuse_score", "country", "isp"])

    for ip in ip_list:
        print(f"[INFO] Enriching IP: {ip}")
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": API_KEY,
                    "Accept": "application/json"
                },
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90
                },
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
            else:
                print(f"[WARN] API failed for {ip}: {response.status_code} - {response.text}")
        except Exception as ex:
            print(f"[ERROR] Request failed for {ip}: {ex}")

        time.sleep(RATE_LIMIT_SECONDS)  # Avoid rate-limiting

print(f"[INFO] Enrichment complete. Output saved to {OUTPUT_CSV}")
