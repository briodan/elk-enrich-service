import requests

ES_HOST = "http://10.10.10.215:9200"

try:
    response = requests.get(ES_HOST, timeout=5)
    print(f"HTTP status: {response.status_code}")
    print(response.text)
except Exception as e:
    print(f"[ERROR] Failed to reach Elasticsearch: {e}")
