import csv
import requests
import time
import json

# Your live Render backend
BASE_URL = "https://phishguard-backend-2rnx.onrender.com/scan"

# Results tracking
results = {
    "DANGEROUS": 0,
    "SUSPICIOUS": 0,
    "SAFE": 0,
    "ERROR": 0
}

total = 0
correctly_flagged = 0  # DANGEROUS or SUSPICIOUS count as correct for phishing URLs

print("Starting PhishGuard Benchmark Test...")
print("=" * 60)

with open("verified_online.csv", "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        if total >= 30:  # Test first 30 URLs
            break

        url = row.get("url", "").strip()
        if not url:
            continue

        try:
            response = requests.post(
                BASE_URL,
                json={"url": url},
                timeout=15
            )
            data = response.json()
            verdict = data.get("verdict", "ERROR")
            score = data.get("score", 0)

            results[verdict] = results.get(verdict, 0) + 1

            if verdict in ["DANGEROUS", "SUSPICIOUS"]:
                correctly_flagged += 1
                status = "DETECTED"
            else:
                status = "MISSED"

            print(f"{status} [{verdict}] Score:{score} - {url[:60]}")
            total += 1
            time.sleep(1)  # Be polite to the API

        except Exception as e:
            results["ERROR"] += 1
            print(f"ERROR - {url[:60]} - {e}")
            total += 1

print("\n" + "=" * 60)
print("BENCHMARK RESULTS SUMMARY")
print("=" * 60)
print(f"Total URLs tested:     {total}")
print(f"Correctly flagged:     {correctly_flagged}")
print(f"Missed (SAFE):         {results.get('SAFE', 0)}")
print(f"Errors:                {results.get('ERROR', 0)}")
print(f"\nDetection Rate:        {(correctly_flagged/total*100):.1f}%")
print(f"  - DANGEROUS:         {results.get('DANGEROUS', 0)}")
print(f"  - SUSPICIOUS:        {results.get('SUSPICIOUS', 0)}")
print("=" * 60)