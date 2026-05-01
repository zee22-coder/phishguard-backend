import os
import requests
from flask import Blueprint, request, jsonify
from app.heuristics import analyse_url
from dotenv import load_dotenv

load_dotenv()

scanner_bp = Blueprint("scanner", __name__)

GOOGLE_KEY = os.getenv("GOOGLE_API_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")
def expand_url(url):
    """Expand shortened URLs to reveal the real destination."""
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                  "is.gd", "buff.ly", "adf.ly", "shorturl.at", "tiny.cc"]
    try:
        domain = url.split("/")[2] if "/" in url else ""
        if any(s in domain for s in shorteners):
            response = requests.head(url, allow_redirects=True, timeout=5)
            expanded = response.url
            if expanded != url:
                return expanded, f"Shortened URL expanded to: {expanded}"
    except Exception:
        pass
    return url, None


def check_google_safe_browsing(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_KEY}"
    payload = {
        "client": {
            "clientId": "phishguard",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        result = response.json()
        if "matches" in result and len(result["matches"]) > 0:
            return True, "Google Safe Browsing flagged this URL as dangerous."
        return False, None
    except Exception:
        return False, None


def check_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_KEY}
    params = {"url": url}
    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data=params,
            timeout=10
        )
        result = response.json()
        analysis_id = result.get("data", {}).get("id", "")
        if not analysis_id:
            return 0, 0
        analysis_response = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10
        )
        analysis = analysis_response.json()
        stats = analysis.get("data", {}).get("attributes", {}).get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return malicious, suspicious
    except Exception:
        return 0, 0


@scanner_bp.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data["url"].strip()

    if not url.startswith("http"):
        url = "http://" + url
        # Expand shortened URLs
    expanded_url, expand_message = expand_url(url)
    if expanded_url != url:
        url = expanded_url
        findings.append(expand_message)
        score += 10

    findings = []
    score = 0

    # Layer 1 — Google Safe Browsing
    gsb_flagged, gsb_message = check_google_safe_browsing(url)
    if gsb_flagged:
        findings.append(gsb_message)
        score += 60

    # Layer 2 — Heuristic Analysis
    heuristic_score, heuristic_findings = analyse_url(url)
    score += heuristic_score
    findings.extend(heuristic_findings)

    # Layer 3 — VirusTotal
    vt_malicious, vt_suspicious = check_virustotal(url)
    if vt_malicious > 0:
        findings.append(f"VirusTotal: {vt_malicious} security engines flagged this URL as malicious.")
        score += min(vt_malicious * 10, 50)
    if vt_suspicious > 0:
        findings.append(f"VirusTotal: {vt_suspicious} security engines flagged this URL as suspicious.")
        score += min(vt_suspicious * 5, 20)

    score = min(score, 100)

    if gsb_flagged or vt_malicious >= 3 or score >= 60:
        verdict = "DANGEROUS"
        message = "This link shows strong signs of being a phishing attempt. Do not click it."
    elif score >= 30:
        verdict = "SUSPICIOUS"
        message = "This link has some suspicious characteristics. Proceed with caution."
    else:
        verdict = "SAFE"
        message = "No obvious phishing patterns were detected in this link."

    if score >= 60:
        confidence = "High"
    elif score >= 30:
        confidence = "Medium"
    else:
        confidence = "Low"

    return jsonify({
        "url": url,
        "verdict": verdict,
        "message": message,
        "score": score,
        "confidence": confidence,
        "findings": findings,
        "layers_checked": {
            "google_safe_browsing": gsb_flagged,
            "heuristics": heuristic_score,
            "virustotal_malicious": vt_malicious,
            "virustotal_suspicious": vt_suspicious
        }
    })


@scanner_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "PhishGuard backend is running!"})