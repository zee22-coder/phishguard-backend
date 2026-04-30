import re
import joblib
import numpy as np
import os
from urllib.parse import urlparse

# Load ML model if available
MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishguard_model.pkl")
try:
    ml_model = joblib.load(MODEL_PATH)
    ML_AVAILABLE = True
except:
    ml_model = None
    ML_AVAILABLE = False


def extract_features(url):
    """Extract numerical features from a URL for ML classification."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        full_url = url.lower()

        features = {
            "url_length": len(url),
            "domain_length": len(domain),
            "num_dots": url.count("."),
            "num_hyphens": url.count("-"),
            "num_slashes": url.count("/"),
            "num_at": url.count("@"),
            "num_question": url.count("?"),
            "num_equals": url.count("="),
            "num_underscores": url.count("_"),
            "num_percent": url.count("%"),
            "num_ampersand": url.count("&"),
            "is_http": 1 if url.startswith("http://") else 0,
            "has_ip": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0,
            "has_suspicious_keyword": 1 if any(k in full_url for k in [
                "login", "verify", "secure", "account", "update",
                "banking", "confirm", "password", "signin", "wallet"
            ]) else 0,
            "has_shortener": 1 if any(s in full_url for s in [
                "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"
            ]) else 0,
            "num_subdomains": domain.count("."),
            "path_length": len(path),
            "has_special_chars": 1 if re.search(r"[^a-zA-Z0-9.\-/:]", domain) else 0,
            "has_brand_in_path": 1 if any(b in path.lower() for b in [
                "paypal", "google", "facebook", "amazon", "apple",
                "microsoft", "netflix", "instagram", "twitter"
            ]) else 0,
        }
        return list(features.values())
    except:
        return [0] * 19


def analyse_url(url):
    findings = []
    score = 0

    parsed = urlparse(url)
    domain = parsed.netloc
    full_url = url.lower()

    # Layer 0: ML Model prediction
    if ML_AVAILABLE:
        try:
            features = extract_features(url)
            prediction = ml_model.predict([features])[0]
            probability = ml_model.predict_proba([features])[0][1]

            if prediction == 1 and probability >= 0.8:
                findings.append(f"ML model flagged this URL as phishing (confidence: {probability*100:.1f}%).")
                score += 40
            elif prediction == 1 and probability >= 0.5:
                findings.append(f"ML model considers this URL suspicious (confidence: {probability*100:.1f}%).")
                score += 20
        except:
            pass

    # Check 0: Insecure HTTP
    if url.startswith("http://"):
        findings.append("Uses insecure HTTP protocol")
        score += 10

    # Check 1: IP address used instead of domain name
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        findings.append("Uses an IP address instead of a domain name — a common phishing trick.")
        score += 30

    # Check 2: URL is excessively long
    if len(url) > 100:
        findings.append("URL is unusually long, which is often used to hide the true destination.")
        score += 10

    # Check 3: Too many hyphens in domain
    if domain.count("-") > 3:
        findings.append("Domain contains excessive hyphens, commonly seen in fake websites.")
        score += 15

    # Check 4: Too many subdomains
    if domain.count(".") > 3:
        findings.append("URL has too many subdomains, which is a common phishing pattern.")
        score += 15

    # Check 5: Suspicious keywords in URL
    suspicious_keywords = ["login", "verify", "secure", "account", "update",
                           "banking", "confirm", "password", "signin", "wallet"]
    for keyword in suspicious_keywords:
        if keyword in full_url:
            findings.append(f"URL contains the suspicious keyword '{keyword}'.")
            score += 10
            break

    # Check 6: URL shortener detected
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
                  "is.gd", "buff.ly", "adf.ly", "shorturl.at"]
    for shortener in shorteners:
        if shortener in full_url:
            findings.append("URL uses a shortening service that hides the real destination.")
            score += 20
            break

    # Check 7: No HTTPS
    if parsed.scheme != "https":
        findings.append("URL does not use HTTPS — the connection is not secure.")
        score += 15

    # Check 8: Special characters in domain
    if re.search(r"[^a-zA-Z0-9.\-]", domain):
        findings.append("Domain contains unusual special characters.")
        score += 20

    # Check 9: Typosquatting common brands
    brands = ["paypal", "google", "facebook", "amazon", "apple",
              "microsoft", "netflix", "instagram", "twitter", "mtn", "airtel"]
    for brand in brands:
        if brand in full_url and brand not in domain:
            findings.append(f"URL mentions '{brand}' but it is not the real {brand} website — possible typosquatting.")
            score += 25
            break

    return score, findings