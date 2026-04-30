import re
from urllib.parse import urlparse

def analyse_url(url):
    findings = []
    score = 0

    parsed = urlparse(url)
    domain = parsed.netloc
    full_url = url.lower()

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