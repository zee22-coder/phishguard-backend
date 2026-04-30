import pandas as pd
import numpy as np
import re
import joblib
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

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


print("Loading PhishTank dataset...")
df = pd.read_csv("verified_online.csv")
print(f"Loaded {len(df)} phishing URLs")

# All PhishTank URLs are phishing (label = 1)
phishing_urls = df["url"].dropna().tolist()[:2000]

# Legitimate URLs for training (label = 0)
legitimate_urls = [
    "https://www.google.com",
    "https://www.facebook.com",
    "https://www.amazon.com",
    "https://www.wikipedia.org",
    "https://www.youtube.com",
    "https://www.twitter.com",
    "https://www.instagram.com",
    "https://www.linkedin.com",
    "https://www.github.com",
    "https://www.stackoverflow.com",
    "https://www.reddit.com",
    "https://www.netflix.com",
    "https://www.apple.com",
    "https://www.microsoft.com",
    "https://www.bbc.com",
    "https://www.cnn.com",
    "https://www.nytimes.com",
    "https://www.ebay.com",
    "https://www.paypal.com",
    "https://www.dropbox.com",
    "https://www.spotify.com",
    "https://www.airbnb.com",
    "https://www.uber.com",
    "https://www.zoom.us",
    "https://www.slack.com",
    "https://www.whatsapp.com",
    "https://www.telegram.org",
    "https://www.mtn.co.ug",
    "https://www.airtel.co.ug",
    "https://www.nkumba.ac.ug",
] * 50  # Repeat to balance dataset

print(f"Using {len(phishing_urls)} phishing URLs")
print(f"Using {len(legitimate_urls)} legitimate URLs")

# Build feature matrix
print("Extracting features...")
X = []
y = []

for url in phishing_urls:
    X.append(extract_features(url))
    y.append(1)  # phishing

for url in legitimate_urls:
    X.append(extract_features(url))
    y.append(0)  # legitimate

X = np.array(X)
y = np.array(y)

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print(f"Training on {len(X_train)} samples...")

# Train Random Forest
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print("\n" + "=" * 60)
print("RANDOM FOREST MODEL RESULTS")
print("=" * 60)
print(f"Accuracy: {accuracy * 100:.1f}%")
print("\nDetailed Report:")
print(classification_report(y_test, y_pred,
      target_names=["Legitimate", "Phishing"]))
print("=" * 60)

# Save model
joblib.dump(model, "app/phishguard_model.pkl")
print("Model saved to app/phishguard_model.pkl")