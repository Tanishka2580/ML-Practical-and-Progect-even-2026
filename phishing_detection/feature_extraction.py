# feature_extraction.py
import re
import urllib.parse as urlparse

# 🧠 Common brand and sensitive keywords for phishing detection
BRAND_KEYWORDS = [
    "paypal", "facebook", "google", "gmail", "amazon", "bank", "login",
    "secure", "ebay", "microsoft", "apple", "netflix"
]
SENSITIVE_WORDS = ["secure", "account", "bank", "login", "update", "verify", "confirm", "password"]

def is_ip(hostname):
    """Return 1 if hostname looks like an IP address, else 0."""
    return 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0

def extract_features(url):
    """
    Returns a list of numeric features (in the same order used for training).
    """
    parsed = urlparse.urlparse(url if "://" in url else "http://" + url)
    hostname = parsed.netloc.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full = url.lower()

    # Basic structural features
    num_dots = full.count(".")
    host_parts = [p for p in hostname.split(".") if p]
    subdomain_level = len(host_parts) - 2 if len(host_parts) > 2 else 0
    path_level = path.count("/")
    url_length = len(full)
    num_dash = full.count("-")
    num_dash_in_hostname = hostname.count("-")
    at_symbol = int("@" in full)
    tilde_symbol = int("~" in full)
    num_underscore = full.count("_")
    num_percent = full.count("%")
    num_query_components = len(query.split("&")) if query else 0
    num_ampersand = full.count("&")
    num_hash = full.count("#")
    num_numeric_chars = sum(c.isdigit() for c in full)
    no_https = int(not full.startswith("https://"))
    ip_address = is_ip(hostname)
    domain_in_subdomains = int(len(host_parts) >= 3 and host_parts[-2] in host_parts[:-2])
    domain_in_paths = int(len(host_parts) >= 2 and (host_parts[-2] in path))
    https_in_hostname = int("https" in hostname)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)
    double_slash_in_path = int("//" in path)
    num_sensitive_words = sum(1 for w in SENSITIVE_WORDS if w in full)
    embedded_brand_name = int(any(b in full for b in BRAND_KEYWORDS))

    return [
        num_dots,
        subdomain_level,
        path_level,
        url_length,
        num_dash,
        num_dash_in_hostname,
        at_symbol,
        tilde_symbol,
        num_underscore,
        num_percent,
        num_query_components,
        num_ampersand,
        num_hash,
        num_numeric_chars,
        no_https,
        ip_address,
        domain_in_subdomains,
        domain_in_paths,
        https_in_hostname,
        hostname_length,
        path_length,
        query_length,
        double_slash_in_path,
        num_sensitive_words,
        embedded_brand_name,
    ]

# 🧩 Utility for showing feature vector + confidence (for UI)
def get_confidence(prob, threshold=0.35):
    """
    Convert phishing probability into a user-friendly confidence value (0–100%).
    The farther it is from the threshold, the higher the confidence.
    """
    confidence = round(abs(prob - threshold) * 200, 2)
    return min(confidence, 100.0)

# 🔍 Quick testing
if __name__ == "__main__":
    tests = [
        "https://www.google.com",
        "http://paypal-login-verify-account.com/login",
        "http://192.168.0.1/admin",
        "https://secure-update-bank123.net/login?user=1"
    ]
    for t in tests:
        print(f"\n🔗 {t}")
        features = extract_features(t)
        print("Feature vector:", features)
