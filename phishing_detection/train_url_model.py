# train_url_model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

# 1) Load CSV
df = pd.read_csv("phishing.csv")

# 2) Columns we can extract from URL (must match feature_extraction.py order)
url_columns = [
    "NumDots", "SubdomainLevel", "PathLevel", "UrlLength", "NumDash",
    "NumDashInHostname", "AtSymbol", "TildeSymbol", "NumUnderscore",
    "NumPercent", "NumQueryComponents", "NumAmpersand", "NumHash",
    "NumNumericChars", "NoHttps", "IpAddress", "DomainInSubdomains",
    "DomainInPaths", "HttpsInHostname", "HostnameLength", "PathLength",
    "QueryLength", "DoubleSlashInPath", "NumSensitiveWords",
    "EmbeddedBrandName"
]

# 3) Verify columns exist
missing = [c for c in url_columns if c not in df.columns]
if missing:
    print("Missing columns from CSV needed for URL model:", missing)
    raise SystemExit

X = df[url_columns]
y = df["CLASS_LABEL"]

# 4) Train/test split (stratify to preserve class balance)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 5) Train model
model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# 6) Evaluate
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"✅ URL-only model trained. Accuracy: {acc*100:.2f}%\n")
print("📊 Classification report:\n")
print(classification_report(y_test, y_pred))

# 7) Save model
joblib.dump(model, "phishing_model_url.pkl")
print("\n💾 Saved model as phishing_model_url.pkl")
