
import streamlit as st
import numpy as np
import pandas as pd
import joblib
from feature_extraction import extract_features

st.set_page_config(page_title="PhishGuard - Smart URL Analyzer", page_icon="🕵‍♀")
st.title("🕵‍♀ PhishGuard: Phishing URL Detection")
st.markdown("A machine learning powered web app to detect phishing websites in real time.")
st.markdown("Paste a URL and the app will show the feature vector, probability and prediction.")

# Load model (URL-only model)
model = joblib.load("phishing_model_url.pkl")

# Column names must match training order
feature_names = [
    "NumDots","SubdomainLevel","PathLevel","UrlLength","NumDash",
    "NumDashInHostname","AtSymbol","TildeSymbol","NumUnderscore",
    "NumPercent","NumQueryComponents","NumAmpersand","NumHash",
    "NumNumericChars","NoHttps","IpAddress","DomainInSubdomains",
    "DomainInPaths","HttpsInHostname","HostnameLength","PathLength",
    "QueryLength","DoubleSlashInPath","NumSensitiveWords",
    "EmbeddedBrandName"
]

url = st.text_input("Enter Website URL (e.g. https://example.com):", "")
threshold = 0.35
st.info(f"🔧 Using fixed phishing probability threshold = {threshold}")



if st.button("🔍 Analyze URL"):
    if not url.strip():
        st.warning("Please enter a URL.")
    else:
        try:
            feats = extract_features(url)  # list of 25 features
            # Convert to DataFrame with column names (exact order)
            df_feats = pd.DataFrame([feats], columns=feature_names)

            # Show the features so you can inspect them
            st.subheader("Feature vector used for prediction")
            st.table(df_feats.T.rename(columns={0: "value"}))

            # Predict
            proba = model.predict_proba(df_feats)[0]  # [prob_legit, prob_phish]
            phish_prob = float(proba[1])
            pred = 1 if phish_prob >= threshold else 0

            st.metric("Phishing probability", f"{phish_prob*100:.2f}%")
            if pred == 1:
                st.error(f"🚨 Predicted: PHISHING (threshold {threshold:.2f})")
            else:
                st.success(f"✅ Predicted: LEGITIMATE (threshold {threshold:.2f})")

            # Append debug info to CSV for later analysis
            log_row = df_feats.copy()
            log_row["phish_prob"] = phish_prob
            log_row["pred_at_threshold"] = pred
            try:
                # append to debug_log.csv (create if not exists)
                log_row.to_csv("debug_log.csv", mode="a", header=not pd.io.common.file_exists("debug_log.csv"), index=False)
            except Exception as e:
                st.write("Warning: could not write debug log:", e)

        except Exception as e:
            st.error(f"Error analyzing URL: {e}")