import streamlit as st
import joblib
import email
from email import policy
from email.parser import BytesParser
import re
import string
import numpy as np
import pickle
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

# --- Load GRU Model and Tokenizer ---
gru_model = load_model("model/phishing_gru_model.h5")
with open("model/tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

# --- Load Legitimate Email Type Classifier ---
legit_model = joblib.load("model/legit_type_classifier.pkl")

# --- Clean Text ---
def clean_text(text):
    text = text.lower()
    text = re.sub(r'https?://\S+|www\.\S+', '', text)
    text = re.sub(r'\[.*?\]', '', text)
    text = re.sub(f"[{re.escape(string.punctuation)}]", '', text)
    text = re.sub(r'\n+', ' ', text)
    text = re.sub(r'\w*\d\w*', '', text)
    return text.strip()

# --- GRU Content Prediction ---
def predict_with_gru(text):
    cleaned = clean_text(text)
    seq = tokenizer.texts_to_sequences([cleaned])
    padded = pad_sequences(seq, maxlen=200, padding='post', truncating='post')
    pred = gru_model.predict(padded)[0][0]
    return 1 if pred >= 0.5 else 0

# --- Extract Body from Email ---
def extract_email_body(uploaded_file):
    try:
        msg = BytesParser(policy=policy.default).parse(uploaded_file)
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    return msg, part.get_content()
        else:
            return msg, msg.get_content()
    except Exception as e:
        return None, f"Error parsing email: {e}"

# --- Header Check Helpers ---
def check_spf(header):
    return "pass" in header.get("Received-SPF", "").lower()

def check_dkim(header):
    return "dkim=pass" in header.get("Authentication-Results", "").lower()

def check_dmarc(header):
    return "dmarc=pass" in header.get("Authentication-Results", "").lower()

def extract_email(addr):
    match = re.search(r'[\w\.-]+@[\w\.-]+', addr)
    return match.group(0).lower() if match else ''

def get_domain(addr):
    match = re.search(r'@([\w\.-]+)', addr)
    return match.group(1).lower() if match else ''

def analyze_from_reply_return(header):
    from_email = extract_email(header.get("From", ""))
    reply_email = extract_email(header.get("Reply-To", ""))
    return_email = extract_email(header.get("Return-Path", ""))

    from_domain = get_domain(from_email)
    reply_domain = get_domain(reply_email)
    return_domain = get_domain(return_email)

    known_relays = ["hubspotemail.net", "sendgrid.net", "mailgun.org", "amazonses.com"]

    if return_domain and any(k in return_domain for k in known_relays):
        domain_match = from_domain == reply_domain
    else:
        domain_match = from_domain == reply_domain == return_domain

    return from_email, reply_email, return_email, domain_match

def analyze_message_id(header):
    from_domain = re.findall(r'@([a-zA-Z0-9.-]+)', header.get("From", ""))
    msgid_domain = re.findall(r'@([a-zA-Z0-9.-]+)', header.get("Message-ID", ""))
    return from_domain == msgid_domain

def phishing_header_score(header):
    score = 0
    notes = []

    if check_spf(header): notes.append("✅ SPF Passed")
    else: notes.append("❌ SPF Failed"); score += 1

    if check_dkim(header): notes.append("✅ DKIM Passed")
    else: notes.append("❌ DKIM Failed"); score += 1

    if check_dmarc(header): notes.append("✅ DMARC Passed")
    else: notes.append("❌ DMARC Failed"); score += 1

    _, _, _, match = analyze_from_reply_return(header)
    if match: notes.append("✅ From/Reply/Return Match")
    else: notes.append("⚠️ From/Reply/Return Mismatch"); score += 1

    if analyze_message_id(header): notes.append("✅ Message-ID domain match")
    else: notes.append("⚠️ Message-ID domain mismatch"); score += 1

    label = "PHISHING ⚠️" if score >= 2 else "LEGITIMATE ✅"
    return score, label, notes

# --- Streamlit UI ---
st.set_page_config(page_title="📧 Email Phishing Detector", layout="centered")
st.title("📧 Email Phishing Detector")

mode = st.radio("Choose Input Method:", ["Upload .eml File", "Paste Email Text + Headers"])

if mode == "Upload .eml File":
    uploaded_file = st.file_uploader("Upload an `.eml` email file", type=["eml"])
    if uploaded_file:
        st.divider()
        st.subheader("📄 Email Details (from file)")

        msg, body = extract_email_body(uploaded_file)

        if msg:
            st.markdown("### ✉️ Email Body (Extracted)")
            st.text_area("Content", body, height=200)

            # Header-based detection
            score, verdict, notes = phishing_header_score(dict(msg.items()))
            st.markdown("### 🛡️ Header-Based Phishing Detection")
            st.write("**Result:**", verdict)
            for note in notes:
                st.markdown(f"- {note}")

            # GRU ML-based detection
            is_phish_content = predict_with_gru(body)

            st.markdown("### 🤖 ML-Based Content Classifier")
            if is_phish_content:
                st.error("This content is likely PHISHING ⚠️")
            else:
                legit_type = legit_model.predict([clean_text(body)])[0]
                st.success(f"Content is LEGITIMATE – Type: {legit_type.capitalize()}")

            st.divider()
            st.subheader("✅ Final Combined Verdict")
            if score >= 2 or is_phish_content:
                st.error("🚨 This email is likely PHISHING.")
            else:
                st.success(f"✅ This email is Legitimate – Category: {legit_type.capitalize()}")
        else:
            st.error("Unable to parse email file.")

else:
    st.subheader("📋 Paste Email Manually")
    pasted_header = st.text_area("📨 Paste Raw Email Headers (from 'Show Original')", height=200)
    pasted_body = st.text_area("✉️ Paste Email Body Text", height=200)

    if st.button("🔍 Analyze"):
        header_dict = {}
        for line in pasted_header.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                header_dict[k.strip()] = v.strip()

        score, verdict, notes = phishing_header_score(header_dict)
        st.markdown("### 🛡️ Header-Based Phishing Detection")
        st.write("**Result:**", verdict)
        for note in notes:
            st.markdown(f"- {note}")

        is_phish_content = predict_with_gru(pasted_body)

        st.markdown("### 🤖 ML-Based Content Classifier")
        if is_phish_content:
            st.error("This content is likely PHISHING ⚠️")
        else:
            legit_type = legit_model.predict([clean_text(pasted_body)])[0]
            st.success(f"Content is LEGITIMATE – Type: {legit_type.capitalize()}")

        st.divider()
        st.subheader("✅ Final Combined Verdict")
        if score >= 3 or is_phish_content:
            st.error("🚨 This email is likely PHISHING.")
        else:
            st.success(f"✅ This email is Legitimate – Category: {legit_type.capitalize()}")
