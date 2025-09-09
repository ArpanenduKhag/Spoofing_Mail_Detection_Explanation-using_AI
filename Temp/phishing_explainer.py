import streamlit as st
import joblib
import pickle
import json
import re
import string
import uuid
from transformers import pipeline
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from email import policy
from email.parser import BytesParser
from PDF_Parser import extract_text_from_pdf, split_forwarded_sections, extract_metadata_from_block, extract_body_from_block

# --- Load Models ---
bilstm_model = load_model("model/phishing_bilstm_model.h5")
with open("model/tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

legit_model = joblib.load("model/legit_type_classifier.pkl")
summarizer = pipeline("summarization", model="facebook/bart-large-cnn")

# --- Clean Text ---
def clean_text(text):
    text = text.lower()
    text = re.sub(r'https?://\S+|www\.\S+', '', text)
    text = re.sub(r'\[.*?\]', '', text)
    text = re.sub(f"[{re.escape(string.punctuation)}]", '', text)
    text = re.sub(r'\n+', ' ', text)
    text = re.sub(r'\w*\d\w*', '', text)
    return text.strip()

# --- Predict using BiLSTM ---
def predict_with_bilstm(text):
    cleaned = clean_text(text)
    seq = tokenizer.texts_to_sequences([cleaned])
    padded = pad_sequences(seq, maxlen=200, padding='post', truncating='post')
    pred = bilstm_model.predict(padded)[0][0]
    return pred

# --- Summarize with BART ---
def summarize_text(text):
    if len(text.strip()) < 50:
        return text.strip()
    try:
        summary = summarizer(text, max_length=100, min_length=30, do_sample=False)[0]['summary_text']
        return summary.strip()
    except:
        return text.strip()

# --- Header-Based Phishing Detection ---
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

def check_known_sender(email):
    known_senders = ["gmail.com", "outlook.com", "yahoo.com"]
    domain = get_domain(email)
    return any(known in domain for known in known_senders)

def detect_misspelled_domains(email):
    suspicious_patterns = ["gma1l", "yah00", "out1ook"]
    domain = get_domain(email)
    return any(spoof in domain for spoof in suspicious_patterns)

def detect_attachment_risks(header):
    attachments = header.get("Content-Type", "")
    risky_types = [".exe", ".js", ".bat"]
    return any(risk in attachments.lower() for risk in risky_types)

def phishing_header_score(header):
    score = 0
    notes = []

    if check_spf(header): notes.append("✅ SPF Passed")
    else: notes.append("❌ SPF Failed"); score += 1

    if check_dkim(header): notes.append("✅ DKIM Passed")
    else: notes.append("❌ DKIM Failed"); score += 1

    if check_dmarc(header): notes.append("✅ DMARC Passed")
    else: notes.append("❌ DMARC Failed"); score += 1

    from_email, _, _, match = analyze_from_reply_return(header)
    if match: notes.append("✅ From/Reply/Return Match")
    else: notes.append("⚠️ From/Reply/Return Mismatch"); score += 1

    if analyze_message_id(header): notes.append("✅ Message-ID domain match")
    else: notes.append("⚠️ Message-ID domain mismatch"); score += 1

    if check_known_sender(from_email): notes.append("✅ Known sender domain")
    else: notes.append("⚠️ Unknown or suspicious sender domain"); score += 1

    if detect_misspelled_domains(from_email): notes.append("❌ Spoofed domain detected"); score += 1

    if detect_attachment_risks(header): notes.append("❌ Risky attachment type detected"); score += 1

    return score, notes
# --- Streamlit UI ---
st.set_page_config(page_title="📧 Email Analyzer", layout="centered")
st.title("📧 Email Phishing Detector + Explanation")

st.sidebar.header("⚙️ Settings")
pred_threshold = st.sidebar.slider("Detection Threshold", 0.0, 1.0, value=0.5, step=0.01)
pdf_weight = st.sidebar.slider("PDF Score Weight", 0.0, 1.0, value=0.5, step=0.05)
eml_weight = 1.0 - pdf_weight
header_pass_score = st.sidebar.slider("Header Score Threshold", 0, 8, value=3)

uploaded_pdf = st.file_uploader("📄 Upload PDF Email File (Required)", type=["pdf"])
uploaded_eml = st.file_uploader("📨 Upload .eml File (Optional)", type=["eml"])

if not uploaded_pdf:
    st.warning("Please upload a PDF email file to proceed.")
    st.stop()

if st.button("🔍 Run Analysis"):
    # --- PDF Analysis ---
    st.header("📄 PDF Analysis")
    full_text = extract_text_from_pdf(uploaded_pdf)
    messages = split_forwarded_sections(full_text)
    st.success(f"✅ Found {len(messages)} forwarded message(s)")

    pdf_results = []
    for idx, msg in enumerate(messages, 1):
        st.markdown(f"### 📩 Forwarded Message {idx}")
        metadata = extract_metadata_from_block(msg)
        body = extract_body_from_block(msg)
        st.text_area("✉️ Extracted Body", body, height=200, key=f"body_{idx}")

        pred_score = predict_with_bilstm(body)
        summary = summarize_text(body)

        label = "phishing" if pred_score >= pred_threshold else "legitimate"
        category = None if label == "phishing" else legit_model.predict([clean_text(body)])[0]

        st.metric("📈 PDF Phishing Probability", f"{round(pred_score * 100, 2)}%")
        if label == "legitimate":
            st.success("LEGITIMATE ✅")
        else:
            st.error("PHISHING ⚠️")

        result = {
            "id": f"client_email_{uuid.uuid4().hex[:8]}",
            "metadata": metadata,
            "body_summary": summary,
            "label": label,
            "category": category,
            "score": float(pred_score)
        }
        pdf_results.append(result)

    # --- EML Analysis ---
    eml_result = None
    if uploaded_eml:
        st.header("📨 EML Analysis")
        msg = BytesParser(policy=policy.default).parse(uploaded_eml)
        header = dict(msg.items())
        body = msg.get_body(preferencelist=('plain')).get_content() if msg.is_multipart() else msg.get_content()

        pred_score = predict_with_bilstm(body)
        label = "phishing" if pred_score >= pred_threshold else "legitimate"
        category = None if label == "phishing" else legit_model.predict([clean_text(body)])[0]
        header_score, notes = phishing_header_score(header)

        st.metric("📈 EML Phishing Probability", f"{round(pred_score * 100, 2)}%")
        for note in notes:
            st.write(note)

        header_verdict = "LEGITIMATE ✅" if header_score < header_pass_score else "PHISHING ⚠️"
        st.info(f"Header Verdict: {header_verdict}")

        combined_eml_score = (pred_score + (0 if header_score < header_pass_score else 1)) / 2
        st.metric("📊 Combined EML Score", f"{round(combined_eml_score * 100, 2)}%")

        eml_result = {
            "label": "phishing" if combined_eml_score >= pred_threshold else "legitimate",
            "category": category,
            "score": combined_eml_score
        }

    # --- Final Verdict ---
    if pdf_results:
        st.header("📌 Final Combined Verdict")
        pdf_score = pdf_results[0]['score']
        eml_score = eml_result['score'] if eml_result else None

        final_score = pdf_score * pdf_weight + (eml_score * eml_weight if eml_score else 0)
        final_label = "phishing" if final_score >= pred_threshold else "legitimate"
        final_category = pdf_results[0]['category'] if final_label == "legitimate" else None

        st.metric("📊 Final Score", f"{round(final_score * 100, 2)}%")
        if final_label == "phishing":
            st.error("🚨 Final Verdict: PHISHING")
        else:
            st.success(f"✅ Final Verdict: LEGITIMATE – Type: {final_category.capitalize() if final_category else 'N/A'}")

        final_result = {
            "id": f"client_email_{uuid.uuid4().hex[:8]}",
            "metadata": pdf_results[0]['metadata'],
            "body_summary": pdf_results[0]['body_summary'],
            "label": final_label,
            "category": final_category,
            "confidence": f"{round(final_score * 100, 2)}%"
        }

        st.subheader("📝 Final JSON Output")
        st.json(final_result)

        st.download_button(
            "💾 Download Final JSON",
            data=json.dumps(final_result, indent=2),
            file_name="final_result.json",
            mime="application/json"
        )
