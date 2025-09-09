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
from utils.threat_analyzers import (
    analyze_ip_with_abuseipdb,
    analyze_domain_with_spamhaus,
    analyze_file_with_virustotal,
    analyze_url_with_phishtank,
    yara_scan_email_content,
    emailrep_check
)

# --- Load Models ---
bilstm_model = load_model("model/phishing_bilstm_model.h5")
with open("model/tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

legit_model = joblib.load("model/legit_type_classifier.pkl")
summarizer = pipeline("summarization", model="facebook/bart-large-cnn")

# --- Utilities ---
def clean_text(text):
    text = text.lower()
    text = re.sub(r'https?://\S+|www\.\S+', '', text)
    text = re.sub(r'\[.*?\]', '', text)
    text = re.sub(f"[{re.escape(string.punctuation)}]", '', text)
    text = re.sub(r'\n+', ' ', text)
    text = re.sub(r'\w*\d\w*', '', text)
    return text.strip()

def predict_with_bilstm(text):
    cleaned = clean_text(text)
    seq = tokenizer.texts_to_sequences([cleaned])
    padded = pad_sequences(seq, maxlen=200, padding='post', truncating='post')
    pred = bilstm_model.predict(padded)[0][0]
    return pred

def summarize_text(text):
    if len(text.strip()) < 50:
        return text.strip()
    try:
        summary = summarizer(text, max_length=100, min_length=30, do_sample=False)[0]['summary_text']
        return summary.strip()
    except:
        return text.strip()

# --- Header Analysis ---
def check_spf(header): return "pass" in header.get("Received-SPF", "").lower()
def check_dkim(header): return "dkim=pass" in header.get("Authentication-Results", "").lower()
def check_dmarc(header): return "dmarc=pass" in header.get("Authentication-Results", "").lower()

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
    reasons = []

    if check_spf(header):
        notes.append("✅ SPF Passed")
    else:
        notes.append("❌ SPF Failed")
        reasons.append("SPF failure: The sender's domain is not authorized to send emails from the IP address in the header (possible spoofing).")
        score += 1

    if check_dkim(header):
        notes.append("✅ DKIM Passed")
    else:
        notes.append("❌ DKIM Failed")
        reasons.append("DKIM failure: The email signature could not be verified, meaning the content may have been altered in transit.")
        score += 1

    if check_dmarc(header):
        notes.append("✅ DMARC Passed")
    else:
        notes.append("❌ DMARC Failed")
        reasons.append("DMARC failure: Both SPF and DKIM failed or misaligned, and the domain policy rejected the email.")
        score += 1

    from_email, reply_email, return_email, match = analyze_from_reply_return(header)
    if match:
        notes.append("✅ From/Reply/Return Match")
    else:
        notes.append("⚠️ From/Reply/Return Mismatch")
        failed_fields = []
        if get_domain(from_email) != get_domain(reply_email):
            failed_fields.append(f"`From ({from_email}) ≠ Reply-To ({reply_email})`")
        if get_domain(from_email) != get_domain(return_email):
            failed_fields.append(f"`From ({from_email}) ≠ Return-Path ({return_email})`")
        reasons.append("Mismatch in email fields: " + "; ".join(failed_fields) + " — can indicate email spoofing or redirection.")
        score += 1

    if analyze_message_id(header):
        notes.append("✅ Message-ID domain match")
    else:
        notes.append("⚠️ Message-ID domain mismatch")
        reasons.append("Message-ID domain mismatch: Sender domain does not match Message-ID domain — could be a fake/generated message.")
        score += 1

    if check_known_sender(from_email):
        notes.append("✅ Known sender domain")
    else:
        notes.append("⚠️ Unknown or suspicious sender domain")
        reasons.append(f"Unknown domain: `{get_domain(from_email)}` is not in known email providers (e.g., Gmail, Outlook).")
        score += 1

    if detect_misspelled_domains(from_email):
        notes.append("❌ Spoofed domain detected")
        reasons.append(f"Domain appears spoofed: `{get_domain(from_email)}` matches known deceptive patterns like `gma1l.com`, `yah00.com`, etc.")
        score += 1

    if detect_attachment_risks(header):
        notes.append("❌ Risky attachment type detected")
        reasons.append("Attachment is of a risky type (.exe, .js, .bat) — may execute malicious code if opened.")
        score += 1

    return score, notes, reasons

def generate_content_reason(body, label):
    body_lower = body.lower()
    reasons = []

    if label == "phishing":
        if re.search(r"(verify|update|validate).{0,10}(account|information|credentials)", body_lower):
            reasons.append("Contains phrases asking to verify or update account information — a common phishing tactic.")

        if re.search(r"(click|login|sign in|access).{0,10}(here|link|now)", body_lower):
            reasons.append("Includes action phrases like 'click here' or 'login now', often used in phishing.")

        if re.search(r"(urgent|immediately|required|final warning)", body_lower):
            reasons.append("Uses urgency or fear-based language to provoke immediate action.")

        if re.search(r"(you(?:'ve| have)? won|congratulations|prize|reward|claim now)", body_lower):
            reasons.append("Mentions prizes or rewards, which are often bait for phishing.")

        if re.search(r"(bit\.ly|tinyurl|t\.co|goo\.gl|shorturl\.at)", body_lower):
            reasons.append("Uses URL shorteners which may hide the final destination of a malicious link.")

        if "password" in body_lower:
            reasons.append("Mentions entering a password — typical of phishing attempts.")

        if "bank account" in body_lower or "payment method" in body_lower:
            reasons.append("Mentions financial account access or payment details.")

        if re.search(r"(invoice|receipt|transaction|payment) attached", body_lower):
            reasons.append("Mentions attachments related to payment/invoice, a common phishing lure.")

    elif label == "legitimate":
        if len(body.split()) > 100 and not re.search(r'https?://', body_lower):
            reasons.append("Long informative message with no links suggests legitimacy.")

        if re.search(r"(internal memo|team update|project report|company policy|onboarding)", body_lower):
            reasons.append("Includes business-specific internal language typical of legitimate emails.")

        if re.search(r"(thank you|regards|sincerely|best wishes)", body_lower):
            reasons.append("Proper closing phrases indicating professional correspondence.")

        if not re.search(r'\.exe|\.bat|\.js', body_lower):
            reasons.append("No mention of risky attachments or scripts in content.")

    return reasons


# --- Helper: Extract sender IP from .eml file ---

def extract_sender_ip(file_obj):
    file_obj.seek(0)
    msg = BytesParser(policy=policy.default).parse(file_obj)
    received_headers = msg.get_all('Received')

    if not received_headers:
        return None

    ip_pattern = re.compile(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]')

    private_ip_patterns = [
        re.compile(r'^10\..*'),
        re.compile(r'^192\.168\..*'),
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\..*'),
        re.compile(r'^127\..*'),
        re.compile(r'^169\.254\..*'),
        re.compile(r'^0\..*'),
        re.compile(r'^255\.255\.255\.255$')
    ]

    for header in reversed(received_headers):
        match = ip_pattern.search(header)
        if match:
            ip = match.group(1)
            if not any(pat.match(ip) for pat in private_ip_patterns):
                return ip
    return None


# --- Streamlit UI ---
st.set_page_config(page_title="📧 Email Analyzer", layout="centered")
st.title("📧 Email Phishing Detector + Threat Intelligence")

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

        content_reasons = generate_content_reason(body, label)


        st.metric("📈 PDF Phishing Probability", f"{round(pred_score * 100, 2)}%")
        st.success("LEGITIMATE ✅" if label == "legitimate" else "PHISHING ⚠️")

        result = {
            "id": f"client_email_{uuid.uuid4().hex[:8]}",
            "metadata": metadata,
            "body_summary": summary,
            "label": label,
            "category": category,
            "score": float(pred_score)
        }
        pdf_results.append(result)

        if content_reasons:
            st.subheader("📌 Content-Based Reasoning")
            for reason in content_reasons:
                st.markdown(f"- {reason}")


    eml_result = None
    if uploaded_eml:
        st.header("📨 EML Analysis")
        msg = BytesParser(policy=policy.default).parse(uploaded_eml)
        header = dict(msg.items())
        body = msg.get_body(preferencelist=('plain')).get_content() if msg.is_multipart() else msg.get_content()

        pred_score = predict_with_bilstm(body)
        label = "phishing" if pred_score >= pred_threshold else "legitimate"
        category = None if label == "phishing" else legit_model.predict([clean_text(body)])[0]
        header_score, notes, reasons = phishing_header_score(header)

        

        uploaded_eml.seek(0)  # rewind before re-reading
        sender_ip = extract_sender_ip(uploaded_eml)
        print(sender_ip)
        st.subheader("📡 Sender IP Extraction")
        if sender_ip:
            st.success(f"🧾 Sender IP: `{sender_ip}`")
        else:
            st.warning("🧾 Sender IP: Not found")


        domain = get_domain(header.get("From", ""))
        sender_email = extract_email(header.get("From", ""))

        st.subheader("🌐 Threat Intelligence-Demo")
        st.write("📡 AbuseIPDB:", analyze_ip_with_abuseipdb(sender_ip))
        st.write("🚫 Spamhaus DBL:", analyze_domain_with_spamhaus(domain))
        st.write("🧬 YARA Match:", yara_scan_email_content(body))
        st.write("🕵️ EmailRep:", emailrep_check(sender_email))

        # In EML Analysis section
        urls = re.findall(r'https?://\S+', body)
        if urls:
            st.subheader("🔗 URL Threat Intelligence")
            for url in urls:
                result = analyze_url_with_phishtank(url)
                if result.get("is_phishing"):
                    st.error(f"⚠️ Phishing Link Detected: {url}")
                    st.markdown(f"- **Reason**: Found in PhishTank's phishing database.")
                else:
                    st.success(f"✅ Safe Link: {url}")
                    st.markdown(f"- **Reason**: Not found in known phishing databases.")
        else:
            st.info("No URLs found in the email body.")



        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                content = part.get_payload(decode=True)
                vt_result = analyze_file_with_virustotal(content)

                if vt_result.get("malicious"):
                    st.error(f"🦠 Malicious Attachment Detected: {filename}")
                    st.markdown(f"- **Reason**: Flagged as malicious by VirusTotal — {vt_result.get('engine_count')} engines flagged this file.")
                else:
                    st.success(f"✅ Safe Attachment: {filename}")
                    st.markdown("- **Reason**: No malware signatures found in VirusTotal.")


        combined_score = (pred_score + (0 if header_score < header_pass_score else 1)) / 2
        eml_result = {
            "label": "phishing" if combined_score >= pred_threshold else "legitimate",
            "category": category,
            "score": combined_score
        }

    if pdf_results:
        st.header("📌 Final Combined Verdict")
        pdf_score = pdf_results[0]['score']
        eml_score = eml_result['score'] if eml_result else None

        final_score = pdf_score * pdf_weight + (eml_score * eml_weight if eml_score else 0)
        final_label = "phishing" if final_score >= pred_threshold else "legitimate"
        final_category = pdf_results[0]['category'] if final_label == "legitimate" else None

        st.metric("📊 Final Score", f"{round(final_score * 100, 2)}%")
        st.error("🚨 Final Verdict: PHISHING" if final_label == "phishing" else f"✅ Final Verdict: LEGITIMATE – Type: {final_category}")

        final_result = {
            "id": f"client_email_{uuid.uuid4().hex[:8]}",
            "metadata": pdf_results[0]['metadata'],
            "body_summary": pdf_results[0]['body_summary'],
            "label": final_label,
            "category": final_category,
            "content_reasons": content_reasons,
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
        if final_label == "phishing":
            st.subheader("🧠 Why this was flagged as phishing?")
            st.write("### 📌 Key Indicators:")
            for reason in reasons:  # from phishing_header_score()
                st.markdown(f"- {reason}")
            if urls:
                st.markdown("### 🔗 URL Analysis:")
                st.markdown("Check above for any flagged URLs.")
            st.markdown("### 📎 Attachment Risk:")
            st.markdown("See attachment section for malicious indicators.")
