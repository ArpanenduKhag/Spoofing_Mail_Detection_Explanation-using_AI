import streamlit as st
import json
import uuid
import re
from email import policy
from email.parser import BytesParser
from utils.PDF_Parser import (
    extract_text_from_pdf,
    split_forwarded_sections,
    extract_metadata_from_block,
    extract_body_from_block
)
from utils.email_classifier import (
    predict_with_bilstm,
    summarize_text,
    classify_legit_type,
)

from utils.header_analysis import (
    analyze_email_header,
    extract_email,
    get_domain
)
from utils.explanation_engine import explain_email_with_gemma

from utils.threat_analyzers import (
    analyze_ip_with_abuseipdb,
    analyze_domain_with_spamhaus,
    analyze_file_with_virustotal,
    analyze_url_with_phishtank,
    yara_scan_email_content,
    emailrep_check
)

from utils.urgency_analyzer import analyze_urgency_level


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
urls = []
if not uploaded_pdf:
    st.warning("Please upload a PDF email file to proceed.")
    st.stop()

if st.button("🔍 Run Analysis"):
    st.header("📄 PDF Analysis")
    full_text = extract_text_from_pdf(uploaded_pdf)
    messages = split_forwarded_sections(full_text)
    st.success(f"✅ Found {len(messages)} forwarded message(s)")

    pdf_results = []
    content_reasons = []

    for idx, msg in enumerate(messages, 1):
        st.markdown(f"### 📩 Forwarded Message {idx}")
        metadata = extract_metadata_from_block(msg)
        body = extract_body_from_block(msg)
        st.text_area("✉️ Extracted Body", body, height=200, key=f"body_{idx}")
        pred_score = predict_with_bilstm(body)
        summary = summarize_text(body)
        label = "phishing" if pred_score >= pred_threshold else "legitimate"
        category = None if label == "phishing" else classify_legit_type(body)

        explanation = explain_email_with_gemma(body,label)
        content_reasons = explanation.get("summary", [])
        llm_reason = explanation.get("reason", "")
        urgency_info = analyze_urgency_level(body)

        st.metric("📈 PDF Phishing Probability", f"{round(pred_score * 100, 2)}%")
        st.success("LEGITIMATE ✅" if label == "legitimate" else "PHISHING ⚠️")

        result = {
            "id": f"client_email_{uuid.uuid4().hex[:8]}",
            "metadata": metadata,
            "body_summary": summary,
            "label": label,
            "category": category,
            "score": float(pred_score),
            "llm_reason": llm_reason
        }
        pdf_results.append(result)

        if content_reasons:
            st.subheader("📌 Content Summary")
            for reason in content_reasons:
                st.markdown(f"- {reason}")

    eml_result = None
    reasons = []

    if uploaded_eml:
        st.header("📨 EML Analysis")
        msg = BytesParser(policy=policy.default).parse(uploaded_eml)
        header = dict(msg.items())
        body = msg.get_body(preferencelist=('plain')).get_content() if msg.is_multipart() else msg.get_content()

        pred_score = predict_with_bilstm(body)
        label = "phishing" if pred_score >= pred_threshold else "legitimate"
        category = None if label == "phishing" else classify_legit_type(body)

        analysis = analyze_email_header(header, body, label, uploaded_eml)
        header_score = analysis["header_score"]
        reasons = analysis["header_reasons"]
        sender_ip = analysis["sender_ip"]

        st.subheader("📡 Sender IP")
        st.success(f"Sender IP: `{sender_ip}`" if sender_ip else "No sender IP found.")

        domain = get_domain(header.get("From", ""))
        sender_email = extract_email(header.get("From", ""))

        st.subheader("🌐 Threat Intelligence")
        st.write("📡 AbuseIPDB:", analyze_ip_with_abuseipdb(sender_ip))
        st.write("🚫 Spamhaus DBL:", analyze_domain_with_spamhaus(domain))
        st.write("🧬 YARA Match:", yara_scan_email_content(body))
        st.write("🕵️ EmailRep:", emailrep_check(sender_email))
        
        urls = re.findall(r'https?://\S+', body)
        if urls:
            st.subheader("🔗 URL Threat Intelligence")
            for url in urls:
                result = analyze_url_with_phishtank(url)
                if result.get("verified_phish"):
                    st.error(f"⚠️ Phishing Link: {url}")
                    st.markdown("- Reason: Listed in PhishTank")
                else:
                    st.success(f"✅ Safe Link: {url}")
        else:
            st.info("No URLs found.")

        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                content = part.get_payload(decode=True)
                vt_result = analyze_file_with_virustotal(content)
                if vt_result.get("malicious"):
                    st.error(f"🦠 Malicious Attachment: {filename}")
                else:
                    st.success(f"✅ Clean Attachment: {filename}")

        combined_score = (pred_score + (1 if header_score >= header_pass_score else 0)) / 2
        eml_result = {
            "label": "phishing" if combined_score >= pred_threshold else "legitimate",
            "category": category,
            "score": combined_score
        }

    if pdf_results:
        st.header("📌 Final Combined Verdict")
        pdf_score = pdf_results[0]['score']
        pdf_label = pdf_results[0]['label']
        eml_score = eml_result['score'] if eml_result else None
        eml_label = eml_result['label'] if eml_result else None

        final_score = pdf_score * pdf_weight + (eml_score * eml_weight if eml_score is not None else 0)
        final_label = "phishing" if final_score >= pred_threshold else "legitimate"
        final_category = pdf_results[0]['category'] if final_label == "legitimate" else None

        # --- NEW MAIL TYPE LOGIC ---
        if eml_label == "phishing":
            mail_type = "spam"
        elif eml_label == "legitimate" and pdf_label == "phishing":
            mail_type = "spam"
        else:
            mail_type = "ham"

        st.metric("📊 Final Score", f"{round(final_score * 100, 2)}%")
        st.error("🚨 Verdict: PHISHING" if final_label == "phishing" else f"✅ Verdict: LEGITIMATE – {final_category}")

        final_result = {
            "id": pdf_results[0]['id'],
            "metadata": pdf_results[0]['metadata'],
            "body_summary": pdf_results[0]['body_summary'],
            "label": final_label,
            "category": final_category,
            "Mail-Type": mail_type,
            "urgency": urgency_info,

            "content_reasons": content_reasons,
            "llm_reason": pdf_results[0].get("llm_reason", ""),
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
            st.markdown("### 📌 Header-Based Indicators:")
            for reason in reasons:
                st.markdown(f"- {reason}")
            if urls:
                st.markdown("### 🔗 URL Analysis:")
                st.markdown("Check URL section for flagged links.")


            st.markdown("### 📎 Attachment Section:")
            st.markdown("See above for malicious file results.")

