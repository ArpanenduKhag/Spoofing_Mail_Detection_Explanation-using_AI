# header_analysis.py

import re
from email import policy
from email.parser import BytesParser
from utils.explanation_engine import explain_email_with_gemma, extract_json_from_output

# --- SPF, DKIM, DMARC Checks ---
def check_spf(header):
    return "pass" in header.get("Received-SPF", "").lower()

def check_dkim(header):
    return "dkim=pass" in header.get("Authentication-Results", "").lower()

def check_dmarc(header):
    return "dmarc=pass" in header.get("Authentication-Results", "").lower()

# --- Email & Domain Extraction ---
def extract_email(addr):
    match = re.search(r'[\w\.-]+@[\w\.-]+', addr)
    return match.group(0).lower() if match else ''

def get_domain(addr):
    match = re.search(r'@([\w\.-]+)', addr)
    return match.group(1).lower() if match else ''

# --- From/Reply/Return Analysis ---
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

# --- Message-ID Analysis ---
def analyze_message_id(header):
    from_domain = re.findall(r'@([a-zA-Z0-9.-]+)', header.get("From", ""))
    msgid_domain = re.findall(r'@([a-zA-Z0-9.-]+)', header.get("Message-ID", ""))
    return from_domain == msgid_domain

# --- Known Senders ---
def check_known_sender(email):
    known_senders = ["gmail.com", "outlook.com", "yahoo.com"]
    domain = get_domain(email)
    return any(known in domain for known in known_senders)

# --- Domain Spoofing ---
def detect_misspelled_domains(email):
    suspicious_patterns = ["gma1l", "yah00", "out1ook"]
    domain = get_domain(email)
    return any(spoof in domain for spoof in suspicious_patterns)

# --- Risky Attachments ---
def detect_attachment_risks(header):
    attachments = header.get("Content-Type", "")
    risky_types = [".exe", ".js", ".bat"]
    return any(risk in attachments.lower() for risk in risky_types)

# --- Phishing Header Score ---
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

# --- Content-based Reasoning (LLM) ---
def generate_content_reason(body, label):
    try:
        explanation_output = explain_email_with_gemma(body, label)
        json_data = extract_json_from_output(explanation_output)
        return json_data.get("reasons", [])
    except Exception as e:
        print(f"[Gemma Explanation Error]: {e}")
        return []

# --- Sender IP Extraction from EML ---
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

# --- Full Header Analysis Wrapper ---
def analyze_email_header(header, body, label, eml_file=None):
    score, notes, reasons = phishing_header_score(header)
    content_reasons = generate_content_reason(body, label)
    ip_address = extract_sender_ip(eml_file) if eml_file else None

    return {
        "header_score": score,
        "header_notes": notes,
        "header_reasons": reasons,
        "content_reasons": content_reasons,
        "sender_ip": ip_address
    }

