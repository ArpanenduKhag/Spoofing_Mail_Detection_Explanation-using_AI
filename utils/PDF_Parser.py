# import streamlit as st
import fitz  # PyMuPDF
import pytesseract
from PIL import Image
import io
import re

pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"


# --- Extract text from PDF ---
def extract_text_from_pdf(pdf_file):
    doc = fitz.open(stream=pdf_file.read(), filetype="pdf")
    full_text = ""
    for i in range(len(doc)):
        page = doc.load_page(i)
        text = page.get_text().strip()
        if not text:
            pix = page.get_pixmap(dpi=300)
            img = Image.open(io.BytesIO(pix.tobytes()))
            text = pytesseract.image_to_string(img)
        full_text += f"\n--- Page {i+1} ---\n{text}"
    return full_text.strip()


# --- Split into forwarded messages based on From: header ---
def is_valid_email_block(text_block):
    """
    Check if the block contains at least basic metadata: From, To, or Subject.
    """
    keywords = ["from", "to", "subject", "sent", "date"]
    for kw in keywords:
        if re.search(rf"\b{kw}\b\s*:?\s?.+@.+", text_block, flags=re.IGNORECASE):
            return True
    return False


def split_forwarded_sections(text):
    pattern = r"(?=^\s*(from:|from)\s+.+<[^@]+@[^>]+>)"
    chunks = re.split(pattern, text, flags=re.IGNORECASE | re.MULTILINE)

    messages = []
    buffer = ""

    for part in chunks:
        part = part.strip()
        if not part:
            continue
        if re.match(r"^\s*(from:|from)\s+.+<[^@]+@[^>]+>", part, flags=re.IGNORECASE):
            if buffer and is_valid_email_block(buffer):
                messages.append(buffer.strip())
                buffer = ""
        buffer += "\n" + part

    if buffer and is_valid_email_block(buffer):
        messages.append(buffer.strip())

    return messages


# --- Extract metadata from a single message block ---
def extract_metadata_from_block(block):
    metadata = {
        "Sender": None,
        "To": None,
        "Date": None,
        "Reply-To": None,
        "Subject": None,
    }

    lines = [line.strip() for line in block.splitlines() if line.strip()]
    emails = []
    possible_subjects = []
    name_email_line = None

    # Fix Outlook-style broken headers (e.g., "Subject" followed by value on next line)
    i = 0
    while i < len(lines) - 1:
        if lines[i].lower() in ["subject", "from", "to", "date", "reply-to"]:
            lines[i] = f"{lines[i]}: {lines[i+1]}"
            lines[i + 1] = ""
            i += 1
        i += 1

    for idx, line in enumerate(lines):
        lower = line.lower()

        # Collect emails
        found_emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}", line)
        if found_emails:
            emails.extend(found_emails)

        # Match labeled metadata
        if lower.startswith("reply-to:") and not metadata["Reply-To"]:
            metadata["Reply-To"] = line.split(":", 1)[1].strip()

        elif lower.startswith("to:") and not metadata["To"]:
            metadata["To"] = line.split(":", 1)[1].strip()

        elif lower.startswith("subject:") and not metadata["Subject"]:
            subject = line.split(":", 1)[1].strip()
            if not re.match(
                r"\b(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*[,]?\s+\w+\s+\d{1,2}[,]?\s+\d{4}",
                subject,
                re.IGNORECASE,
            ):
                metadata["Subject"] = subject

        elif lower.startswith("date:") and not metadata["Date"]:
            metadata["Date"] = line.split(":", 1)[1].strip()

        elif lower.startswith("from:") and not metadata["Sender"]:
            metadata["Sender"] = line.split(":", 1)[1].strip()

        # Fallbacks within first few lines
        if idx < 6:
            if not metadata["Sender"] and re.search(r"<.+@.+>", line):
                name_email_line = line.strip()

            if not metadata["Date"] and re.search(
                r"\b\d{1,2}:\d{2}\s*(AM|PM|am|pm)", line
            ):
                metadata["Date"] = line.strip()

            # Possible fallback subject (reject lines with @ or AM/PM or that look like a date)
            if (
                not metadata["Subject"]
                and 15 < len(line) < 120
                and not re.search(r"@|https?://", line)
                and not re.search(r"\b\d{1,2}:\d{2}\s*(AM|PM|am|pm)", line)
                and not re.match(r"\d{1,2} \w+ \d{4}", line)
                and not lower.startswith(("from", "to", "date", "sent", "reply-to"))
            ):
                possible_subjects.append(line.strip())

    # Fallbacks
    if not metadata["Sender"] and name_email_line:
        metadata["Sender"] = name_email_line

    if not metadata["To"] and len(emails) >= 1:
        metadata["To"] = emails[0]
    if not metadata["Sender"] and len(emails) >= 2:
        metadata["Sender"] = emails[1]

    if not metadata["Subject"] and possible_subjects:
        metadata["Subject"] = possible_subjects[0]

    return metadata


# --- Extract email body from a message block ---
def extract_body_from_block(block):
    lines = block.splitlines()
    body_lines = []
    header_keywords = ["from:", "to:", "subject:", "date:", "sent:", "reply-to:"]
    skip_header_lines = 0
    max_header_lines = 8
    started = False

    for line in lines:
        line_clean = line.strip()
        lower = line_clean.lower()

        # Skip header section at the top
        if not started:
            if any(lower.startswith(k) for k in header_keywords):
                skip_header_lines += 1
                if skip_header_lines <= max_header_lines:
                    continue
            if len(line_clean) > 30 and not any(
                x in lower for x in ["gmail", "outlook", "unsubscribe", "@", "http"]
            ):
                started = True
                body_lines.append(line_clean)
        else:
            # Handle OCR "From:" / "To:" errors inside body
            if any(lower.startswith(k) for k in header_keywords):
                content_after = line_clean.split(":", 1)[-1].strip()
                # If what's after the colon is not an email or date, treat as normal sentence
                if not re.search(r"@|[0-9]{1,2}[:][0-9]{2}", content_after):
                    body_lines.append(line_clean)
                continue

            if re.match(r"--- Page \d+ ---", line_clean):
                continue
            if (
                "unsubscribe" in lower
                or "view in browser" in lower
                or "gmail - " in lower
            ):
                continue
            if "https://" in lower or "mailto:" in lower:
                continue
            body_lines.append(line_clean)

    return "\n".join(body_lines).strip()


def parse_forwarded_emails_from_pdf(pdf_file_path):
    with open(pdf_file_path, "rb") as f:
        full_text = extract_text_from_pdf(f)

    forwarded_blocks = split_forwarded_sections(full_text)

    emails = []
    for block in forwarded_blocks:
        metadata = extract_metadata_from_block(block)
        body = extract_body_from_block(block)
        emails.append({"metadata": metadata, "body": body})

    return emails


# # --- Streamlit UI ---
# st.set_page_config(page_title="📧 PDF Forwarded Email Parser", layout="centered")
# st.title("📧 PDF Email Parser with Forwarded Message Support")

# uploaded_file = st.file_uploader("Upload an email as PDF", type=["pdf"])

# if uploaded_file:
#     with st.spinner("⏳ Extracting all forwarded messages..."):
#         full_text = extract_text_from_pdf(uploaded_file)
#         messages = split_forwarded_sections(full_text)
#         print(full_text)  # JUST FOR TESTING

#     st.success(f"✅ Found {len(messages)} message(s) in the thread!")

#     for idx, msg in enumerate(messages, 1):
#         metadata = extract_metadata_from_block(msg)
#         body = extract_body_from_block(msg)

#         st.markdown(f"### 📩 Forwarded Message {idx}")
#         col1, col2 = st.columns(2)
#         with col1:
#             st.markdown(f"**Sender:** `{metadata.get('Sender', 'Not found')}`")
#             st.markdown(f"**To:** `{metadata.get('To', 'Not found')}`")
#         with col2:
#             st.markdown(f"**Date:** `{metadata.get('Date', 'Not found')}`")
#             st.markdown(f"**Subject:** `{metadata.get('Subject', 'Not found')}`")

#         st.text_area("✉️ Body", body, height=300, key=f"body_{idx}")
