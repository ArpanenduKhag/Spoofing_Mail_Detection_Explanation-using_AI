import subprocess
import json
import re

def clean_email_text(raw_text: str) -> str:
    """
    Clean OCR-scanned email by removing timestamps, footers, page numbers, etc.
    """
    lines = raw_text.splitlines()
    cleaned_lines = []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if re.search(r'^\d+/\d+$', line):  # Page numbers like "1/2"
            continue
        if "COPYRIGHT" in line.upper():
            continue
        if re.search(r'\d{1,2} [A-Za-z]+ 20\d{2}', line):  # Dates like "18 May 2025"
            continue
        if re.match(r'^\d{2}/\d{2}/\d{4}, \d{2}:\d{2}$', line):  # Timestamps
            continue
        if "message" in line.lower() and "@" not in line:  # Lines like "1 message"
            continue

        cleaned_lines.append(line)

    return "\n".join(cleaned_lines)


def extract_json_from_output(output):
    """
    Extract first JSON object from LLM output.
    """
    try:
        json_match = re.search(r'\{[\s\S]*?\}', output)
        if json_match:
            return json.loads(json_match.group(0))
    except json.JSONDecodeError:
        pass
    return None


def explain_email_with_gemma(email_body: str):
    """
    Run Gemma model through Ollama to explain and classify the email.
    Returns a dict with summary, label, category, and reason.
    """
    cleaned_body = clean_email_text(email_body)

    prompt = f"""
You are an intelligent email explanation engine. Your task is to analyze an email and output the following in valid JSON format only:

1. "summary": A concise list of 3–5 bullet points explaining what the email is about.
2. "label": 
 the email is "phishing" or "legitimate".
3. "category": The type of content if legitimate — one of "job-related", "marketing", "personal", "transactional", or null.
4. "reason": A brief explanation (1–2 lines) of why the email is classified that way. This field is mandatory.

Here is the email:
\"\"\"
{cleaned_body.strip()}
\"\"\"

Respond ONLY with a valid JSON object in this format:

{{
  "summary": [...],
  "label": "...",
  "category": "...",
  "reason": "..."
}}
"""


    try:
        result = subprocess.run(
            ['ollama', 'run', 'gemma3:1b'],
            input=prompt,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=True
        )

        output_text = result.stdout.strip()

        parsed = extract_json_from_output(output_text)
        if parsed:
            # Ensure all fields exist even if model skips one
            parsed.setdefault("summary", [])
            parsed.setdefault("label", "unparseable")
            parsed.setdefault("category", None)
            parsed.setdefault("reason", "No reason provided by the model.")
            return parsed

        else:
            print("⚠️ Unable to extract valid JSON.")
            return {
                "summary": [],
                "label": "unparseable",
                "category": None,
                "reason": None,
                "raw_output": output_text
            }

    except subprocess.CalledProcessError as e:
        print("❌ Ollama execution failed:", e.stderr)
        return {
            "summary": [],
            "label": "error",
            "category": None,
            "reason": None,
            "error": e.stderr
        }

'''
# --- Optional: Local test runner ---
if __name__ == "__main__":
    raw_email = """
Welcome to Royal Enfield - Your New Account
1 message
noreply@royalenfield.com <noreply@royalenfield.com>
18 May 2025 at 01:32

Dear Vishal singh,

We welcome you to the Royal Enfield community! Your registration at RoyalEnfield.com is complete, and we
are excited to have you on board.

To access and manage your user profile, simply click on the link provided below (or copy and paste the URL
into your web browser):

If you encounter any challenges or have questions, our dedicated support team is here to assist you. Feel free
to contact us at support@royalenfield.com, and we'll be delighted to provide the support you need.

Thank you for choosing Royal Enfield. We are excited about the journey ahead and can't wait to offer you an
exceptional and pure motorcycling experience!

FOLLOW ROYAL ENFIELD

07/07/2025, 19:42
1/2
COPYRIGHT 2025 ROYAL ENFIELD RESERVED.
07/07/2025, 19:42
2/2
"""
    result = explain_email_with_gemma(raw_email)
    print(json.dumps(result, indent=2))
"""
'''