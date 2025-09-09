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


def explain_email_with_gemma(email_body: str, predicted_label: str):
    """
    Use the given label (from BiLSTM) and ask Gemma to explain why the email is that type.
    """
    cleaned_body = clean_email_text(email_body)

    prompt = f"""
You are an intelligent email explanation engine. The email below has already been classified as **"{predicted_label}"**.

Your job is to do the following and return only a JSON object:
1. "summary": A concise list of 3–5 bullet points summarizing the email.
2. "label": Copy the given label: "{predicted_label}".
3. "category": If the email is legitimate, classify it as one of "job-related", "marketing", "personal", "transactional", or null. Otherwise, use null.
4. "reason": Provide a brief 1–2 line explanation for why this email is labeled as "{predicted_label}". (e.g., suspicious links, impersonation, urgency cues, etc.)

Here is the email:
\"\"\" 
{cleaned_body.strip()}
\"\"\"

Respond ONLY with a valid JSON object like this:

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
            parsed.setdefault("summary", [])
            parsed.setdefault("label", predicted_label)
            parsed.setdefault("category", None)
            parsed.setdefault("reason", "No reason provided by the model.")
            return parsed

        else:
            print("⚠️ Unable to extract valid JSON.")
            return {
                "summary": [],
                "label": predicted_label,
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
