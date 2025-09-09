# utils/urgency_analyzer.py
import json
import os
import re

# Dynamically resolve the path to the JSON file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
URGENCY_JSON_PATH = os.path.join(BASE_DIR, "..", "data", "categorized_urgency_words_23000.json")


# Load once
with open(URGENCY_JSON_PATH, "r") as f:
    urgency_data = json.load(f)

def analyze_urgency_level(text):
    """
    Analyzes the urgency level of the input text based on categorized urgency keywords.

    Returns:
        {
            "level": "high" / "intermediate" / "basic" / "None",
            "score": int,
            "triggers": [matched phrases],
            "categories": {
                "high": [...],
                "intermediate": [...],
                "basic": [...]
            }
        }
    """
    if not text:
        return {
            "level": "None",
            "score": 0,
            "triggers": [],
            "categories": {}
        }

    # Normalize text
    text = text.lower()
    text = re.sub(r"[^\w\s]", " ", text)  # remove punctuation

    matches = {
        "high": [],
        "intermediate": [],
        "basic": []
    }

    # Search for matches in each category
    for level in matches:
        for phrase in urgency_data.get(level, []):
            if phrase in text:
                matches[level].append(phrase)

    total_triggers = matches["high"] + matches["intermediate"] + matches["basic"]

    if matches["high"]:
        level = "high"
        score = 3 * len(matches["high"]) + 2 * len(matches["intermediate"]) + len(matches["basic"])
    elif matches["intermediate"]:
        level = "intermediate"
        score = 2 * len(matches["intermediate"]) + len(matches["basic"])
    elif matches["basic"]:
        level = "basic"
        score = len(matches["basic"])
    else:
        level = "None"
        score = 0

    # Remove empty categories
    matches = {k: v for k, v in matches.items() if v}

    return {
        "level": level,
        "score": score,
        "triggers": total_triggers,
        "categories": matches
    }
# Example usage
'''
test_text = """Subject: ⚠️ Immediate Action Required: Verify Your Royal Enfield Account
From: noreply@royalenfield.com
Date: 18 May 2025 at 01:32

Dear Vishal Singh,

We welcome you to the Royal Enfield community! Your registration at RoyalEnfield.com is almost complete — however, urgent verification is required to activate your account fully.

⚠️ Failure to verify within 24 hours may result in account suspension.

Please click the secure link below immediately to confirm your identity and ensure uninterrupted access to your profile and services:

👉 Verify Now

If you do not complete this urgent verification, your access will be restricted and your profile may be flagged for review due to incomplete activation.

For any issues, contact our support team without delay at support@royalenfield.com.

Thank you for choosing Royal Enfield. Act quickly to avoid service disruption and enjoy a limited-time exclusive offer available only to verified users!

FOLLOW ROYAL ENFIELD

📅 07/07/2025, 19:42
📄 COPYRIGHT 2025 ROYAL ENFIELD RESERVED."""
print(analyze_urgency_level(test_text))
'''