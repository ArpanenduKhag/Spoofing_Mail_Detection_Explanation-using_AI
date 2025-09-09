# utils/threat_analyzers.py
import random
import re

# --- Simulated or placeholder analyzer responses (replace with real API calls or modules) ---

def analyze_ip_with_abuseipdb(ip):
    # Placeholder for AbuseIPDB analysis
    return {
        "ip": ip,
        "score": random.randint(0, 100),
        "abuseConfidence": "High" if random.random() > 0.5 else "Low",
        "reason": "Detected abusive behavior"
    }
'''
ABUSEIPDB_API_KEY = "your_abuseipdb_key"

def analyze_ip_with_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    response = requests.get(url, headers=headers, params=params)
    data = response.json().get("data", {})

    return {
        "ip": ip,
        "score": data.get("abuseConfidenceScore", 0),
        "abuseConfidence": "High" if data.get("abuseConfidenceScore", 0) > 50 else "Low",
        "reason": data.get("countryCode", "Unknown") + " - " + data.get("domain", "No domain")
    }
'''
def analyze_domain_with_spamhaus(domain):
    # Placeholder for Spamhaus check
    return {
        "domain": domain,
        "listed": random.choice([True, False]),
        "reason": "Spam source" if random.random() > 0.5 else "Clean"
    }
'''
import dns.resolver

def analyze_domain_with_spamhaus(domain):
    try:
        query = ".".join(reversed(domain.split("."))) + ".dbl.spamhaus.org"
        dns.resolver.resolve(query, "A")
        return {
            "domain": domain,
            "listed": True,
            "reason": "Listed in Spamhaus DBL"
        }
    except dns.resolver.NXDOMAIN:
        return {
            "domain": domain,
            "listed": False,
            "reason": "Not listed"
        }
    except Exception as e:
        return {
            "domain": domain,
            "listed": False,
            "reason": f"Error checking domain: {e}"
        }
'''


def analyze_file_with_virustotal(file_bytes):
    # Simulated result from VirusTotal scan
    return {
        "malicious": True,
        "positives": random.randint(5, 20),
        "total": 70,
        "scan_date": "2025-07-09",
        "engine_results": {
            "Sophos": "Mal/Phish-A",
            "Kaspersky": "Trojan-Phisher",
            "McAfee": "Phish-FakeBank"
        }
    }
'''
import requests

VT_API_KEY = "your_virustotal_api_key"

def analyze_file_with_virustotal(file_bytes):
    headers = {
        "x-apikey": VT_API_KEY
    }
    # Upload the file
    response = requests.post(
        "https://www.virustotal.com/api/v3/files",
        files={"file": ("upload", file_bytes)},
        headers=headers
    )
    upload_data = response.json()
    analysis_id = upload_data["data"]["id"]

    # Wait a moment then fetch the results
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    analysis = requests.get(analysis_url, headers=headers).json()

    stats = analysis["data"]["attributes"]["stats"]
    results = analysis["data"]["attributes"].get("results", {})

    return {
        "malicious": stats["malicious"] > 0,
        "positives": stats["malicious"],
        "total": sum(stats.values()),
        "scan_date": analysis["data"]["attributes"]["date"],
        "engine_results": results
    }
'''

def analyze_url_with_phishtank(url):
    # Simulated result from PhishTank
    return {
        "url": url,
        "verified_phish": "login" in url.lower() or random.choice([True, False]),
        "confidence": "High" if "login" in url else "Low"
    }
'''
def analyze_url_with_phishtank(url):
    response = requests.post(
        "https://checkurl.phishtank.com/checkurl/",
        data={"url": url, "format": "json"},
    )
    result = response.json()
    verified = result["results"]["valid"]
    confidence = "High" if verified else "Low"
    return {
        "url": url,
        "verified_phish": verified,
        "confidence": confidence
    }    
'''

def yara_scan_email_content(content):
    # Dummy rule matching using regex
    suspicious_keywords = ["invoice", "payment overdue", "urgent", "click here", "reset password"]
    matched = [kw for kw in suspicious_keywords if re.search(kw, content, re.IGNORECASE)]
    return {
        "matched_rules": matched if matched else [],
        "suspicious": bool(matched)
    }
'''
import yara

# Sample YARA rule set for phishing
RULES = """
rule phishing_keywords {
    strings:
        $a = "urgent"
        $b = "click here"
        $c = "update your account"
        $d = "reset password"
    condition:
        any of them
}
"""

rules = yara.compile(source=RULES)

def yara_scan_email_content(content):
    matches = rules.match(data=content)
    matched_rules = [str(m.rule) for m in matches]
    return {
        "matched_rules": matched_rules,
        "suspicious": bool(matched_rules)
    }
'''

def emailrep_check(email):
    # Simulated reputation check
    suspicious = bool(re.search(r"(support|admin|info|pay|reset)", email, re.IGNORECASE))
    return {
        "email": email,
        "reputation": "suspicious" if suspicious else "neutral",
        "suspicious": suspicious,
        "references": random.randint(0, 15)
    }

'''
def emailrep_check(email):
    headers = {
        "Key": "your_emailrep_api_key",  # optional if using free tier
        "Accept": "application/json"
    }
    response = requests.get(f"https://emailrep.io/{email}", headers=headers)
    data = response.json()

    return {
        "email": email,
        "reputation": data.get("reputation", "unknown"),
        "suspicious": data.get("suspicious", False),
        "references": data.get("references", 0)
    }
'''