"""Message & Social Engineering Scanner for SMS, WhatsApp, and Chats"""
import re
from typing import Dict, Any, List
from backend.config import (
    URGENCY_TRIGGERS,
    CREDENTIAL_TRIGGERS,
    FINANCIAL_TRIGGERS,
    IMPERSONATION_TRIGGERS
)
from backend.engines.url_scanner import analyze_url

URL_REGEX = re.compile(r"(https?://[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)")
PHONE_REGEX = re.compile(r"(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")

def extract_links_from_text(text: str) -> List[str]:
    """Finds all URLs and domain-like substrings in the message"""
    matches = URL_REGEX.findall(text)
    clean_urls = []
    for match in matches:
        m = match.strip(".,;:!?()[]\"'")
        # Filter out obvious false positives like email addresses or single words
        if "." in m and not "@" in m and len(m) > 4:
            clean_urls.append(m)
    return clean_urls

def analyze_message(text: str) -> Dict[str, Any]:
    """
    Analyzes message content for social engineering tactics, urgency pressure,
    financial triggers, credential phishing, and embedded suspicious links.
    """
    findings: List[Dict[str, Any]] = []
    score_penalty = 0
    lower_text = text.lower()

    # 1. Urgency & Coercive Pressure
    urgency_matches = [trig for trig in URGENCY_TRIGGERS if trig in lower_text]
    if urgency_matches:
        count = len(urgency_matches)
        penalty = min(35, count * 15 + 10)
        score_penalty += penalty
        findings.append({
            "type": "urgency_pressure",
            "title": f"High Urgency / Pressure Tactic ({', '.join(urgency_matches[:3])})",
            "severity": "high" if count > 1 else "medium",
            "description": f"The message attempts to manufacture immediate panic ('{', '.join(urgency_matches[:3])}').",
            "educational_note": "Scammers rush you so you act before having time to verify with the real organization."
        })

    # 2. Credential & Identity Harvesting
    cred_matches = [trig for trig in CREDENTIAL_TRIGGERS if trig in lower_text]
    if cred_matches:
        count = len(cred_matches)
        score_penalty += 40
        findings.append({
            "type": "credential_request",
            "title": f"Sensitive Information Request ({', '.join(cred_matches[:2])})",
            "severity": "high",
            "description": f"The message requests sensitive credentials or private verification data ({cred_matches[:2]}).",
            "educational_note": "Legitimate banks and tech platforms will NEVER ask for passwords, OTPs, or PINs via text message."
        })

    # 3. Financial, Prize, or Lottery Baits
    fin_matches = [trig for trig in FINANCIAL_TRIGGERS if trig in lower_text]
    if fin_matches:
        score_penalty += 30
        findings.append({
            "type": "financial_bait",
            "title": f"Financial / Prize Incentive Detected ({', '.join(fin_matches[:2])})",
            "severity": "medium",
            "description": f"Contains unsolicited offers or financial demands ('{', '.join(fin_matches[:2])}').",
            "educational_note": "Unsolicited claims that you won money or must pay with gift cards/crypto are always fraudulent."
        })

    # 4. Impersonation of Authorities or Companies
    impersonation_matches = [trig for trig in IMPERSONATION_TRIGGERS if trig in lower_text]
    if impersonation_matches:
        score_penalty += 25
        findings.append({
            "type": "authority_impersonation",
            "title": f"Organizational Impersonation ('{impersonation_matches[0]}')",
            "severity": "high",
            "description": f"Claiming to represent an official team ({impersonation_matches[:2]}).",
            "educational_note": "Always contact companies directly using the phone number on their official website or back of your card."
        })

    # 5. Delivery & Parcel Notification Scams (USPS, DHL, FedEx, package failed)
    delivery_terms = ["package", "parcel", "delivery failed", "reschedule fee", "shipping address"]
    if any(t in lower_text for t in delivery_terms) and ("link" in lower_text or "http" in lower_text or ".com" in lower_text or ".xyz" in lower_text):
        score_penalty += 25
        findings.append({
            "type": "delivery_scam_pattern",
            "title": "Delivery Reschedule / Courier Scam Indicator",
            "severity": "high",
            "description": "Notice claiming a package delivery failed and requires a small payment or link verification.",
            "educational_note": "Postal services do not text you asking for small fees to redeliver packages from unknown links."
        })

    # 6. Embedded Link Inspection
    extracted_links = extract_links_from_text(text)
    link_results = []
    if extracted_links:
        score_penalty += 15 # Simply having a link in an unsolicited text is a common risk factor
        for link in extracted_links[:3]:
            res = analyze_url(link)
            link_results.append(res)
            # Add severe findings from the link directly into the message report
            for finding in res.get("findings", []):
                if finding["severity"] in ["high", "medium"]:
                    findings.append({
                        "type": f"link_{finding['type']}",
                        "title": f"Embedded Link: {finding['title']}",
                        "severity": finding["severity"],
                        "description": f"Link '{link}': {finding['description']}",
                        "educational_note": finding.get("educational_note")
                    })
            if res.get("score_penalty", 0) > 30:
                score_penalty += res["score_penalty"] // 2

    # 7. Job or Work-From-Home Scam Indicators
    job_terms = ["work from home", "daily salary", "part-time job", "earn $", "telegram recruiter", "hr manager"]
    if any(jt in lower_text for jt in job_terms) and any(f in lower_text for f in ["whatsapp", "telegram", "daily pay", "task"]):
        score_penalty += 45
        findings.append({
            "type": "fake_job_offer",
            "title": "Fake Job / Task-Based Recruitment Scam",
            "severity": "high",
            "description": "Unsolicited job offer promising high daily returns for simple rating/clicking tasks via messaging apps.",
            "educational_note": "Scammers ask you to deposit money to 'unlock' tasks or commission earnings."
        })

    # Cap component penalty
    risk_score = min(score_penalty, 100)

    if risk_score == 0:
        findings.append({
            "type": "benign_message",
            "title": "No Obvious Threat Signals",
            "severity": "info",
            "description": "No urgent threats, credential requests, or deceptive links detected.",
            "educational_note": "Always remain mindful when receiving unsolicited contact from unknown senders."
        })

    return {
        "score_penalty": risk_score,
        "findings": findings,
        "extracted_links": extracted_links,
        "raw_length": len(text)
    }
