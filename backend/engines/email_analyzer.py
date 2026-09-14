"""Email Security & Header Spoofing Analyzer"""
import re
from email import message_from_string
from typing import Dict, Any, List, Optional
from backend.config import PROTECTED_BRANDS
from backend.engines.message_scanner import analyze_message
from backend.engines.url_scanner import analyze_url

EMAIL_EXTRACT_REGEX = re.compile(r"[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}")
NAME_EMAIL_REGEX = re.compile(r'"?([^"<]+)"?\s*<([^>]+)>')

def parse_email_sender(sender_str: str) -> Dict[str, str]:
    """Extracts display name and clean email address from a From: header"""
    match = NAME_EMAIL_REGEX.search(sender_str)
    if match:
        return {
            "display_name": match.group(1).strip(),
            "email": match.group(2).strip().lower()
        }
    email_match = EMAIL_EXTRACT_REGEX.search(sender_str)
    if email_match:
        return {
            "display_name": "",
            "email": email_match.group(0).lower()
        }
    return {
        "display_name": "",
        "email": sender_str.strip().lower()
    }

def analyze_email(
    raw_email: Optional[str] = None,
    sender: Optional[str] = None,
    reply_to: Optional[str] = None,
    subject: Optional[str] = None,
    body: Optional[str] = None
) -> Dict[str, Any]:
    """
    Parses and inspects email headers and content for sender spoofing,
    reply-to redirection, brand misalignment, and malicious text patterns.
    """
    findings: List[Dict[str, Any]] = []
    score_penalty = 0

    # If raw email string provided (e.g. pasted headers or .eml), parse via stdlib
    if raw_email and not body:
        try:
            msg = message_from_string(raw_email)
            sender = sender or msg.get("From", "")
            reply_to = reply_to or msg.get("Reply-To", "")
            subject = subject or msg.get("Subject", "")
            if msg.is_multipart():
                payloads = []
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        payloads.append(part.get_payload(decode=True).decode(errors="ignore"))
                body = "\n".join(payloads)
            else:
                raw_payload = msg.get_payload(decode=True)
                body = raw_payload.decode(errors="ignore") if raw_payload else msg.get_payload()
        except Exception:
            body = raw_email

    sender_parsed = parse_email_sender(sender or "")
    sender_email = sender_parsed["email"]
    display_name = sender_parsed["display_name"]
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

    # 1. Display Name Spoofing Check
    # e.g., Display name is "PayPal Support", but sender domain is "gmail.com"
    if display_name:
        lower_name = display_name.lower()
        for brand, official_domains in PROTECTED_BRANDS.items():
            if brand in lower_name:
                is_official = any(sender_domain == off or sender_domain.endswith("." + off) for off in official_domains)
                if not is_official:
                    score_penalty += 45
                    findings.append({
                        "type": "display_name_spoofing",
                        "title": f"Display Name Spoofing ({brand.title()})",
                        "severity": "high",
                        "description": f"Display name claims to be '{display_name}', but actual sender domain is '{sender_domain}'.",
                        "educational_note": "Scammers change their sender name to trusted companies because most mobile email clients hide the real email address."
                    })
                break

    # 2. Reply-To Mismatch Check
    if reply_to:
        reply_parsed = parse_email_sender(reply_to)
        reply_email = reply_parsed["email"]
        reply_domain = reply_email.split("@")[-1] if "@" in reply_email else ""
        if sender_domain and reply_domain and sender_domain != reply_domain:
            score_penalty += 35
            findings.append({
                "type": "reply_to_mismatch",
                "title": "Reply-To Address Mismatch",
                "severity": "high",
                "description": f"Responses will be sent to '{reply_email}' instead of the apparent sender '{sender_email}'.",
                "educational_note": "Attackers send from compromised accounts or spoofed addresses but redirect your responses to their private inbox."
            })

    # 3. Free Webmail Domain Impersonating Corporations
    free_mail_providers = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "protonmail.com"}
    if sender_domain in free_mail_providers and display_name:
        for brand in ["bank", "support", "security", "officer", "helpdesk", "billing", "service", "irs"]:
            if brand in display_name.lower():
                score_penalty += 30
                findings.append({
                    "type": "free_webmail_impersonation",
                    "title": "Official Entity Using Free Public Webmail",
                    "severity": "high",
                    "description": f"Claims to be '{display_name}' but sends from a free consumer email account (@{sender_domain}).",
                    "educational_note": "Financial institutions and corporate teams will never contact customers using personal webmail services."
                })
                break

    # 4. Dangerous File Attachment References in Email
    dangerous_exts = [".exe", ".scr", ".iso", ".vbs", ".zip", ".bat", ".cmd", ".js", ".hta"]
    combined_text = f"{subject or ''}\n{body or ''}".lower()
    for ext in dangerous_exts:
        if ext in combined_text:
            score_penalty += 25
            findings.append({
                "type": "malicious_attachment_reference",
                "title": f"Executable / Archive Attachment ({ext})",
                "severity": "high",
                "description": f"Mentions or includes dangerous file attachment type '{ext}' commonly carrying ransomware or info-stealers.",
                "educational_note": "Never open unexpected zip, iso, or executable attachments—even if labeled 'Invoice' or 'Receipt'."
            })
            break

    # 5. Body Linguistic & Link Analysis
    if body:
        msg_result = analyze_message(body)
        for mf in msg_result.get("findings", []):
            if mf["severity"] in ["high", "medium"]:
                findings.append(mf)
        score_penalty += msg_result.get("score_penalty", 0) // 2

    risk_score = min(score_penalty, 100)

    if risk_score == 0:
        findings.append({
            "type": "clean_email",
            "title": "Email Appears Standard",
            "severity": "info",
            "description": "No sender spoofing, reply-to discrepancies, or coercive social engineering language detected.",
            "educational_note": "Always check sender address headers carefully before replying to financial notices."
        })

    return {
        "sender_email": sender_email,
        "display_name": display_name,
        "reply_to": reply_to,
        "score_penalty": risk_score,
        "findings": findings
    }
