"""ScamShield Configuration & Threat Constants"""
import os
from typing import Dict, List, Set

# Base Paths & Environment Loading
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE_PATH = os.path.join(BASE_DIR, ".env")

try:
    from dotenv import load_dotenv
    load_dotenv(ENV_FILE_PATH, override=False)
except Exception:
    pass

def update_env_file(key: str, value: str) -> bool:
    """Synchronizes or updates an environment variable inside .env"""
    os.environ[key] = value
    try:
        lines = []
        if os.path.exists(ENV_FILE_PATH):
            with open(ENV_FILE_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
        
        new_lines = []
        found = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(f"{key}=") or stripped.startswith(f"#{key}="):
                new_lines.append(f"{key}={value}\n")
                found = True
            else:
                new_lines.append(line)
        
        if not found:
            new_lines.append(f"{key}={value}\n")
            
        with open(ENV_FILE_PATH, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        return True
    except Exception as e:
        print(f"Notice: Failed to update .env: {e}")
        return False

# Risk Score Thresholds
RISK_THRESHOLD_SAFE = 29
RISK_THRESHOLD_SUSPICIOUS = 69
# 70+ is DANGEROUS / HIGH RISK

# High Risk TLDs commonly abused in automated phishing campaigns
SUSPICIOUS_TLDS: Set[str] = {
    "xyz", "top", "zip", "mov", "click", "loan", "work", "icu", "buzz", "club",
    "fit", "surf", "monster", "cfd", "sbs", "rest", "cam", "quest", "link", "gq",
    "ml", "cf", "ga", "tk"
}

# Known URL Shorteners that conceal the real destination
URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "bl.ink"
}

# High-Value Protected Brands frequently targeted by typosquatting and phishing
PROTECTED_BRANDS: Dict[str, List[str]] = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.in"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"],
    "citibank": ["citi.com", "citibank.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "irs": ["irs.gov"]
}

# Linguistic Indicators for Social Engineering Analysis
URGENCY_TRIGGERS: List[str] = [
    "urgent", "immediately", "within 24 hours", "account suspended", "blocked today",
    "action required", "final notice", "immediate response", "permanently closed",
    "expires today", "unauthorized transaction", "legal action", "law enforcement",
    "arrest warrant", "restricted access", "confirm now", "suspended", "card is suspended",
    "card suspended", "account blocked"
]

CREDENTIAL_TRIGGERS: List[str] = [
    "verify your password", "enter otp", "confirm pin", "ssn", "social security",
    "credit card number", "cvv", "security question", "login to restore",
    "confirm identity", "wallet seed phrase", "private key", "recovery phrase",
    "two-factor code", "account verification", "debit card", "credit card"
]

FINANCIAL_TRIGGERS: List[str] = [
    "wire transfer", "gift card", "bitcoin", "crypto payment", "western union",
    "refund processing", "claim lottery", "guaranteed returns", "investment payout",
    "unclaimed funds", "million dollars", "cash prize", "inheritance", "tax refund",
    "earn $", "daily income", "daily salary"
]

IMPERSONATION_TRIGGERS: List[str] = [
    "customer support team", "fraud prevention department", "security division",
    "geek squad", "apple support", "it desk", "bank compliance", "irs officer",
    "fedex tracking manager", "meta security center"
]

# High-Risk Suspicious Subdomain / Path Keywords
SUSPICIOUS_PATH_KEYWORDS: Set[str] = {
    "login", "signin", "verify", "secure", "banking", "account-update",
    "restore-access", "wallet-connect", "claim-reward", "billing", "confirm",
    "auth", "webscr", "session", "resolution", "portal", "validate",
    "update", "recover", "authenticate", "credential", "security-alert",
    "pwd", "passwd", "passcode", "identity-verification", "owa", "zimbra",
    "exch", "webmail", "cpanel", "roundcube"
}

# Webmail & Corporate Authentication Portal Keywords
WEBMAIL_AND_ENTERPRISE_KEYWORDS: Set[str] = {
    "owa", "zimbra", "exch", "exchange", "webmail", "roundcube", "cpanel",
    "whm", "squirrelmail", "horde", "office365", "outlook365", "sharepoint",
    "onedrive", "adfs", "sso", "idp", "saml", "okta", "duo", "pingidentity",
    "webaccess", "mail2", "web-mail", "email-login", "inbox", "uleth", "alumni",
    "student-portal", "employee-portal", "hr-portal", "intranet", "portal"
}

# Generic, Shared, or Compromised Web Hosting Indicators
GENERIC_OR_FREE_HOSTING_INDICATORS: Set[str] = {
    "host", "hosting", "vps", "server", "000webhost", "ngrok", "duckdns",
    "weebly", "wixsite", "firebaseapp", "netlify", "glitch", "repl", "pages.dev",
    "workers.dev", "github.io", "surge.sh", "vercel", "render", "pythonanywhere",
    "godaddysites", "mystrikingly", "squarespace", "wordpress.com", "blogspot",
    "gtphost", "freehost", "webcindario", "byethost", "0fees", "awardspace", "hostinger"
}

