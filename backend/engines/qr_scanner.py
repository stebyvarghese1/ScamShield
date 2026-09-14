"""QR Code Safety & Quishing Detection Scanner"""
import re
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs
from backend.engines.url_scanner import analyze_url

def analyze_qr_payload(payload: str) -> Dict[str, Any]:
    """
    Analyzes decoded QR Code payload (URLs, Payment URIs, Wi-Fi configs, contacts)
    for deceptive redirection, payment manipulation, and credential phishing (Quishing).
    """
    findings: List[Dict[str, Any]] = []
    score_penalty = 0
    clean_payload = payload.strip()
    payload_lower = clean_payload.lower()

    payload_type = "TEXT"

    # 1. UPI or Payment Link (upi://pay?pa=... or paytm/phonepe)
    if payload_lower.startswith("upi://") or "pa=" in payload_lower and "pn=" in payload_lower:
        payload_type = "UPI_PAYMENT"
        score_penalty += 25
        findings.append({
            "type": "direct_payment_trigger",
            "title": "Direct Payment Intent (UPI / QR Payment)",
            "severity": "medium",
            "description": "This QR code triggers a direct financial payment or money transfer request from your device.",
            "educational_note": "Scammers paste fake QR codes on parking meters, store counters, or send them pretending you are 'receiving' money. Remember: YOU NEVER ENTER A PIN TO RECEIVE MONEY."
        })

    # 2. Crypto Wallet Address / Transfer
    elif any(payload_lower.startswith(c) for c in ["bitcoin:", "ethereum:", "litecoin:", "bitcoincash:"]) or re.search(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$", clean_payload):
        payload_type = "CRYPTO_ADDRESS"
        score_penalty += 35
        findings.append({
            "type": "crypto_address_payload",
            "title": "Cryptocurrency Transfer Destination",
            "severity": "medium",
            "description": "This QR code contains a cryptocurrency wallet address. Crypto transactions are strictly non-reversible.",
            "educational_note": "Scammers frequently use QR codes at crypto ATMs or on social media claiming investment doubling."
        })

    # 3. Direct App Download / APK
    elif any(payload_lower.endswith(ext) for ext in [".apk", ".exe", ".ipa"]):
        payload_type = "APP_DOWNLOAD"
        score_penalty += 60
        findings.append({
            "type": "direct_executable_qr",
            "title": "Direct Mobile App / Executable Download",
            "severity": "high",
            "description": "Scanning this QR code initiates a direct download of an application file (.apk/.exe) bypassing official app stores.",
            "educational_note": "Sideloading unverified mobile APKs via QR codes is a primary method for installing mobile banking Trojans."
        })

    # 4. Web URL (Quishing)
    elif payload_lower.startswith("http://") or payload_lower.startswith("https://") or ("." in clean_payload and "/" in clean_payload):
        payload_type = "URL"
        url_res = analyze_url(clean_payload)
        for f in url_res.get("findings", []):
            findings.append(f)
        score_penalty += url_res.get("score_penalty", 0)

        # Additional quishing context
        if score_penalty > 30:
            findings.append({
                "type": "quishing_attack",
                "title": "QR Phishing ('Quishing') Indicator",
                "severity": "high",
                "description": "A suspicious web destination delivered via QR code to evade traditional email text filters.",
                "educational_note": "Quishing tricks users into using their mobile phones, where security protections and URL inspection are harder."
            })

    # 5. Wi-Fi Configuration
    elif payload_lower.startswith("wifi:"):
        payload_type = "WIFI_CONFIG"
        score_penalty += 15
        findings.append({
            "type": "wifi_network_profile",
            "title": "Automatic Wi-Fi Network Connection",
            "severity": "low",
            "description": "Attempts to connect your phone to an external Wi-Fi network.",
            "educational_note": "Unverified public Wi-Fi networks can enable man-in-the-middle attacks that intercept your traffic."
        })

    risk_score = min(score_penalty, 100)

    if risk_score == 0:
        findings.append({
            "type": "clean_qr",
            "title": "Safe QR Code Payload",
            "severity": "info",
            "description": "Standard legitimate format with no malicious redirection or fraudulent payment triggers detected.",
            "educational_note": "Always inspect the URL in your camera app preview before opening."
        })

    return {
        "payload_type": payload_type,
        "payload": clean_payload,
        "score_penalty": risk_score,
        "findings": findings
    }
