"""Screenshot & Visual Scam Analyzer"""
import io
from typing import Dict, Any, List, Optional
from PIL import Image
from backend.engines.message_scanner import analyze_message

def inspect_image_file(image_bytes: bytes) -> Dict[str, Any]:
    """Validates and extracts metadata from an uploaded image"""
    try:
        img = Image.open(io.BytesIO(image_bytes))
        return {
            "format": img.format,
            "mode": img.mode,
            "width": img.width,
            "height": img.height,
            "is_valid": True
        }
    except Exception as e:
        return {
            "is_valid": False,
            "error": str(e)
        }

def classify_screenshot_type(text: str) -> str:
    """Classifies screenshot archetype based on visual cues and extracted text"""
    lower = text.lower()
    if any(k in lower for k in ["whatsapp", "telegram", "imessage", "text message", "chat"]):
        return "CHAT_CONVERSATION"
    elif any(k in lower for k in ["balance", "portfolio", "profit", "roi", "deposit bonus", "usdt", "metamask", "trading"]):
        return "FAKE_INVESTMENT_DASHBOARD"
    elif any(k in lower for k in ["payment successful", "transaction id", "paid to", "transferred", "upi ref"]):
        return "PAYMENT_RECEIPT"
    elif any(k in lower for k in ["critical alert", "virus detected", "call microsoft support", "toll-free", "pc locked"]):
        return "TECH_SUPPORT_LOCKSCREEN"
    elif any(k in lower for k in ["fedex", "usps", "delivery notice", "reschedule package"]):
        return "COURIER_NOTIFICATION"
    return "GENERIC_SCREENSHOT"

def analyze_screenshot_text(extracted_text: str, image_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Evaluates screenshot extracted text and image properties for fraud,
    fake receipts, and deceptive chat tactics.
    """
    findings: List[Dict[str, Any]] = []
    text_clean = (extracted_text or "").strip()

    if not text_clean:
        return {
            "score_penalty": 0,
            "category": "SAFE",
            "findings": [{
                "type": "no_text_detected",
                "title": "No Text Detected In Screenshot",
                "severity": "info",
                "description": "ScamShield could not identify readable text in the provided image.",
                "educational_note": "Ensure your screenshot has good contrast and clear text for best results."
            }]
        }

    screenshot_type = classify_screenshot_type(text_clean)
    msg_analysis = analyze_message(text_clean)
    score_penalty = msg_analysis.get("score_penalty", 0)

    # Archetype-specific security warnings
    if screenshot_type == "TECH_SUPPORT_LOCKSCREEN":
        score_penalty = max(score_penalty, 85)
        findings.append({
            "type": "tech_support_pop_up",
            "title": "Fake Technical Support Lockscreen",
            "severity": "high",
            "description": "Detected fake browser virus pop-up or Microsoft/Apple impersonation demanding you call a toll-free number.",
            "educational_note": "Microsoft and Apple NEVER lock your computer screen or ask you to call phone numbers for malware removal."
        })
    elif screenshot_type == "FAKE_INVESTMENT_DASHBOARD":
        score_penalty = max(score_penalty, 75)
        findings.append({
            "type": "fake_investment_ui",
            "title": "Unrealistic Investment / Crypto Returns Interface",
            "severity": "high",
            "description": "Visual layout mimics a crypto wallet or trading platform showing guaranteed high yields.",
            "educational_note": "Pig-butchering and crypto investment scammers use fake trading interfaces displaying inflated artificial balances."
        })
    elif screenshot_type == "PAYMENT_RECEIPT":
        findings.append({
            "type": "payment_receipt_verification",
            "title": "Payment Confirmation Screenshot",
            "severity": "low",
            "description": "Visual receipt detected. Be cautious of fake banking receipt generator apps used by fraudulent buyers.",
            "educational_note": "Always check your own real banking application to verify funds arrived before releasing items or services."
        })

    # Add message findings
    for f in msg_analysis.get("findings", []):
        findings.append(f)

    risk_score = min(score_penalty, 100)

    return {
        "screenshot_type": screenshot_type,
        "score_penalty": risk_score,
        "findings": findings,
        "image_meta": image_meta
    }
