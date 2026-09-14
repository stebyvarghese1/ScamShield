"""Explainable Risk Scoring Engine & Scam Taxonomy Classifier"""
import re
from typing import Dict, Any, List, Tuple
from backend.config import (
    RISK_THRESHOLD_SAFE,
    RISK_THRESHOLD_SUSPICIOUS
)

def classify_category(findings: List[Dict[str, Any]], context_text: str = "") -> str:
    """Classifies the threat category based on detected signals and taxonomy rules"""
    lower = context_text.lower()
    types = [f.get("type", "").lower() for f in findings]

    # Rule-based priority matching
    if any("delivery" in t for t in types) or any(w in lower for w in ["fedex", "usps", "dhl", "ups", "package", "parcel"]):
        return "DELIVERY_SCAM"
    if any("bank" in t for t in types) or any(w in lower for w in ["bank", "chase", "wells fargo", "bofa", "citibank", "debit card", "credit card", "blocked today"]):
        return "BANKING_SCAM"
    if any("crypto" in t for t in types) or any(w in lower for w in ["bitcoin", "ethereum", "binance", "metamask", "seed phrase", "usdt"]) or re.search(r'\beth\b', lower):
        return "CRYPTO_SCAM"
    if any("job" in t for t in types) or any(w in lower for w in ["part-time", "daily salary", "hiring", "task job", "work from home"]):
        return "JOB_SCAM"
    if any(w in lower for w in ["lottery", "prize", "jackpot", "winner", "won $", "claim prize"]):
        return "PRIZE_SCAM"
    if any("tech_support" in t for t in types) or any(w in lower for w in ["geek squad", "virus detected", "call support", "toll-free", "windows defender alert"]):
        return "TECH_SUPPORT"
    if any(w in lower for w in ["irs", "tax refund", "arrest warrant", "police", "court", "fbi"]):
        return "GOV_IMPERSONATION"
    if any("phish" in t or "webmail" in t or "typosquatting" in t or "credential" in t or "punycode" in t or "sensitive_action" in t for t in types):
        return "PHISHING"
    if any("urgency" in t for t in types) and any(w in lower for w in ["account", "password", "login"]):
        return "ACCOUNT_TAKEOVER"
    if any("ssn" in lower or "social security" in lower or "identity" in lower for w in [lower]):
        return "IDENTITY_THEFT"
    if any("investment" in lower or "guaranteed return" in lower or "trading bot" in lower for w in [lower]):
        return "INVESTMENT_SCAM"

    return "PHISHING" if any(f.get("severity") in ["high", "medium"] for f in findings) else "SAFE"

def evaluate_risk(
    base_score: int,
    findings: List[Dict[str, Any]],
    context_text: str = ""
) -> Dict[str, Any]:
    """
    Synthesizes raw heuristic penalties into an explainable 0-100 score,
    determines severity tier, and produces human-oriented recommendations.
    """
    score = min(max(base_score, 0), 100)

    # Risk level thresholding
    if score <= RISK_THRESHOLD_SAFE:
        risk_level = "SAFE"
        recommendation = "No critical danger signals detected. Continue to verify sources before sharing personal info."
        educational_tip = "Always remember that legitimate services will never penalize you for taking a moment to double-check their official website."
    elif score <= RISK_THRESHOLD_SUSPICIOUS:
        risk_level = "SUSPICIOUS"
        recommendation = "Exercise caution. Do not click unverified links or provide sensitive credentials."
        educational_tip = "Pause and verify. Contact the sender directly through a known official phone number or app, not via the contact info in this message."
    else:
        risk_level = "HIGH"
        recommendation = "DO NOT click this link, do not reply, and never enter passwords or payment details."
        educational_tip = "Urgency and fear are psychological levers. Real security problems can always be resolved through your bank's verified official portal."

    category = classify_category(findings, context_text) if risk_level != "SAFE" else "SAFE"

    # Calculate confidence based on evidence count
    high_count = sum(1 for f in findings if f.get("severity") == "high")
    med_count = sum(1 for f in findings if f.get("severity") == "medium")
    evidence_points = high_count * 0.3 + med_count * 0.15
    confidence = min(0.98, max(0.85, 0.85 + evidence_points))

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "category": category,
        "confidence": round(confidence, 2),
        "findings": findings,
        "recommendation": recommendation,
        "educational_tip": educational_tip
    }
