import os
from typing import Dict, Any, Optional
import httpx

PHISHTANK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

def get_phishtank_key() -> str:
    """Retrieves PhishTank app key if configured in environment (.env)"""
    return os.getenv("PHISHTANK_API_KEY", "").strip()

def check_phishtank_url(url: str) -> Optional[Dict[str, Any]]:
    """
    Checks if a URL is currently listed in PhishTank's verified active phishing database.
    """
    clean_url = url.strip()
    key = get_phishtank_key()

    data = {
        "url": clean_url,
        "format": "json"
    }
    if key:
        data["app_key"] = key

    headers = {"User-Agent": "phishtank/scamshield"}

    try:
        with httpx.Client(timeout=3.5) as client:
            resp = client.post(PHISHTANK_ENDPOINT, data=data, headers=headers)
            if resp.status_code == 200:
                res_json = resp.json().get("results", {})
                in_db = res_json.get("in_database", False)
                is_valid = res_json.get("valid", False)
                verified = res_json.get("verified", False)
                phish_id = res_json.get("phish_id")

                is_active_phish = bool(in_db and is_valid)

                return {
                    "provider": "PhishTank",
                    "url": clean_url,
                    "in_database": in_db,
                    "is_phish": is_active_phish,
                    "verified": verified,
                    "phish_id": phish_id,
                    "detail_page": res_json.get("phish_detail_page")
                }
    except Exception as e:
        print(f"PhishTank query error: {e}")
        return None

    return None

def evaluate_phishtank_findings(pt_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Generates explainable findings based on PhishTank response"""
    if not pt_data:
        return {"score_penalty": 0, "findings": []}

    findings = []
    penalty = 0

    if pt_data.get("is_phish"):
        penalty = 85
        findings.append({
            "type": "phishtank_confirmed_phish",
            "title": f"PhishTank Verified Active Phishing (ID #{pt_data.get('phish_id')})",
            "severity": "high",
            "description": "This exact URL is confirmed as an active phishing website in the community-verified PhishTank security repository.",
            "educational_note": "PhishTank entries are reviewed and verified by security researchers worldwide. DO NOT provide any credentials or sensitive information."
        })

    return {"score_penalty": penalty, "findings": findings}
