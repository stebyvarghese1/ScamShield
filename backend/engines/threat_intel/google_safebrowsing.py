"""Google Safe Browsing v4 Threat Intelligence Client"""
import os
from typing import Dict, Any, Optional, List
import httpx
from backend.config import update_env_file

GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

def get_gsb_key() -> str:
    """Retrieves Google Safe Browsing API key from environment (.env)"""
    return os.getenv("GOOGLE_SAFEBROWSING_API_KEY", "").strip()

def set_gsb_key(api_key: str) -> bool:
    """Updates Google Safe Browsing API key in environment and .env"""
    clean = api_key.strip()
    os.environ["GOOGLE_SAFEBROWSING_API_KEY"] = clean
    return update_env_file("GOOGLE_SAFEBROWSING_API_KEY", clean)

def check_google_safebrowsing(url: str) -> Optional[Dict[str, Any]]:
    """
    Checks URL against Google Safe Browsing v4 for malware and social engineering.
    """
    key = get_gsb_key()
    if not key:
        return None

    clean_url = url.strip()
    payload = {
        "client": {
            "clientId": "scamshield-assistant",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": clean_url}]
        }
    }

    try:
        with httpx.Client(timeout=3.5) as client:
            resp = client.post(f"{GSB_ENDPOINT}?key={key}", json=payload)
            if resp.status_code == 200:
                matches = resp.json().get("matches", [])
                is_threat = len(matches) > 0
                threat_types = [m.get("threatType") for m in matches]

                return {
                    "provider": "Google Safe Browsing v4",
                    "url": clean_url,
                    "is_threat": is_threat,
                    "threat_types": threat_types,
                    "matches_count": len(matches)
                }
    except Exception as e:
        print(f"Google Safe Browsing error: {e}")
        return None

    return None

def evaluate_gsb_findings(gsb_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Generates explainable findings based on Google Safe Browsing matches"""
    if not gsb_data or not gsb_data.get("is_threat"):
        return {"score_penalty": 0, "findings": []}

    types = gsb_data.get("threat_types", [])
    penalty = 90
    findings = [{
        "type": "google_safebrowsing_match",
        "title": f"Google Safe Browsing Threat Flagged ({', '.join(types)})",
        "severity": "high",
        "description": f"URL is blacklisted by Google Safe Browsing for {', '.join(types)}. Chrome and Android devices actively block this target.",
        "educational_note": "Google Safe Browsing analyzes billions of URLs daily to protect billions of devices from phishing, malware, and social engineering."
    }]

    return {"score_penalty": penalty, "findings": findings}
