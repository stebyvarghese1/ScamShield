"""AbuseIPDB Malicious IP Address Intelligence Client"""
import os
from typing import Dict, Any, Optional
import httpx
from backend.config import update_env_file

ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

def get_abuseipdb_key() -> str:
    """Retrieves AbuseIPDB API key from environment (.env)"""
    return os.getenv("ABUSEIPDB_API_KEY", "").strip()

def set_abuseipdb_key(api_key: str) -> bool:
    """Updates AbuseIPDB API key in environment and .env"""
    clean = api_key.strip()
    os.environ["ABUSEIPDB_API_KEY"] = clean
    return update_env_file("ABUSEIPDB_API_KEY", clean)

def check_ip_reputation(ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Checks an IP address against AbuseIPDB for malicious activity reports and confidence score.
    """
    key = get_abuseipdb_key()
    if not key or not ip_address:
        return None

    clean_ip = ip_address.strip()
    headers = {
        "Key": key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": clean_ip,
        "maxAgeInDays": 90,
        "verbose": False
    }

    try:
        with httpx.Client(timeout=3.5) as client:
            resp = client.get(ABUSEIPDB_ENDPOINT, headers=headers, params=params)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                isp = data.get("isp", "Unknown ISP")
                country = data.get("countryCode", "Unknown")

                return {
                    "provider": "AbuseIPDB",
                    "ip": clean_ip,
                    "abuse_confidence_score": score,
                    "total_reports": reports,
                    "isp": isp,
                    "country": country,
                    "is_whitelisted": data.get("isWhitelisted", False)
                }
    except Exception as e:
        print(f"AbuseIPDB query error: {e}")
        return None

    return None

def evaluate_abuseipdb_findings(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Generates explainable findings based on AbuseIPDB score"""
    if not data:
        return {"score_penalty": 0, "findings": []}

    score = data.get("abuse_confidence_score", 0)
    reports = data.get("total_reports", 0)
    ip = data.get("ip", "")
    isp = data.get("isp", "Unknown")

    findings = []
    penalty = 0

    if score >= 25:
        penalty = min(85, score)
        findings.append({
            "type": "abuseipdb_high_malice_ip",
            "title": f"AbuseIPDB Threat Flag ({score}% Confidence, {reports} Reports)",
            "severity": "high" if score >= 50 else "medium",
            "description": f"Resolved hosting server ({ip} - {isp}) has an AbuseIPDB confidence score of {score}% based on {reports} security incident reports.",
            "educational_note": "High-abuse IPs are often servers hijacked for DDoS, botnet C2 traffic, brute-force attacks, or phishing hosts."
        })
    elif data.get("is_whitelisted"):
        findings.append({
            "type": "abuseipdb_whitelisted_ip",
            "title": "AbuseIPDB Verified Safe Infrastructure",
            "severity": "info",
            "description": f"Server IP ({ip}) is recognized on verified legitimate infrastructure.",
            "educational_note": "Major trusted CDNs (Cloudflare, Fastly, Akamai) are maintained on verified IP lists."
        })

    return {"score_penalty": penalty, "findings": findings}
