"""AlienVault OTX (Open Threat Exchange) Intelligence Client"""
import os
from typing import Dict, Any, Optional, List
import httpx
from backend.config import update_env_file

OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

def get_otx_key() -> str:
    """Retrieves AlienVault OTX API key from environment (.env)"""
    return os.getenv("ALIENVAULT_OTX_API_KEY", "").strip()

def set_otx_key(api_key: str) -> bool:
    """Updates AlienVault OTX API key in environment and .env"""
    clean = api_key.strip()
    os.environ["ALIENVAULT_OTX_API_KEY"] = clean
    return update_env_file("ALIENVAULT_OTX_API_KEY", clean)

def check_alienvault_domain(domain: str) -> Optional[Dict[str, Any]]:
    """Checks domain against AlienVault OTX threat pulses"""
    key = get_otx_key()
    if not key:
        return None

    clean = domain.lower().strip()
    if "//" in clean:
        clean = clean.split("//")[1]
    clean = clean.split("/")[0].split(":")[0].split("?")[0]

    endpoint = f"{OTX_BASE_URL}/indicators/domain/{clean}/general"
    headers = {
        "X-OTX-API-KEY": key,
        "Accept": "application/json"
    }

    try:
        with httpx.Client(timeout=3.5) as client:
            resp = client.get(endpoint, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                pulse_info = data.get("pulse_info", {})
                pulse_count = pulse_info.get("count", 0)
                pulses = pulse_info.get("pulses", [])

                pulse_names: List[str] = [p.get("name") for p in pulses if p.get("name")]
                tags: List[str] = []
                for p in pulses:
                    tags.extend(p.get("tags", []))

                return {
                    "provider": "AlienVault OTX",
                    "domain": clean,
                    "pulse_count": pulse_count,
                    "pulse_names": pulse_names[:3],
                    "tags": list(set(tags))[:5]
                }
    except Exception as e:
        print(f"AlienVault OTX error: {e}")
        return None

    return None

def evaluate_otx_findings(otx_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Generates explainable findings based on AlienVault OTX pulses"""
    if not otx_data or otx_data.get("pulse_count", 0) == 0:
        return {"score_penalty": 0, "findings": []}

    count = otx_data.get("pulse_count", 0)
    penalty = min(80, count * 20 + 20)
    names = ", ".join(otx_data.get("pulse_names", [])[:2]) or "Adversary Campaign"

    findings = [{
        "type": "alienvault_otx_pulse_threat",
        "title": f"AlienVault OTX Active Threat Pulses ({count} Pulses)",
        "severity": "high" if count >= 2 else "medium",
        "description": f"Domain matches {count} threat intelligence pulses on AlienVault OTX ({names}).",
        "educational_note": "AlienVault OTX crowdsources threat indicators submitted by enterprise SOC analysts and threat research teams."
    }]

    return {"score_penalty": penalty, "findings": findings}
