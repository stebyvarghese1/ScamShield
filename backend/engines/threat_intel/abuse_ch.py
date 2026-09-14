"""abuse.ch Threat Intelligence Client: URLhaus & ThreatFox"""
import os
from typing import Dict, Any, Optional
import httpx
from backend.config import update_env_file

URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
THREATFOX_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"

def get_abusech_key() -> str:
    """Retrieves abuse.ch Auth-Key from environment (.env)"""
    return os.getenv("ABUSECH_API_KEY", "").strip()

def set_abusech_key(api_key: str) -> bool:
    """Updates abuse.ch API key in environment and .env"""
    clean = api_key.strip()
    os.environ["ABUSECH_API_KEY"] = clean
    return update_env_file("ABUSECH_API_KEY", clean)

def check_urlhaus(url: str) -> Optional[Dict[str, Any]]:
    """Checks URL against URLhaus for malware delivery campaigns"""
    clean_url = url.strip()
    headers = {}
    key = get_abusech_key()
    if key:
        headers["Auth-Key"] = key

    try:
        with httpx.Client(timeout=3.5) as client:
            resp = client.post(URLHAUS_ENDPOINT, data={"url": clean_url}, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("query_status")
                if status == "ok":
                    return {
                        "provider": "URLhaus (abuse.ch)",
                        "is_malware": True,
                        "url_status": data.get("url_status"),
                        "threat": data.get("threat"),
                        "tags": data.get("tags", []),
                        "reporter": data.get("reporter")
                    }
                elif status == "no_results":
                    return {
                        "provider": "URLhaus (abuse.ch)",
                        "is_malware": False
                    }
    except Exception as e:
        print(f"URLhaus query error: {e}")
        return None

    return None

def check_threatfox_ioc(indicator: str) -> Optional[Dict[str, Any]]:
    """Checks domain or IP against ThreatFox for botnet C2 and malware infrastructure"""
    clean_ind = indicator.strip()
    headers = {}
    key = get_abusech_key()
    if key:
        headers["Auth-Key"] = key

    payload = {
        "query": "search_ioc",
        "search_term": clean_ind
    }

    try:
        with httpx.Client(timeout=3.5) as client:
            resp = client.post(THREATFOX_ENDPOINT, json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("query_status")
                if status == "ok" and data.get("data"):
                    target_ind = clean_ind.lower().split(":")[0]
                    matching_ioc = None
                    for item in data["data"]:
                        raw_ioc = (item.get("ioc") or "").lower()
                        ioc_host = raw_ioc.split("/")[0].split(":")[0]
                        if raw_ioc.startswith("http"):
                            try:
                                from urllib.parse import urlparse
                                ioc_host = urlparse(raw_ioc).hostname or ioc_host
                            except Exception:
                                pass
                        if ioc_host == target_ind or target_ind.endswith("." + ioc_host) or raw_ioc == clean_ind.lower():
                            matching_ioc = item
                            break

                    if matching_ioc:
                        return {
                            "provider": "ThreatFox (abuse.ch)",
                            "is_ioc": True,
                            "threat_type": matching_ioc.get("threat_type_desc"),
                            "malware": matching_ioc.get("malware_printable"),
                            "confidence_level": matching_ioc.get("confidence_level"),
                            "tags": matching_ioc.get("tags", [])
                        }
                    else:
                        return {
                            "provider": "ThreatFox (abuse.ch)",
                            "is_ioc": False
                        }
                elif status == "no_result":
                    return {
                        "provider": "ThreatFox (abuse.ch)",
                        "is_ioc": False
                    }
    except Exception as e:
        print(f"ThreatFox query error: {e}")
        return None

    return None

def evaluate_abusech_findings(urlhaus_data: Optional[Dict[str, Any]], tf_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Generates explainable findings for URLhaus and ThreatFox detections"""
    findings = []
    penalty = 0

    if urlhaus_data and urlhaus_data.get("is_malware"):
        penalty += 85
        tags = ", ".join(urlhaus_data.get("tags", [])[:3]) or "Malware Dropper"
        findings.append({
            "type": "urlhaus_malware_confirmed",
            "title": f"URLhaus Confirmed Malware Distribution ({tags})",
            "severity": "high",
            "description": f"URL is documented in abuse.ch URLhaus database as an active malware payload distributor (Threat: {urlhaus_data.get('threat', 'Payload')}).",
            "educational_note": "Visiting this page risks downloading ransomware, trojans, or infostealer binaries directly to your device."
        })

    if tf_data and tf_data.get("is_ioc"):
        penalty += 80
        findings.append({
            "type": "threatfox_ioc_confirmed",
            "title": f"ThreatFox Botnet / C2 Indicator ({tf_data.get('malware', 'Threat')})",
            "severity": "high",
            "description": f"Target matches active IOC in ThreatFox (Malware: {tf_data.get('malware')}, Type: {tf_data.get('threat_type')}) with {tf_data.get('confidence_level')}% confidence.",
            "educational_note": "ThreatFox tracks infrastructure operated by cybercrime cartels to manage infected victim computers."
        })

    return {"score_penalty": penalty, "findings": findings}
