"""VirusTotal v3 Threat Intelligence Client with In-Memory TTL Caching"""
import os
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
import httpx
from backend.config import update_env_file

VT_BASE_URL = "https://www.virustotal.com/api/v3"
CACHE_TTL_HOURS = 6

_VT_CACHE: Dict[str, Dict[str, Any]] = {}

def get_virustotal_api_key() -> str:
    """Retrieves VirusTotal API key from environment (.env)"""
    return os.getenv("VIRUSTOTAL_API_KEY", "").strip()

def set_virustotal_api_key(api_key: str) -> bool:
    """Updates VirusTotal API key in environment and .env"""
    clean_key = api_key.strip()
    os.environ["VIRUSTOTAL_API_KEY"] = clean_key
    return update_env_file("VIRUSTOTAL_API_KEY", clean_key)

def mask_api_key(key: str) -> str:
    """Returns a masked preview of the API key for safe UI display"""
    if not key or len(key) < 8:
        return ""
    return f"{key[:4]}...{key[-4:]}"

def get_virustotal_status() -> Dict[str, Any]:
    """Returns current integration status"""
    key = get_virustotal_api_key()
    return {
        "configured": bool(key),
        "key_preview": mask_api_key(key),
        "provider": "VirusTotal v3"
    }

def generate_vt_url_id(url: str) -> str:
    """Computes VirusTotal v3 URL base64 identifier without padding"""
    return base64.urlsafe_b64encode(url.strip().encode("utf-8")).decode("utf-8").strip("=")

def check_cached_result(url: str) -> Optional[Dict[str, Any]]:
    """Checks if a valid non-expired VirusTotal analysis exists in memory"""
    clean = url.strip()
    entry = _VT_CACHE.get(clean)
    if not entry:
        return None
    cutoff = datetime.now(timezone.utc) - timedelta(hours=CACHE_TTL_HOURS)
    if entry.get("timestamp", datetime.min.replace(tzinfo=timezone.utc)) < cutoff:
        _VT_CACHE.pop(clean, None)
        return None
    res = dict(entry["data"])
    res["source"] = "cache"
    return res

def save_cached_result(url: str, result: Dict[str, Any]):
    """Stores a fresh VirusTotal analysis in memory cache"""
    clean = url.strip()
    _VT_CACHE[clean] = {
        "timestamp": datetime.now(timezone.utc),
        "data": result
    }

def query_virustotal_url(url: str) -> Optional[Dict[str, Any]]:
    """
    Queries VirusTotal v3 for URL reputation and vendor detections.
    Returns analysis summary or None if unconfigured or unreachable.
    """
    key = get_virustotal_api_key()
    if not key:
        return None

    clean_url = url.strip()
    # Check cache first to preserve rate limits
    cached = check_cached_result(clean_url)
    if cached:
        return cached

    url_id = generate_vt_url_id(clean_url)
    endpoint = f"{VT_BASE_URL}/urls/{url_id}"
    headers = {
        "x-apikey": key,
        "Accept": "application/json"
    }

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(endpoint, headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                attr = data.get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                results = attr.get("last_analysis_results", {})
                reputation = attr.get("reputation", 0)

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                total = sum(stats.values()) if stats else 0

                flagged_vendors: List[str] = []
                for vendor_name, vendor_info in results.items():
                    if vendor_info.get("category") == "malicious":
                        flagged_vendors.append(vendor_name)

                result_data = {
                    "source": "live_api",
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "total_vendors": total,
                    "reputation": reputation,
                    "flagged_vendors": flagged_vendors[:8]
                }
                save_cached_result(clean_url, result_data)
                return result_data
            elif resp.status_code == 404:
                # URL has not been submitted or observed by VirusTotal yet
                return {
                    "source": "live_api",
                    "status": "not_found",
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "total_vendors": 0,
                    "reputation": 0,
                    "flagged_vendors": []
                }
            elif resp.status_code == 429:
                print("VirusTotal rate limit reached.")
                return None
    except Exception as e:
        print(f"VirusTotal query error: {e}")
        return None

    return None

def test_virustotal_connection(api_key: Optional[str] = None) -> Dict[str, Any]:
    """Tests validity of a VirusTotal API key"""
    key = api_key.strip() if api_key else get_virustotal_api_key()
    if not key:
        return {"success": False, "message": "No API key provided."}

    # Query google.com as a known safe test domain
    url_id = generate_vt_url_id("https://www.google.com")
    endpoint = f"{VT_BASE_URL}/urls/{url_id}"
    headers = {"x-apikey": key, "Accept": "application/json"}

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(endpoint, headers=headers)
            if resp.status_code == 200:
                return {"success": True, "message": "Successfully connected to VirusTotal API v3!"}
            elif resp.status_code == 401 or resp.status_code == 403:
                return {"success": False, "message": "Invalid VirusTotal API key. Please check your credentials."}
            elif resp.status_code == 429:
                return {"success": True, "message": "Key is valid, but rate limit quota is reached. Ready to use."}
            else:
                return {"success": False, "message": f"VirusTotal returned HTTP {resp.status_code}."}
    except Exception as e:
        return {"success": False, "message": f"Connection failed: {str(e)}"}
