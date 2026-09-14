"""Settings & Multi-Provider Integrations Management Router"""
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from backend.engines.threat_intel.manager import get_all_providers_status
from backend.engines.virustotal_client import (
    set_virustotal_api_key,
    test_virustotal_connection
)
from backend.engines.threat_intel.google_safebrowsing import set_gsb_key
from backend.engines.threat_intel.phishtank import get_phishtank_key
from backend.engines.threat_intel.abuseipdb import set_abuseipdb_key
from backend.engines.threat_intel.abuse_ch import set_abusech_key
from backend.engines.threat_intel.alienvault_otx import set_otx_key
from backend.engines.threat_intel.hibp_client import (
    set_hibp_key,
    check_password_pwned,
    check_email_breaches
)
from backend.config import update_env_file

PROVIDER_ENV_MAP = {
    "virustotal": "VIRUSTOTAL_API_KEY",
    "google_safebrowsing": "GOOGLE_SAFEBROWSING_API_KEY",
    "gsb": "GOOGLE_SAFEBROWSING_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "urlhaus": "ABUSECH_API_KEY",
    "threatfox": "ABUSECH_API_KEY",
    "abusech": "ABUSECH_API_KEY",
    "alienvault_otx": "ALIENVAULT_OTX_API_KEY",
    "otx": "ALIENVAULT_OTX_API_KEY",
    "hibp": "HIBP_API_KEY",
    "phishtank": "PHISHTANK_API_KEY"
}

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])

class ProviderKeyRequest(BaseModel):
    api_key: str = Field(..., description="API or Auth Key for the specified provider")

class PasswordCheckRequest(BaseModel):
    password: str = Field(..., min_length=1, description="Password to test against HIBP k-anonymity API")

class EmailCheckRequest(BaseModel):
    email: str = Field(..., min_length=3, description="Email address to check against HIBP breach database")

@router.get("/integrations")
def list_integrations():
    """Returns status and configuration details for all 10 Threat Intelligence providers"""
    return {
        "providers": get_all_providers_status()
    }

@router.post("/integrations/{provider_id}")
def update_provider_key(provider_id: str, req: ProviderKeyRequest):
    """Saves API key for a specified threat intelligence provider"""
    clean_id = provider_id.lower().strip()
    clean_key = req.api_key.strip()

    if clean_id == "virustotal":
        test_res = test_virustotal_connection(clean_key)
        if not test_res.get("success"):
            raise HTTPException(status_code=400, detail=test_res.get("message"))
        set_virustotal_api_key(clean_key)
    elif clean_id in ["google_safebrowsing", "gsb"]:
        set_gsb_key(clean_key)
    elif clean_id == "abuseipdb":
        set_abuseipdb_key(clean_key)
    elif clean_id in ["urlhaus", "threatfox", "abusech"]:
        set_abusech_key(clean_key)
    elif clean_id in ["alienvault_otx", "otx"]:
        set_otx_key(clean_key)
    elif clean_id == "hibp":
        set_hibp_key(clean_key)
    elif clean_id == "phishtank":
        update_env_file("PHISHTANK_API_KEY", clean_key)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider_id}")

    # Synchronize with .env file and process environment
    env_var = PROVIDER_ENV_MAP.get(clean_id)
    if env_var:
        update_env_file(env_var, clean_key)

    return {
        "success": True,
        "message": f"Successfully updated key for {provider_id}.",
        "providers": get_all_providers_status()
    }

@router.post("/integrations/{provider_id}/test")
def test_provider_key(provider_id: str, req: ProviderKeyRequest):
    """Validates an API key against the provider's verification endpoint"""
    import httpx
    clean_id = provider_id.lower().strip()
    clean_key = req.api_key.strip()

    if not clean_key and clean_id not in ["rdap", "dns"]:
        raise HTTPException(status_code=400, detail="API key cannot be empty.")

    try:
        if clean_id == "virustotal":
            res = test_virustotal_connection(clean_key)
            if not res.get("success"):
                raise HTTPException(status_code=400, detail=res.get("message", "VirusTotal validation failed."))
            return {"success": True, "message": "VirusTotal connection verified successfully!"}

        elif clean_id in ["google_safebrowsing", "gsb"]:
            url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={clean_key}"
            payload = {
                "client": {"clientId": "scamshield-test", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": "https://example.com"}]
                }
            }
            resp = httpx.post(url, json=payload, timeout=5.0)
            if resp.status_code == 200:
                return {"success": True, "message": "Google Safe Browsing v4 key is active and valid!"}
            elif resp.status_code in [400, 403]:
                err = resp.json().get("error", {}).get("message", "Invalid API key")
                raise HTTPException(status_code=400, detail=f"Google Safe Browsing rejected key: {err}")
            else:
                return {"success": True, "message": f"Connected to Google Safe Browsing (HTTP {resp.status_code})"}

        elif clean_id == "abuseipdb":
            resp = httpx.get(
                "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8",
                headers={"Key": clean_key, "Accept": "application/json"},
                timeout=5.0
            )
            if resp.status_code == 200:
                return {"success": True, "message": "AbuseIPDB key is active and verified!"}
            elif resp.status_code in [401, 403]:
                raise HTTPException(status_code=400, detail="AbuseIPDB authentication failed: invalid API key.")
            else:
                return {"success": True, "message": f"Connected to AbuseIPDB (HTTP {resp.status_code})"}

        elif clean_id in ["urlhaus", "threatfox", "abusech"]:
            # URLhaus allows testing with auth-key
            resp = httpx.post(
                "https://urlhaus-api.abuse.ch/v1/urls/recent/",
                headers={"Auth-Key": clean_key},
                timeout=5.0
            )
            if resp.status_code in [200, 400]: # Valid Auth-Key or accepted request
                return {"success": True, "message": "abuse.ch (URLhaus/ThreatFox) connection established!"}
            elif resp.status_code in [401, 403]:
                raise HTTPException(status_code=400, detail="abuse.ch rejected Auth-Key.")
            else:
                return {"success": True, "message": f"Connected to abuse.ch (HTTP {resp.status_code})"}

        elif clean_id in ["alienvault_otx", "otx"]:
            resp = httpx.get(
                "https://otx.alienvault.com/api/v1/indicators/domain/example.com/general",
                headers={"X-OTX-API-KEY": clean_key},
                timeout=5.0
            )
            if resp.status_code == 200:
                return {"success": True, "message": "AlienVault OTX API key is active and valid!"}
            elif resp.status_code in [401, 403]:
                raise HTTPException(status_code=400, detail="AlienVault OTX rejected API key.")
            else:
                return {"success": True, "message": f"Connected to AlienVault OTX (HTTP {resp.status_code})"}

        elif clean_id == "hibp":
            resp = httpx.get(
                "https://haveibeenpwned.com/api/v3/breaches",
                headers={"hibp-api-key": clean_key, "user-agent": "ScamShield-Client"},
                timeout=5.0
            )
            if resp.status_code == 200:
                return {"success": True, "message": "Have I Been Pwned API key is active and valid!"}
            elif resp.status_code in [401, 403]:
                raise HTTPException(status_code=400, detail="Have I Been Pwned rejected API key.")
            else:
                return {"success": True, "message": f"Connected to HIBP (HTTP {resp.status_code})"}

        elif clean_id in ["rdap", "dns", "phishtank"]:
            return {"success": True, "message": f"{clean_id.upper()} operates without restrictions."}

        else:
            raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider_id}")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Connection test failed: {str(e)}")

@router.delete("/integrations/{provider_id}")
def disconnect_provider(provider_id: str):
    """Disconnects or clears API key for a provider in .env and environment"""
    clean_id = provider_id.lower().strip()
    env_var = PROVIDER_ENV_MAP.get(clean_id)
    if env_var:
        update_env_file(env_var, "")

    return {
        "success": True,
        "message": f"Disconnected {provider_id}.",
        "providers": get_all_providers_status()
    }

@router.post("/hibp/check-password")
def check_password_breach(req: PasswordCheckRequest):
    """
    Checks if a password is exposed in global breaches via HIBP k-anonymity protocol.
    Your password text is NEVER sent to the network.
    """
    return check_password_pwned(req.password)

@router.post("/hibp/check-email")
def check_email_breach(req: EmailCheckRequest):
    """Checks an email address for known data breaches"""
    return check_email_breaches(req.email)
