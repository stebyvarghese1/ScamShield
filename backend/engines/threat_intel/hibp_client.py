"""Have I Been Pwned (HIBP) Credential & Breach Engine (Free K-Anonymity)"""
import os
import hashlib
from typing import Dict, Any, Optional
import httpx
from backend.config import update_env_file

HIBP_RANGE_ENDPOINT = "https://api.pwnedpasswords.com/range"
HIBP_ACCOUNT_ENDPOINT = "https://haveibeenpwned.com/api/v3/breachedaccount"

def get_hibp_key() -> str:
    """Retrieves Have I Been Pwned API key from environment (.env)"""
    return os.getenv("HIBP_API_KEY", "").strip()

def set_hibp_key(api_key: str) -> bool:
    """Updates HIBP API key in environment and .env"""
    clean = api_key.strip()
    os.environ["HIBP_API_KEY"] = clean
    return update_env_file("HIBP_API_KEY", clean)

def check_password_pwned(password: str) -> Dict[str, Any]:
    """
    Checks if a password has been leaked in known data breaches using
    Have I Been Pwned's mathematical k-anonymity protocol.
    Your password is NEVER transmitted across the network!
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(
                f"{HIBP_RANGE_ENDPOINT}/{prefix}",
                headers={"User-Agent": "ScamShield-Cybersecurity-Assistant", "Add-Padding": "true"}
            )
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    parts = line.strip().split(":")
                    if len(parts) == 2 and parts[0] == suffix:
                        count = int(parts[1])
                        return {
                            "pwned": True,
                            "count": count,
                            "breach_count": count,
                            "status": "compromised",
                            "hash_prefix": prefix,
                            "message": f"CRITICAL: This password has appeared {count:,} times in known data breaches!"
                        }

                return {
                    "pwned": False,
                    "count": 0,
                    "breach_count": 0,
                    "status": "safe",
                    "hash_prefix": prefix,
                    "message": "Good news: No matches found in known exposed credential dictionaries."
                }
    except Exception as e:
        return {"pwned": False, "count": 0, "status": "error", "error": str(e)}

    return {"pwned": False, "count": 0, "status": "safe", "breach_count": 0}

def check_email_breaches(email: str) -> Dict[str, Any]:
    """Checks email against HIBP breached accounts API (requires key) or returns verification link"""
    clean_email = email.strip().lower()
    key = get_hibp_key()

    if not key:
        return {
            "has_key": False,
            "provider": "Have I Been Pwned",
            "lookup_url": f"https://haveibeenpwned.com/account/{clean_email}",
            "message": "HIBP API key is optional. You can also verify this address directly on haveibeenpwned.com."
        }

    headers = {
        "hibp-api-key": key,
        "User-Agent": "ScamShield-Cybersecurity-Assistant"
    }

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(f"{HIBP_ACCOUNT_ENDPOINT}/{clean_email}?truncateResponse=false", headers=headers)
            if resp.status_code == 200:
                breaches = resp.json()
                return {
                    "has_key": True,
                    "is_breached": True,
                    "breaches_count": len(breaches),
                    "breaches": [b.get("Name") for b in breaches]
                }
            elif resp.status_code == 404:
                return {
                    "has_key": True,
                    "is_breached": False,
                    "breaches_count": 0
                }
    except Exception as e:
        print(f"HIBP email check error: {e}")

    return {"has_key": True, "error": "Lookup failed"}
