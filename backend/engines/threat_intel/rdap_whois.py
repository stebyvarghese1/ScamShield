"""ICANN RDAP / WHOIS Domain Registration & Age Engine (100% Free, Zero Key)"""
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import httpx

def _parse_iso_date(date_str: str) -> Optional[datetime]:
    if not date_str:
        return None
    try:
        clean = date_str.replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        try:
            return datetime.strptime(date_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            return None

COMMON_TWO_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "co.nz", "co.jp", "com.br", "co.za"
}

def extract_root_domain(domain_or_url: str) -> str:
    """Extracts root domain for WHOIS/RDAP query (e.g. sub.example.co.uk -> example.co.uk)"""
    cleaned = domain_or_url.lower().strip()
    if "//" in cleaned:
        cleaned = cleaned.split("//")[1]
    cleaned = cleaned.split("/")[0].split(":")[0].split("?")[0]
    parts = cleaned.split(".")
    if len(parts) >= 3:
        two_part = f"{parts[-2]}.{parts[-1]}"
        if two_part in COMMON_TWO_PART_TLDS:
            return f"{parts[-3]}.{two_part}"
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return cleaned

def check_domain_rdap(domain: str) -> Optional[Dict[str, Any]]:
    """
    Queries open ICANN RDAP to determine exact domain registration timestamp,
    age in days, registrar, and active domain status.
    """
    root_domain = extract_root_domain(domain)
    if not root_domain or "." not in root_domain:
        return None

    endpoint = f"https://rdap.org/domain/{root_domain}"

    try:
        with httpx.Client(timeout=4.0, follow_redirects=True) as client:
            resp = client.get(endpoint, headers={"Accept": "application/rdap+json, application/json"})
            if resp.status_code == 200:
                data = resp.json()
                events = data.get("events", [])
                entities = data.get("entities", [])

                reg_date = None
                exp_date = None
                for ev in events:
                    action = ev.get("eventAction")
                    date_str = ev.get("eventDate")
                    if action == "registration" and date_str:
                        reg_date = _parse_iso_date(date_str)
                    elif action == "expiration" and date_str:
                        exp_date = _parse_iso_date(date_str)

                # Find registrar name
                registrar_name = "Unknown Registrar"
                for entity in entities:
                    if "registrar" in entity.get("roles", []):
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for prop in vcard[1]:
                                if prop[0] == "fn":
                                    registrar_name = prop[3]
                                    break

                age_days = None
                if reg_date:
                    if reg_date.tzinfo is None:
                        reg_date = reg_date.replace(tzinfo=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - reg_date).days

                return {
                    "provider": "ICANN RDAP / WHOIS",
                    "domain": root_domain,
                    "registered_at": reg_date.isoformat() if reg_date else None,
                    "expires_at": exp_date.isoformat() if exp_date else None,
                    "age_days": age_days,
                    "registrar": registrar_name,
                    "status": data.get("status", [])
                }
    except Exception as e:
        print(f"RDAP lookup error for {root_domain}: {e}")
        return None

    return None

def evaluate_rdap_findings(rdap_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Generates findings and risk penalties based on domain registration age"""
    if not rdap_data or rdap_data.get("age_days") is None:
        return {"score_penalty": 0, "findings": []}

    age = rdap_data["age_days"]
    domain = rdap_data.get("domain", "")
    registrar = rdap_data.get("registrar", "Unknown")

    findings = []
    penalty = 0

    if age < 0:
        age = 0

    if age <= 7:
        penalty = 50
        findings.append({
            "type": "newly_registered_domain_critical",
            "title": f"Newly Registered Domain ({age} Days Old)",
            "severity": "high",
            "description": f"Domain '{domain}' was created just {age} day(s) ago via {registrar}. Over 75% of zero-day phishing sites operate on domains under a week old.",
            "educational_note": "Scammers quickly spin up disposable new domains for campaigns and abandon them once flagged."
        })
    elif age <= 30:
        penalty = 30
        findings.append({
            "type": "recently_registered_domain",
            "title": f"Recently Registered Domain ({age} Days Old)",
            "severity": "medium",
            "description": f"Domain '{domain}' was registered only {age} days ago. Legitimate banking and institutional portals have existed for years.",
            "educational_note": "Always exercise elevated caution on websites less than a month old."
        })
    elif age <= 90:
        penalty = 15
        findings.append({
            "type": "young_domain",
            "title": f"Young Domain ({age} Days Old)",
            "severity": "low",
            "description": f"Domain was registered {age} days ago ({registrar}).",
            "educational_note": "Established services typically possess domain histories spanning several years."
        })
    elif age >= 730:
        findings.append({
            "type": "established_domain_rdap",
            "title": f"Established Domain History ({round(age / 365, 1)} Years Old)",
            "severity": "info",
            "description": f"Domain has been active for {round(age / 365, 1)} years ({registrar}), indicating consistent tenure.",
            "educational_note": "Long domain history reduces the likelihood of automated disposable phishing kits."
        })

    return {"score_penalty": penalty, "findings": findings, "age_days": age}
