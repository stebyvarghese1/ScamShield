"""URL Security & Domain Intelligence Scanner"""
import re
from urllib.parse import urlparse, unquote
from typing import Dict, Any, List
from backend.engines.threat_intel import (
    calculate_entropy,
    detect_typosquatting,
    is_suspicious_tld,
    is_url_shortener,
)
from backend.config import (
    SUSPICIOUS_PATH_KEYWORDS,
    WEBMAIL_AND_ENTERPRISE_KEYWORDS,
    GENERIC_OR_FREE_HOSTING_INDICATORS,
    PROTECTED_BRANDS
)

IP_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

def analyze_url(raw_url: str) -> Dict[str, Any]:
    """
    Analyzes a URL or domain string for phishing kits, deceptive redirection,
    typosquatting, webmail harvesting, and malicious infrastructure indicators.
    """
    findings: List[Dict[str, Any]] = []
    score_penalty = 0
    url_str = raw_url.strip()

    if not url_str.startswith("http://") and not url_str.startswith("https://"):
        parsed = urlparse("https://" + url_str)
        had_scheme = False
    else:
        parsed = urlparse(url_str)
        had_scheme = True

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    netloc = parsed.netloc or ""
    lower_path = path.lower()
    lower_host = hostname.lower()

    # 1. Check for Embedded Credentials or Userinfo tricks (e.g. http://google.com@phishing.com)
    if "@" in netloc:
        score_penalty += 45
        findings.append({
            "type": "credential_obfuscation",
            "title": "Embedded Authentication / Spoofed Hostname",
            "severity": "high",
            "description": "URL uses '@' symbol to mislead users about the actual destination server.",
            "educational_note": "Browsers ignore text before the '@' sign, directing you to the domain after it."
        })

    # 2. IP Address as Hostname
    clean_host = hostname.strip("[]")
    if IP_REGEX.match(clean_host):
        score_penalty += 40
        findings.append({
            "type": "ip_hostname",
            "title": "Raw IP Address Hostname",
            "severity": "high",
            "description": f"Target uses a raw IP address ({hostname}) rather than a verified registered domain name.",
            "educational_note": "Legitimate services almost never direct consumers to bare IP addresses for logins."
        })

    # 3. Protocol: Plain HTTP vs HTTPS
    if had_scheme and parsed.scheme == "http":
        score_penalty += 20
        findings.append({
            "type": "insecure_protocol",
            "title": "Insecure Connection (HTTP)",
            "severity": "medium",
            "description": "URL uses unencrypted HTTP. Any credentials or personal data can be intercepted.",
            "educational_note": "Never submit passwords or payment details on unencrypted HTTP websites."
        })

    # 4. Punycode / IDN Homograph
    if "xn--" in lower_host:
        score_penalty += 35
        findings.append({
            "type": "punycode_detected",
            "title": "Internationalized / Punycode Domain",
            "severity": "high",
            "description": f"Domain contains Punycode prefix '{hostname}', often used to visually mimic characters.",
            "educational_note": "Scammers use international characters that look identical to English letters to fool victims."
        })

    # 5. Excessive Subdomains & Deceptive Domain Stacking
    subdomain_parts = hostname.split(".")
    if len(subdomain_parts) >= 4:
        score_penalty += 25
        findings.append({
            "type": "excessive_subdomains",
            "title": "Multi-Layered Subdomains Detected",
            "severity": "medium",
            "description": f"Domain has {len(subdomain_parts)} levels. Often used to embed trusted brand names as prefixes.",
            "educational_note": "Look at the very last two words before the slash (e.g., 'evil.com' in 'paypal.com.evil.com')."
        })

    # 6. Typosquatting / Brand Impersonation Check
    brand_check = detect_typosquatting(hostname)
    if brand_check:
        score_penalty += 50
        findings.append({
            "type": "brand_typosquatting",
            "title": f"Suspected Impersonation: {brand_check['brand']}",
            "severity": "high",
            "description": brand_check['details'],
            "educational_note": f"Authentic {brand_check['brand']} services operate only on {brand_check['official_domains']}."
        })

    # 7. High-Risk / Suspicious TLD
    if is_suspicious_tld(hostname):
        score_penalty += 25
        findings.append({
            "type": "suspicious_tld",
            "title": "High-Risk Top-Level Domain (TLD)",
            "severity": "medium",
            "description": f"Domain uses a top-level domain frequently associated with spam and automated phishing.",
            "educational_note": "Free or ultra-cheap TLDs are frequently chosen by cybercriminals because of minimal verification."
        })

    # 8. URL Shortener Service
    if is_url_shortener(hostname):
        score_penalty += 25
        findings.append({
            "type": "url_shortener",
            "title": "URL Shortener Detected",
            "severity": "medium",
            "description": f"Domain '{hostname}' is a link redirection shortener that hides the ultimate destination.",
            "educational_note": "Always expand shortened links before clicking to know where they actually lead."
        })

    # 9. Webmail / Corporate Authentication Portal Impersonation (OWA, Zimbra, Exchange, Webmail)
    path_tokens = set(re.split(r'[/._\-&=?]', lower_path + "?" + query.lower()))
    matched_webmail = [w for w in WEBMAIL_AND_ENTERPRISE_KEYWORDS if w in path_tokens or f"/{w}/" in lower_path or lower_path.startswith(f"/{w}")]
    
    is_official_microsoft = any(hostname.endswith(off) for off in PROTECTED_BRANDS.get("microsoft", []))
    if matched_webmail and not is_official_microsoft:
        # Multiple tokens like /zimbra/exch/owa/... indicate an automated multi-target phishing kit
        is_stacked = len(matched_webmail) >= 2
        score_penalty += 55 if is_stacked else 40
        findings.append({
            "type": "webmail_portal_phishing",
            "title": f"Webmail / Corporate Login Phishing Kit ({', '.join(matched_webmail[:3])})",
            "severity": "high",
            "description": f"URL targets enterprise webmail services ({', '.join(matched_webmail[:3])}) hosted on an unverified third-party domain ('{hostname}').",
            "educational_note": "Phishing kits copy Outlook Web Access (OWA) and Zimbra login portals onto compromised servers to harvest organization credentials."
        })

    # 10. Deeply Nested Phishing Directory Stacking
    path_dirs = [p for p in path.split("/") if p and not p.endswith((".html", ".htm", ".php", ".jsp", ".aspx"))]
    if len(path_dirs) >= 3 and (matched_webmail or any(kw in lower_path for kw in SUSPICIOUS_PATH_KEYWORDS)):
        score_penalty += 30
        findings.append({
            "type": "nested_phishing_kit_path",
            "title": "Deeply Nested Phishing Directory Structure",
            "severity": "high",
            "description": f"URL uses a deeply nested directory path ({path}) typical of phishing kits hidden within compromised web server folders.",
            "educational_note": "Attackers deploy phishing kit scripts inside deep subdirectories on hacked websites to evade detection by site owners."
        })

    # 11. Generic / Shared / Free Web Hosting Running Login or Webmail Page
    matched_hosts = [h for h in GENERIC_OR_FREE_HOSTING_INDICATORS if h in lower_host]
    if matched_hosts and (matched_webmail or any(kw in lower_path for kw in SUSPICIOUS_PATH_KEYWORDS)):
        score_penalty += 35
        findings.append({
            "type": "shared_hosting_phish",
            "title": f"Generic/Shared Hosting Provider Hosting Auth Page ({matched_hosts[0]})",
            "severity": "high",
            "description": f"The domain '{hostname}' appears to be hosted on generic, shared, or free hosting infrastructure while serving sensitive login/email portals.",
            "educational_note": "Legitimate enterprise portals and banks are never hosted on free or shared web hosting accounts."
        })

    # 12. General Sensitive / Banking / Auth keywords in path or query
    matched_keywords = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in lower_path or kw in query.lower()]
    if matched_keywords:
        penalty = 30 if len(matched_keywords) >= 2 else 20
        score_penalty += penalty
        findings.append({
            "type": "sensitive_action_path",
            "title": f"Sensitive Action Route ({', '.join(matched_keywords[:3])})",
            "severity": "medium",
            "description": f"Target path points directly to authentication or verification endpoints ({matched_keywords[:3]}).",
            "educational_note": "Combined with an unverified domain, direct links to login pages are hallmark phishing signs."
        })

    # 13. Suspicious Query Parameters (Pre-filled victim email or base64 redirects)
    if re.search(r"(email|user|victim|account|target)=[^&]+@[^&]+", query, re.IGNORECASE) or re.search(r"(redirect|url|goto)=(https?|aHR0)", query, re.IGNORECASE):
        score_penalty += 25
        findings.append({
            "type": "credential_query_harvesting",
            "title": "Victim Pre-Filling or Open Redirect Parameter",
            "severity": "medium",
            "description": "URL query parameters include targeted victim email pre-fills or external redirect parameters.",
            "educational_note": "Phishers pre-populate login forms with your email address to make the fake page appear authentic."
        })

    # 14. Shannon Entropy of Hostname
    entropy = calculate_entropy(hostname.replace(".", ""))
    if entropy >= 3.8 and len(hostname) >= 14:
        score_penalty += 15
        findings.append({
            "type": "high_entropy_domain",
            "title": "High Domain Entropy (Random Characters)",
            "severity": "low",
            "description": f"Hostname entropy score is {entropy}, indicating an algorithmically generated or random string.",
            "educational_note": "Automated phishing kits generate random domains to bypass security filters."
        })

    # 15. Multi-Provider Global Threat Intelligence Feeds (10 APIs)
    threat_intel = {}
    try:
        from backend.engines.threat_intel.manager import query_threat_intel_parallel
        intel_res = query_threat_intel_parallel(raw_url)
        threat_intel = intel_res
        score_penalty += intel_res.get("score_penalty", 0)
        findings.extend(intel_res.get("findings", []))
    except Exception as e:
        print(f"Threat intelligence feeds error: {e}")

    # Calculate final component risk score (capped at 100)
    risk_score = min(score_penalty, 100)

    # Safe assessment if zero penalties
    if risk_score == 0:
        findings.append({
            "type": "clean_domain",
            "title": "No Obvious Suspicious Indicators",
            "severity": "info",
            "description": "Standard domain structure, recognized format, and no known malicious patterns found.",
            "educational_note": "Always ensure you are expecting this website before sharing personal details."
        })

    return {
        "hostname": hostname,
        "score_penalty": risk_score,
        "findings": findings,
        "entropy": entropy,
        "threat_intel": threat_intel
    }
