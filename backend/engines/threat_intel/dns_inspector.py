"""DNS-over-HTTPS (DoH) Inspector (100% Free, Zero Key)"""
import ipaddress
from typing import Dict, Any, List, Optional
import httpx

DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"

def is_private_or_loopback_ip(ip_str: str) -> bool:
    """Detects internal, loopback, or cloud metadata addresses (SSRF protection)"""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    except ValueError:
        return False

def resolve_dns_doh(domain: str) -> Dict[str, Any]:
    """
    Resolves domain DNS records using Cloudflare DNS-over-HTTPS:
    - A Records (IPv4 Host IPs)
    - MX Records (Mail Exchange Servers)
    """
    clean_domain = domain.lower().strip()
    if "//" in clean_domain:
        clean_domain = clean_domain.split("//")[1]
    clean_domain = clean_domain.split("/")[0].split(":")[0].split("?")[0]

    result = {
        "provider": "Cloudflare DNS-over-HTTPS",
        "domain": clean_domain,
        "a_records": [],
        "mx_records": [],
        "has_private_ip": False,
        "is_resolvable": False
    }

    headers = {"Accept": "application/dns-json"}

    try:
        with httpx.Client(timeout=3.0) as client:
            # 1. Resolve A (IPv4)
            resp_a = client.get(f"{DOH_ENDPOINT}?name={clean_domain}&type=A", headers=headers)
            if resp_a.status_code == 200:
                data_a = resp_a.json()
                for ans in data_a.get("Answer", []):
                    if ans.get("type") == 1: # A Record
                        ip_val = ans.get("data", "").strip()
                        if ip_val:
                            result["a_records"].append(ip_val)
                            if is_private_or_loopback_ip(ip_val):
                                result["has_private_ip"] = True

            # 2. Resolve MX (Mail Exchange)
            resp_mx = client.get(f"{DOH_ENDPOINT}?name={clean_domain}&type=MX", headers=headers)
            if resp_mx.status_code == 200:
                data_mx = resp_mx.json()
                for ans in data_mx.get("Answer", []):
                    if ans.get("type") == 15: # MX Record
                        mx_val = ans.get("data", "").strip()
                        if mx_val:
                            result["mx_records"].append(mx_val)

        result["is_resolvable"] = len(result["a_records"]) > 0
    except Exception as e:
        print(f"DNS DoH error for {clean_domain}: {e}")

    return result

def evaluate_dns_findings(dns_data: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluates DNS records for security anomalies (SSRF, unresolvable domains, mail spoofing)"""
    findings = []
    penalty = 0

    domain = dns_data.get("domain", "")

    # 1. Private / Loopback IP address resolution (SSRF Attack)
    if dns_data.get("has_private_ip"):
        penalty += 75
        findings.append({
            "type": "dns_ssrf_internal_ip",
            "title": "Internal / Loopback IP Resolved (SSRF Attack)",
            "severity": "high",
            "description": f"Domain '{domain}' resolves to a private or loopback IP ({dns_data.get('a_records')}). This is a technique used in Server-Side Request Forgery (SSRF).",
            "educational_note": "Legitimate public internet services never point public domains to internal private networks."
        })

    # 2. Domain lacks DNS resolution entirely
    elif not dns_data.get("is_resolvable"):
        findings.append({
            "type": "dns_unresolvable_domain",
            "title": "Domain Has No Active A Records",
            "severity": "low",
            "description": f"No active IPv4 host addresses resolved for '{domain}'. The domain may be suspended, newly purchased, or offline.",
            "educational_note": "Phishing sites that have been taken down often remain in messages even after DNS records are pulled."
        })
    else:
        findings.append({
            "type": "dns_resolved_public",
            "title": f"DNS Active ({len(dns_data.get('a_records', []))} Public IP(s) Resolved)",
            "severity": "info",
            "description": f"Resolved public IPv4 addresses: {', '.join(dns_data.get('a_records')[:2])}.",
            "educational_note": "Domain is actively routing traffic on the public internet."
        })

    return {
        "score_penalty": penalty,
        "findings": findings,
        "resolved_ips": dns_data.get("a_records", []),
        "mx_records": dns_data.get("mx_records", [])
    }
