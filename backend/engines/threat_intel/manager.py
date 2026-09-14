"""Unified Threat Intelligence Manager Orchestrating 10 Security Providers"""
import concurrent.futures
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional

from backend.engines.threat_intel.rdap_whois import check_domain_rdap, evaluate_rdap_findings, extract_root_domain
from backend.engines.threat_intel.dns_inspector import resolve_dns_doh, evaluate_dns_findings
from backend.engines.threat_intel.phishtank import check_phishtank_url, evaluate_phishtank_findings, get_phishtank_key
from backend.engines.threat_intel.google_safebrowsing import check_google_safebrowsing, evaluate_gsb_findings, get_gsb_key
from backend.engines.threat_intel.abuseipdb import check_ip_reputation, evaluate_abuseipdb_findings, get_abuseipdb_key
from backend.engines.threat_intel.abuse_ch import check_urlhaus, check_threatfox_ioc, evaluate_abusech_findings, get_abusech_key
from backend.engines.threat_intel.alienvault_otx import check_alienvault_domain, evaluate_otx_findings, get_otx_key
from backend.engines.threat_intel.hibp_client import get_hibp_key
from backend.engines.virustotal_client import query_virustotal_url, get_virustotal_api_key

def get_all_providers_status() -> List[Dict[str, Any]]:
    """Returns real-time status for all 10 Threat Intelligence services"""
    return [
        {
            "id": "rdap",
            "name": "ICANN RDAP / WHOIS",
            "type": "Domain Age & Registrar",
            "free": True,
            "requires_key": False,
            "status": "active",
            "description": "Calculates domain creation date, age, and registrar without requiring any API key."
        },
        {
            "id": "dns",
            "name": "Cloudflare DNS-over-HTTPS",
            "type": "DNS & Infrastructure",
            "free": True,
            "requires_key": False,
            "status": "active",
            "description": "Resolves public IPv4/IPv6 host addresses and MX mail servers via encrypted DNS."
        },
        {
            "id": "phishtank",
            "name": "PhishTank (OpenDNS)",
            "type": "Phishing Database",
            "free": True,
            "requires_key": False,
            "status": "active",
            "has_key": bool(get_phishtank_key()),
            "description": "Community-verified phishing URL repository. Operates automatically out of the box."
        },
        {
            "id": "hibp",
            "name": "Have I Been Pwned",
            "type": "Credential Exposure",
            "free": True,
            "requires_key": False,
            "status": "active",
            "has_key": bool(get_hibp_key()),
            "description": "K-anonymity SHA-1 range search for leaked credentials (zero keys required for passwords)."
        },
        {
            "id": "virustotal",
            "name": "VirusTotal v3",
            "type": "Antivirus Consensus (70+ Engines)",
            "free": True,
            "requires_key": True,
            "status": "active" if get_virustotal_api_key() else "optional",
            "has_key": bool(get_virustotal_api_key()),
            "description": "Consensus verdicts from Kaspersky, Sophos, Google, Microsoft, and 70+ vendors."
        },
        {
            "id": "google_safebrowsing",
            "name": "Google Safe Browsing v4",
            "type": "Malware & Phishing URLs",
            "free": True,
            "requires_key": True,
            "status": "active" if get_gsb_key() else "optional",
            "has_key": bool(get_gsb_key()),
            "description": "Official Google threat list protecting Google Chrome and Android devices."
        },
        {
            "id": "abuseipdb",
            "name": "AbuseIPDB",
            "type": "IP Address Reputation",
            "free": True,
            "requires_key": True,
            "status": "active" if get_abuseipdb_key() else "optional",
            "has_key": bool(get_abuseipdb_key()),
            "description": "Checks hosting IP address against crowdsourced reports of hacking and DDoS."
        },
        {
            "id": "urlhaus",
            "name": "URLhaus (abuse.ch)",
            "type": "Malware URL Distribution",
            "free": True,
            "requires_key": True,
            "status": "active" if get_abusech_key() else "optional",
            "has_key": bool(get_abusech_key()),
            "description": "Tracks websites actively distributing malware payloads and ransomware."
        },
        {
            "id": "threatfox",
            "name": "ThreatFox (abuse.ch)",
            "type": "IOCs & Botnet Infrastructure",
            "free": True,
            "requires_key": True,
            "status": "active" if get_abusech_key() else "optional",
            "has_key": bool(get_abusech_key()),
            "description": "Shares Indicators of Compromise (IOCs) associated with cybercrime cartels."
        },
        {
            "id": "alienvault_otx",
            "name": "AlienVault OTX",
            "type": "Open Threat Exchange",
            "free": True,
            "requires_key": True,
            "status": "active" if get_otx_key() else "optional",
            "has_key": bool(get_otx_key()),
            "description": "Community pulses and adversary campaign tags from security analysts."
        }
    ]

def query_threat_intel_parallel(url: str) -> Dict[str, Any]:
    """
    Executes concurrent queries across all active Threat Intelligence services:
    - Zero-key services (RDAP, DoH, PhishTank) run automatically.
    - Configured services (VirusTotal, Google, AbuseIPDB, abuse.ch, OTX) query their respective APIs.
    """
    clean_url = url.strip()
    if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
        parsed = urlparse("https://" + clean_url)
    else:
        parsed = urlparse(clean_url)

    hostname = parsed.hostname or clean_url.split("/")[0].split(":")[0]

    all_findings: List[Dict[str, Any]] = []
    total_penalty = 0
    providers_queried = []

    # Prepare parallel task execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        # 1. RDAP Domain Age
        future_rdap = executor.submit(check_domain_rdap, hostname)
        # 2. DNS DoH Records
        future_dns = executor.submit(resolve_dns_doh, hostname)
        # 3. PhishTank
        future_pt = executor.submit(check_phishtank_url, clean_url)
        # 4. VirusTotal
        future_vt = executor.submit(query_virustotal_url, clean_url)
        # 5. Google Safe Browsing
        future_gsb = executor.submit(check_google_safebrowsing, clean_url)
        # 6. URLhaus (abuse.ch)
        future_uh = executor.submit(check_urlhaus, clean_url)
        # 7. ThreatFox (abuse.ch)
        future_tf = executor.submit(check_threatfox_ioc, hostname)
        # 8. AlienVault OTX
        future_otx = executor.submit(check_alienvault_domain, hostname)

        # Collect RDAP
        try:
            rdap_res = future_rdap.result(timeout=3.5)
            if rdap_res:
                providers_queried.append("ICANN RDAP")
                eval_rdap = evaluate_rdap_findings(rdap_res)
                total_penalty += eval_rdap.get("score_penalty", 0)
                all_findings.extend(eval_rdap.get("findings", []))
        except Exception:
            pass

        # Collect DNS & Trigger AbuseIPDB for resolved IPs
        resolved_ips = []
        try:
            dns_res = future_dns.result(timeout=3.0)
            if dns_res:
                providers_queried.append("Cloudflare DoH")
                eval_dns = evaluate_dns_findings(dns_res)
                total_penalty += eval_dns.get("score_penalty", 0)
                all_findings.extend(eval_dns.get("findings", []))
                resolved_ips = eval_dns.get("resolved_ips", [])
        except Exception:
            pass

        # AbuseIPDB (Query first resolved public IP if key configured)
        if resolved_ips and get_abuseipdb_key():
            try:
                first_public = resolved_ips[0]
                aipdb_res = check_ip_reputation(first_public)
                if aipdb_res:
                    providers_queried.append("AbuseIPDB")
                    eval_aipdb = evaluate_abuseipdb_findings(aipdb_res)
                    total_penalty += eval_aipdb.get("score_penalty", 0)
                    all_findings.extend(eval_aipdb.get("findings", []))
            except Exception:
                pass

        # Collect PhishTank
        try:
            pt_res = future_pt.result(timeout=3.5)
            if pt_res:
                providers_queried.append("PhishTank")
                eval_pt = evaluate_phishtank_findings(pt_res)
                total_penalty += eval_pt.get("score_penalty", 0)
                all_findings.extend(eval_pt.get("findings", []))
        except Exception:
            pass

        # Collect VirusTotal
        try:
            vt_res = future_vt.result(timeout=3.5)
            if vt_res:
                providers_queried.append("VirusTotal")
                malicious = vt_res.get("malicious", 0)
                suspicious = vt_res.get("suspicious", 0)
                total = vt_res.get("total_vendors", 0)
                reputation = vt_res.get("reputation", 0)
                flagged = vt_res.get("flagged_vendors", [])

                if malicious > 0 or suspicious > 0:
                    vt_pen = min(90, (malicious * 25) + (suspicious * 10))
                    total_penalty += vt_pen
                    all_findings.append({
                        "type": "virustotal_threat_consensus",
                        "title": f"VirusTotal Threat Consensus ({malicious}/{total} Security Engines)",
                        "severity": "high" if malicious >= 2 else "medium",
                        "description": f"Target was flagged as malicious by {malicious} security vendor(s) ({', '.join(flagged[:4]) or 'Threat Detected'}). Global reputation: {reputation}.",
                        "educational_note": "VirusTotal aggregates detection feeds from global antivirus labs. Detections confirm active threat status."
                    })
                elif total > 0 and vt_res.get("harmless", 0) >= 5:
                    all_findings.append({
                        "type": "virustotal_verified_clean",
                        "title": f"VirusTotal Verified Clean ({vt_res.get('harmless', 0)} Security Engines)",
                        "severity": "info",
                        "description": f"Target was scanned across {total} global security vendors with 0 malicious reports.",
                        "educational_note": "Consensus across global antivirus engines confirms the domain has no known malware or phishing reports."
                    })
        except Exception:
            pass

        # Collect Google Safe Browsing
        try:
            gsb_res = future_gsb.result(timeout=3.5)
            if gsb_res:
                providers_queried.append("Google Safe Browsing")
                eval_gsb = evaluate_gsb_findings(gsb_res)
                total_penalty += eval_gsb.get("score_penalty", 0)
                all_findings.extend(eval_gsb.get("findings", []))
        except Exception:
            pass

        # Collect URLhaus & ThreatFox
        try:
            uh_res = future_uh.result(timeout=3.0)
            tf_res = future_tf.result(timeout=3.0)
            if uh_res or tf_res:
                if uh_res: providers_queried.append("URLhaus")
                if tf_res: providers_queried.append("ThreatFox")
                eval_ach = evaluate_abusech_findings(uh_res, tf_res)
                total_penalty += eval_ach.get("score_penalty", 0)
                all_findings.extend(eval_ach.get("findings", []))
        except Exception:
            pass

        # Collect AlienVault OTX
        try:
            otx_res = future_otx.result(timeout=3.0)
            if otx_res:
                providers_queried.append("AlienVault OTX")
                eval_otx = evaluate_otx_findings(otx_res)
                total_penalty += eval_otx.get("score_penalty", 0)
                all_findings.extend(eval_otx.get("findings", []))
        except Exception:
            pass

    return {
        "score_penalty": total_penalty,
        "findings": all_findings,
        "providers_queried": list(set(providers_queried)),
        "resolved_ips": resolved_ips
    }
