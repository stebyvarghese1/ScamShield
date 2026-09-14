"""Threat Intelligence & Brand Impersonation Heuristics"""
import math
import re
from typing import Dict, List, Optional, Tuple
from backend.config import PROTECTED_BRANDS, SUSPICIOUS_TLDS, URL_SHORTENERS

# Common Cyrillic / Greek homoglyphs targeting Latin characters
HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't'
}

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string to detect random DGA strings"""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def levenshtein_distance(s1: str, s2: str) -> int:
    """Standard Levenshtein edit distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def normalize_homoglyphs(text: str) -> Tuple[str, bool]:
    """Detects and replaces look-alike unicode homoglyphs with standard latin"""
    has_homoglyphs = False
    normalized = []
    for char in text:
        if char in HOMOGLYPH_MAP:
            normalized.append(HOMOGLYPH_MAP[char])
            has_homoglyphs = True
        else:
            normalized.append(char)
    return "".join(normalized), has_homoglyphs

def detect_typosquatting(domain: str) -> Optional[Dict[str, str]]:
    """
    Checks if domain mimics a protected brand (e.g., paypa1, micros0ft, wellsfargo-verify).
    Returns details if detected, or None if legitimate or unrelated.
    """
    cleaned_domain = domain.lower().strip()
    if cleaned_domain.startswith("www."):
        cleaned_domain = cleaned_domain[4:]

    # Remove TLD
    parts = cleaned_domain.split(".")
    if len(parts) >= 2:
        root_name = parts[-2]
    else:
        root_name = cleaned_domain

    normalized_root, used_homoglyphs = normalize_homoglyphs(root_name)

    # Replace visual leetspeak numbers
    leetspeak_normalized = (
        normalized_root
        .replace('0', 'o')
        .replace('1', 'l')
        .replace('3', 'e')
        .replace('4', 'a')
        .replace('5', 's')
        .replace('@', 'a')
    )

    for brand, official_domains in PROTECTED_BRANDS.items():
        # If the domain is officially owned by the brand, it's safe
        if any(cleaned_domain == off or cleaned_domain.endswith("." + off) for off in official_domains):
            return None

        # Check for brand name embedded into domain or subdomain
        # e.g. paypal-security.xyz or chase-online-banking.com
        if brand in cleaned_domain or brand in leetspeak_normalized:
            return {
                "brand": brand.title(),
                "official_domains": ", ".join(official_domains),
                "type": "brand_impersonation",
                "details": f"Domain contains brand name '{brand}', but is not registered to {', '.join(official_domains)}."
            }

        # Check edit distance (typosquatting like paypa1, amzon, nelflix)
        dist = levenshtein_distance(leetspeak_normalized, brand)
        if 1 <= dist <= 2 and len(brand) >= 4:
            return {
                "brand": brand.title(),
                "official_domains": ", ".join(official_domains),
                "type": "typosquatting",
                "details": f"Domain closely resembles '{brand}' (distance: {dist}), a common typosquatting deceptive technique."
            }

        if used_homoglyphs and brand in normalized_root:
            return {
                "brand": brand.title(),
                "official_domains": ", ".join(official_domains),
                "type": "homoglyph_attack",
                "details": f"Domain uses deceptive Cyrillic/Greek Unicode homoglyphs to visually mimic '{brand}'."
            }

    return None

def is_suspicious_tld(domain: str) -> bool:
    """Checks if domain uses a frequently abused TLD"""
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        return tld in SUSPICIOUS_TLDS
    return False

def is_url_shortener(domain: str) -> bool:
    """Checks if domain is a URL shortener"""
    cleaned = domain.lower().strip()
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    return cleaned in URL_SHORTENERS
