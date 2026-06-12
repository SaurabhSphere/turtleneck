import math
import re

BRANDS = [
    "google",
    "facebook",
    "amazon",
    "paypal",
    "microsoft",
    "apple",
    "instagram",
    "netflix",
    "bank",
    "sbi",
    "hdfc",
    "icici"
]

def entropy(domain: str) -> float:
    if not domain:
        return 0.0
    prob = [
        float(domain.count(c)) / len(domain)
        for c in dict.fromkeys(list(domain))
    ]
    return -sum(p * math.log2(p) for p in prob)

def is_ip_address(domain: str) -> bool:
    # Check if domain looks like an IPv4 address
    ipv4_pattern = r"^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$"
    # Check if domain looks like an IPv6 address
    ipv6_pattern = r"^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$"
    
    match_ipv4 = re.match(ipv4_pattern, domain)
    if match_ipv4:
        return all(0 <= int(part) <= 255 for part in match_ipv4.groups())
        
    return bool(re.match(ipv6_pattern, domain))

def has_homoglyphs(domain: str) -> bool:
    # Homoglyphs are often non-ASCII characters that look similar to Latin letters.
    # A simple indicator is checking if we have non-ASCII characters,
    # OR if we have mixed scripts (e.g., both Cyrillic and Latin characters).
    latin_chars = set(re.findall(r'[a-zA-Z]', domain))
    cyrillic_chars = set(re.findall(r'[\u0400-\u04FF]', domain))
    
    # If the domain contains a mixture of both Latin and Cyrillic character sets, it's highly suspicious
    if latin_chars and cyrillic_chars:
        return True
    
    # Check for general non-ASCII if it's not a valid internationalized punycode format
    if any(ord(char) > 127 for char in domain) and not domain.startswith("xn--"):
        return True
        
    return False

def extract_features(domain: str) -> dict:
    # Preprocess domain (strip spaces, convert to lowercase)
    domain = domain.strip().lower()
    
    # Basic URL cleaning: remove protocol if user inputs full URL instead of domain
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]  # Take only host
    domain = domain.split(':')[0]  # Take only domain without port
    
    parts = domain.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    
    # Core features matching training dataset columns
    base_features = {
        "length": len(domain),
        "subdomain_count": max(len(parts) - 2, 0),
        "hyphen_count": domain.count("-"),
        "digit_count": sum(c.isdigit() for c in domain),
        "entropy": entropy(domain),
        "has_login": int("login" in domain),
        "has_secure": int("secure" in domain),
        "has_verify": int("verify" in domain),
        "has_account": int("account" in domain),
        "has_update": int("update" in domain),
        "brand_match": int(any(brand in domain for brand in BRANDS)),
        "has_punycode": int("xn--" in domain),
        "tld": tld
    }
    
    return base_features

def get_additional_indicators(domain: str) -> dict:
    """
    Returns advanced threat indicators that are NOT fed to the XGBoost model,
    but can be returned by the API to the React frontend.
    """
    cleaned = domain.strip().lower()
    cleaned = re.sub(r'^https?://', '', cleaned).split('/')[0].split(':')[0]
    
    return {
        "is_ip": is_ip_address(cleaned),
        "has_mixed_script": has_homoglyphs(cleaned),
        "tld_is_risky": cleaned.split(".")[-1] in ["tk", "xyz", "cam", "shop", "cyou", "cfd"] if "." in cleaned else False
    }
