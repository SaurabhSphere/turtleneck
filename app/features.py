"""
Feature Engineering Module — Single Source of Truth
===================================================
This module extracts 23 lexical, structural, and IDN-based features from
raw domain name strings.  It is shared across:
  - Training pipeline  (Turtleneck_Assignment.py / train.py)
  - Inference pipeline  (inference.py)

Feature categories (per AIML assignment spec):
  1. URL / Domain Structure  — length, subdomain_count,
     hyphen_count, digit_count, special_char_count, entropy,
     is_country_code_tld, is_common_tld, is_suspicious_tld
  2. Lexical Similarity      — brand_match, known_brand_root,
     min_brand_distance, has_login, has_secure, has_verify,
     has_account, has_update, has_signin, has_support, has_payment
  3. IDN / Homoglyph         — has_punycode, contains_unicode,
     unicode_ratio
"""

import math
import re
import tldextract
from Levenshtein import distance

KNOWN_BRANDS = [
    # Technology
    "google",
    "gmail",
    "youtube",
    "android",
    "microsoft",
    "outlook",
    "office365",
    "onedrive",
    "skype",
    "github",
    "apple",
    "icloud",
    "itunes",

    # Social Media
    "facebook",
    "instagram",
    "whatsapp",
    "twitter",
    "x",
    "linkedin",
    "snapchat",
    "tiktok",
    "reddit",
    "discord",
    "telegram",
    "pinterest",

    # E-commerce
    "amazon",
    "flipkart",
    "ebay",
    "walmart",
    "shopify",
    "etsy",
    "aliexpress",

    # Payments & Finance
    "paypal",
    "paytm",
    "phonepe",
    "gpay",
    "googlepay",
    "razorpay",
    "stripe",
    "visa",
    "mastercard",
    "americanexpress",

    # Indian Banks
    "sbi",
    "hdfc",
    "icici",
    "axis",
    "kotak",
    "pnb",
    "bob",
    "canara",
    "unionbank",
    "indusind",
    "yesbank",
    "idfc",

    # Government / Public Services
    "uidai",
    "epfo",
    "gov",
    "income_tax",
    "gst",
    "digilocker",
    "npci",
    "irctc",

    # Streaming
    "netflix",
    "primevideo",
    "disney",
    "hotstar",
    "spotify",

    # Cloud / SaaS
    "aws",
    "azure",
    "gcp",
    "dropbox",
    "zoom",
    "slack",

    # Telecom
    "jio",
    "airtel",
    "vi",
    "bsnl",

    # Delivery & Travel
    "swiggy",
    "zomato",
    "ola",
    "uber",
    "makemytrip",
    "goibibo",
    "booking",

    # Crypto
    "binance",
    "coinbase",
    "wazirx"
]

KNOWN_ROOTS = {
    # Google
    "google.com",
    "gmail.com",
    "youtube.com",

    # Microsoft
    "microsoft.com",
    "outlook.com",
    "office.com",
    "live.com",
    "onedrive.com",
    "github.com",

    # Apple
    "apple.com",
    "icloud.com",

    # Meta
    "facebook.com",
    "instagram.com",
    "whatsapp.com",

    # Social
    "x.com",
    "twitter.com",
    "linkedin.com",
    "snapchat.com",
    "tiktok.com",
    "reddit.com",
    "discord.com",
    "telegram.org",
    "pinterest.com",

    # E-commerce
    "amazon.com",
    "amazon.in",
    "flipkart.com",
    "ebay.com",
    "walmart.com",
    "shopify.com",
    "etsy.com",
    "aliexpress.com",

    # Payments
    "paypal.com",
    "paytm.com",
    "phonepe.com",
    "googlepay.com",
    "razorpay.com",
    "stripe.com",
    "visa.com",
    "mastercard.com",
    "americanexpress.com",

    # Indian Banks
    "sbi.co.in",
    "onlinesbi.sbi",
    "hdfcbank.com",
    "icicibank.com",
    "axisbank.com",
    "kotak.com",
    "pnbindia.in",
    "bankofbaroda.in",
    "canarabank.com",
    "unionbankofindia.co.in",
    "indusind.com",
    "yesbank.in",
    "idfcfirstbank.com",

    # Government
    "uidai.gov.in",
    "epfindia.gov.in",
    "incometax.gov.in",
    "gst.gov.in",
    "digilocker.gov.in",
    "npci.org.in",
    "irctc.co.in",

    # Streaming
    "netflix.com",
    "primevideo.com",
    "disneyplus.com",
    "hotstar.com",
    "spotify.com",

    # Cloud
    "aws.amazon.com",
    "azure.microsoft.com",
    "cloud.google.com",
    "dropbox.com",
    "zoom.us",
    "slack.com",

    # Telecom
    "jio.com",
    "airtel.in",
    "myvi.in",
    "bsnl.co.in",

    # Travel / Delivery
    "swiggy.com",
    "zomato.com",
    "olacabs.com",
    "uber.com",
    "makemytrip.com",
    "goibibo.com",
    "booking.com",

    # Crypto
    "binance.com",
    "coinbase.com",
    "wazirx.com"
}

KEYWORDS = [
    "login",
    "secure",
    "verify",
    "account",
    "update",
    "signin",
    "support",
    "banking",
    "payment"
]

COMMON_TLDS = {
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "mil",
    "int"
}

COUNTRY_CODE_TLDS = {
    "in", "us", "uk", "au", "ca", "de", "fr",
    "jp", "cn", "sg", "ae", "ru", "br",
    "it", "es", "nl", "ch", "se", "no",
    "fi", "za", "kr"
}

HIGH_RISK_TLDS = {
    "xyz",
    "top",
    "click",
    "work",
    "gq",
    "ml",
    "cf",
    "tk",
    "ga",
    "pw",
    "buzz",
    "cam",
    "cyou",
    "icu",
    "monster",
    "rest",
    "fit",
    "accountant",
    "science",
    "support",
    "review",
    "country",
    "kim",
    "party",
    "trade",
    "stream",
    "download",
    "racing",
    "win",
    "loan",
    "men",
    "date",
    "faith",
    "cricket",
    "zip",
    "mov"
}

def entropy(domain: str) -> float:
    if not domain:
        return 0.0
    probs = [
        float(domain.count(c)) / len(domain)
        for c in set(domain)
    ]
    return -sum(p * math.log2(p) for p in probs)

def is_ip_address(domain: str) -> bool:
    ipv4_pattern = r"^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$"
    ipv6_pattern = r"^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$"
    
    match_ipv4 = re.match(ipv4_pattern, domain)
    if match_ipv4:
        return all(0 <= int(part) <= 255 for part in match_ipv4.groups())
    return bool(re.match(ipv6_pattern, domain))

def has_homoglyphs(domain: str) -> bool:
    latin_chars = set(re.findall(r'[a-zA-Z]', domain))
    cyrillic_chars = set(re.findall(r'[\u0400-\u04FF]', domain))
    if latin_chars and cyrillic_chars:
        return True
    if any(ord(char) > 127 for char in domain) and not domain.startswith("xn--"):
        return True
    return False

def min_brand_distance(domain: str) -> int:
    ext = tldextract.extract(domain)
    name = ext.domain.lower()
    distances = [
        distance(name, brand)
        for brand in KNOWN_BRANDS
    ]
    return min(distances) if distances else 99

def known_brand_root(domain: str) -> int:
    ext = tldextract.extract(domain)
    root = f"{ext.domain}.{ext.suffix}"
    return int(root in KNOWN_ROOTS)

def extract_features(domain: str) -> dict:
    """
    Extract all 24 ML features from a raw domain string.

    The returned dictionary contains numeric features aligned with the
    trained XGBoost model columns, plus a ``tld`` string field (dropped
    before prediction).

    Parameters
    ----------
    domain : str
        A bare domain name or URL fragment (protocol is stripped automatically).

    Returns
    -------
    dict
        Feature name → value mapping (24 numeric features + ``tld``).
    """
    domain_clean = domain.strip().lower()
    domain_clean = re.sub(r'^https?://', '', domain_clean).split('/')[0].split(':')[0]
    
    ext = tldextract.extract(domain_clean)
    root = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain
    
    domain_parts = domain_clean.split(".")
    subdomain_count = max(len(domain_parts) - 2, 0)
    unicode_count = sum(ord(c) > 127 for c in domain_clean)
    
    return {
        "length": len(domain_clean),
        "subdomain_count": subdomain_count,
        "hyphen_count": domain_clean.count("-"),
        "digit_count": sum(c.isdigit() for c in domain_clean),
        "special_char_count": sum(not c.isalnum() and c != "." for c in domain_clean),
        "entropy": entropy(domain_clean),
        
        "has_login": int("login" in domain_clean),
        "has_secure": int("secure" in domain_clean),
        "has_verify": int("verify" in domain_clean),
        "has_account": int("account" in domain_clean),
        "has_update": int("update" in domain_clean),
        "has_signin": int("signin" in domain_clean),
        "has_support": int("support" in domain_clean),
        "has_payment": int("payment" in domain_clean),
        
        "brand_match": int(any(brand in domain_clean for brand in KNOWN_BRANDS)),
        "known_brand_root": known_brand_root(domain_clean),
        "min_brand_distance": min_brand_distance(domain_clean),
        
        "has_punycode": int("xn--" in domain_clean),
        "contains_unicode": int(unicode_count > 0),
        "unicode_ratio": unicode_count / max(len(domain_clean), 1),
        
        "tld": suffix,
        "is_country_code_tld": int(suffix in COUNTRY_CODE_TLDS),
        "is_common_tld": int(suffix in COMMON_TLDS),
        "is_suspicious_tld": int(suffix in HIGH_RISK_TLDS)
    }

def get_additional_indicators(domain: str) -> dict:
    """
    Compute supplementary risk indicators for the UI.

    These indicators are **not** used by the ML model but provide
    additional context displayed in the frontend dashboard.

    Parameters
    ----------
    domain : str
        A bare domain name or URL fragment.

    Returns
    -------
    dict
        Keys: ``is_ip``, ``has_mixed_script``, ``tld_is_risky``.
    """
    domain_clean = domain.strip().lower()
    domain_clean = re.sub(r'^https?://', '', domain_clean).split('/')[0].split(':')[0]
    
    ext = tldextract.extract(domain_clean)
    suffix = ext.suffix
    
    return {
        "is_ip": is_ip_address(domain_clean),
        "has_mixed_script": has_homoglyphs(domain_clean),
        "tld_is_risky": suffix in HIGH_RISK_TLDS
    }
