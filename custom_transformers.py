"""
Advanced Feature Engineering and Transformers for AI-Powered Phishing Detection.
Includes lexical URL analysis, typosquatting/homoglyph brand matching, urgency scoring,
and scikit-learn compatible feature extraction pipelines.
"""

import re
import math
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

# =====================================================================
# KNOWLEDGE BASES & THREAT SIGNATURES
# =====================================================================

TARGETED_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "chase",
    "bankofamerica", "wellsfargo", "citibank", "facebook", "instagram", "meta",
    "whatsapp", "twitter", "x.com", "linkedin", "dropbox", "docusign", "adobe",
    "spotify", "binance", "coinbase", "metamask", "steam", "dhl", "fedex", "ups"
]

TRUSTED_BRAND_DOMAINS = {
    "paypal.com", "paypal.me", "apple.com", "icloud.com", "microsoft.com",
    "office.com", "live.com", "outlook.com", "google.com", "gmail.com",
    "amazon.com", "netflix.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citi.com", "facebook.com", "instagram.com", "meta.com", "whatsapp.com",
    "twitter.com", "x.com", "linkedin.com", "dropbox.com", "docusign.com",
    "adobe.com", "spotify.com", "binance.com", "coinbase.com", "github.com",
    "zoom.us", "slack.com", "dhl.com", "fedex.com", "ups.com"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".online", ".club", ".info", ".biz", ".live",
    ".cc", ".click", ".link", ".work", ".gq", ".ml", ".cf", ".ga", ".rest",
    ".support", ".auth", ".help", ".vip", ".buzz", ".monster", ".space",
    ".fit", ".icu", ".cam", ".store", ".site", ".cyou", ".kim", ".country"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "is.gd", "t.co", "ow.ly", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "soo.gd", "s.id", "tiny.cc", "bc.vc"
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".zip", ".iso", ".vbs", ".bat", ".cmd", ".ps1", ".hta",
    ".jar", ".msi", ".rar", ".7z", ".tar.gz", ".docm", ".xlsm"
}

# Categorized threat keywords
KEYWORD_CATEGORIES = {
    "urgency": {
        "urgent", "immediately", "action required", "locked", "suspended",
        "security alert", "risk", "unauthorized", "compromised", "termination",
        "critical", "warning", "expire", "deadline", "attention", "restricted",
        "freeze", "24 hours", "immediate response", "final notice"
    },
    "credentials": {
        "password", "verify", "verification", "confirm", "identity", "credential",
        "auth", "security question", "pin", "login", "unlock", "re-activate",
        "validation", "sign in", "reset password", "passcode", "otp", "2fa"
    },
    "financial": {
        "bank", "account", "wire transfer", "payment", "invoice", "refund",
        "credit card", "billing", "declined", "overdue", "salary", "payroll",
        "deposit", "transaction", "cryptocurrency", "bitcoin", "wallet",
        "tax refund", "irs", "beneficiary", "claim your money"
    },
    "lures_rewards": {
        "claim", "winner", "reward", "lottery", "prize", "gift card", "selected",
        "exclusive offer", "congratulations", "$1,000", "free bonus", "free cash",
        "airdrop", "sweepstakes", "jackpot", "unclaimed funds"
    }
}

ALL_SUSPICIOUS_KEYWORDS = set().union(*KEYWORD_CATEGORIES.values())

URL_REGEX = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
IP_REGEX = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s\"'>]*)?", re.IGNORECASE)
EMAIL_DOMAIN_REGEX = re.compile(r"@([a-zA-Z0-9.\-]+)")


# =====================================================================
# ADVANCED UTILITY FUNCTIONS
# =====================================================================

def extract_urls(text: Optional[str]) -> List[str]:
    """Extract all valid HTTP/HTTPS URLs from text."""
    if not text:
        return []
    return URL_REGEX.findall(text)


def get_domain(email: Optional[str]) -> Optional[str]:
    """Extract domain portion from an email address."""
    if not email or "@" not in email:
        return None
    match = EMAIL_DOMAIN_REGEX.search(email.strip().lower())
    return match.group(1) if match else None


def calculate_entropy(text: str) -> float:
    """Calculate Shannon Entropy of a string to detect random DGA/obfuscated domains."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def is_domain_trusted(domain: Optional[str]) -> bool:
    """Check if the domain is a verified authentic brand domain."""
    if not domain:
        return False
    domain = domain.lower().strip()
    return any(domain == td or domain.endswith("." + td) for td in TRUSTED_BRAND_DOMAINS)


def check_typosquatting(domain: Optional[str]) -> Optional[Tuple[str, str]]:
    """
    Detects typosquatting, brand lookalikes, or homoglyphs in domain names.
    Returns (brand_name, reason) if suspicious lookalike is detected.
    """
    if not domain:
        return None
    
    clean_domain = domain.lower()
    
    # Common character substitutions (0 -> o, 1/l -> i/l, rn -> m, etc.)
    normalized = clean_domain.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('5', 's').replace('8', 'b')
    
    for brand in TARGETED_BRANDS:
        # If the domain contains the brand name but is NOT an official brand domain
        if brand in clean_domain or brand in normalized:
            if not is_domain_trusted(clean_domain):
                return (brand, f"Domain '@{domain}' attempts to imitate legitimate brand '{brand.title()}'")
                
    return None


def inspect_url_details(url: str) -> Dict[str, Any]:
    """Detailed heuristic analysis for a specific URL."""
    url_lower = url.lower()
    issues = []
    risk_score = 0
    
    is_ip = bool(IP_REGEX.search(url))
    if is_ip:
        issues.append("Uses direct raw IP address instead of domain name")
        risk_score += 40

    is_shortener = any(short in url_lower for short in SHORTENER_DOMAINS)
    if is_shortener:
        issues.append("Uses URL shortener (hides true destination)")
        risk_score += 25

    has_suspicious_tld = any(url_lower.endswith(tld) or f"{tld}/" in url_lower or f"{tld}?" in url_lower for tld in SUSPICIOUS_TLDS)
    if has_suspicious_tld:
        issues.append("Uses high-risk Top-Level Domain (TLD)")
        risk_score += 30

    has_at_symbol = "@" in url.split("//")[-1]
    if has_at_symbol:
        issues.append("Contains '@' symbol in URL (browser redirection trick)")
        risk_score += 35

    has_dangerous_ext = any(url_lower.endswith(ext) or f"{ext}?" in url_lower for ext in DANGEROUS_EXTENSIONS)
    if has_dangerous_ext:
        issues.append("Links directly to executable/archive payload")
        risk_score += 45

    # Check for brand impersonation in URL path/subdomains
    for brand in TARGETED_BRANDS:
        if brand in url_lower and not is_domain_trusted(url_lower):
            issues.append(f"Impersonates brand '{brand.title()}' in link path or subdomain")
            risk_score += 30
            break

    # Subdomain depth check
    domain_part = url_lower.split("://")[-1].split("/")[0].split("?")[0]
    subdomains = domain_part.split(".")
    if len(subdomains) > 3 and not is_ip:
        issues.append("Excessive subdomain nesting")
        risk_score += 15

    return {
        "url": url,
        "is_ip": is_ip,
        "is_shortener": is_shortener,
        "has_suspicious_tld": has_suspicious_tld,
        "issues": issues,
        "risk_score": min(risk_score, 100)
    }


def detect_suspicious_features(sender: str, subject: str, email_text: str) -> List[str]:
    """
    Comprehensive explainability engine: generates human-readable diagnostics
    explaining exactly why an email was classified as safe or phishing.
    """
    full_text = f"{subject or ''} {email_text or ''}".lower()
    urls = extract_urls(f"{subject or ''} {email_text or ''}")
    sender_domain = get_domain(sender)
    
    reasons = []

    # 1. URL Analysis
    if urls:
        reasons.append(f"Contains {len(urls)} embedded hyperlink(s)")
        for url in urls[:3]:
            details = inspect_url_details(url)
            for issue in details["issues"]:
                reason_str = f"Link '{url[:40]}...': {issue}" if len(url) > 40 else f"Link '{url}': {issue}"
                if reason_str not in reasons:
                    reasons.append(reason_str)

    # 2. Sender Domain & Brand Impersonation
    if not sender_domain:
        reasons.append("Missing or malformed sender email address")
    else:
        typo_match = check_typosquatting(sender_domain)
        if typo_match:
            brand, desc = typo_match
            reasons.append(desc)
        elif not is_domain_trusted(sender_domain):
            # Check subject for brand claims
            for brand in TARGETED_BRANDS:
                if brand in (subject or "").lower():
                    reasons.append(f"Brand Mismatch: Subject mentions '{brand.title()}', but sender is from '@{sender_domain}'")
                    break
            else:
                if any(sender_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                    reasons.append(f"Sender domain '@{sender_domain}' uses an untrusted high-risk TLD")
                else:
                    reasons.append(f"Sender domain '@{sender_domain}' is not in the enterprise trusted registry")

    # 3. Categorized Keyword Triggers
    found_categories = {}
    for cat_name, kw_set in KEYWORD_CATEGORIES.items():
        matched = [k for k in kw_set if k in full_text]
        if matched:
            found_categories[cat_name] = matched

    if found_categories:
        for cat, kws in found_categories.items():
            cat_title = cat.replace("_", " ").title()
            reasons.append(f"{cat_title} keywords detected: {', '.join([repr(k) for k in kws[:3]])}")

    # 4. Stylometry & Pressure Tactics
    if subject and len(subject) > 8:
        caps_count = sum(1 for c in subject if c.isupper())
        if caps_count / len(subject) > 0.40:
            reasons.append("Aggressive ALL-CAPS detected in subject line (urgency pressure indicator)")

    exclamation_count = full_text.count("!") + full_text.count("?")
    if exclamation_count >= 3:
        reasons.append(f"Excessive exclamation/question marks ({exclamation_count}) indicating coercive tone")

    return reasons


# =====================================================================
# SCIKIT-LEARN PIPELINE TRANSFORMERS
# =====================================================================

class TextSelector(BaseEstimator, TransformerMixin):
    """Extracts text content for TF-IDF vectorization."""
    def __init__(self, key: str):
        self.key = key
    
    def fit(self, X, y=None): 
        return self
    
    def transform(self, X): 
        if isinstance(X, pd.DataFrame):
            return X[self.key].fillna("").values
        return [row.get(self.key, "") for row in X]


class NumericFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts high-dimensional structured numeric & heuristic signals
    including URL analysis, entropy, typosquatting flags, and urgency densities.
    """
    def fit(self, X, y=None): 
        return self
    
    def transform(self, X):
        features = []
        if isinstance(X, pd.DataFrame):
            rows = X.to_dict(orient="records")
        else:
            rows = X

        for row in rows:
            sender = str(row.get("sender") or "")
            subject = str(row.get("subject") or "")
            email_text = str(row.get("email_text") or "")
            full_text = f"{subject} {email_text}".lower()

            # 1. URL metrics
            urls = extract_urls(f"{subject} {email_text}")
            url_count = len(urls)
            has_ip_url = 1.0 if any(IP_REGEX.search(u) for u in urls) else 0.0
            has_suspicious_tld_url = 1.0 if any(any(u.lower().endswith(tld) or f"{tld}/" in u.lower() for tld in SUSPICIOUS_TLDS) for u in urls) else 0.0
            has_shortener = 1.0 if any(any(sh in u.lower() for sh in SHORTENER_DOMAINS) for u in urls) else 0.0

            # 2. Domain & Sender Metrics
            sender_domain = get_domain(sender) or ""
            sender_trust = 1.0 if is_domain_trusted(sender_domain) else 0.0
            sender_is_suspicious_tld = 1.0 if any(sender_domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0.0
            is_typosquat = 1.0 if check_typosquatting(sender_domain) is not None else 0.0
            domain_entropy = calculate_entropy(sender_domain)

            # 3. Categorized Keyword Frequencies
            urgency_score = sum(1 for kw in KEYWORD_CATEGORIES["urgency"] if kw in full_text)
            credential_score = sum(1 for kw in KEYWORD_CATEGORIES["credentials"] if kw in full_text)
            financial_score = sum(1 for kw in KEYWORD_CATEGORIES["financial"] if kw in full_text)
            reward_score = sum(1 for kw in KEYWORD_CATEGORIES["lures_rewards"] if kw in full_text)

            # 4. Stylometry
            subj_caps_ratio = (sum(1 for c in subject if c.isupper()) / max(len(subject), 1)) if subject else 0.0
            exclamation_count = float(full_text.count("!") + full_text.count("?"))
            text_length = float(len(full_text))

            features.append([
                url_count,
                has_ip_url,
                has_suspicious_tld_url,
                has_shortener,
                sender_trust,
                sender_is_suspicious_tld,
                is_typosquat,
                domain_entropy,
                urgency_score,
                credential_score,
                financial_score,
                reward_score,
                subj_caps_ratio,
                exclamation_count,
                text_length
            ])
            
        return np.array(features, dtype=np.float32)