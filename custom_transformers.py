"""
Custom Transformers and Feature Extraction for AI-Powered Phishing Detection.
Defines scikit-learn compatible transformers for text selection and heuristic feature extraction.
"""

import re
from typing import List, Optional
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

# Suspicious keyword dictionaries categorized by attack vector
SUSPICIOUS_KEYWORDS = {
    # Urgency / Threat
    "urgent", "immediately", "action required", "locked", "suspended", "security alert",
    "risk", "unauthorized", "compromised", "termination", "critical", "warning", "expire",
    "deadline", "attention", "restricted", "freeze",
    # Credential Harvesting / Authentication
    "password", "verify", "verification", "confirm", "identity", "credential", "auth",
    "security question", "pin", "login", "unlock", "re-activate", "validation",
    # Financial / Banking / Invoice Fraud
    "bank", "account", "wire transfer", "payment", "invoice", "refund", "credit card",
    "billing", "declined", "overdue", "salary", "payroll", "deposit", "transaction",
    "cryptocurrency", "bitcoin", "wallet",
    # Prize / Lottery / Rewards
    "claim", "winner", "reward", "lottery", "prize", "gift card", "selected",
    "exclusive offer", "congratulations", "$1,000", "free bonus"
}

TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "netflix.com", "spotify.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "github.com", "zoom.us", "slack.com", "linkedin.com", "twitter.com", "facebook.com"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".online", ".club", ".info", ".biz", ".live",
    ".cc", ".click", ".link", ".work", ".gq", ".ml", ".cf", ".ga", ".rest",
    ".support", ".auth", ".help"
}

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "is.gd", "t.co", "ow.ly", "buff.ly", "cutt.ly"}

URL_REGEX = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
IP_REGEX = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}", re.IGNORECASE)


def extract_urls(text: Optional[str]) -> List[str]:
    """Extract all HTTP/HTTPS URLs from given text."""
    return URL_REGEX.findall(text or "")


def get_domain(email: Optional[str]) -> Optional[str]:
    """Extract domain from email address."""
    if not email or "@" not in email:
        return None
    return email.split("@")[-1].strip().lower()


def is_domain_trusted(domain: Optional[str]) -> bool:
    """Check if the sender domain matches trusted enterprise domains."""
    if not domain:
        return False
    domain = domain.lower()
    return any(domain == td or domain.endswith("." + td) for td in TRUSTED_DOMAINS)


def detect_suspicious_features(sender: str, subject: str, email_text: str):
    """
    Analyzes an email to produce explainable security findings.
    Returns a list of clear diagnostic reasons for classification.
    """
    full_text = f"{subject or ''} {email_text or ''}".lower()
    urls = extract_urls(f"{subject or ''} {email_text or ''}")
    sender_domain = get_domain(sender)
    
    reasons = []
    
    # 1. URL Analysis
    if urls:
        reasons.append(f"Contains {len(urls)} embedded URL(s)")
        for url in urls:
            url_lower = url.lower()
            if IP_REGEX.search(url):
                reasons.append(f"Suspicious raw IP address detected in link ({url})")
            if any(url_lower.endswith(tld) or f"{tld}/" in url_lower for tld in SUSPICIOUS_TLDS):
                reasons.append("Link uses a high-risk suspicious top-level domain (TLD)")
            if any(shortener in url_lower for shortener in SHORTENER_DOMAINS):
                reasons.append("Link uses a URL shortener which masks the destination")

    # 2. Sender Domain Analysis
    if not sender_domain:
        reasons.append("Invalid or missing sender email format")
    elif not is_domain_trusted(sender_domain):
        # Check if claiming to be a trusted brand while coming from an untrusted domain
        for brand in ["paypal", "apple", "microsoft", "google", "netflix", "amazon", "chase", "bank"]:
            if brand in (subject or "").lower() and brand not in sender_domain:
                reasons.append(f"Brand impersonation detected: Subject mentions '{brand.title()}' but sender is '@{sender_domain}'")
                break
        else:
            if any(sender_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
                reasons.append(f"Sender domain '@{sender_domain}' belongs to a high-risk TLD")
            else:
                reasons.append(f"Untrusted sender domain: '@{sender_domain}'")

    # 3. Suspicious Keyword Analysis
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_text]
    if matched_keywords:
        top_matches = matched_keywords[:4]
        reasons.append(f"Urgent/Phishing keywords detected: {', '.join([repr(k) for k in top_matches])}")

    # 4. Subject line capitalization heuristics
    if subject and len(subject) > 8:
        caps_count = sum(1 for c in subject if c.isupper())
        if caps_count / len(subject) > 0.45:
            reasons.append("Aggressive capitalization (ALL-CAPS) detected in subject")

    return reasons


class TextSelector(BaseEstimator, TransformerMixin):
    """Selects a specific string column from pandas DataFrame for text TF-IDF processing."""
    def __init__(self, key: str):
        self.key = key
    
    def fit(self, X, y=None): 
        return self
    
    def transform(self, X): 
        if isinstance(X, pd.DataFrame):
            return X[self.key].fillna("").values
        return [row.get(self.key, "") for row in X]


class NumericFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extracts numeric and structural heuristic signals from email metadata."""
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

            # URL features
            urls = extract_urls(f"{subject} {email_text}")
            url_count = len(urls)
            has_ip_url = 1 if any(IP_REGEX.search(u) for u in urls) else 0
            has_suspicious_tld_url = 1 if any(any(u.lower().endswith(tld) or f"{tld}/" in u.lower() for tld in SUSPICIOUS_TLDS) for u in urls) else 0
            has_shortener = 1 if any(any(sh in u.lower() for sh in SHORTENER_DOMAINS) for u in urls) else 0

            # Keyword features
            keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_text)

            # Sender features
            sender_domain = get_domain(sender)
            sender_trust = 1 if is_domain_trusted(sender_domain) else 0
            sender_is_suspicious_tld = 1 if (sender_domain and any(sender_domain.endswith(tld) for tld in SUSPICIOUS_TLDS)) else 0

            # Subject styling heuristics
            subj_caps_ratio = (sum(1 for c in subject if c.isupper()) / max(len(subject), 1)) if subject else 0.0
            exclamation_count = full_text.count("!") + full_text.count("?")

            features.append([
                url_count,
                has_ip_url,
                has_suspicious_tld_url,
                has_shortener,
                keyword_count,
                sender_trust,
                sender_is_suspicious_tld,
                subj_caps_ratio,
                exclamation_count
            ])
            
        return np.array(features, dtype=np.float32)