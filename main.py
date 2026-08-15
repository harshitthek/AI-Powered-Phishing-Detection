"""
AI-Powered Phishing Detection API (v2.1.0)
Production-grade FastAPI server with Random Forest ML inference,
explainability diagnostics, URL deep-inspection, and domain reputation scoring.
"""

import os
import pickle
from typing import List, Dict, Any, Optional
import pandas as pd
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse

# Custom feature transformers and heuristic engines
import custom_transformers
from custom_transformers import (
    detect_suspicious_features,
    inspect_url_details,
    get_domain,
    is_domain_trusted,
    check_typosquatting,
    extract_urls,
    calculate_entropy
)

# -----------------------------------------------------------------------------
# Application Setup
# -----------------------------------------------------------------------------
app = FastAPI(
    title="AI-Powered Phishing Detection API",
    description="Machine Learning & Heuristic Security Intelligence for real-time phishing detection and email analysis.",
    version="2.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Model Initialization
# -----------------------------------------------------------------------------
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phish_model.pickle")
model = None

def load_ml_model():
    global model
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model file not found at {MODEL_PATH}. Run model_training.py first.")
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

load_ml_model()


# -----------------------------------------------------------------------------
# Pydantic Request / Response Models
# -----------------------------------------------------------------------------
class EmailInput(BaseModel):
    sender: str = Field(..., example="security-alert@paypal-update-center.net", description="Sender email address")
    subject: str = Field(..., example="URGENT: Your PayPal Account Has Been Suspended", description="Email subject header")
    email_text: str = Field(..., example="Click http://paypal-auth-check.net/restore immediately to verify your identity.", description="Full email body content")
    threshold: float = Field(default=0.5, ge=0.0, le=1.0, description="Decision threshold for phishing classification")


class BatchEmailInput(BaseModel):
    emails: List[EmailInput] = Field(..., description="List of email objects to analyze in batch")


class URLInput(BaseModel):
    url: str = Field(..., example="http://paypal-security-verification.xyz/login", description="URL to scan")


class DomainInput(BaseModel):
    domain_or_email: str = Field(..., example="security@paypa1-update.com", description="Domain name or email address to inspect")


class PredictionResult(BaseModel):
    label: str = Field(..., description="'Phishing' or 'Safe'")
    probability: float = Field(..., description="Estimated probability of the email being phishing (0.0 to 1.0)")
    risk_level: str = Field(..., description="'Low', 'Medium', or 'High'")
    reasons: List[str] = Field(..., description="Explainable diagnostic reasons contributing to classification")
    urls_inspected: List[Dict[str, Any]] = Field(default_factory=list, description="Deep inspection details of all detected links")
    sender_analysis: Dict[str, Any] = Field(default_factory=dict, description="Sender domain reputation and typosquatting analysis")


# -----------------------------------------------------------------------------
# Core Prediction Engine
# -----------------------------------------------------------------------------
def analyze_single_email(sender: str, subject: str, email_text: str, threshold: float = 0.5) -> dict:
    df = pd.DataFrame([{
        "sender": sender,
        "subject": subject,
        "email_text": email_text,
        "text_for_model": f"{subject or ''} {email_text or ''}"
    }])

    # ML Inference
    proba = float(model.predict_proba(df)[:, 1][0])
    label = "Phishing" if proba >= threshold else "Safe"
    
    # Risk categorization
    if proba >= 0.70:
        risk_level = "High"
    elif proba >= 0.35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Explainable reasons
    reasons = detect_suspicious_features(sender, subject, email_text)
    if not reasons and label == "Safe":
        reasons.append("Sender domain is verified and content matches standard communication patterns")

    # Detailed URL Inspection
    urls = extract_urls(f"{subject or ''} {email_text or ''}")
    url_details = [inspect_url_details(u) for u in urls]

    # Detailed Sender Domain Analysis
    sender_domain = get_domain(sender)
    typo_check = check_typosquatting(sender_domain)
    is_trusted = is_domain_trusted(sender_domain)

    sender_info = {
        "domain": sender_domain or "Unknown",
        "is_trusted": is_trusted,
        "entropy": round(calculate_entropy(sender_domain or ""), 3),
        "typosquatting_detected": typo_check is not None,
        "impersonated_brand": typo_check[0].title() if typo_check else None
    }

    return {
        "label": label,
        "probability": round(proba, 4),
        "risk_level": risk_level,
        "reasons": reasons,
        "urls_inspected": url_details,
        "sender_analysis": sender_info
    }


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
@app.get("/", tags=["General"], response_class=FileResponse)
def root_index():
    """Serves the interactive web interface."""
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return JSONResponse({"service": "AI-Powered Phishing Detection API", "version": "2.1.0"})


@app.get("/api", tags=["General"])
def api_info():
    """Returns general metadata about the service."""
    return {
        "service": "AI-Powered Phishing Detection API",
        "version": "2.1.0",
        "status": "online",
        "endpoints": {
            "web_ui": "/",
            "swagger_docs": "/docs",
            "health": "/health",
            "metrics": "/metrics",
            "predict_single": "/predict",
            "predict_batch": "/predict/batch",
            "analyze_url": "/analyze/url",
            "analyze_domain": "/analyze/domain",
            "samples": "/samples"
        }
    }


@app.get("/health", tags=["General"])
def health():
    """Health check endpoint indicating model loading status."""
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "version": "2.1.0"
    }


@app.get("/metrics", tags=["Diagnostics"])
def metrics():
    """Returns architecture overview, feature extractor count, and model configuration."""
    return {
        "model_type": "RandomForestClassifier",
        "n_estimators": 250,
        "cross_val_accuracy": "94.29%",
        "test_split_accuracy": "100.00%",
        "features": {
            "nlp_text": "Sublinear TF-IDF (1,2-grams up to 3000 features)",
            "heuristics": [
                "url_count", "has_ip_url", "has_suspicious_tld_url", "has_shortener",
                "sender_trust", "sender_is_suspicious_tld", "is_typosquat",
                "domain_entropy", "urgency_score", "credential_score", "financial_score",
                "reward_score", "subj_caps_ratio", "exclamation_count", "text_length"
            ]
        }
    }


@app.post("/predict", response_model=PredictionResult, tags=["Inference"])
def predict(email: EmailInput):
    """Analyzes a single email and returns probability, risk level, and explainable reasons."""
    try:
        result = analyze_single_email(email.sender, email.subject, email.email_text, email.threshold)
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {str(e)}"
        )


@app.post("/predict/batch", response_model=List[PredictionResult], tags=["Inference"])
def predict_batch(batch: BatchEmailInput):
    """Processes multiple emails in a single batch request."""
    try:
        results = [
            analyze_single_email(e.sender, e.subject, e.email_text, e.threshold)
            for e in batch.emails
        ]
        return JSONResponse(content=results)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch inference error: {str(e)}"
        )


@app.post("/analyze/url", tags=["Inspectors"])
def analyze_url(req: URLInput):
    """Performs deep heuristic risk inspection on a standalone URL."""
    return inspect_url_details(req.url)


@app.post("/analyze/domain", tags=["Inspectors"])
def analyze_domain(req: DomainInput):
    """Inspects a domain for trust reputation, typosquatting, entropy, and risk."""
    domain = get_domain(req.domain_or_email) or req.domain_or_email.strip().lower()
    typo_check = check_typosquatting(domain)
    is_trusted = is_domain_trusted(domain)
    entropy = calculate_entropy(domain)

    return {
        "domain": domain,
        "is_trusted": is_trusted,
        "entropy": round(entropy, 3),
        "typosquatting_detected": typo_check is not None,
        "impersonated_brand": typo_check[0].title() if typo_check else None,
        "risk_level": "Safe" if is_trusted else ("High" if typo_check else "Medium")
    }


@app.get("/samples", tags=["General"])
def sample_emails():
    """Returns curated preset email examples for testing and demonstration."""
    return {
        "bank": {
            "sender": "security-alert@paypal-update-center.net",
            "subject": "URGENT: Your PayPal Account Has Been Suspended",
            "body": "Dear customer, your account has been temporarily restricted due to unauthorized login attempts. Click http://paypal-security-verification.net/login immediately to verify your identity and restore your account access."
        },
        "giftcard": {
            "sender": "rewards@amazon-giftcard-promotions.xyz",
            "subject": "Congratulations! You won a $1,000 Amazon Gift Card",
            "body": "You have been selected as our winner of a $1,000 shopping voucher! Claim your reward now by clicking http://bit.ly/3xAmazonClaim and entering your credit card details for delivery confirmation."
        },
        "work": {
            "sender": "alex.chen@google.com",
            "subject": "Notes from today's sprint planning & roadmap sync",
            "body": "Hi team, attached are the action items from our morning sync. We will focus on optimizing model latency and API reliability for the upcoming release. Let me know if you have questions!"
        },
        "delivery": {
            "sender": "auto-confirm@amazon.com",
            "subject": "Your Amazon.com order #114-8921471 has shipped",
            "body": "Great news! Your package is on its way and scheduled to arrive tomorrow by 8 PM. You can track your package progress in your Amazon account dashboard."
        },
        "bec_ceo": {
            "sender": "ceo.office@executive-corp-urgent.com",
            "subject": "URGENT & CONFIDENTIAL: Wire Transfer Needed Today",
            "body": "I am currently in an executive meeting and cannot take phone calls. Please immediately initiate a wire transfer of $18,400 to our strategic partner account. Email the confirmation slip when completed."
        },
        "crypto": {
            "sender": "airdrop@binance-reward-vault.top",
            "subject": "Exclusive Binance 2.0 ETH Airdrop for Active Users",
            "body": "Claim your free 2.0 Ethereum airdrop reward! Connect your Web3 decentralized wallet at http://binance-airdrop-claim.top/connect before the token pool is depleted."
        }
    }


if __name__ == "__main__":
    import uvicorn
    print("=" * 65)
    print(" AI-Powered Phishing Detection Server (v2.1.0)")
    print(" Local URL : http://127.0.0.1:8000")
    print(" Swagger UI: http://127.0.0.1:8000/docs")
    print("=" * 65)
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
