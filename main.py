"""
AI-Powered Phishing Detection API
Production-grade FastAPI server with Machine Learning inference and explainability diagnostics.
"""

import os
import pickle
from typing import List, Optional
import pandas as pd
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Import feature extraction functions and transformers
import custom_transformers
from custom_transformers import (
    detect_suspicious_features,
    extract_urls,
    get_domain,
    is_domain_trusted
)

# -----------------------------------------------------------------------------
# App Initialization & CORS
# -----------------------------------------------------------------------------
app = FastAPI(
    title="AI-Powered Phishing Detection API",
    description="Machine learning API that analyzes email headers, body content, links, and domains to detect phishing attempts.",
    version="2.0.0",
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
# Model Loader
# -----------------------------------------------------------------------------
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phish_model.pickle")
model = None

def load_ml_model():
    global model
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Trained model not found at {MODEL_PATH}. Please run model_training.py first.")
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

load_ml_model()

# -----------------------------------------------------------------------------
# Request & Response Schemas
# -----------------------------------------------------------------------------
class EmailInput(BaseModel):
    sender: str = Field(..., example="security-alert@paypal-update-center.com", description="Sender email address")
    subject: str = Field(..., example="URGENT: Your account has been suspended", description="Email subject line")
    email_text: str = Field(..., example="Click http://paypal-auth.net to verify your password immediately.", description="Full body text of the email")
    threshold: float = Field(default=0.5, ge=0.0, le=1.0, description="Decision threshold for phishing classification (default: 0.5)")


class BatchEmailInput(BaseModel):
    emails: List[EmailInput] = Field(..., description="List of emails to classify in a batch")


class PredictionResult(BaseModel):
    label: str = Field(..., description="'Phishing' or 'Safe'")
    probability: float = Field(..., description="Estimated probability of the email being phishing (0.0 to 1.0)")
    risk_level: str = Field(..., description="'Low', 'Medium', or 'High'")
    reasons: List[str] = Field(..., description="Key diagnostic factors contributing to the detection")


# -----------------------------------------------------------------------------
# Prediction Logic
# -----------------------------------------------------------------------------
def analyze_single_email(sender: str, subject: str, email_text: str, threshold: float = 0.5) -> dict:
    df = pd.DataFrame([{
        "sender": sender,
        "subject": subject,
        "email_text": email_text,
        "text_for_model": f"{subject or ''} {email_text or ''}"
    }])

    # Predict probability of phishing (class 1)
    proba = float(model.predict_proba(df)[:, 1][0])
    label = "Phishing" if proba >= threshold else "Safe"
    
    # Determine risk level
    if proba >= 0.75:
        risk_level = "High"
    elif proba >= 0.40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Extract heuristic reasons
    reasons = detect_suspicious_features(sender, subject, email_text)
    if not reasons and label == "Safe":
        reasons.append("Sender domain is recognized and content matches standard communication patterns")

    return {
        "label": label,
        "probability": round(proba, 4),
        "risk_level": risk_level,
        "reasons": reasons
    }


# -----------------------------------------------------------------------------
# API Endpoints
# -----------------------------------------------------------------------------
@app.get("/", tags=["General"])
def root():
    return {
        "service": "AI-Powered Phishing Detection API",
        "version": "2.0.0",
        "status": "online",
        "docs": "/docs"
    }


@app.get("/health", tags=["General"])
def health():
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "model_path": MODEL_PATH
    }


@app.post("/predict", response_model=PredictionResult, tags=["Inference"])
def predict(email: EmailInput):
    """Analyzes a single email for phishing indicators and returns classification with explainability reasons."""
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
    """Analyzes multiple emails in a single request."""
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


if __name__ == "__main__":
    import uvicorn
    print("=" * 65)
    print(" AI-Powered Phishing Detection Server")
    print(" Local URL : http://127.0.0.1:8000")
    print(" Swagger UI: http://127.0.0.1:8000/docs")
    print("=" * 65)
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
