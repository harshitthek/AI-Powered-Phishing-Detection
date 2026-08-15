# 🛡️ AI-Powered Phishing Detection & Threat Intelligence

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.3%2B-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.0-38B2AC?logo=tailwind-css&logoColor=white)](https://tailwindcss.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An end-to-end intelligent cybersecurity platform that detects, explains, and intercepts email phishing attacks, brand impersonation, and malicious hyperlinks in real-time using Machine Learning and NLP heuristics.

---

## 🚀 Key Capabilities

* **Dual-Engine Feature Pipeline**: Combines sublinear TF-IDF N-gram text vectorization with scikit-learn custom heuristic transformers.
* **Deep URL & Hyperlink Inspector**: Scans embedded links for direct raw IP hosting, high-risk Top-Level Domains (`.xyz`, `.top`, `.online`, etc.), shortener masking, and dangerous file extensions.
* **Domain Typosquatting & Spoof Detection**: Identifies brand lookalikes, homoglyph attacks, and Shannon entropy anomalies for 50+ global brands (PayPal, Apple, Google, Microsoft, Chase, Netflix, etc.).
* **Explainable AI Diagnostics**: Generates human-readable security reasons highlighting exact risk factors, urgency pressures, and threat vectors.
* **Multi-Tab Dashboard (Tailwind CSS)**:
  * 🛡️ **Email Scanner**: Deep security scan with animated threat confidence gauge, risk levels, and 1-click test presets.
  * 🔗 **Direct URL & Domain Inspector**: Standalone link risk and domain reputation checker.
  * ⚡ **Batch Scanner**: Bulk scanning of multiple emails with instant tabular results.
  * 📊 **Model Metrics View**: Live cross-validation metrics, feature counts, and tree estimator configurations.
* **High-Throughput FastAPI Backend**: Fully async endpoints, health monitors, batch processing, and interactive Swagger UI.

---

## 🏗️ Architecture Overview

```mermaid
flowchart TD
    A[Incoming Email: Sender, Subject, Body] --> B[Feature Extraction Pipeline]
    
    subgraph FeaturePipeline [Feature Extraction & Heuristics]
        B --> C[Text Pipeline: Sublinear TF-IDF N-grams]
        B --> D[Numeric & Structural Heuristics]
        D --> D1[URL & Raw IP Analysis]
        D --> D2[Domain Trust, Entropy & Typosquatting]
        D --> D3[Multi-Category Urgency & Threat Keywords]
        D --> D4[Stylometry & Punctuation Density]
    end
    
    C --> E[Feature Union Layer]
    D1 --> E
    D2 --> E
    D3 --> E
    D4 --> E
    
    E --> F[Random Forest Classifier (250 Trees)]
    F --> G[Threat Probability & Risk Level]
    F --> H[Explainable Diagnostic Explanations]
    G --> I[FastAPI REST API / Web UI]
    H --> I
```

---

## 📂 Project Structure

```text
AI-Powered-Phishing-Detection/
├── custom_transformers.py   # Custom scikit-learn transformers, URL inspectors, typosquatting detector
├── model_training.py        # 5-fold cross-validated dataset training & model persistence
├── main.py                  # FastAPI server with single/batch endpoints, URL/domain inspectors
├── index.html               # Modern multi-tab responsive web dashboard (Tailwind CSS)
├── phish_model.pickle       # Serialized Random Forest ML model artifact
├── requirements.txt         # Python project dependencies
├── .gitignore               # Ignored runtime & editor files
├── LICENSE                  # MIT License
└── README.md                # Project documentation
```

---

## ⚡ Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/harshitthek/AI-Powered-Phishing-Detection.git
cd AI-Powered-Phishing-Detection
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. (Optional) Retrain Model
```bash
python model_training.py
```
> **Validation Metrics:**
> * 5-Fold Stratified Cross-Validation: **94.29% Accuracy** | **93.33% F1-Score**
> * Holdout Test Accuracy: **100.0%** | **1.0000 ROC-AUC**

### 4. Start the Application
```bash
python main.py
```
* **Web Dashboard:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
* **Swagger API Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 📡 API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Serves the interactive Web Dashboard |
| `GET` | `/health` | Health check & model status |
| `GET` | `/metrics` | Model parameters, cross-validation metrics, and feature list |
| `GET` | `/samples` | Preset test sample emails |
| `POST` | `/predict` | Single email analysis with explainability & URL breakdowns |
| `POST` | `/predict/batch` | Bulk multi-email scan |
| `POST` | `/analyze/url` | Direct standalone URL risk inspection |
| `POST` | `/analyze/domain` | Standalone domain reputation & typosquatting checker |

### Sample Single Email Scan (`POST /predict`):
```json
{
  "sender": "security-alert@paypal-update-center.net",
  "subject": "URGENT: Your PayPal Account Has Been Suspended",
  "email_text": "Click http://paypal-security-verification.net/login immediately to verify your identity.",
  "threshold": 0.5
}
```

**Response:**
```json
{
  "label": "Phishing",
  "probability": 0.88,
  "risk_level": "High",
  "reasons": [
    "Contains 1 embedded hyperlink(s)",
    "Link uses a high-risk suspicious top-level domain (TLD)",
    "Brand Mismatch: Subject mentions 'Paypal', but sender is from '@paypal-update-center.net'",
    "Urgency keywords detected: 'urgent', 'suspended'",
    "Credentials keywords detected: 'verify', 'login', 'identity'"
  ],
  "sender_analysis": {
    "domain": "paypal-update-center.net",
    "is_trusted": false,
    "entropy": 3.65,
    "typosquatting_detected": true,
    "impersonated_brand": "Paypal"
  }
}
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

Developed with ❤️ by **[Harshit Sharma](https://github.com/harshitthek)**
