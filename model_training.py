"""
Production Model Training Pipeline for AI-Powered Phishing Detection.
Trains a composite NLP & Heuristic Feature Classifier using Random Forest with Cross Validation.
"""

import os
import pickle
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score, f1_score

from custom_transformers import (
    TextSelector,
    NumericFeatureExtractor,
    detect_suspicious_features
)


def get_training_dataset() -> pd.DataFrame:
    """Returns a balanced, high-diversity dataset of real-world phishing and legitimate communications."""
    data = [
        # =====================================================================
        # 1. BRAND IMPERSONATION & ACCOUNT TAKEOVER (Phishing)
        # =====================================================================
        {
            "sender": "security-alert@paypal-update-center.net",
            "subject": "URGENT: Your PayPal Account Has Been Suspended",
            "email_text": "Dear customer, we detected unusual login activity from an unknown IP address in Moscow. Your account access has been restricted. Click http://paypal-auth-check.net/restore immediately to verify your identity and unlock your funds.",
            "label": 1
        },
        {
            "sender": "account-update@netflix-billing-auth.com",
            "subject": "Payment Declined: Update Your Credit Card Information Immediately",
            "email_text": "We were unable to process your subscription renewal payment. Please visit http://netflix-account-reactivate.co/update within 24 hours to avoid account termination.",
            "label": 1
        },
        {
            "sender": "no-reply@apple-icloud-secure.org",
            "subject": "Your Apple ID was locked due to security risks",
            "email_text": "Your Apple ID was used to sign into iCloud from an unrecognized device. If this was not you, confirm your password at http://icloud-session-check.biz/login right away.",
            "label": 1
        },
        {
            "sender": "support@bankofamerica-online-secure.club",
            "subject": "Security Notice: Online Banking Access Restricted",
            "email_text": "Your online banking credentials have been flagged for multiple invalid login attempts. Unlock your profile at http://boa-account-unlock.club/verify now.",
            "label": 1
        },
        {
            "sender": "fraud-prevention@chase-bank-resolution.net",
            "subject": "Chase Alert: Unauthorized Wire Transfer of $3,500.00",
            "email_text": "A wire transfer was scheduled from your checking account. If you did not authorize this transaction, click http://chase-wire-cancel.net/auth to dispute immediately.",
            "label": 1
        },
        {
            "sender": "admin@google-security-team.top",
            "subject": "CRITICAL: Google Password Compromised",
            "email_text": "Someone knows your password! A suspicious third-party app was granted full account access. Click http://google-security-reset.top/auth to secure your account immediately.",
            "label": 1
        },
        {
            "sender": "meta-copyright@facebook-support-case.rest",
            "subject": "Notice: Your Facebook Page is Scheduled for Deletion",
            "email_text": "Your page has repeatedly violated our Community Standards on intellectual property. Appeal the decision within 24 hours at http://meta-appeal-portal.rest/case-8219 or your page will be permanently removed.",
            "label": 1
        },
        {
            "sender": "security@msoffice365-pass-keep.cc",
            "subject": "Microsoft 365: Mandatory Password Expiration Warning",
            "email_text": "Your corporate Microsoft Office 365 password will expire in 2 hours. Keep your current credentials by authenticating at http://msoffice365-pass-keep.cc/auth.",
            "label": 1
        },

        # =====================================================================
        # 2. INVOICE FRAUD, BEC & PAYROLL SCAMS (Phishing)
        # =====================================================================
        {
            "sender": "hr-payroll@corporate-direct-deposit.info",
            "subject": "ACTION REQUIRED: Mandatory Direct Deposit & Payroll Verification",
            "email_text": "All staff members must verify their banking details on the new employee portal at http://192.168.1.105/payroll before Friday to prevent delayed paycheck processing.",
            "label": 1
        },
        {
            "sender": "billing@quickbooks-invoice-notice.link",
            "subject": "OVERDUE INVOICE: Invoice #INV-2024-9182 Requires Immediate Settlement",
            "email_text": "Please find the outstanding invoice for $4,120.00 attached. Pay immediately at http://quickbooks-invoice-view.link/pay to avoid legal collection penalties.",
            "label": 1
        },
        {
            "sender": "ceo.office@executive-corp-urgent.com",
            "subject": "URGENT & CONFIDENTIAL: Wire Transfer Needed Today",
            "email_text": "I am in a private meeting and cannot take calls. Please process an urgent wire transfer of $18,400 to our vendor immediately. Send confirmation slip once done.",
            "label": 1
        },
        {
            "sender": "tax-refund@irs-government-portal.online",
            "subject": "IRS Notification: Pending Tax Refund $1,840.50 Approved",
            "email_text": "You are eligible for an unclaimed federal tax refund. Click http://irs-electronic-deposit.online/claim and input your SSN and bank routing number to receive direct deposit.",
            "label": 1
        },

        # =====================================================================
        # 3. PRIZE SCAMS, CRYPTO AIRDROPS & PACKAGE FRAUD (Phishing)
        # =====================================================================
        {
            "sender": "rewards@amazon-giftcard-promotions.xyz",
            "subject": "Congratulations! You have been selected for a $1,000 Amazon Gift Card",
            "email_text": "You are our lucky winner! Claim your $1000 shopping voucher immediately by visiting http://bit.ly/3xAmazonClaim and entering your credit card details for delivery confirmation.",
            "label": 1
        },
        {
            "sender": "crypto-airdrop@binance-reward-vault.top",
            "subject": "Exclusive Binance 2.0 ETH Airdrop for Active Users",
            "email_text": "Claim your free Ethereum airdrop! Connect your Web3 wallet at http://binance-airdrop-claim.top/connect immediately before the allocation period closes.",
            "label": 1
        },
        {
            "sender": "tracking@dhl-express-package-held.com",
            "subject": "Delivery Exception: Package #US-98214 held at customs",
            "email_text": "Your shipment could not be dispatched due to an unpaid customs clearance fee of $2.50. Settle the fee at http://dhl-express-redelivery.com/pay to resume shipment.",
            "label": 1
        },
        {
            "sender": "lottery@international-sweepstakes-winner.biz",
            "subject": "OFFICIAL NOTIFICATION: You Won $750,000.00 USD",
            "email_text": "Your email address won 2nd prize in the Global Sweepstakes draw. Claim your funds by sending your identity verification to claim@international-sweepstakes-winner.biz.",
            "label": 1
        },
        {
            "sender": "service@docusign-document-secure.xyz",
            "subject": "DocuSign: Please review and sign Confidential Settlement Agreement",
            "email_text": "A confidential document has been sent to you for electronic signature. View and sign at http://docusign-sign-document.xyz/session-82910.",
            "label": 1
        },
        {
            "sender": "support@coinbase-security-resolution.online",
            "subject": "Coinbase Alert: Withdrawal of 0.85 BTC Requested",
            "email_text": "A withdrawal request of 0.85 BTC was initiated. If this was not you, cancel the transaction immediately at http://coinbase-cancel-withdrawal.online/dispute.",
            "label": 1
        },

        # =====================================================================
        # 4. LEGITIMATE WORKPLACE & PEER COMMUNICATIONS (Safe)
        # =====================================================================
        {
            "sender": "alex.chen@google.com",
            "subject": "Notes from today's sprint planning & roadmap sync",
            "email_text": "Hi team, attached are the action items from our sync this morning. We decided to prioritize the latency improvements for Q3. Let me know if you have any feedback before tomorrow's standup.",
            "label": 0
        },
        {
            "sender": "sarah.miller@company.com",
            "subject": "Team Lunch on Thursday at 12:30 PM",
            "email_text": "Hey team, we are planning a casual lunch at the new Mexican restaurant across the street this Thursday. Please reply if you can make it so I can reserve a table.",
            "label": 0
        },
        {
            "sender": "professor.johnson@university.edu",
            "subject": "CS 401: Grading Feedback for Assignment 3",
            "email_text": "Dear student, your Assignment 3 submission has been reviewed. Excellent implementation of the graph traversal algorithm. Office hours will be held on Wednesday from 2 PM to 4 PM.",
            "label": 0
        },
        {
            "sender": "david.williams@enterprise.com",
            "subject": "Design Review: Mobile App Architecture Diagram",
            "email_text": "Hi everyone, I have uploaded the updated Figma wireframes and architecture diagrams for the authentication flow. Feel free to leave comments directly in Figma.",
            "label": 0
        },
        {
            "sender": "hr-team@microsoft.com",
            "subject": "Annual Benefits Enrollment Window Open (Nov 1 - Nov 15)",
            "email_text": "Dear team member, the annual benefits open enrollment period is now active. Please review your health and dental coverage options on the Microsoft internal portal.",
            "label": 0
        },

        # =====================================================================
        # 5. LEGITIMATE TRANSACTIONAL & NOTIFICATION EMAILS (Safe)
        # =====================================================================
        {
            "sender": "notifications@github.com",
            "subject": "[GitHub] Pull Request #14 merged into main branch",
            "email_text": "harshitthek merged pull request #14: Optimize feature extraction pipeline and update documentation. View commit details on GitHub.",
            "label": 0
        },
        {
            "sender": "no-reply@zoom.us",
            "subject": "Meeting Invitation: Engineering Architecture Review",
            "email_text": "You are invited to join a Zoom meeting. Topic: System Architecture Review. Meeting ID: 894 2841 0921. Passcode: 482019.",
            "label": 0
        },
        {
            "sender": "auto-confirm@amazon.com",
            "subject": "Your Amazon.com order #114-8921471-291823 has shipped",
            "email_text": "Great news! Your package containing USB-C Cables is on its way. Estimated delivery date: Tuesday by 8:00 PM. Track your package in your Amazon account.",
            "label": 0
        },
        {
            "sender": "billing@spotify.com",
            "subject": "Your Spotify Premium Monthly Receipt",
            "email_text": "Thank you for subscribing to Spotify Premium. Your payment of $10.99 for the upcoming month was successful. You can manage your subscription in your account settings.",
            "label": 0
        },
        {
            "sender": "university-recruiting@microsoft.com",
            "subject": "Interview Confirmation: Software Engineer Role",
            "email_text": "Thank you for taking the time to interview with Microsoft. We enjoyed learning more about your technical background and will follow up with next steps within five business days.",
            "label": 0
        },
        {
            "sender": "statements@chase.com",
            "subject": "Your Monthly Account Statement is Ready to View",
            "email_text": "Your latest electronic statement for account ending in 8192 is now available in your Chase Mobile app or on chase.com. Thank you for banking with us.",
            "label": 0
        },
        {
            "sender": "service@paypal.com",
            "subject": "Receipt for your payment to DigitalOcean LLC",
            "email_text": "You sent a payment of $24.00 USD to DigitalOcean LLC. Transaction ID: 9KL81920LA. To view details, log in to your PayPal account at paypal.com.",
            "label": 0
        },
        {
            "sender": "hiring-team@linkedin.com",
            "subject": "New job alerts matching your software engineering preferences",
            "email_text": "Here are 5 new positions matching your profile in Full Stack and Python development. See details and apply on LinkedIn.",
            "label": 0
        },
        {
            "sender": "support@slack.com",
            "subject": "Workspace weekly summary for Dev-Team",
            "email_text": "Here is your team activity overview for the week: 420 messages posted, 12 files shared across 6 active channels.",
            "label": 0
        },
        {
            "sender": "updates@apple.com",
            "subject": "Your receipt from Apple Store for iCloud+ 50GB",
            "email_text": "Your monthly subscription for iCloud+ 50 GB storage ($0.99) has been charged to your payment card on file. Manage storage in iOS Settings.",
            "label": 0
        },
        {
            "sender": "newsletter@morningbrew.com",
            "subject": "Tech markets rally and today's top business news",
            "email_text": "Good morning! Technology indices surged following strong earnings reports. In today's edition: AI hardware breakthroughs and the shift in electric vehicle markets.",
            "label": 0
        },
        {
            "sender": "info@netflix.com",
            "subject": "Coming this month to Netflix: New movies and series",
            "email_text": "Check out what is new on Netflix this month. Browse top picks, documentaries, and new seasons tailored to your watchlist.",
            "label": 0
        },
        {
            "sender": "calendar-notification@google.com",
            "subject": "Reminder: Team Demo Day @ Fri Nov 14, 2025 3pm - 4pm",
            "email_text": "You have a scheduled calendar event: Team Demo Day. Location: Google Meet (meet.google.com/xyz-abc-def). Attendees: Engineering Staff.",
            "label": 0
        }
    ]
    return pd.DataFrame(data)


def build_pipeline() -> Pipeline:
    """Constructs the combined ML pipeline featuring TF-IDF and heuristic feature extractors."""
    text_pipeline = Pipeline([
        ("selector", TextSelector("text_for_model")),
        ("tfidf", TfidfVectorizer(
            stop_words="english",
            ngram_range=(1, 2),
            max_features=3000,
            sublinear_tf=True
        ))
    ])
    
    numeric_pipeline = Pipeline([
        ("num_features", NumericFeatureExtractor())
    ])
    
    combined_features = FeatureUnion([
        ("text_features", text_pipeline),
        ("numeric_features", numeric_pipeline)
    ])
    
    pipeline = Pipeline([
        ("features", combined_features),
        ("clf", RandomForestClassifier(
            n_estimators=250,
            max_depth=16,
            min_samples_split=2,
            random_state=42,
            class_weight="balanced"
        ))
    ])
    
    return pipeline


def train_and_evaluate():
    """Trains the model with cross-validation and persists artifact."""
    print("=" * 65)
    print(" AI-Powered Phishing Detection - Model Training & Evaluation")
    print("=" * 65)

    df = get_training_dataset()
    df["text_for_model"] = df["subject"] + " " + df["email_text"]
    
    X = df[["sender", "subject", "email_text", "text_for_model"]]
    y = df["label"]
    
    print(f"Total training samples: {len(df)} (Phishing: {sum(y==1)}, Legitimate: {sum(y==0)})")
    
    # 5-Fold Stratified Cross Validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(build_pipeline(), X, y, cv=cv, scoring="accuracy")
    cv_f1 = cross_val_score(build_pipeline(), X, y, cv=cv, scoring="f1")
    
    print(f"\n5-Fold Stratified Cross-Validation Results:")
    print(f" - Mean Accuracy : {cv_scores.mean() * 100:.2f}% (+/- {cv_scores.std() * 100:.2f}%)")
    print(f" - Mean F1 Score : {cv_f1.mean() * 100:.2f}% (+/- {cv_f1.std() * 100:.2f}%)")

    # Holdout Test Evaluation
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    
    model = build_pipeline()
    model.fit(X_train, y_train)
    
    preds = model.predict(X_test)
    probas = model.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, preds) * 100
    auc = roc_auc_score(y_test, probas)
    
    print(f"\nHoldout Test Performance:")
    print(f" - Test Accuracy : {acc:.2f}%")
    print(f" - ROC-AUC Score : {auc:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, preds, target_names=["Safe (0)", "Phishing (1)"]))
    
    # Train on full dataset for maximum production power
    model.fit(X, y)
    
    model_filename = "phish_model.pickle"
    with open(model_filename, "wb") as f:
        pickle.dump(model, f)
        
    print(f"[SUCCESS] Production model successfully serialized & saved to: {model_filename}")
    print("=" * 65)


if __name__ == "__main__":
    train_and_evaluate()
