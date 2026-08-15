import os
import main
from fastapi.testclient import TestClient

client = TestClient(main.app)

# 1. Health
r1 = client.get('/health')
assert r1.status_code == 200
print("1. Health PASSED:", r1.json())

# 2. Metrics
m = client.get('/metrics').json()
assert m['model_type'] == 'RandomForestClassifier'
print("2. Metrics PASSED (5-Fold CV Accuracy):", m['cross_val_accuracy'])

# 3. Predict Single
p = client.post('/predict', json={
    'sender': 'security-alert@paypal-update-center.net',
    'subject': 'URGENT: Your PayPal Account Has Been Suspended',
    'email_text': 'Click http://paypal-auth-check.net/restore immediately to verify your identity.',
    'threshold': 0.5
}).json()
assert p['label'] == 'Phishing'
assert 'sender_analysis' in p
print(f"3. Predict Single PASSED: {p['label']} ({p['probability']*100:.1f}%) - Risk: {p['risk_level']}")

# 4. URL Inspector
u = client.post('/analyze/url', json={'url': 'http://192.168.1.1/pay.exe'}).json()
assert u['is_ip'] is True
assert u['risk_score'] > 50
print(f"4. URL Inspector PASSED (Risk Score: {u['risk_score']}%, Issues: {u['issues']})")

# 5. Domain Inspector
d = client.post('/analyze/domain', json={'domain_or_email': 'support@paypa1-update.com'}).json()
assert d['typosquatting_detected'] is True
print(f"5. Domain Inspector PASSED (Impersonating: {d['impersonated_brand']})")

# 6. Batch Predict
b = client.post('/predict/batch', json={'emails': [
    {'sender': 'support@paypa1.com', 'subject': 'Urgent', 'email_text': 'Click here', 'threshold': 0.5},
    {'sender': 'alex@google.com', 'subject': 'Meeting', 'email_text': 'Sync tomorrow', 'threshold': 0.5}
]}).json()
assert len(b) == 2
print("6. Batch Predict PASSED (2 items processed)")

print("\nALL 6 TEST SUITE CHECKS PASSED SUCCESSFULLY!")
