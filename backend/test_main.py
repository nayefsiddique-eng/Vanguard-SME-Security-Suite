import os
import pytest
from fastapi.testclient import TestClient

# Ensure test environment variables
os.environ["DATABASE_URL"] = "sqlite:///./test_db.db"
os.environ["SECRET_KEY"] = "testsecretkey-for-hardened-mvp-suite"
os.environ["ALLOWED_ORIGINS"] = "http://localhost:3000"

from app.main import app
from app.db.database import Base, engine
from app.ml.trainer import ensure_models_ready, get_model_metadata

# Setup test database & ensure ML models are initialized
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
ensure_models_ready()

client = TestClient(app)

# Helper fixture for auth headers
def get_auth_headers(email="testuser@example.com"):
    client.post("/register", json={"email": email, "password": "password123"})
    login_res = client.post("/login", json={"email": email, "password": "password123"})
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ── Auth Tests ───────────────────────────────────────────────────────────────

def test_register_and_login():
    reg = client.post("/register", json={"email": "analyst@vanguard.com", "password": "securepass123"})
    assert reg.status_code in (200, 400)
    login = client.post("/login", json={"email": "analyst@vanguard.com", "password": "securepass123"})
    assert login.status_code == 200
    assert "access_token" in login.json()

def test_unauthorized_endpoints():
    url_res = client.post("/api/scan/url", json={"url": "http://example.com"})
    assert url_res.status_code in (401, 403)


# ── ML Model Metadata & Training Evaluation Tests ────────────────────────────

def test_ml_model_info():
    headers = get_auth_headers("mlinfo@vanguard.com")
    res = client.get("/api/ml/model-info", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "models" in data
    assert len(data["models"]) == 3

    model_names = [m["algorithm"] for m in data["models"]]
    assert "RandomForestClassifier" in model_names
    assert "GradientBoostingClassifier" in model_names
    assert "IsolationForest" in model_names

    # Check metrics existence
    for m in data["models"]:
        assert "metrics" in m
        assert "dataset" in m
        assert m["dataset"]["dataset_type"] == "Synthetic Prototype Dataset"


# ── Phishing Scan & ML Predictor Integration Tests ───────────────────────────

def test_email_scan_with_ml_prediction():
    headers = get_auth_headers("phishuser@vanguard.com")
    phishing_header = (
        "From: support@paytm.com.malicious-login.ru\n"
        "Reply-To: steal@phishingsite.xyz\n"
        "Return-Path: <bounce@malicious-login.ru>\n"
        "Subject: Your Paytm KYC is expiring - Verify Now\n"
        "Received-SPF: fail\n"
        "Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\n"
    )
    res = client.post("/api/scan/email", json={"header": phishing_header}, headers=headers)
    assert res.status_code == 200
    data = res.json()

    # Verify standard fields
    assert data["tool"] == "email_analyser"
    assert data["verdict"] in ("PHISHING", "SUSPICIOUS")
    assert "actions" in data
    assert len(data["actions"]) > 0

    # Verify ML Prediction attachment
    assert "ml_prediction" in data
    ml = data["ml_prediction"]
    assert ml is not None
    assert ml["model"] == "RandomForestClassifier"
    assert ml["task"] == "phishing_detection"
    assert ml["prediction"] in ("PHISHING", "SUSPICIOUS")
    assert ml["score_type"] == "probability"
    assert 0.0 <= ml["score"] <= 1.0
    assert len(ml["features"]) == 6
    assert len(ml["feature_importances"]) == 6


# ── UPI Scan & ML Integration Tests ──────────────────────────────────────────

def test_upi_scan_fraud_with_ml_prediction():
    headers = get_auth_headers("upiuser@vanguard.com")
    fraud_upi = "fake-kyc-refund99283@paytm"
    res = client.post("/api/scan/upi", json={"upi_id": fraud_upi}, headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["tool"] == "upi_verifier"
    assert data["verdict"] == "DANGEROUS"
    assert "ml_prediction" in data
    ml = data["ml_prediction"]
    assert ml is not None
    assert ml["model"] == "GradientBoostingClassifier"
    assert ml["task"] == "upi_fraud_detection"
    assert ml["prediction"] in ("FRAUDULENT", "SUSPICIOUS")
    assert ml["score_type"] == "probability"


def test_upi_scan_clean():
    headers = get_auth_headers("upiclean@vanguard.com")
    safe_upi = "merchant.kirana@okaxis"
    res = client.post("/api/scan/upi", json={"upi_id": safe_upi}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "SUSPICIOUS"  # Default low risk for unverified brand
    assert data["ml_prediction"]["prediction"] in ("SAFE", "SUSPICIOUS")


# ── Network Scan & Isolation Forest Anomaly Detection Tests ──────────────────

def test_network_scan_with_isolation_forest():
    headers = get_auth_headers("netuser@vanguard.com")
    target = "demo.vanguard.local"  # Hits test mock profile in nmap_scanner
    res = client.post("/api/scan/network", json={"target": target}, headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["verdict"] == "DANGEROUS"
    assert data["total_open_ports"] == 4
    assert len(data["raw_ports"]) == 4

    # Verify Isolation Forest output semantics
    ml = data["ml_prediction"]
    assert ml is not None
    assert ml["model"] == "IsolationForest"
    assert ml["task"] == "network_anomaly_detection"
    assert ml["prediction"] == "ANOMALOUS"
    assert ml["score_type"] == "anomaly_score"
    assert 0.0 <= ml["score"] <= 1.0

    # Ensure contributing signals exist and active indicators are marked
    active_signals = [f for f in ml["features"] if f["contribution"] == "positive"]
    assert len(active_signals) > 0


# ── Input Validation & Injection Hardening Tests ─────────────────────────────

def test_network_scan_command_injection_rejected():
    headers = get_auth_headers("secuser@vanguard.com")
    malicious_target = "127.0.0.1; cat /etc/passwd"
    res = client.post("/api/scan/network", json={"target": malicious_target}, headers=headers)
    assert res.status_code == 422  # Rejected by Pydantic regex validator


def test_upi_scan_malformed_input():
    headers = get_auth_headers("secuser2@vanguard.com")
    bad_upi = "not-a-valid-upi-id"
    res = client.post("/api/scan/upi", json={"upi_id": bad_upi}, headers=headers)
    assert res.status_code == 422


# ── Dashboard Summary Real Scan Aggregation Tests ────────────────────────────

def test_dashboard_summary_metrics():
    headers = get_auth_headers("dashuser@vanguard.com")
    # Execute a scan to populate history
    client.post("/api/scan/upi", json={"upi_id": "fraud-alert@paytm"}, headers=headers)

    res = client.get("/dashboard-summary", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "total_scans" in data
    assert data["total_scans"] >= 1
    assert "ml_detections" in data
    assert data["ml_detections"] >= 1
