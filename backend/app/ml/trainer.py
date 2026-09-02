"""
ML model trainer for Vanguard SME Security Suite.

Generates synthetic but realistic labeled training data and trains three models:
  1. Phishing Email Classifier   — RandomForestClassifier
  2. UPI Fraud Scorer            — GradientBoostingClassifier
  3. Network Anomaly Detector    — IsolationForest (anomaly detection)

Models are serialized to backend/app/ml/models/ with joblib.
Call ensure_models_ready() at application startup.
"""

import os
import logging
import numpy as np
import joblib
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Paths ────────────────────────────────────────────────────────────────────
_ML_DIR = Path(__file__).parent
MODELS_DIR = _ML_DIR / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

PHISHING_MODEL_PATH = MODELS_DIR / "phishing_classifier.joblib"
UPI_MODEL_PATH      = MODELS_DIR / "upi_fraud_scorer.joblib"
NETWORK_MODEL_PATH  = MODELS_DIR / "network_anomaly_detector.joblib"

# ── Label maps ───────────────────────────────────────────────────────────────
PHISHING_LABELS = ["CLEAN", "SUSPICIOUS", "PHISHING"]
UPI_LABELS      = ["SAFE", "SUSPICIOUS", "FRAUDULENT"]


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic data generators
# ─────────────────────────────────────────────────────────────────────────────

def _gen_phishing_data(n: int = 1200, seed: int = 42):
    """
    6 binary features: spf_fail, dkim_fail, dmarc_fail,
                       domain_mismatch, spoofed, reply_to_mismatch
    Labels: 0=CLEAN, 1=SUSPICIOUS, 2=PHISHING
    """
    rng = np.random.default_rng(seed)
    X, y = [], []

    # CLEAN emails (40%)
    n_clean = int(n * 0.40)
    for _ in range(n_clean):
        row = [
            rng.integers(0, 2) * 0,          # spf_fail — mostly 0
            rng.integers(0, 2) * 0,
            rng.integers(0, 2) * 0,
            0,                                # domain_mismatch
            0,                                # spoofed
            rng.integers(0, 2) * 0,
        ]
        # allow occasional noise
        if rng.random() < 0.05:
            row[0] = 1
        X.append(row)
        y.append(0)

    # SUSPICIOUS emails (30%)
    n_susp = int(n * 0.30)
    for _ in range(n_susp):
        row = [
            int(rng.random() < 0.50),        # spf sometimes fails
            int(rng.random() < 0.30),
            int(rng.random() < 0.30),
            int(rng.random() < 0.40),        # domain_mismatch sometimes
            0,
            int(rng.random() < 0.40),
        ]
        X.append(row)
        y.append(1)

    # PHISHING emails (30%)
    n_phish = n - n_clean - n_susp
    for _ in range(n_phish):
        row = [
            int(rng.random() < 0.85),        # spf usually fails
            int(rng.random() < 0.80),
            int(rng.random() < 0.80),
            int(rng.random() < 0.90),        # domain_mismatch almost always
            int(rng.random() < 0.75),        # spoofed
            int(rng.random() < 0.70),
        ]
        X.append(row)
        y.append(2)

    return np.array(X, dtype=float), np.array(y)


def _gen_upi_data(n: int = 1200, seed: int = 43):
    """
    6 numeric features: handle_length, has_numbers, digit_ratio,
                        suspicious_keyword_score, brand_keyword_score, handle_entropy
    Labels: 0=SAFE, 1=SUSPICIOUS, 2=FRAUDULENT
    """
    rng = np.random.default_rng(seed)
    X, y = [], []

    # SAFE (40%)
    n_safe = int(n * 0.40)
    for _ in range(n_safe):
        length = rng.integers(5, 18)
        has_num = int(rng.random() < 0.40)
        X.append([
            float(length),
            float(has_num),
            rng.uniform(0, 0.3) if has_num else 0.0,
            0.0,                              # no suspicious keywords
            float(rng.integers(0, 2)),        # maybe one brand keyword
            rng.uniform(2.5, 3.5),
        ])
        y.append(0)

    # SUSPICIOUS (35%)
    n_susp = int(n * 0.35)
    for _ in range(n_susp):
        length = rng.integers(8, 30)
        has_num = int(rng.random() < 0.60)
        X.append([
            float(length),
            float(has_num),
            rng.uniform(0.2, 0.5) if has_num else 0.0,
            float(rng.integers(0, 2)),
            float(rng.integers(1, 3)),
            rng.uniform(2.8, 3.8),
        ])
        y.append(1)

    # FRAUDULENT (25%)
    n_fraud = n - n_safe - n_susp
    for _ in range(n_fraud):
        length = rng.integers(15, 45)
        X.append([
            float(length),
            1.0,
            rng.uniform(0.4, 0.8),
            float(rng.integers(1, 4)),        # suspicious keywords
            float(rng.integers(2, 4)),        # brand keywords (impersonation)
            rng.uniform(3.2, 4.2),
        ])
        y.append(2)

    return np.array(X, dtype=float), np.array(y)


def _gen_network_data(n: int = 1000, seed: int = 44):
    """
    7 features: num_open_ports, has_critical, has_rdp, has_smb,
                has_db, has_ftp, has_telnet
    For IsolationForest: normal (80%) vs anomalous (20%).
    Returns only X (unsupervised).  y is used for evaluation only.
    """
    rng = np.random.default_rng(seed)
    X, y = [], []

    # Normal hosts (80%)
    n_normal = int(n * 0.80)
    for _ in range(n_normal):
        ports = rng.integers(1, 5)
        row = [
            float(ports),
            0.0,
            0.0,
            0.0,
            0.0,
            int(rng.random() < 0.10),
            0.0,
        ]
        X.append(row)
        y.append(0)

    # Anomalous (20%) — many open critical ports
    n_anom = n - n_normal
    for _ in range(n_anom):
        ports = rng.integers(5, 15)
        row = [
            float(ports),
            1.0,
            int(rng.random() < 0.75),
            int(rng.random() < 0.65),
            int(rng.random() < 0.55),
            int(rng.random() < 0.60),
            int(rng.random() < 0.50),
        ]
        X.append(row)
        y.append(1)

    idx = rng.permutation(len(X))
    return np.array(X, dtype=float)[idx], np.array(y)[idx]


# ─────────────────────────────────────────────────────────────────────────────
# Training functions
# ─────────────────────────────────────────────────────────────────────────────

def _train_phishing_model():
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    logger.info("ML: Training phishing email classifier (RandomForest)…")
    X, y = _gen_phishing_data()

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=120,
            max_depth=6,
            class_weight="balanced",
            random_state=42,
        )),
    ])
    model.fit(X, y)
    joblib.dump(model, PHISHING_MODEL_PATH)
    logger.info(f"ML: Phishing model saved → {PHISHING_MODEL_PATH}")
    return model


def _train_upi_model():
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    logger.info("ML: Training UPI fraud scorer (GradientBoosting)…")
    X, y = _gen_upi_data()

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=4,
            random_state=43,
        )),
    ])
    model.fit(X, y)
    joblib.dump(model, UPI_MODEL_PATH)
    logger.info(f"ML: UPI fraud model saved → {UPI_MODEL_PATH}")
    return model


def _train_network_model():
    from sklearn.ensemble import IsolationForest
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    logger.info("ML: Training network anomaly detector (IsolationForest)…")
    X, y = _gen_network_data()
    # IsolationForest is unsupervised — train on full data
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", IsolationForest(
            n_estimators=150,
            contamination=0.20,
            random_state=44,
        )),
    ])
    model.fit(X)
    joblib.dump(model, NETWORK_MODEL_PATH)
    logger.info(f"ML: Network anomaly model saved → {NETWORK_MODEL_PATH}")
    return model


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def ensure_models_ready():
    """
    Called once at application startup.
    Trains and saves models only if they don't exist on disk yet.
    """
    if not PHISHING_MODEL_PATH.exists():
        _train_phishing_model()
    else:
        logger.info("ML: Phishing model already exists, skipping training.")

    if not UPI_MODEL_PATH.exists():
        _train_upi_model()
    else:
        logger.info("ML: UPI fraud model already exists, skipping training.")

    if not NETWORK_MODEL_PATH.exists():
        _train_network_model()
    else:
        logger.info("ML: Network anomaly model already exists, skipping training.")

    logger.info("ML: All models ready.")


def retrain_all():
    """Force-retrain all models (useful for admin endpoints)."""
    _train_phishing_model()
    _train_upi_model()
    _train_network_model()
    logger.info("ML: All models retrained.")
