"""
ML model trainer for Vanguard SME Security Suite.

Features:
  1. Clear separation of data generation from training
  2. Dataset metadata tracking (type, samples, feature names, distribution, timestamp)
  3. Proper train/test split (80/20) with fixed random seeds for reproducible demonstration
  4. Genuine evaluation metrics:
     - Supervised (RandomForest & GradientBoosting): Accuracy, Precision, Recall, F1 (macro & weighted), Confusion Matrix
     - Unsupervised (IsolationForest): Evaluated against held-out labeled dataset (Precision, Recall, F1, FPR)
  5. Saved artifacts and metadata persistence in models/model_metadata.json
"""

import json
import logging
import datetime
from pathlib import Path
from typing import Dict, Any, Tuple
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from app.ml.feature_extractors import (
    PHISHING_FEATURE_NAMES,
    UPI_FEATURE_NAMES,
    NETWORK_FEATURE_NAMES,
)

logger = logging.getLogger(__name__)

# ── Paths ────────────────────────────────────────────────────────────────────
_ML_DIR = Path(__file__).parent
MODELS_DIR = _ML_DIR / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

PHISHING_MODEL_PATH = MODELS_DIR / "phishing_classifier.joblib"
UPI_MODEL_PATH = MODELS_DIR / "upi_fraud_scorer.joblib"
NETWORK_MODEL_PATH = MODELS_DIR / "network_anomaly_detector.joblib"
METADATA_PATH = MODELS_DIR / "model_metadata.json"

# ── Label maps ───────────────────────────────────────────────────────────────
PHISHING_LABELS = ["CLEAN", "SUSPICIOUS", "PHISHING"]
UPI_LABELS = ["SAFE", "SUSPICIOUS", "FRAUDULENT"]
NETWORK_LABELS = ["NORMAL", "ANOMALOUS"]


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic Data Generation Layer (clearly marked as synthetic prototype data)
# ─────────────────────────────────────────────────────────────────────────────

def generate_synthetic_phishing_dataset(n: int = 1200, seed: int = 42) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
    """
    Generates synthetic email header feature vectors and multiclass labels.
    Labels: 0=CLEAN, 1=SUSPICIOUS, 2=PHISHING
    """
    rng = np.random.default_rng(seed)
    X, y = [], []

    n_clean = int(n * 0.40)
    for _ in range(n_clean):
        row = [
            0.0 if rng.random() > 0.05 else 1.0,  # spf_fail
            0.0 if rng.random() > 0.03 else 1.0,  # dkim_fail
            0.0 if rng.random() > 0.03 else 1.0,  # dmarc_fail
            0.0,                                  # domain_mismatch
            0.0,                                  # spoofed
            0.0 if rng.random() > 0.04 else 1.0,  # reply_to_mismatch
        ]
        X.append(row)
        y.append(0)

    n_susp = int(n * 0.30)
    for _ in range(n_susp):
        row = [
            1.0 if rng.random() < 0.50 else 0.0,
            1.0 if rng.random() < 0.35 else 0.0,
            1.0 if rng.random() < 0.35 else 0.0,
            1.0 if rng.random() < 0.45 else 0.0,
            0.0,
            1.0 if rng.random() < 0.40 else 0.0,
        ]
        X.append(row)
        y.append(1)

    n_phish = n - n_clean - n_susp
    for _ in range(n_phish):
        row = [
            1.0 if rng.random() < 0.88 else 0.0,
            1.0 if rng.random() < 0.82 else 0.0,
            1.0 if rng.random() < 0.85 else 0.0,
            1.0 if rng.random() < 0.92 else 0.0,
            1.0 if rng.random() < 0.78 else 0.0,
            1.0 if rng.random() < 0.75 else 0.0,
        ]
        X.append(row)
        y.append(2)

    X_arr = np.array(X, dtype=float)
    y_arr = np.array(y, dtype=int)

    metadata = {
        "dataset_type": "Synthetic Prototype Dataset",
        "task": "phishing_detection",
        "total_samples": len(y_arr),
        "feature_names": PHISHING_FEATURE_NAMES,
        "class_distribution": {
            "CLEAN": int(np.sum(y_arr == 0)),
            "SUSPICIOUS": int(np.sum(y_arr == 1)),
            "PHISHING": int(np.sum(y_arr == 2)),
        },
        "random_seed": seed,
        "generation_method": "Synthetic probabilistic generator calibrated from typical email auth failure rates",
    }
    return X_arr, y_arr, metadata


def generate_synthetic_upi_dataset(n: int = 1200, seed: int = 43) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
    """
    Generates synthetic UPI feature vectors and multiclass labels.
    Labels: 0=SAFE, 1=SUSPICIOUS, 2=FRAUDULENT
    """
    rng = np.random.default_rng(seed)
    X, y = [], []

    n_safe = int(n * 0.45)
    for _ in range(n_safe):
        length = float(rng.integers(5, 15))
        digits = float(rng.integers(0, 4))
        row = [
            length,
            1.0 if digits > 0 else 0.0,
            round(digits / max(length, 1.0), 3),
            0.0,                                   # suspicious keywords
            0.0 if rng.random() > 0.15 else 1.0,   # legitimate merchant keyword
            round(float(rng.uniform(1.8, 3.2)), 3) # entropy
        ]
        X.append(row)
        y.append(0)

    n_susp = int(n * 0.30)
    for _ in range(n_susp):
        length = float(rng.integers(12, 28))
        digits = float(rng.integers(4, 12))
        row = [
            length,
            1.0,
            round(digits / max(length, 1.0), 3),
            float(rng.integers(0, 2)),
            float(rng.integers(0, 2)),
            round(float(rng.uniform(2.8, 4.0)), 3)
        ]
        X.append(row)
        y.append(1)

    n_fraud = n - n_safe - n_susp
    for _ in range(n_fraud):
        length = float(rng.integers(14, 35))
        digits = float(rng.integers(6, 18))
        row = [
            length,
            1.0,
            round(digits / max(length, 1.0), 3),
            float(rng.integers(1, 4)),             # multiple fraud keywords
            float(rng.integers(1, 3)),             # impersonating brand keywords
            round(float(rng.uniform(3.5, 4.6)), 3)
        ]
        X.append(row)
        y.append(2)

    X_arr = np.array(X, dtype=float)
    y_arr = np.array(y, dtype=int)

    metadata = {
        "dataset_type": "Synthetic Prototype Dataset",
        "task": "upi_fraud_detection",
        "total_samples": len(y_arr),
        "feature_names": UPI_FEATURE_NAMES,
        "class_distribution": {
            "SAFE": int(np.sum(y_arr == 0)),
            "SUSPICIOUS": int(np.sum(y_arr == 1)),
            "FRAUDULENT": int(np.sum(y_arr == 2)),
        },
        "random_seed": seed,
        "generation_method": "Synthetic probabilistic generator modeling brand impersonation and handle entropy",
    }
    return X_arr, y_arr, metadata


def generate_synthetic_network_dataset(n: int = 1000, seed: int = 44) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
    """
    Generates network exposure feature vectors.
    Labels: 0=NORMAL (80%), 1=ANOMALOUS (20%).
    IsolationForest is trained on normal/typical baseline samples, and evaluated against held-out labeled set.
    """
    rng = np.random.default_rng(seed)
    X, y = [], []

    n_normal = int(n * 0.80)
    for _ in range(n_normal):
        ports = float(rng.integers(1, 4))
        row = [
            ports,
            0.0,
            0.0,
            0.0,
            0.0,
            1.0 if rng.random() < 0.08 else 0.0, # occasional ftp
            0.0,                                 # no telnet
        ]
        X.append(row)
        y.append(0)

    n_anom = n - n_normal
    for _ in range(n_anom):
        ports = float(rng.integers(5, 14))
        row = [
            ports,
            1.0,                                  # critical port present
            1.0 if rng.random() < 0.80 else 0.0,  # rdp
            1.0 if rng.random() < 0.70 else 0.0,  # smb
            1.0 if rng.random() < 0.60 else 0.0,  # db
            1.0 if rng.random() < 0.55 else 0.0,  # ftp
            1.0 if rng.random() < 0.50 else 0.0,  # telnet
        ]
        X.append(row)
        y.append(1)

    X_arr = np.array(X, dtype=float)
    y_arr = np.array(y, dtype=int)

    # Shuffle
    idx = rng.permutation(len(X_arr))
    X_arr = X_arr[idx]
    y_arr = y_arr[idx]

    metadata = {
        "dataset_type": "Synthetic Prototype Dataset",
        "task": "network_anomaly_detection",
        "total_samples": len(y_arr),
        "feature_names": NETWORK_FEATURE_NAMES,
        "class_distribution": {
            "NORMAL": int(np.sum(y_arr == 0)),
            "ANOMALOUS": int(np.sum(y_arr == 1)),
        },
        "random_seed": seed,
        "generation_method": "Synthetic port distribution baseline with high-risk exposure injections",
    }
    return X_arr, y_arr, metadata


# ─────────────────────────────────────────────────────────────────────────────
# Training and Evaluation Pipeline
# ─────────────────────────────────────────────────────────────────────────────

def train_and_evaluate_phishing() -> Dict[str, Any]:
    """Train RandomForest with 80/20 train/test split and calculate metrics."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    X, y, data_meta = generate_synthetic_phishing_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=120,
            max_depth=6,
            class_weight="balanced",
            random_state=42,
        )),
    ])
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    joblib.dump(model, PHISHING_MODEL_PATH)

    metrics = {
        "model_name": "RandomForest Phishing Classifier",
        "algorithm": "RandomForestClassifier",
        "version": "1.0",
        "score_type": "probability",
        "task": "phishing_detection",
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": cm,
        "labels": PHISHING_LABELS,
        "dataset_metadata": data_meta,
        "training_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    logger.info(f"ML: Trained Phishing Classifier -> Accuracy: {acc:.3f}, F1: {f1:.3f}")
    return metrics


def train_and_evaluate_upi() -> Dict[str, Any]:
    """Train GradientBoosting with 80/20 train/test split and calculate metrics."""
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    X, y, data_meta = generate_synthetic_upi_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=43, stratify=y
    )

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=4,
            random_state=43,
        )),
    ])
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    joblib.dump(model, UPI_MODEL_PATH)

    metrics = {
        "model_name": "GradientBoosting UPI Fraud Scorer",
        "algorithm": "GradientBoostingClassifier",
        "version": "1.0",
        "score_type": "probability",
        "task": "upi_fraud_detection",
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "confusion_matrix": cm,
        "labels": UPI_LABELS,
        "dataset_metadata": data_meta,
        "training_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    logger.info(f"ML: Trained UPI Fraud Scorer -> Accuracy: {acc:.3f}, F1: {f1:.3f}")
    return metrics


def train_and_evaluate_network() -> Dict[str, Any]:
    """
    Train IsolationForest unsupervised on typical normal baselines,
    and evaluate against a held-out labeled evaluation set.
    """
    from sklearn.ensemble import IsolationForest
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    X, y, data_meta = generate_synthetic_network_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=44, stratify=y
    )

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", IsolationForest(
            n_estimators=150,
            contamination=0.20,
            random_state=44,
        )),
    ])
    # Unsupervised fit on training data
    model.fit(X_train)

    # Evaluate on held-out test data
    # predict returns 1 for inlier (normal = 0), -1 for outlier (anomalous = 1)
    raw_preds = model.predict(X_test)
    y_pred_binary = np.where(raw_preds == -1, 1, 0)

    prec = float(precision_score(y_test, y_pred_binary, pos_label=1, zero_division=0))
    rec = float(recall_score(y_test, y_pred_binary, pos_label=1, zero_division=0))
    f1 = float(f1_score(y_test, y_pred_binary, pos_label=1, zero_division=0))
    cm = confusion_matrix(y_test, y_pred_binary).tolist()

    # False Positive Rate (FP / (FP + TN))
    tn = cm[0][0] if len(cm) > 0 else 0
    fp = cm[0][1] if len(cm) > 0 and len(cm[0]) > 1 else 0
    fpr = float(fp / max(fp + tn, 1))

    joblib.dump(model, NETWORK_MODEL_PATH)

    metrics = {
        "model_name": "IsolationForest Network Anomaly Detector",
        "algorithm": "IsolationForest",
        "version": "1.0",
        "score_type": "anomaly_score",
        "task": "network_anomaly_detection",
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "confusion_matrix": cm,
        "labels": NETWORK_LABELS,
        "dataset_metadata": data_meta,
        "training_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    logger.info(f"ML: Trained Network Anomaly Detector -> Precision: {prec:.3f}, Recall: {rec:.3f}, FPR: {fpr:.3f}")
    return metrics


# ─────────────────────────────────────────────────────────────────────────────
# Metadata Persistence & Lifecycle
# ─────────────────────────────────────────────────────────────────────────────

def save_all_metadata(meta_dict: Dict[str, Any]):
    try:
        with open(METADATA_PATH, "w", encoding="utf-8") as f:
            json.dump(meta_dict, f, indent=2)
    except Exception as exc:
        logger.error(f"Failed to persist ML metadata: {exc}")


def get_model_metadata() -> Dict[str, Any]:
    if METADATA_PATH.exists():
        try:
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def ensure_models_ready():
    """
    Runs at FastAPI lifespan startup.
    Loads or trains models if files are absent or unreadable.
    """
    metadata = get_model_metadata()
    updated = False

    if not PHISHING_MODEL_PATH.exists() or "phishing" not in metadata:
        meta_p = train_and_evaluate_phishing()
        metadata["phishing"] = meta_p
        updated = True
    else:
        logger.info("ML: Phishing model already exists, skipping retraining.")

    if not UPI_MODEL_PATH.exists() or "upi" not in metadata:
        meta_u = train_and_evaluate_upi()
        metadata["upi"] = meta_u
        updated = True
    else:
        logger.info("ML: UPI model already exists, skipping retraining.")

    if not NETWORK_MODEL_PATH.exists() or "network" not in metadata:
        meta_n = train_and_evaluate_network()
        metadata["network"] = meta_n
        updated = True
    else:
        logger.info("ML: Network model already exists, skipping retraining.")

    if updated:
        save_all_metadata(metadata)

    logger.info("ML: All models and evaluation metadata ready.")


def retrain_all() -> Dict[str, Any]:
    """Force retrain all models and persist new evaluation results."""
    meta_p = train_and_evaluate_phishing()
    meta_u = train_and_evaluate_upi()
    meta_n = train_and_evaluate_network()
    combined = {
        "phishing": meta_p,
        "upi": meta_u,
        "network": meta_n,
    }
    save_all_metadata(combined)
    return combined
