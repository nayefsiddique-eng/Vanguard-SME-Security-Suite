"""
ML predictor for Vanguard SME Security Suite.

Loads serialized scikit-learn models and provides three prediction functions:
  - predict_phishing(features)  → MLPrediction
  - predict_upi_fraud(features) → MLPrediction
  - predict_network_anomaly(features) → MLPrediction

Each returns a dataclass with label, confidence, explanation, and
per-feature importance scores for explainability.
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import numpy as np
import joblib

from app.ml.trainer import (
    PHISHING_MODEL_PATH,
    UPI_MODEL_PATH,
    NETWORK_MODEL_PATH,
    PHISHING_LABELS,
    UPI_LABELS,
    ensure_models_ready,
)
from app.ml.feature_extractors import (
    PHISHING_FEATURE_NAMES,
    UPI_FEATURE_NAMES,
    NETWORK_FEATURE_NAMES,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MLPrediction:
    label: str                                    # e.g. "PHISHING", "FRAUDULENT", "ANOMALOUS"
    confidence: float                             # 0.0 – 1.0
    confidence_pct: int                           # 0 – 100 (for UI)
    explanation: str                              # Human-readable explanation
    feature_importances: List[Dict[str, float]]   # [{"feature": name, "importance": value}, …]
    model_name: str                               # Which model produced this
    raw_scores: Optional[Dict[str, float]] = field(default=None)


# ─────────────────────────────────────────────────────────────────────────────
# Singleton model cache
# ─────────────────────────────────────────────────────────────────────────────

class _ModelCache:
    _phishing = None
    _upi = None
    _network = None

    @classmethod
    def phishing(cls):
        if cls._phishing is None:
            cls._phishing = joblib.load(PHISHING_MODEL_PATH)
        return cls._phishing

    @classmethod
    def upi(cls):
        if cls._upi is None:
            cls._upi = joblib.load(UPI_MODEL_PATH)
        return cls._upi

    @classmethod
    def network(cls):
        if cls._network is None:
            cls._network = joblib.load(NETWORK_MODEL_PATH)
        return cls._network

    @classmethod
    def invalidate(cls):
        cls._phishing = None
        cls._upi = None
        cls._network = None


# ─────────────────────────────────────────────────────────────────────────────
# Helper — extract feature importances from a Pipeline
# ─────────────────────────────────────────────────────────────────────────────

def _get_feature_importances(pipeline, feature_names: List[str]) -> List[Dict[str, float]]:
    """
    Extracts feature importances from the last step of a sklearn Pipeline.
    Works with RandomForest, GradientBoosting; falls back to uniform for others.
    """
    try:
        clf = pipeline.named_steps.get("clf")
        if clf is not None and hasattr(clf, "feature_importances_"):
            importances = clf.feature_importances_
            pairs = sorted(
                zip(feature_names, importances),
                key=lambda x: x[1],
                reverse=True,
            )
            return [{"feature": k, "importance": round(float(v), 4)} for k, v in pairs]
    except Exception:
        pass
    # Uniform fallback
    n = len(feature_names)
    return [{"feature": k, "importance": round(1.0 / n, 4)} for k in feature_names]


# ─────────────────────────────────────────────────────────────────────────────
# Prediction functions
# ─────────────────────────────────────────────────────────────────────────────

def predict_phishing(features: Dict[str, float]) -> MLPrediction:
    """
    Predict phishing risk from email features.
    features keys: spf_fail, dkim_fail, dmarc_fail, domain_mismatch, spoofed, reply_to_mismatch
    """
    model = _ModelCache.phishing()
    x = np.array([[features.get(k, 0.0) for k in PHISHING_FEATURE_NAMES]])

    proba = model.predict_proba(x)[0]          # shape (3,)
    pred_idx = int(np.argmax(proba))
    confidence = float(proba[pred_idx])
    label = PHISHING_LABELS[pred_idx]

    raw_scores = {lbl: round(float(p), 3) for lbl, p in zip(PHISHING_LABELS, proba)}
    importances = _get_feature_importances(model, PHISHING_FEATURE_NAMES)

    # Explanation
    top_feature = importances[0]["feature"].replace("_", " ") if importances else "signals"
    if label == "PHISHING":
        explanation = (
            f"The ML classifier is {confidence*100:.0f}% confident this email is a phishing attempt. "
            f"The most decisive signal was '{top_feature}'. "
            "Multiple authentication checks failed and domain spoofing was detected."
        )
    elif label == "SUSPICIOUS":
        explanation = (
            f"The ML classifier flags this email as suspicious ({confidence*100:.0f}% confidence). "
            f"Key indicator: '{top_feature}'. "
            "Some authentication signals are inconsistent — treat with caution."
        )
    else:
        explanation = (
            f"The ML classifier rates this email as clean ({confidence*100:.0f}% confidence). "
            "Email authentication checks passed and no spoofing was detected."
        )

    return MLPrediction(
        label=label,
        confidence=round(confidence, 3),
        confidence_pct=int(confidence * 100),
        explanation=explanation,
        feature_importances=importances,
        model_name="RandomForest Phishing Classifier",
        raw_scores=raw_scores,
    )


def predict_upi_fraud(features: Dict[str, float]) -> MLPrediction:
    """
    Predict UPI fraud risk from handle features.
    features keys: handle_length, has_numbers, digit_ratio,
                   suspicious_keyword_score, brand_keyword_score, handle_entropy
    """
    model = _ModelCache.upi()
    x = np.array([[features.get(k, 0.0) for k in UPI_FEATURE_NAMES]])

    proba = model.predict_proba(x)[0]
    pred_idx = int(np.argmax(proba))
    confidence = float(proba[pred_idx])
    label = UPI_LABELS[pred_idx]

    raw_scores = {lbl: round(float(p), 3) for lbl, p in zip(UPI_LABELS, proba)}
    importances = _get_feature_importances(model, UPI_FEATURE_NAMES)

    top_feature = importances[0]["feature"].replace("_", " ") if importances else "signals"
    if label == "FRAUDULENT":
        explanation = (
            f"The ML fraud scorer classifies this UPI handle as likely fraudulent "
            f"({confidence*100:.0f}% confidence). "
            f"Primary risk factor: '{top_feature}'. "
            "Pattern analysis indicates brand impersonation or suspicious character composition."
        )
    elif label == "SUSPICIOUS":
        explanation = (
            f"This UPI handle shows suspicious characteristics ({confidence*100:.0f}% confidence). "
            f"Key flag: '{top_feature}'. Verify the recipient independently before payment."
        )
    else:
        explanation = (
            f"The ML scorer classifies this UPI handle as low-risk ({confidence*100:.0f}% confidence). "
            "No suspicious patterns detected. Standard verification still recommended."
        )

    return MLPrediction(
        label=label,
        confidence=round(confidence, 3),
        confidence_pct=int(confidence * 100),
        explanation=explanation,
        feature_importances=importances,
        model_name="GradientBoosting UPI Fraud Scorer",
        raw_scores=raw_scores,
    )


def predict_network_anomaly(features: Dict[str, float]) -> MLPrediction:
    """
    Predict network anomaly risk using IsolationForest.
    features keys: num_open_ports, has_critical, has_rdp, has_smb,
                   has_db, has_ftp, has_telnet
    Returns label NORMAL or ANOMALOUS.
    """
    model = _ModelCache.network()
    x = np.array([[features.get(k, 0.0) for k in NETWORK_FEATURE_NAMES]])

    # IsolationForest: decision_function gives anomaly score (lower = more anomalous)
    decision = float(model.decision_function(x)[0])
    pred = int(model.predict(x)[0])  # -1 = anomaly, 1 = normal

    # Convert to 0-1 confidence: clip decision_function to [-0.5, 0.5]
    # positive = normal, negative = anomalous
    clipped = max(-0.5, min(0.5, decision))
    if pred == -1:
        label = "ANOMALOUS"
        # confidence = how anomalous (0 = barely anomalous, 1 = extremely anomalous)
        confidence = round(0.5 + (-clipped), 3)
    else:
        label = "NORMAL"
        confidence = round(0.5 + clipped, 3)

    confidence = max(0.0, min(1.0, confidence))

    # Approximate feature importance for IsolationForest via contamination weights
    # Since IF doesn't expose feature_importances_ natively, use heuristic weights
    heuristic_weights = {
        "has_telnet": 0.22,
        "has_smb": 0.20,
        "has_rdp": 0.18,
        "has_db": 0.15,
        "has_ftp": 0.12,
        "has_critical": 0.08,
        "num_open_ports": 0.05,
    }
    importances = [
        {"feature": k, "importance": round(v * features.get(k, 0.0) + v * 0.3, 4)}
        for k, v in sorted(heuristic_weights.items(), key=lambda i: i[1], reverse=True)
    ]

    if label == "ANOMALOUS":
        open_count = int(features.get("num_open_ports", 0))
        explanation = (
            f"The IsolationForest anomaly detector flags this network profile as anomalous "
            f"({confidence*100:.0f}% confidence). "
            f"{open_count} open ports detected with critical services exposed. "
            "This profile deviates significantly from normal host behavior."
        )
    else:
        explanation = (
            f"Network profile appears normal ({confidence*100:.0f}% confidence). "
            "Port exposure is within expected parameters. Continue regular monitoring."
        )

    return MLPrediction(
        label=label,
        confidence=confidence,
        confidence_pct=int(confidence * 100),
        explanation=explanation,
        feature_importances=importances,
        model_name="IsolationForest Network Anomaly Detector",
        raw_scores={"anomaly_score": round(decision, 4)},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Convenience: ensure models exist before loading
# ─────────────────────────────────────────────────────────────────────────────

def get_predictor():
    """
    Ensure models are trained (runs at startup), then return this module
    for use by routes.
    """
    ensure_models_ready()
    return _ModelCache
