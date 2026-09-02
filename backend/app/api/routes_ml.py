"""
ML API routes for Vanguard SME Security Suite.

Endpoints:
  POST /api/ml/predict         — Run ML prediction for a given scan type + features
  GET  /api/ml/model-info      — Metadata about loaded models
  POST /api/ml/retrain         — Force retrain all models (Admin only)
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List, Optional

from app.core.security import get_current_user
from app.core.rbac import require_role
from app.ml.feature_extractors import (
    extract_phishing_features,
    extract_upi_features,
    extract_network_features,
)
from app.ml.predictor import (
    predict_phishing,
    predict_upi_fraud,
    predict_network_anomaly,
    _ModelCache,
)
from app.ml.trainer import (
    retrain_all,
    PHISHING_MODEL_PATH,
    UPI_MODEL_PATH,
    NETWORK_MODEL_PATH,
)

router = APIRouter(prefix="/api/ml", tags=["ML"])


# ── Request / Response schemas ────────────────────────────────────────────────

class MLPredictRequest(BaseModel):
    scan_type: str          # "phishing_email" | "upi" | "network"
    features: Dict[str, Any]  # Raw feature dict (see feature_extractors.py)


class FeatureImportanceItem(BaseModel):
    feature: str
    importance: float


class MLPredictResponse(BaseModel):
    label: str
    confidence: float
    confidence_pct: int
    explanation: str
    feature_importances: List[FeatureImportanceItem]
    model_name: str
    raw_scores: Optional[Dict[str, float]] = None


class ModelInfoResponse(BaseModel):
    models: List[Dict[str, Any]]


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/predict", response_model=MLPredictResponse)
async def ml_predict(
    body: MLPredictRequest,
    current_user: str = Depends(get_current_user),
):
    """
    Run an ML prediction.

    scan_type values:
      - "phishing_email"  → RandomForest phishing classifier
      - "upi"             → GradientBoosting UPI fraud scorer
      - "network"         → IsolationForest network anomaly detector

    The `features` dict should match what the corresponding service returns
    (or can be a manually crafted feature dict for the ML Predictor page).
    """
    scan_type = body.scan_type.lower().strip()

    try:
        if scan_type == "phishing_email":
            # features may be a raw scan result dict or a pre-extracted feature dict
            extracted = _coerce_phishing_features(body.features)
            result = predict_phishing(extracted)

        elif scan_type == "upi":
            extracted = _coerce_upi_features(body.features)
            result = predict_upi_fraud(extracted)

        elif scan_type == "network":
            extracted = _coerce_network_features(body.features)
            result = predict_network_anomaly(extracted)

        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown scan_type '{scan_type}'. Valid values: phishing_email, upi, network."
            )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"ML prediction failed: {str(exc)}")

    return MLPredictResponse(
        label=result.label,
        confidence=result.confidence,
        confidence_pct=result.confidence_pct,
        explanation=result.explanation,
        feature_importances=[
            FeatureImportanceItem(feature=fi["feature"], importance=fi["importance"])
            for fi in result.feature_importances
        ],
        model_name=result.model_name,
        raw_scores=result.raw_scores,
    )


@router.get("/model-info", response_model=ModelInfoResponse)
async def model_info(current_user: str = Depends(get_current_user)):
    """Return metadata about all loaded ML models."""
    import os, datetime

    def _file_info(path):
        if path.exists():
            stat = path.stat()
            return {
                "exists": True,
                "size_kb": round(stat.st_size / 1024, 1),
                "trained_at": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }
        return {"exists": False, "size_kb": 0, "trained_at": None}

    models = [
        {
            "name": "RandomForest Phishing Classifier",
            "scan_type": "phishing_email",
            "algorithm": "RandomForestClassifier",
            "labels": ["CLEAN", "SUSPICIOUS", "PHISHING"],
            "features": ["spf_fail", "dkim_fail", "dmarc_fail", "domain_mismatch", "spoofed", "reply_to_mismatch"],
            "training_samples": 1200,
            **_file_info(PHISHING_MODEL_PATH),
        },
        {
            "name": "GradientBoosting UPI Fraud Scorer",
            "scan_type": "upi",
            "algorithm": "GradientBoostingClassifier",
            "labels": ["SAFE", "SUSPICIOUS", "FRAUDULENT"],
            "features": ["handle_length", "has_numbers", "digit_ratio", "suspicious_keyword_score", "brand_keyword_score", "handle_entropy"],
            "training_samples": 1200,
            **_file_info(UPI_MODEL_PATH),
        },
        {
            "name": "IsolationForest Network Anomaly Detector",
            "scan_type": "network",
            "algorithm": "IsolationForest",
            "labels": ["NORMAL", "ANOMALOUS"],
            "features": ["num_open_ports", "has_critical", "has_rdp", "has_smb", "has_db", "has_ftp", "has_telnet"],
            "training_samples": 1000,
            **_file_info(NETWORK_MODEL_PATH),
        },
    ]

    return ModelInfoResponse(models=models)


@router.post("/retrain")
async def retrain_models(
    current_user: str = Depends(get_current_user),
    _: None = Depends(require_role(["Admin"])),
):
    """Force retrain all ML models. Admin only."""
    try:
        retrain_all()
        _ModelCache.invalidate()
        return {"status": "success", "message": "All ML models retrained successfully."}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Retraining failed: {str(exc)}")


# ── Feature coercers — accept both raw scan result and pre-extracted feature dicts ──

def _coerce_phishing_features(data: Dict[str, Any]) -> Dict[str, float]:
    """
    Accepts either:
      - A raw email_analyser result dict (has spf_status, dkim_status, etc.)
      - A pre-extracted feature dict (has spf_fail, dkim_fail, etc.)
    """
    if "spf_fail" in data:
        return {k: float(v) for k, v in data.items()}
    return extract_phishing_features(data)


def _coerce_upi_features(data: Dict[str, Any]) -> Dict[str, float]:
    if "handle_length" in data:
        return {k: float(v) for k, v in data.items()}
    upi_id = data.get("upi_id") or data.get("target") or ""
    return extract_upi_features(upi_id)


def _coerce_network_features(data: Dict[str, Any]) -> Dict[str, float]:
    if "num_open_ports" in data:
        return {k: float(v) for k, v in data.items()}
    return extract_network_features(data)
