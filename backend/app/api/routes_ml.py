"""
ML API routes for Vanguard SME Security Suite.

Endpoints:
  POST /api/ml/predict         — Run standardized ML prediction for a given scan type + features
  GET  /api/ml/model-info      — Real metadata & evaluation metrics about loaded models
  POST /api/ml/retrain         — Force retrain all models (Admin only)
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import datetime

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
    get_model_metadata,
    ensure_models_ready,
    PHISHING_MODEL_PATH,
    UPI_MODEL_PATH,
    NETWORK_MODEL_PATH,
)

router = APIRouter(prefix="/api/ml", tags=["ML"])


# ── Request / Response schemas ────────────────────────────────────────────────

class MLPredictRequest(BaseModel):
    scan_type: str          # "phishing_email" | "upi" | "network"
    features: Dict[str, Any]


class MLFeatureItemResponse(BaseModel):
    name: str
    value: float
    importance: Optional[float] = 0.0
    contribution: Optional[str] = "neutral"
    description: Optional[str] = None


class FeatureImportanceItem(BaseModel):
    feature: str
    importance: float


class MLPredictResponse(BaseModel):
    model: str
    model_version: str
    task: str
    prediction: str
    score: float
    score_type: str
    risk_level: str
    explanation: str
    features: List[MLFeatureItemResponse]
    model_name: str
    label: str
    confidence: float
    confidence_pct: int
    feature_importances: List[FeatureImportanceItem]
    raw_scores: Optional[Dict[str, Any]] = None


class ModelInfoResponse(BaseModel):
    models: List[Dict[str, Any]]


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/predict", response_model=MLPredictResponse)
async def ml_predict(
    body: MLPredictRequest,
    current_user: str = Depends(get_current_user),
):
    """
    Run an ML prediction returning standardized output.
    """
    scan_type = body.scan_type.lower().strip()

    try:
        if scan_type in ("phishing_email", "email", "phishing"):
            extracted = _coerce_phishing_features(body.features)
            pred = predict_phishing(extracted)

        elif scan_type in ("upi", "upi_fraud"):
            extracted = _coerce_upi_features(body.features)
            pred = predict_upi_fraud(extracted)

        elif scan_type in ("network", "network_anomaly", "nmap"):
            extracted = _coerce_network_features(body.features)
            pred = predict_network_anomaly(extracted)

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
        model=pred.model,
        model_version=pred.model_version,
        task=pred.task,
        prediction=pred.prediction,
        score=pred.score,
        score_type=pred.score_type,
        risk_level=pred.risk_level,
        explanation=pred.explanation,
        features=[
            MLFeatureItemResponse(
                name=f["name"],
                value=f["value"],
                importance=f.get("importance", 0.0),
                contribution=f.get("contribution", "neutral"),
                description=f.get("description"),
            )
            for f in pred.features
        ],
        model_name=pred.model_name,
        label=pred.label,
        confidence=pred.confidence,
        confidence_pct=pred.confidence_pct,
        feature_importances=[
            FeatureImportanceItem(feature=fi["feature"], importance=fi["importance"])
            for fi in pred.feature_importances
        ],
        raw_scores=pred.raw_scores,
    )


@router.get("/model-info", response_model=ModelInfoResponse)
async def model_info(current_user: str = Depends(get_current_user)):
    """Return genuine metadata & evaluation metrics about all loaded ML models."""
    ensure_models_ready()
    saved_meta = get_model_metadata()

    def _file_info(path):
        if path.exists():
            stat = path.stat()
            return {
                "exists": True,
                "size_kb": round(stat.st_size / 1024, 1),
                "last_modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat() + "Z",
            }
        return {"exists": False, "size_kb": 0, "last_modified": None}

    phishing_metrics = saved_meta.get("phishing", {})
    upi_metrics = saved_meta.get("upi", {})
    network_metrics = saved_meta.get("network", {})

    models = [
        {
            "name": "RandomForest Phishing Classifier",
            "scan_type": "phishing_email",
            "algorithm": "RandomForestClassifier",
            "version": "1.0",
            "score_type": "probability",
            "labels": ["CLEAN", "SUSPICIOUS", "PHISHING"],
            "features": ["spf_fail", "dkim_fail", "dmarc_fail", "domain_mismatch", "spoofed", "reply_to_mismatch"],
            "metrics": {
                "accuracy": phishing_metrics.get("accuracy"),
                "precision": phishing_metrics.get("precision"),
                "recall": phishing_metrics.get("recall"),
                "f1_score": phishing_metrics.get("f1_score"),
                "confusion_matrix": phishing_metrics.get("confusion_matrix"),
                "training_samples": phishing_metrics.get("training_samples", 960),
                "test_samples": phishing_metrics.get("test_samples", 240),
            },
            "dataset": phishing_metrics.get("dataset_metadata", {
                "dataset_type": "Synthetic Prototype Dataset",
                "notes": "Generated from representative email authentication fail rates"
            }),
            **_file_info(PHISHING_MODEL_PATH),
        },
        {
            "name": "GradientBoosting UPI Fraud Scorer",
            "scan_type": "upi",
            "algorithm": "GradientBoostingClassifier",
            "version": "1.0",
            "score_type": "probability",
            "labels": ["SAFE", "SUSPICIOUS", "FRAUDULENT"],
            "features": ["handle_length", "has_numbers", "digit_ratio", "suspicious_keyword_score", "brand_keyword_score", "handle_entropy"],
            "metrics": {
                "accuracy": upi_metrics.get("accuracy"),
                "precision": upi_metrics.get("precision"),
                "recall": upi_metrics.get("recall"),
                "f1_score": upi_metrics.get("f1_score"),
                "confusion_matrix": upi_metrics.get("confusion_matrix"),
                "training_samples": upi_metrics.get("training_samples", 960),
                "test_samples": upi_metrics.get("test_samples", 240),
            },
            "dataset": upi_metrics.get("dataset_metadata", {
                "dataset_type": "Synthetic Prototype Dataset",
                "notes": "Simulated handle length, keyword flags, and entropy"
            }),
            **_file_info(UPI_MODEL_PATH),
        },
        {
            "name": "IsolationForest Network Anomaly Detector",
            "scan_type": "network",
            "algorithm": "IsolationForest",
            "version": "1.0",
            "score_type": "anomaly_score",
            "labels": ["NORMAL", "ANOMALOUS"],
            "features": ["num_open_ports", "has_critical", "has_rdp", "has_smb", "has_db", "has_ftp", "has_telnet"],
            "metrics": {
                "precision": network_metrics.get("precision"),
                "recall": network_metrics.get("recall"),
                "f1_score": network_metrics.get("f1_score"),
                "false_positive_rate": network_metrics.get("false_positive_rate"),
                "confusion_matrix": network_metrics.get("confusion_matrix"),
                "training_samples": network_metrics.get("training_samples", 750),
                "test_samples": network_metrics.get("test_samples", 250),
            },
            "dataset": network_metrics.get("dataset_metadata", {
                "dataset_type": "Synthetic Prototype Dataset",
                "notes": "Trained unsupervised on normal port baseline; evaluated on held-out test data"
            }),
            **_file_info(NETWORK_MODEL_PATH),
        },
    ]

    return ModelInfoResponse(models=models)


@router.post("/retrain")
async def retrain_models(
    current_user: str = Depends(get_current_user),
    _: None = Depends(require_role(["Admin"])),
):
    """Force retrain all ML models with fresh evaluation metrics. Admin only."""
    try:
        new_metrics = retrain_all()
        _ModelCache.invalidate()
        return {
            "status": "success",
            "message": "All ML models retrained and evaluated successfully.",
            "metrics": new_metrics,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Retraining failed: {str(exc)}")


# ── Feature coercers ─────────────────────────────────────────────────────────

def _coerce_phishing_features(data: Dict[str, Any]) -> Dict[str, float]:
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
