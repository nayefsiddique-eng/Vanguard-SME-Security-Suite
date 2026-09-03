from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import List, Optional, Dict, Any
import re

class DeviceData(BaseModel):
    device_name: str
    password_length: int
    failed_logins: int
    outdated_software: bool
    suspicious_ip: bool
    antivirus_enabled: bool
    open_ports: int

class RiskResponse(BaseModel):
    device_name: str
    risk_score: int
    risk_level: str
    issues_found: List[str]
    recommendations: List[str]

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=4)

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class URLScanRequest(BaseModel):
    url: str
    email: Optional[str] = None

    @field_validator("url")
    def validate_url(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        return v

class NetworkScanRequest(BaseModel):
    target: str
    email: Optional[str] = None

    @field_validator("target")
    def validate_target(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")
        # Ensure target is valid IP or valid domain name without shell injection characters
        ip_pattern = r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))*$"
        if not re.match(ip_pattern, v) or len(v) > 253:
            raise ValueError("Invalid target format. Must be a valid IP address or hostname without special shell characters.")
        return v

class EmailScanRequest(BaseModel):
    header: str
    email: Optional[str] = None

    @field_validator("header")
    def validate_header(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Email header cannot be empty")
        if len(v) > 100000:
            raise ValueError("Email header exceeds maximum permissible length (100KB)")
        return v

class UPIScanRequest(BaseModel):
    upi_id: str
    email: Optional[str] = None

    @field_validator("upi_id")
    def validate_upi(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("UPI ID cannot be empty")
        if "@" not in v:
            raise ValueError("Invalid UPI ID format. Must contain '@'")
        upi_pattern = r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$"
        if not re.match(upi_pattern, v):
            raise ValueError("Invalid UPI handle syntax. Expected format: handle@bank")
        return v

# ── ML Schemas ───────────────────────────────────────────────────────────────

class MLFeatureItem(BaseModel):
    name: str
    value: float
    importance: Optional[float] = 0.0
    contribution: Optional[str] = "neutral"
    description: Optional[str] = None

class FeatureImportanceItem(BaseModel):
    feature: str
    importance: float

class MLPredictionSchema(BaseModel):
    model: str
    model_version: str
    task: str
    prediction: str
    score: float
    score_type: str                     # "probability" | "anomaly_score"
    risk_level: str                     # "HIGH" | "MEDIUM" | "LOW"
    explanation: str
    features: List[MLFeatureItem]
    model_name: str
    label: str                          # Backwards compatibility
    confidence: float                   # Backwards compatibility
    confidence_pct: int                 # Backwards compatibility
    feature_importances: List[FeatureImportanceItem]
    raw_scores: Optional[Dict[str, Any]] = None

# ── Scan Result ──────────────────────────────────────────────────────────────

class ScanResult(BaseModel):
    tool: str
    verdict: str
    severity: str
    summary: str
    actions: List[str]
    target: Optional[str] = None
    subject: Optional[str] = None
    from_domain: Optional[str] = None
    reply_to_domain: Optional[str] = None
    sending_domain: Optional[str] = None
    spf_status: Optional[str] = None
    dkim_status: Optional[str] = None
    dmarc_status: Optional[str] = None
    domain_mismatch: Optional[bool] = None
    spoofed: Optional[bool] = None
    upi_brand_targeted: Optional[str] = None
    risk_score: Optional[int] = None
    threat_name: Optional[str] = None
    threat_type: Optional[str] = None
    raw_ports: Optional[List[dict]] = None
    total_open_ports: Optional[int] = None
    ml_prediction: Optional[MLPredictionSchema] = None

# Forward ref rebuild
ScanResult.model_rebuild()
