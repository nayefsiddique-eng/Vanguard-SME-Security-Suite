from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import json

from app.db.database import get_db
from app.db.models import ScanHistory, RiskReport
from app.core.security import get_current_user

router = APIRouter()

@router.get("/scan-history")
def get_scan_history(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    scans = db.query(ScanHistory).filter(ScanHistory.user_email == current_user).order_by(ScanHistory.timestamp.desc()).all()
    return scans

@router.get("/scan-history/{scan_id}")
def get_scan(scan_id: int, current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )
    return scan

@router.delete("/scan-history/{scan_id}")
def delete_scan(scan_id: int, current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted successfully"}

@router.get("/dashboard-summary")
def get_dashboard_summary(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    # 1. Device reports
    reports = db.query(RiskReport).all()
    total_devices = len(reports)
    critical_devices = len([r for r in reports if r.risk_level == "Critical"])
    high_devices = len([r for r in reports if r.risk_level == "High"])
    medium_devices = len([r for r in reports if r.risk_level == "Medium"])
    low_devices = len([r for r in reports if r.risk_level == "Low"])

    # 2. Real scan history statistics
    user_scans = db.query(ScanHistory).filter(ScanHistory.user_email == current_user).all()
    total_scans = len(user_scans)
    
    threats_found = 0
    scans_clean = 0
    ml_detections = 0
    anomalies_detected = 0

    for s in user_scans:
        res_str = s.result or ""
        if "DANGEROUS" in res_str or "INFECTED" in res_str or "PHISHING" in res_str:
            threats_found += 1
        elif "SUSPICIOUS" in res_str:
            threats_found += 1
        elif "CLEAN" in res_str or "SAFE" in res_str:
            scans_clean += 1

        if "ml_prediction" in res_str:
            ml_detections += 1
            if "ANOMALOUS" in res_str or "PHISHING" in res_str or "FRAUDULENT" in res_str:
                anomalies_detected += 1

    return {
        "total_devices": total_devices,
        "critical_risk": critical_devices,
        "high_risk": high_devices,
        "medium_risk": medium_devices,
        "low_risk": low_devices,
        "total_scans": total_scans,
        "threats_found": threats_found,
        "scans_clean": scans_clean,
        "ml_detections": ml_detections,
        "anomalies_detected": anomalies_detected,
    }
