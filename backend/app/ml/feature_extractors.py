"""
Feature extraction functions for each ML model in Vanguard SME Security Suite.
Converts raw scan result dicts (already produced by existing services)
into fixed-length numeric feature vectors with safe fallbacks and bounds.
"""
import math
import re
from typing import Dict, Any, List


# ---------------------------------------------------------------------------
# Phishing / Email feature extractor
# ---------------------------------------------------------------------------

PHISHING_FEATURE_NAMES: List[str] = [
    "spf_fail",
    "dkim_fail",
    "dmarc_fail",
    "domain_mismatch",
    "spoofed",
    "reply_to_mismatch",
]


def extract_phishing_features(scan_result: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract numeric features from an email scan result dict
    (output of email_analyser.analyse_header).

    Returns a dict with 6 binary float features:
      - spf_fail: 1.0 if SPF failed/softfailed, 0.0 otherwise
      - dkim_fail: 1.0 if DKIM verification failed, 0.0 otherwise
      - dmarc_fail: 1.0 if DMARC policy failed, 0.0 otherwise
      - domain_mismatch: 1.0 if From domain != Sending domain
      - spoofed: 1.0 if known brand impersonation detected
      - reply_to_mismatch: 1.0 if Reply-To domain differs from From domain
    """
    if not isinstance(scan_result, dict):
        scan_result = {}

    spf = str(scan_result.get("spf_status") or "NONE").upper()
    dkim = str(scan_result.get("dkim_status") or "NONE").upper()
    dmarc = str(scan_result.get("dmarc_status") or "NONE").upper()

    from_domain = str(scan_result.get("from_domain") or "").strip().lower()
    reply_to_domain = str(scan_result.get("reply_to_domain") or "").strip().lower()

    return {
        "spf_fail": 1.0 if spf in ("FAIL", "SOFTFAIL") else 0.0,
        "dkim_fail": 1.0 if dkim == "FAIL" else 0.0,
        "dmarc_fail": 1.0 if dmarc == "FAIL" else 0.0,
        "domain_mismatch": 1.0 if scan_result.get("domain_mismatch") else 0.0,
        "spoofed": 1.0 if scan_result.get("spoofed") else 0.0,
        "reply_to_mismatch": (
            1.0
            if reply_to_domain and from_domain and reply_to_domain != from_domain
            else 0.0
        ),
    }


# ---------------------------------------------------------------------------
# UPI Fraud feature extractor
# ---------------------------------------------------------------------------

SUSPICIOUS_UPI_KEYWORDS = [
    "fake", "fraud", "scam", "phish", "steal", "hack", "suspicious",
    "verify", "secure", "kyc", "refund", "cashback", "lottery", "win"
]

UPI_BRAND_KEYWORDS = [
    "paytm", "phonepe", "bhim", "gpay", "googlepay",
    "sbi", "hdfcbank", "hdfc", "icicibank", "icici",
    "axisbank", "axis", "yesbank", "kotakbank", "kotak",
    "npci", "irctc", "amazon", "flipkart", "airtel", "jio"
]

UPI_FEATURE_NAMES: List[str] = [
    "handle_length",
    "has_numbers",
    "digit_ratio",
    "suspicious_keyword_score",
    "brand_keyword_score",
    "handle_entropy",
]


def _string_entropy(s: str) -> float:
    """Shannon entropy of a string (higher = more random-looking / algorithmically generated)."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def extract_upi_features(upi_id: str) -> Dict[str, float]:
    """
    Extract numeric features from a raw UPI handle string.
    Features:
      - handle_length: Character count of handle prefix
      - has_numbers: 1.0 if handle contains digits, 0.0 otherwise
      - digit_ratio: Proportion of digits in handle prefix
      - suspicious_keyword_score: Count of fraud keywords in handle (capped at 3.0)
      - brand_keyword_score: Count of recognized brand keywords in handle (capped at 3.0)
      - handle_entropy: Shannon entropy of handle prefix
    """
    if not isinstance(upi_id, str):
        upi_id = ""

    upi = upi_id.lower().strip()
    handle = upi.split("@")[0] if "@" in upi else upi

    digit_count = sum(c.isdigit() for c in handle)
    suspicious_kw_hits = sum(1 for kw in SUSPICIOUS_UPI_KEYWORDS if kw in handle)
    brand_kw_hits = sum(1 for kw in UPI_BRAND_KEYWORDS if kw in handle)

    length = float(len(handle))
    digit_ratio = (digit_count / max(length, 1.0)) if length > 0 else 0.0

    return {
        "handle_length": min(length, 64.0),
        "has_numbers": 1.0 if digit_count > 0 else 0.0,
        "digit_ratio": round(digit_ratio, 4),
        "suspicious_keyword_score": float(min(suspicious_kw_hits, 3)),
        "brand_keyword_score": float(min(brand_kw_hits, 3)),
        "handle_entropy": round(_string_entropy(handle), 4),
    }


# ---------------------------------------------------------------------------
# Network Anomaly feature extractor
# ---------------------------------------------------------------------------

CRITICAL_PORTS = {"23", "445", "3306", "3389"}
HIGH_RISK_PORTS = {"21", "22"}
MEDIUM_PORTS = {"80", "8080"}

NETWORK_FEATURE_NAMES: List[str] = [
    "num_open_ports",
    "has_critical",
    "has_rdp",
    "has_smb",
    "has_db",
    "has_ftp",
    "has_telnet",
]


def extract_network_features(scan_result: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract numeric features from a network scan result dict
    (output of nmap_scanner.scan).
    """
    if not isinstance(scan_result, dict):
        scan_result = {}

    raw_ports = scan_result.get("raw_ports") or scan_result.get("ports") or []
    port_strings = {str(p.get("port", "")) for p in raw_ports if isinstance(p, dict)}

    has_critical = any(p in port_strings for p in CRITICAL_PORTS)
    has_rdp = "3389" in port_strings
    has_smb = "445" in port_strings
    has_db = "3306" in port_strings
    has_ftp = "21" in port_strings
    has_telnet = "23" in port_strings

    return {
        "num_open_ports": float(len(port_strings)),
        "has_critical": 1.0 if has_critical else 0.0,
        "has_rdp": 1.0 if has_rdp else 0.0,
        "has_smb": 1.0 if has_smb else 0.0,
        "has_db": 1.0 if has_db else 0.0,
        "has_ftp": 1.0 if has_ftp else 0.0,
        "has_telnet": 1.0 if has_telnet else 0.0,
    }
