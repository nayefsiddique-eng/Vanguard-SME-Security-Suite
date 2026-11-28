import shutil
import subprocess
import os

THREAT_RULES = {
    "ransomware": ["Ransom", "Wannacry", "Cryptolocker", "Locky", "Petya", "Ryuk", "Sodinokibi", "Revil", "Darkside", "Conti", "Maze", "Dharma", "Phobos", "Cerber"],
    "trojan": ["Trojan", "Backdoor", "Rootkit", "RAT", "Remcos", "Emotet", "Trickbot", "Dridex", "Qakbot", "Agent"],
    "phishing": ["Phishing", "Phish", "Fraud", "Spoof", "Fake"],
    "adware": ["Adware", "PUA", "PUP", "Unwanted", "Toolbar", "Downloader"],
    "spyware": ["Spy", "Keylogger", "Stealer", "Infostealer", "Banker"],
    "test": ["Eicar", "Test-Signature", "EICAR"]
}

THREAT_SEVERITY = {
    "ransomware": "Critical",
    "trojan": "High",
    "phishing": "High",
    "spyware": "High",
    "adware": "Medium",
    "test": "Low",
    "unknown": "Low"
}

THREAT_SUMMARY = {
    "ransomware": "This file contains ransomware. It is designed to lock all your business files and demand a payment to unlock them.",
    "trojan": "This file contains a trojan. It secretly gives attackers remote control of your computer without you knowing.",
    "phishing": "This file is a phishing attack. It is designed to steal your passwords, banking details, or UPI credentials.",
    "spyware": "This file contains spyware. It silently records your activity, passwords, and UPI transactions in the background.",
    "adware": "This file contains adware. It installs unwanted software on your computer and may slow it down or show fake alerts.",
    "test": "This is a standard antivirus test file. It is not a real threat. ClamAV is working correctly.",
    "unknown": "This file was flagged as suspicious. It does not match a known threat but should not be opened until verified."
}

THREAT_ACTIONS = {
    "ransomware": [
        "Do NOT open this file under any circumstances",
        "Delete it immediately from your computer",
        "Check if any of your files have been renamed or cannot be opened",
        "Disconnect your computer from WiFi or ethernet right now",
        "Contact your IT support or call a cybersecurity professional immediately"
    ],
    "trojan": [
        "Do NOT open this file",
        "Delete it immediately",
        "Run a full system scan using ClamAV",
        "Change all your passwords from a different device",
        "Check if any unknown software has been installed recently"
    ],
    "phishing": [
        "Do NOT open or click anything in this file",
        "Delete it immediately",
        "Do not enter any passwords or UPI PINs if you already opened it",
        "Inform your team not to open similar files",
        "Report it to your bank if it was related to a payment"
    ],
    "spyware": [
        "Delete this file immediately",
        "Change your UPI PIN and banking passwords from a different device",
        "Run a full system scan",
        "Check your recent UPI and bank transactions for anything unusual"
    ],
    "adware": [
        "Delete this file",
        "Check your browser for any new extensions you did not install",
        "Run a full system scan to check for additional unwanted software"
    ],
    "test": [
        "No action needed, this is a test file",
        "ClamAV is working correctly on your system"
    ],
    "unknown": [
        "Do not open this file until it has been verified",
        "Delete it if you do not know where it came from",
        "Run a full system scan as a precaution"
    ]
}

def classify_threat(signature):
    signature_lower = signature.lower()
    for threat_type, keywords in THREAT_RULES.items():
        for keyword in keywords:
            if keyword.lower() in signature_lower:
                return threat_type
    return "unknown"

def scan_file(filepath):
    def unavailable(summary):
        return {
            "tool": "clamav",
            "verdict": "ERROR",
            "severity": "None",
            "summary": summary,
            "actions": ["Check the ClamAV installation and signature database, then retry."],
        }

    binary = os.getenv("CLAMAV_EXECUTABLE") or shutil.which("clamscan")
    if not binary and os.name == "nt":
        binary = r"C:\Program Files\ClamAV\clamscan.exe"
    if not binary:
        return unavailable("ClamAV is unavailable.")
    try:
        result = subprocess.run(
            [binary, "--no-summary", filepath],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return unavailable("ClamAV could not complete the scan.")

    if result.returncode == 0:
        return {
            "tool": "clamav",
            "verdict": "CLEAN",
            "severity": "None",
            "summary": "ClamAV did not detect a known signature.",
            "actions": ["Use your normal file handling precautions."],
        }

    if result.returncode == 1:
        for line in result.stdout.splitlines():
            if line.endswith(" FOUND") and ": " in line:
                signature = line.rsplit(": ", 1)[-1].removesuffix(" FOUND")
                threat_type = classify_threat(signature)
                return {
                    "tool": "clamav",
                    "verdict": "INFECTED",
                    "threat_name": signature,
                    "threat_type": threat_type,
                    "severity": THREAT_SEVERITY[threat_type],
                    "summary": THREAT_SUMMARY[threat_type],
                    "actions": THREAT_ACTIONS[threat_type],
                }
        return unavailable("ClamAV reported a detection without a readable result.")
    return unavailable("ClamAV could not complete the scan.")
