import time

import requests
import json
from app.core.config import VIRUSTOTAL_API_KEY as API_KEY

URL_SUMMARY = {
    "dangerous": "This link is dangerous. It has been flagged by multiple security engines as a phishing page, malware source, or fake payment site.",
    "suspicious": "This link looks suspicious. It has not been confirmed as safe and may be trying to steal your information.",
    "clean": "This link appears to be safe. No security engines flagged it as dangerous."
}

URL_ACTIONS = {
    "dangerous": [
        "Do NOT click this link",
        "Delete the message or email containing this link immediately",
        "If you already clicked it, do not enter any passwords or UPI PINs",
        "Inform your team not to click this link",
        "Report it to your bank if it was related to a payment request"
    ],
    "suspicious": [
        "Do not click this link until it has been verified",
        "Check if the sender is someone you trust",
        "If it claims to be a payment link, call the sender directly to confirm",
        "When in doubt, do not click"
    ],
    "clean": [
        "This link appears safe to visit",
        "Always stay cautious with links received over WhatsApp or email"
    ]
}

def unavailable_result(url, summary):
    return {
        "tool": "virustotal",
        "url": url,
        "target": url,
        "verdict": "ERROR",
        "severity": "None",
        "summary": summary,
        "actions": ["Retry when VirusTotal is available."],
    }


def check_url(url):
    if not API_KEY or API_KEY == "your_virustotal_api_key_here":
        return unavailable_result(url, "VirusTotal credentials are missing.")

    headers = {"x-apikey": API_KEY}
    try:
        submission = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=(3, 10),
        )
        submission.raise_for_status()
        analysis_id = submission.json()["data"]["id"]

        for attempt in range(3):
            analysis = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=(3, 10),
            )
            analysis.raise_for_status()
            attributes = analysis.json()["data"]["attributes"]
            if attributes.get("status") == "completed":
                break
            if attempt < 2:
                time.sleep(1)
        else:
            return unavailable_result(url, "VirusTotal analysis is still pending.")
        stats = attributes["stats"]
        malicious = int(stats["malicious"])
        suspicious = int(stats["suspicious"])
    except (requests.RequestException, KeyError, TypeError, ValueError):
        return unavailable_result(url, "VirusTotal could not complete this request.")

    if malicious > 0:
        verdict = "dangerous"
    elif suspicious > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "tool": "virustotal",
        "url": url,
        "malicious_engines": malicious,
        "suspicious_engines": suspicious,
        "verdict": verdict.upper(),
        "severity": "Critical" if verdict == "dangerous" else "Medium" if verdict == "suspicious" else "None",
        "summary": URL_SUMMARY[verdict],
        "actions": URL_ACTIONS[verdict]
    }

if __name__ == "__main__":
    result = check_url("http://testsafebrowsing.appspot.com/s/phishing.html")
    print(json.dumps(result, indent=2))