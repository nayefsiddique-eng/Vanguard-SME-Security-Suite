"""Exercise the running Vanguard container using disposable accounts and files."""
import sys

import requests

BASE = "http://127.0.0.1:8000"
MARKER = b"vanguard CI harmless sample for the local signature database\n"


def call(method, path, expected=200, **kwargs):
    response = requests.request(method, f"{BASE}{path}", timeout=15, **kwargs)
    assert response.status_code == expected, (method, path, response.status_code)
    return response.json()


def run(restarted):
    assert call("GET", "/health")["status"] == "ok"
    accounts = []
    for account in ("owner", "other"):
        credentials = {"email": f"ci-{account}@example.com", "password": "local-ci-password-only"}
        if not restarted:
            call("POST", "/register", json=credentials)
        token = call("POST", "/login", json=credentials)["access_token"]
        accounts.append({"Authorization": f"Bearer {token}"})
    owner, other = accounts

    if not restarted:
        assert call("POST", "/api/scan/file", headers=owner,
                    files={"file": ("sample.txt", MARKER)})["verdict"] == "INFECTED"
        assert call("POST", "/api/scan/file", headers=owner,
                    files={"file": ("clean.txt", b"ordinary CI test file")})["verdict"] == "CLEAN"

    records = call("GET", "/scan-history", headers=owner)
    assert len(records) == 2
    assert call("GET", "/scan-history", headers=other) == []
    path = f"/scan-history/{records[0]['id']}"
    call("GET", path, expected=401)
    call("GET", path, expected=404, headers=other)
    call("DELETE", path, expected=404, headers=other)
    call("GET", path, headers=owner)
    if restarted:
        call("DELETE", path, headers=owner)
        call("GET", path, expected=404, headers=owner)
        print("PostgreSQL persistence and authorized deletion passed.")
    else:
        print("ClamAV synthetic signatures and cross-account boundaries passed.")


if __name__ == "__main__":
    run("--restarted" in sys.argv)
