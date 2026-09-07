import subprocess
import os
import json

STATUS_FILE = "/run/ph4ntxm-lockdown-status.json"
LOCKDOWN_CMD = ["/usr/local/bin/ph4ntxm-lockdown"]

def result(ok, message=None, error=None):
    return {
        "ok": ok,
        "message": message,
        "error": error
    }

def toggle_lockdown():
    """Launch lockdown dialog and report success/failure."""
    try:
        proc = subprocess.run(
            LOCKDOWN_CMD,
            capture_output=True,
            text=True,
            check=False
        )
        if proc.returncode != 0:
            return result(False, error=proc.stderr.strip() or proc.stdout.strip())
        return result(True, message="Network lockdown dialog launched")
    except Exception as exc:
        return result(False, error=str(exc))

def lockdown_enabled():
    """Check if lockdown is currently enabled."""
    if not os.path.exists(STATUS_FILE):
        return False
    try:
        with open(STATUS_FILE, "r") as f:
            data = json.load(f)
        return data.get("enabled", False)
    except Exception:
        return False

def lockdown_remediation():
    """Return a dynamic remediation entry depending on current state."""
    enabled = lockdown_enabled()

    label = "Disable Network Lockdown" if enabled else "Enable Network Lockdown"
    description = "Block all incoming and outgoing traffic to reduce exposure"

    return {
        "label": label,
        "description": description,
        "severity": "bad",
        "action": toggle_lockdown,
    }

REMEDIATIONS = {
    "active_connections_present": lockdown_remediation(),
    "suspicious_connections_present": lockdown_remediation(),
    "dns_external_resolver": lockdown_remediation(),
    "unauthorized_dns_traffic": lockdown_remediation(),
    "unexpected_public_connection": lockdown_remediation(),
}
