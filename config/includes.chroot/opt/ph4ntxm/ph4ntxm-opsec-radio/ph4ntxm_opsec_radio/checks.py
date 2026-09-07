import subprocess
import re

SEVERITY = {
    "bluetooth_on": 10,
    "wifi_on": 10,
    "modem_active": 10,
    "wwan_on": 10,
    "monitor_mode_active": 20,
    "nearby_devices_detected": 0,
    "nfc_enabled": 10,
    "gps_location_active": 30,
}

def result(ok, data=None, error=None, findings=None):
    return {"ok": ok, "data": data or {}, "error": error, "findings": findings or []}

def run(command, timeout=5):
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode != 0:
            return result(False, error=proc.stderr.strip())
        return result(True, data={"stdout": proc.stdout.strip()})
    except Exception as exc:
        return result(False, error=str(exc))

def check_bluetooth():
    res = run(["rfkill", "list", "bluetooth"])

    if not res["ok"]:
        return result(False, error=res["error"])

    out = res["data"]["stdout"].lower()

    if "bluetooth" not in out:
        findings = ["bluetooth_unavailable"]
    elif "soft blocked: yes" in out or "hard blocked: yes" in out:
        findings = ["bluetooth_off"]
    else:
        findings = ["bluetooth_on"]

    return result(True, findings=findings)

def check_wifi():
    res = run(["nmcli", "radio", "wifi"])
    if not res["ok"]: return result(False, error=res["error"])
    state = res["data"]["stdout"].strip().lower()
    findings = ["wifi_on"] if state == "enabled" else ["wifi_off"]
    return result(True, findings=findings)

def check_modem_state():
    radio = run(["nmcli", "radio", "wwan"])
    if not radio["ok"]: return result(False, error=radio["error"])
    state = radio["data"]["stdout"].strip().lower()
    findings = ["wwan_on"] if state == "enabled" else ["wwan_off"]
    modems = run(["mmcli", "-L"])
    if modems["ok"] and "No modems were found" not in modems["data"]["stdout"]:
        findings.append("modem_active")
    else:
        findings.append("modem_inactive")
    return result(True, findings=findings)

def check_monitor_mode():
    res = run(["iw", "dev"])
    if not res["ok"]: return result(False, error=res["error"])
    findings = ["monitor_mode_active"] if "type monitor" in res["data"]["stdout"] else ["monitor_mode_inactive"]
    return result(True, findings=findings)

def check_nearby_scan():
    res = run([
        "nmcli", "-t", "-f", "BSSID", "device", "wifi", "list",
        "--rescan", "no",
    ])
    if not res["ok"]: return result(False, error=res["error"])
    cached = any(line.strip() for line in res["data"]["stdout"].splitlines())
    findings = ["nearby_devices_detected"] if cached else ["no_nearby_devices"]
    return result(True, findings=findings)

def check_nfc():
    res = run(["rfkill", "list", "nfc"])
    if not res["ok"]:
        return result(True, findings=["nfc_unavailable"])
    output = res["data"]["stdout"].lower()
    if not output.strip():
        findings = ["nfc_unavailable"]
    elif "soft blocked: yes" in output or "hard blocked: yes" in output:
        findings = ["nfc_disabled"]
    else:
        findings = ["nfc_enabled"]
    return result(True, findings=findings)

def check_gps_activity():
    res = run(["mmcli", "-L"])

    if not res["ok"]:
        return result(True, findings=["gps_location_unavailable"])

    out = res["data"]["stdout"].lower()

    if "no modems were found" in out:
        return result(True, findings=["gps_location_unavailable"])

    modem_ids = re.findall(r"/Modem/(\d+)", res["data"]["stdout"])
    gps_active = False
    for modem_id in modem_ids:
        res2 = run(["mmcli", "-m", modem_id, "--location-status"])
        if not res2["ok"]:
            continue
        enabled_lines = [
            line.lower()
            for line in res2["data"]["stdout"].splitlines()
            if "enabled:" in line.lower()
        ]
        if any("gps" in line for line in enabled_lines):
            gps_active = True
            break

    findings = ["gps_location_active"] if gps_active else ["gps_location_inactive"]

    return result(True, findings=findings)

def assess_radio(results):
    score = 100
    findings = []

    for r in results:
        if not r["ok"]:
            findings.append(f"error: {r.get('error','check_failed')}")
            score -= 20
        else:
            for f in r.get("findings", []):
                findings.append(f)
                score -= SEVERITY.get(f, 0)

    score = max(0, min(score, 100))

    return result(
        True,
        data={
            "score": score,
            "findings": findings,
        },
        findings=findings
    )

def format_finding(f):
    mapping = {
        "bluetooth_on": ("Bluetooth enabled", "warn"),
        "bluetooth_off": ("Bluetooth disabled/blocked", "good"),
        "bluetooth_unavailable": ("Bluetooth hardware unavailable", "good"),

        "wifi_on": ("WiFi enabled", "warn"),
        "wifi_off": ("WiFi disabled", "good"),

        "wwan_on": ("WWAN radio enabled", "warn"),
        "wwan_off": ("WWAN radio disabled", "good"),
        "modem_active": ("Modem present", "warn"),
        "modem_inactive": ("No modem present", "good"),

        "monitor_mode_active": ("Monitor Mode enabled", "bad"),
        "monitor_mode_inactive": ("Monitor Mode inactive", "good"),

        "nearby_devices_detected": ("Nearby WiFi networks present in the local cache", "info"),
        "no_nearby_devices": ("No nearby WiFi networks in the local cache", "good"),

        "nfc_enabled": ("NFC enabled", "warn"),
        "nfc_disabled": ("NFC disabled", "good"),
        "nfc_unavailable": ("NFC hardware unavailable", "good"),

        "gps_location_active": ("GPS location active", "bad"),
        "gps_location_inactive": ("GPS location inactive", "good"),
        "gps_location_unavailable": ("GPS hardware unavailable", "good"),
    }

    return mapping.get(f, (f.replace("_"," "), "warn"))

checks = [
    check_bluetooth,
    check_wifi,
    check_modem_state,
    check_monitor_mode,
    check_nearby_scan,
    check_nfc,
    check_gps_activity
]

def main():
    results = [check() for check in checks]
    assessment = assess_radio(results)
    return results, assessment

if __name__ == "__main__":
    main()
