import subprocess
import re

def result(ok, message=None, error=None):
    return {
        "ok": ok,
        "message": message,
        "error": error
    }

def run(command, timeout=10):
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        if proc.returncode != 0:
            return result(
                False,
                error=proc.stderr.strip() or proc.stdout.strip()
            )

        return result(
            True,
            message=proc.stdout.strip()
        )

    except Exception as exc:
        return result(False, error=str(exc))

def disable_bluetooth():
    return run([
        "rfkill",
        "block",
        "bluetooth"
    ])

def disable_wifi():
    return run([
        "nmcli",
        "radio",
        "wifi",
        "off"
    ])

def disable_modem():
    return run([
        "nmcli",
        "radio",
        "wwan",
        "off"
    ])

def disable_monitor_mode():
    try:
        iw = subprocess.run(
            ["iw", "dev"],
            capture_output=True,
            text=True,
            check=False
        )

        interfaces = []
        current_iface = None

        for line in iw.stdout.splitlines():
            line = line.strip()

            if line.startswith("Interface"):
                current_iface = line.split()[1]

            if "type monitor" in line and current_iface:
                interfaces.append(current_iface)

        if not interfaces:
            return result(
                True,
                message="No monitor mode interfaces found"
            )

        for iface in interfaces:
            down = run(["ip", "link", "set", "dev", iface, "down"])
            if not down["ok"]:
                return down

            managed = run(["iw", "dev", iface, "set", "type", "managed"])
            if not managed["ok"]:
                run(["ip", "link", "set", "dev", iface, "up"])
                return managed

            up = run(["ip", "link", "set", "dev", iface, "up"])
            if not up["ok"]:
                return up

        return result(
            True,
            message="Monitor mode disabled"
        )

    except Exception as exc:
        return result(False, error=str(exc))

def disable_nfc():
    return run([
        "rfkill",
        "block",
        "nfc"
    ])

def disable_gps():
    try:
        modem_check = subprocess.run(
            ["mmcli", "-L"],
            capture_output=True,
            text=True,
            check=False
        )

        if modem_check.returncode != 0:
            return result(
                False,
                error=modem_check.stderr.strip() or modem_check.stdout.strip()
            )

        modem_ids = re.findall(r"/Modem/(\d+)", modem_check.stdout)
        if "No modems were found" in modem_check.stdout or not modem_ids:
            return result(
                True,
                message="No modem available"
            )

        gps_options = (
            "--location-disable-gps-nmea",
            "--location-disable-gps-raw",
            "--location-disable-gps-unmanaged",
            "--location-disable-agps-msa",
            "--location-disable-agps-msb",
        )
        for modem_id in modem_ids:
            for option in gps_options:
                subprocess.run(
                    ["mmcli", "-m", modem_id, option],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

            status = subprocess.run(
                ["mmcli", "-m", modem_id, "--location-status"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            enabled_lines = [
                line.lower()
                for line in status.stdout.splitlines()
                if "enabled:" in line.lower()
            ]
            if status.returncode != 0 or any("gps" in line for line in enabled_lines):
                return result(False, error=f"GPS remains enabled on modem {modem_id}")

        return result(True, message="GPS location sources disabled")

    except Exception as exc:
        return result(False, error=str(exc))

REMEDIATIONS = {
    "bluetooth_on": {
        "label": "Disable Bluetooth RF",
        "description": "Reduce Bluetooth discoverability",
        "severity": "warn",
        "action": disable_bluetooth,
    },

    "wifi_on": {
        "label": "Disable WiFi RF",
        "description": "Reduce wireless network exposure",
        "severity": "warn",
        "action": disable_wifi,
    },

    "modem_active": {
        "label": "Disable WWAN/Modem",
        "description": "Reduce cellular network exposure",
        "severity": "warn",
        "action": disable_modem,
    },

    "wwan_on": {
        "label": "Disable WWAN/Modem",
        "description": "Reduce cellular network exposure",
        "severity": "warn",
        "action": disable_modem,
    },

    "monitor_mode_active": {
        "label": "Disable Monitor Mode",
        "description": "Return wireless interface to managed mode",
        "severity": "bad",
        "action": disable_monitor_mode,
    },

    "nfc_enabled": {
        "label": "Disable NFC",
        "description": "Reduce near-field communication exposure",
        "severity": "warn",
        "action": disable_nfc,
    },

    "gps_location_active": {
        "label": "Disable GPS Location Services",
        "description": "Prevent modem-assisted geolocation",
        "severity": "bad",
        "action": disable_gps,
    },
}
