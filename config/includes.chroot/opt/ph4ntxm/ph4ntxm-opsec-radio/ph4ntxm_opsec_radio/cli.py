# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import sys
import os
from ph4ntxm_opsec_radio.checks import checks, assess_radio
from ph4ntxm_opsec_radio.remediation import REMEDIATIONS

RESET = "\033[0m"
PH4NTXM_CYAN = "\033[38;2;0;171;255m"
PH4NTXM_MAGENTA = "\033[38;2;255;61;251m"
GREEN = "\033[38;2;68;209;122m"
AMBER = "\033[38;2;255;176;32m"
RED = "\033[38;2;255;77;90m"
GRAY = "\033[38;2;165;175;195m"
LINE_WIDTH = 78


def safe_text(value, limit=512):
    value = str(value)
    cleaned = "".join(char if char.isprintable() else "?" for char in value)
    return cleaned[:limit]


def color(text, code):
    return f"{code}{text}{RESET}"


def cyan(text):
    return color(text, PH4NTXM_CYAN)


def magenta(text):
    return color(text, PH4NTXM_MAGENTA)


def green(text):
    return color(text, GREEN)


def amber(text):
    return color(text, AMBER)


def red(text):
    return color(text, RED)


def gray(text):
    return color(text, GRAY)


def separator():
    print(gray("─" * LINE_WIDTH))


def section(title):
    print()
    separator()
    print(cyan(f"[ {title} ]"))
    separator()


def status_tag(level):
    mapping = {
        "good": green("[OK]"),
        "warn": amber("[Warn]"),
        "bad": red("[Crit]"),
        "active": magenta("[Live]"),
        "info": gray("[Info]"),
        None: gray("[Info]"),
    }

    return mapping.get(level, gray("[Info]"))


def kv(key, value, status=None):
    print(
        f"{status_tag(status)} "
        f"{gray(f'{display_key(key)}:'):<30} "
        f"{safe_text(value)}"
    )


def format_finding(finding):
    mapping = {
        "bluetooth_on": ("Bluetooth enabled", "warn"),
        "bluetooth_off": ("Bluetooth disabled/blocked", "good"),
        "bluetooth_unavailable": ("Bluetooth hardware unavailable", "good"),
        "wifi_on": ("Wi-Fi enabled", "warn"),
        "wifi_off": ("Wi-Fi disabled", "good"),
        "wwan_on": ("WWAN radio enabled", "warn"),
        "wwan_off": ("WWAN radio disabled", "good"),
        "modem_active": ("Modem present", "warn"),
        "modem_inactive": ("No modem present", "good"),
        "monitor_mode_active": ("Monitor mode enabled", "bad"),
        "monitor_mode_inactive": ("Monitor mode inactive", "good"),
        "nearby_devices_detected": ("Nearby Wi-Fi networks in local cache", "info"),
        "no_nearby_devices": ("No nearby Wi-Fi networks in local cache", "good"),
        "nfc_enabled": ("NFC enabled", "warn"),
        "nfc_disabled": ("NFC disabled", "good"),
        "nfc_unavailable": ("NFC hardware unavailable", "good"),
        "gps_location_active": ("GPS location active", "bad"),
        "gps_location_inactive": ("GPS location inactive", "good"),
        "gps_location_unavailable": ("GPS hardware unavailable", "good"),
    }

    return mapping.get(finding, (finding.replace("_", " ").capitalize(), "warn"))


def verdict(score):
    if score >= 85:
        return "No high-severity findings", "good"

    if score >= 60:
        return "Review recommended", "warn"

    return "Attention required", "bad"


CHECK_NAMES = {
    "check_bluetooth": "Bluetooth Status",
    "check_wifi": "Wi-Fi Status",
    "check_modem_state": "Modem Status",
    "check_monitor_mode": "Monitor Mode",
    "check_nearby_scan": "Cached Wi-Fi Observations",
    "check_nfc": "NFC Status",
    "check_gps_activity": "GPS Activity",
}


def display_key(value):
    text = safe_text(value, 80)
    labels = {
        "ssid": "SSID",
        "bssid": "BSSID",
        "ip": "IP",
        "ipv4": "IPv4",
        "ipv6": "IPv6",
        "mac": "MAC",
        "pid": "PID",
        "uid": "UID",
        "wifi": "Wi-Fi",
        "wwan": "WWAN",
        "nfc": "NFC",
        "gps": "GPS",
    }
    return labels.get(text.lower(), text.replace("_", " ").capitalize())


def display_data(data):
    if isinstance(data, list):

        for item in data:

            if isinstance(item, dict):
                print(
                    f"{status_tag('info')} Data: "
                    + ", ".join(
                        f"{display_key(k)}={safe_text(v)}" for k, v in item.items()
                    )
                )

            else:
                print(f"{status_tag('info')} Data: {safe_text(item)}")

    elif isinstance(data, dict):

        for key, value in data.items():

            if isinstance(value, (list, dict)):
                print(f"{status_tag('info')} " f"{display_key(key)}:")
                display_data(value)

            else:
                kv(display_key(key), str(value), "info")

    else:
        print(f"{status_tag('info')} Data: {data}")


def remediation_menu(findings):

    remediable = []

    seen = set()

    for finding in findings:

        if finding not in REMEDIATIONS:
            continue

        if finding in seen:
            continue

        seen.add(finding)

        remediable.append(finding)

    if not remediable:
        return

    section("Available Remediations")

    indexed = {}

    for idx, finding in enumerate(remediable, start=1):

        remediation = REMEDIATIONS[finding]

        indexed[str(idx)] = {"finding": finding, "remediation": remediation}

        print(f"{cyan(f'[{idx}]')} " f"{remediation['label']}")

        print(f"    " f"{gray(remediation['description'])}")

    print()

    choice = input(gray("Select targets " "[1,2 = Apply | Q = Quit]: ")).strip().lower()

    if not choice or choice == "q":
        return

    selections = [item.strip() for item in choice.split(",")]

    valid_entries = []

    print()

    for sel in selections:

        entry = indexed.get(sel)

        if not entry:

            print(f"{red('[Fail]')} " f"Invalid selection: {sel}")

            continue

        valid_entries.append(entry)

    if not valid_entries:
        print()
        return

    print()

    for entry in valid_entries:

        remediation = entry["remediation"]

        print(f"{status_tag('active')} " f"Action: " f"{remediation['label']}")

        confirm = input(gray("Apply remediation? [y/N]: ")).strip().lower()

        if confirm != "y":

            print(f"{status_tag('info')} " f"Skipped")

            print()

            continue

        result = remediation["action"]()

        if result["ok"]:

            print(f"{green('[OK]')} " f"Remediation applied")

            message = result.get("message")

            if message:
                print(f"{status_tag('info')} " f"{safe_text(message)}")

        else:

            error = result.get("error") or "Unknown Error"

            print(f"{red('[Fail]')} " f"{safe_text(error)}")

        print()


def main():
    section("PH4NTXM OpSec Radio")

    results = [check() for check in checks]
    assessment = assess_radio(results)

    for i, result in enumerate(results):

        check_name = checks[i].__name__

        section(CHECK_NAMES.get(check_name, check_name))

        if not result["ok"]:
            kv("Error", result.get("error", "Failed"), "bad")

        else:
            display_data(result.get("data", {}))

            findings = result.get("findings", [])

            if findings:

                for finding in findings:
                    text, severity = format_finding(finding)

                    print(f"{status_tag(severity)} " f"Finding: {text}")

            else:
                print(f"{green('[OK]')} Finding: None")

    section("System Assessment")

    score = assessment["data"]["score"]

    verdict_text, verdict_status = verdict(score)

    kv("Score", str(score), verdict_status)
    kv("Verdict", verdict_text, verdict_status)

    section("Findings")

    all_findings = assessment["data"].get("findings", [])

    issues = []

    for finding in all_findings:

        text, severity = format_finding(finding)

        if severity != "good":
            issues.append((text, severity))

    if issues:

        for text, severity in issues:
            print(f"{status_tag(severity)} " f"Finding: {text}")

    else:
        print(f"{green('[OK]')} Finding: None")

    remediation_menu(all_findings)

    print()
    separator()
    print()


if __name__ == "__main__":
    main()
