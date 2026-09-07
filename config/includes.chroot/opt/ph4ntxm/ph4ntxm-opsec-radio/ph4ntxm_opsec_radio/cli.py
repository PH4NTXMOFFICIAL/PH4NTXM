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

def color(text, code): return f"{code}{text}{RESET}"
def cyan(text): return color(text, PH4NTXM_CYAN)
def magenta(text): return color(text, PH4NTXM_MAGENTA)
def green(text): return color(text, GREEN)
def amber(text): return color(text, AMBER)
def red(text): return color(text, RED)
def gray(text): return color(text, GRAY)

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
        "warn": amber("[WARN]"),
        "bad": red("[CRIT]"),
        "active": magenta("[LIVE]"),
        "info": gray("[INFO]"),
        None: gray("[INFO]")
    }

    return mapping.get(level, gray("[INFO]"))

def kv(key, value, status=None):
    print(
        f"{status_tag(status)} "
        f"{gray(f'{safe_text(key, 80)}:'):<30} "
        f"{safe_text(value)}"
    )

def format_finding(finding):
    mapping = {
        "bluetooth_on": ("BLUETOOTH ENABLED", "warn"),
        "bluetooth_off": ("BLUETOOTH DISABLED/BLOCKED", "good"),
        "bluetooth_unavailable": ("BLUETOOTH HARDWARE UNAVAILABLE", "good"),

        "wifi_on": ("WIFI ENABLED", "warn"),
        "wifi_off": ("WIFI DISABLED", "good"),

        "wwan_on": ("WWAN RADIO ENABLED", "warn"),
        "wwan_off": ("WWAN RADIO DISABLED", "good"),
        "modem_active": ("MODEM PRESENT", "warn"),
        "modem_inactive": ("NO MODEM PRESENT", "good"),

        "monitor_mode_active": ("MONITOR MODE ENABLED", "bad"),
        "monitor_mode_inactive": ("MONITOR MODE INACTIVE", "good"),

        "nearby_devices_detected": ("NEARBY WIFI NETWORKS IN LOCAL CACHE", "info"),
        "no_nearby_devices": ("NO NEARBY WIFI NETWORKS IN LOCAL CACHE", "good"),

        "nfc_enabled": ("NFC ENABLED", "warn"),
        "nfc_disabled": ("NFC DISABLED", "good"),
        "nfc_unavailable": ("NFC HARDWARE UNAVAILABLE", "good"),

        "gps_location_active": ("GPS LOCATION ACTIVE", "bad"),
        "gps_location_inactive": ("GPS LOCATION INACTIVE", "good"),
        "gps_location_unavailable": ("GPS HARDWARE UNAVAILABLE", "good"),
    }

    return mapping.get(
        finding,
        (finding.replace("_", " ").upper(), "warn")
    )

def verdict(score):
    if score >= 85:
        return "NO HIGH-SEVERITY FINDINGS", "good"

    if score >= 60:
        return "REVIEW RECOMMENDED", "warn"

    return "ATTENTION REQUIRED", "bad"

CHECK_NAMES = {
    "check_bluetooth": "BLUETOOTH STATUS",
    "check_wifi": "WIFI STATUS",
    "check_modem_state": "MODEM STATUS",
    "check_monitor_mode": "MONITOR MODE",
    "check_nearby_scan": "CACHED WIFI OBSERVATIONS",
    "check_nfc": "NFC STATUS",
    "check_gps_activity": "GPS ACTIVITY"
}

def display_data(data):
    if isinstance(data, list):

        for item in data:

            if isinstance(item, dict):
                print(
                    f"{status_tag('info')} DATA: "
                    + ", ".join(
                        f"{safe_text(k, 80)}={safe_text(v)}"
                        for k, v in item.items()
                    )
                )

            else:
                print(f"{status_tag('info')} DATA: {safe_text(item)}")

    elif isinstance(data, dict):

        for key, value in data.items():

            if isinstance(value, (list, dict)):
                print(
                    f"{status_tag('info')} "
                    f"{safe_text(key, 80).upper()}:"
                )
                display_data(value)

            else:
                kv(key.upper(), str(value), "info")

    else:
        print(f"{status_tag('info')} DATA: {data}")

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

    section("AVAILABLE REMEDIATIONS")

    indexed = {}

    for idx, finding in enumerate(remediable, start=1):

        remediation = REMEDIATIONS[finding]

        indexed[str(idx)] = {
            "finding": finding,
            "remediation": remediation
        }

        print(
            f"{cyan(f'[{idx}]')} "
            f"{remediation['label'].upper()}"
        )

        print(
            f"    "
            f"{gray(remediation['description'].upper())}"
        )

    print()

    choice = input(
        gray(
            "SELECT TARGETS "
            "[1,2 = APPLY | Q = QUIT]: "	
        )
    ).strip().lower()

    if not choice or choice == "q":
        return

    selections = [
        item.strip()
        for item in choice.split(",")
    ]

    valid_entries = []

    print()

    for sel in selections:

        entry = indexed.get(sel)

        if not entry:

            print(
                f"{red('[FAIL]')} "
                f"INVALID SELECTION: {sel}"
            )

            continue

        valid_entries.append(entry)

    if not valid_entries:
        print()
        return

    print()

    for entry in valid_entries:

        remediation = entry["remediation"]

        print(
            f"{status_tag('active')} "
            f"ACTION: "
            f"{remediation['label'].upper()}"
        )

        confirm = input(
            gray(
                "APPLY REMEDIATION? [y/N]: "
            )
        ).strip().lower()

        if confirm != "y":

            print(
                f"{status_tag('info')} "
                f"SKIPPED"
            )

            print()

            continue

        result = remediation["action"]()

        if result["ok"]:

            print(
                f"{green('[OK]')} "
                f"REMEDIATION APPLIED"
            )

            message = result.get("message")

            if message:
                print(
                    f"{status_tag('info')} "
                    f"{safe_text(message).upper()}"
                )

        else:

            error = (
                result.get("error")
                or "Unknown error"
            )

            print(
                f"{red('[FAIL]')} "
                f"{safe_text(error).upper()}"
            )

        print()

def main():
    section("PH4NTXM OPSEC RADIO DIAGNOSTICS")

    results = [check() for check in checks]
    assessment = assess_radio(results)

    for i, result in enumerate(results):

        check_name = checks[i].__name__

        section(
            CHECK_NAMES.get(
                check_name,
                check_name
            )
        )

        if not result["ok"]:
            kv(
                "ERROR",
                result.get("error", "FAILED"),
                "bad"
            )

        else:
            display_data(
                result.get("data", {})
            )

            findings = result.get(
                "findings",
                []
            )

            if findings:

                for finding in findings:
                    text, severity = format_finding(finding)

                    print(
                        f"{status_tag(severity)} "
                        f"FINDING: {text}"
                    )

            else:
                print(f"{green('[OK]')} FINDING: NONE")

    section("SYSTEM ASSESSMENT")

    score = assessment["data"]["score"]

    verdict_text, verdict_status = verdict(score)

    kv("SCORE", str(score), verdict_status)
    kv("VERDICT", verdict_text, verdict_status)

    section("FINDINGS")

    all_findings = assessment["data"].get(
        "findings",
        []
    )

    issues = []

    for finding in all_findings:

        text, severity = format_finding(finding)

        if severity != "good":
            issues.append((text, severity))

    if issues:

        for text, severity in issues:
            print(
                f"{status_tag(severity)} "
                f"FINDING: {text}"
            )

    else:
        print(f"{green('[OK]')} FINDING: NONE")

    remediation_menu(all_findings)

    print()
    separator()
    print()

if __name__ == "__main__":
    main()
