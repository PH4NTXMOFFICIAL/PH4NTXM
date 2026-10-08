# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from datetime import datetime, timezone
from pathlib import Path

from ph4ntxm_opsec_radio.checks import assess_radio, checks
from ph4ntxm_opsec_radio.checks import format_finding as describe_finding
from ph4ntxm_opsec_radio.remediation import REMEDIATIONS

CHECK_NAMES = {
    "check_bluetooth": "Bluetooth",
    "check_wifi": "Wi-Fi",
    "check_modem_state": "WWAN and modems",
    "check_monitor_mode": "Monitor mode",
    "check_nearby_scan": "Cached Wi-Fi observations",
    "check_nfc": "NFC",
    "check_gps_activity": "GPS location",
}

RADIO_ACTIONS = {
    "disable-bluetooth": {
        "check": "check_bluetooth",
        "findings": ("bluetooth_on",),
        "remediation": "bluetooth_on",
        "consequence": "Bluetooth peripherals will disconnect.",
    },
    "disable-wifi": {
        "check": "check_wifi",
        "findings": ("wifi_on",),
        "remediation": "wifi_on",
        "consequence": "Wi-Fi connections will disconnect.",
    },
    "disable-wwan": {
        "check": "check_modem_state",
        "findings": ("wwan_on", "modem_active"),
        "remediation": "wwan_on",
        "consequence": "Cellular network connections will disconnect.",
    },
    "disable-monitor": {
        "check": "check_monitor_mode",
        "findings": ("monitor_mode_active",),
        "remediation": "monitor_mode_active",
        "consequence": "Monitor interfaces will return to managed mode.",
    },
    "disable-nfc": {
        "check": "check_nfc",
        "findings": ("nfc_enabled",),
        "remediation": "nfc_enabled",
        "consequence": "Near-field communication will be blocked.",
    },
    "disable-gps": {
        "check": "check_gps_activity",
        "findings": ("gps_location_active",),
        "remediation": "gps_location_active",
        "consequence": "Modem GPS location sources will be disabled.",
    },
}


def verdict(score):
    if score >= 85:
        return "No high-severity findings", "good"
    if score >= 60:
        return "Review recommended", "warn"
    return "Attention required", "bad"


def format_finding(finding):
    text, status = describe_finding(finding)
    if finding.endswith("_unavailable"):
        status = "info"
    return text, status


def assessment_summary(report):
    score = report["assessment"]["data"]["score"]
    title, status = verdict(score)
    findings = report["assessment"]["data"].get("findings", [])
    if any(format_finding(finding)[1] == "bad" for finding in findings):
        title, status = "Attention required", "bad"
    if report["unavailable"]:
        title = "Assessment incomplete"
        if status == "good":
            status = "warn"
    return title, status


def collect_report(progress=None):
    outcomes = []
    unavailable = []
    try:
        mode = Path("/run/ph4ntxm/mode").read_text().strip().lower()
    except OSError:
        mode = None
    if mode not in ("linux", "windows", "lonewolf"):
        mode = None
        unavailable.append("The active PH4NTXM mode is unavailable.")

    for check in checks:
        name = check.__name__
        title = CHECK_NAMES.get(name, name)
        if progress is not None:
            progress(f"Checking {title}")
        try:
            outcome = check()
        except Exception as exc:
            outcome = {"ok": False, "data": {}, "findings": [], "error": str(exc)}
        outcomes.append({"name": name, "title": title, "result": outcome})
        if not outcome["ok"]:
            error = outcome.get("error") or "No error details were returned."
            unavailable.append(f"{title} could not be checked: {error}")

    assessment = assess_radio([item["result"] for item in outcomes])
    return {
        "mode": mode,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "checks": outcomes,
        "assessment": assessment,
        "unavailable": unavailable,
    }


def available_actions(report):
    findings = set(report["assessment"]["data"].get("findings", []))
    actions = []
    for name, definition in RADIO_ACTIONS.items():
        if not findings.intersection(definition["findings"]):
            continue
        remediation = REMEDIATIONS[definition["remediation"]]
        actions.append(
            {
                "name": name,
                "label": remediation["label"],
                "description": remediation["description"],
                "severity": remediation["severity"],
                "consequence": definition["consequence"],
            }
        )
    return actions


def report_text(report):
    score = report["assessment"]["data"]["score"]
    title, status = assessment_summary(report)
    lines = [
        "PH4NTXM OpSec Radio",
        f"Collected: {report['collected_at']}",
        f"Mode: {report.get('mode') or 'Unavailable'}",
        f"Score: {score}/100",
        f"Verdict: {title} [{status.upper()}]",
        "",
    ]
    for item in report["checks"]:
        lines.append(item["title"])
        outcome = item["result"]
        if not outcome["ok"]:
            lines.append(f"  [UNAVAILABLE] {outcome.get('error') or 'Check failed'}")
        for finding in outcome.get("findings", []):
            text, severity = format_finding(finding)
            lines.append(f"  [{severity.upper()}] {text}")
        for key, value in outcome.get("data", {}).items():
            lines.append(f"  {key}: {value}")
        lines.append("")
    lines.append("Wi-Fi observations use the local cache. No active scan is requested.")
    actions = available_actions(report)
    if actions:
        lines.extend(("", "Available actions"))
        for action in actions:
            lines.append(f"  {action['label']}: {action['description']}")
    return "\n".join(lines)
