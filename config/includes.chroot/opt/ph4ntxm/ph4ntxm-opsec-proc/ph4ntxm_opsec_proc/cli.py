# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import sys
import os
from ph4ntxm_opsec_proc.checks import (
    list_processes,
    analyze_processes,
    assess_system,
)

from ph4ntxm_opsec_proc.remediation import (
    PROCESS_ACTIONS,
    available_actions,
)

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
        f"{gray(f'{safe_text(key, 80)}:'):<30} "
        f"{safe_text(value)}"
    )


def verdict(score):
    if score >= 85:
        return "No high-severity findings", "good"

    if score >= 60:
        return "Review recommended", "warn"

    return "Attention required", "bad"


def format_finding(finding):
    mapping = {
        "memfd_execution": ("memfd execution detected", "bad"),
        "deleted_executable": ("Deleted executable detected", "bad"),
        "ephemeral_executable": ("tmpfs execution detected", "bad"),
        "untrusted_executable_path": ("Untrusted executable path", "warn"),
        "suspicious_processes_present": ("Suspicious processes detected", "bad"),
        "hidden_process_detected": ("Hidden process indication", "info"),
        "process_visibility_mismatch": ("Process visibility mismatch", "warn"),
        "detached_shell": ("Suspicious detached shell", "warn"),
    }

    return mapping.get(finding, (finding.replace("_", " ").capitalize(), "warn"))


def process_status(proc):
    reasons = proc.get("reasons", [])

    if "memfd_execution" in reasons or "deleted_executable" in reasons:
        return "bad"

    if reasons:
        return "warn"

    return "active"


def format_process(proc):
    parts = []

    if proc.get("pid"):
        parts.append(f"PID={safe_text(proc['pid'], 32)}")

    if proc.get("ppid"):
        parts.append(f"PPID={safe_text(proc['ppid'], 32)}")

    if proc.get("uid") is not None:
        parts.append(f"UID={safe_text(proc['uid'], 32)}")

    if proc.get("state"):
        parts.append(f"State={safe_text(proc['state'], 32)}")

    if proc.get("exe"):
        parts.append(f"Executable={safe_text(proc['exe'], 320)}")

    return " ".join(parts)


def remediation_menu(suspicious):

    actionable = []

    for proc in suspicious:

        actions = available_actions(proc)

        if not actions:
            continue

        actionable.append({"proc": proc, "actions": actions})

    if not actionable:
        return

    section("Process Remediation")

    indexed = {}

    counter = 1

    for item in actionable:

        proc = item["proc"]

        print(
            f"{status_tag(process_status(proc))} " f"Target: " f"{format_process(proc)}"
        )

        print(f"    " f"{gray('Available Actions:')}")

        for action_key in item["actions"]:

            action = PROCESS_ACTIONS[action_key]

            indexed[str(counter)] = {
                "proc": proc,
                "action_key": action_key,
            }

            print(f"    " f"{cyan(f'[{counter}]')} " f"{action['label']}")

            print(f"        " f"{gray(action['description'])}")

            counter += 1

        print()

    choice = input(gray("Select targets " "[1,2 = Apply | Q = Quit]: ")).strip().lower()

    if not choice or choice == "q":
        return

    selections = [item.strip() for item in choice.split(",")]

    print()

    for sel in selections:

        entry = indexed.get(sel)

        if not entry:

            print(f"{red('[Fail]')} " f"Invalid selection: {sel}")

            print()

            continue

        proc = entry["proc"]

        action_key = entry["action_key"]

        action = PROCESS_ACTIONS[action_key]

        print(f"{status_tag('active')} " f"Action: " f"{action['label']}")

        print(f"{status_tag('info')} " f"Target PID={proc.get('pid')}")

        confirm = input(gray("Apply remediation? [y/N]: ")).strip().lower()

        if confirm != "y":

            print(f"{status_tag('info')} " f"Skipped")

            print()

            continue

        result = action["action"](proc)

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
    section("PH4NTXM OpSec Process")

    process_data = list_processes()

    section("Process Enumeration")

    if process_data["ok"]:

        processes = process_data["data"].get("processes", [])

        kv("Processes", str(len(processes)), "active")

        print()

        for proc in processes[:20]:

            kv(proc.get("name", "Unknown"), format_process(proc), "active")

    else:
        kv("Processes", process_data["error"], "bad")

    analysis = analyze_processes(process_data)

    section("Suspicious Processes")

    if analysis["ok"]:

        suspicious = analysis["data"].get("suspicious", [])

        if suspicious:

            for proc in suspicious[:20]:

                reasons = proc.get("reasons", [])

                displayed_reasons = [
                    reason for reason in reasons if reason != "detached_shell"
                ]

                reason_str = (
                    ", ".join(displayed_reasons)
                    if displayed_reasons
                    else "Detached Shell"
                )

                print(
                    f"{status_tag(process_status(proc))} "
                    f"Target: "
                    f"{format_process(proc)}"
                )

                print(f"    " f"{gray('Reasons:')} " f"{reason_str}")

        else:
            print(f"{green('[OK]')} Finding: None")

    else:
        kv("Analysis", analysis["error"], "bad")

    assessment = assess_system(analysis)

    section("System Assessment")

    if assessment["ok"]:

        score = assessment["data"]["score"]

        verdict_text, verdict_status = verdict(score)

        kv("Score", str(score), verdict_status)

        kv("Verdict", verdict_text, verdict_status)

        section("Findings")

        findings = assessment["data"].get("findings", [])

        if findings:

            for finding in findings:

                text, severity = format_finding(finding)

                print(f"{status_tag(severity)} " f"Finding: {text}")

        else:
            print(f"{green('[OK]')} Finding: None")

    else:
        kv("Assessment", assessment["error"], "bad")

    if analysis["ok"]:
        remediation_menu(suspicious)

    print()
    separator()
    print()


if __name__ == "__main__":
    main()
