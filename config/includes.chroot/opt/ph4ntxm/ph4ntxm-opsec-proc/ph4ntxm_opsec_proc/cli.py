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

def verdict(score):
    if score >= 85:
        return "NO HIGH-SEVERITY FINDINGS", "good"

    if score >= 60:
        return "REVIEW RECOMMENDED", "warn"

    return "ATTENTION REQUIRED", "bad"

def format_finding(finding):
    mapping = {
        "memfd_execution": ("MEMFD EXECUTION DETECTED", "bad"),
        "deleted_executable": ("DELETED EXECUTABLE DETECTED", "bad"),
        "ephemeral_executable": ("TMPFS EXECUTION DETECTED", "bad"),
        "untrusted_executable_path": ("UNTRUSTED EXECUTABLE PATH", "warn"),
        "suspicious_processes_present": ("SUSPICIOUS PROCESSES DETECTED", "bad"),
        "hidden_process_detected": ("HIDDEN PROCESS INDICATION", "info"),
        "process_visibility_mismatch": ("PROCESS VISIBILITY MISMATCH", "warn"),
        "detached_shell": ("SUSPICIOUS DETACHED SHELL", "warn"),
    }

    return mapping.get(
        finding,
        (finding.replace("_", " ").upper(), "warn")
    )

def process_status(proc):
    reasons = proc.get("reasons", [])

    if (
        "memfd_execution" in reasons
        or "deleted_executable" in reasons
    ):
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
        parts.append(f"STATE={safe_text(proc['state'], 32)}")

    if proc.get("exe"):
        parts.append(f"EXE={safe_text(proc['exe'], 320)}")

    return " ".join(parts)

def remediation_menu(suspicious):

    actionable = []

    for proc in suspicious:

        actions = available_actions(proc)

        if not actions:
            continue

        actionable.append({
            "proc": proc,
            "actions": actions
        })

    if not actionable:
        return

    section("PROCESS REMEDIATION")

    indexed = {}

    counter = 1

    for item in actionable:

        proc = item["proc"]

        print(
            f"{status_tag(process_status(proc))} "
            f"TARGET: "
            f"{format_process(proc)}"
        )

        print(
            f"    "
            f"{gray('AVAILABLE ACTIONS:')}"
        )

        for action_key in item["actions"]:

            action = PROCESS_ACTIONS[action_key]

            indexed[str(counter)] = {
                "proc": proc,
                "action_key": action_key,
            }

            print(
                f"    "
                f"{cyan(f'[{counter}]')} "
                f"{action['label'].upper()}"
            )

            print(
                f"        "
                f"{gray(action['description'].upper())}"
            )

            counter += 1

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

    print()

    for sel in selections:

        entry = indexed.get(sel)

        if not entry:

            print(
                f"{red('[FAIL]')} "
                f"INVALID SELECTION: {sel}"
            )

            print()

            continue

        proc = entry["proc"]

        action_key = entry["action_key"]

        action = PROCESS_ACTIONS[action_key]

        print(
            f"{status_tag('active')} "
            f"ACTION: "
            f"{action['label'].upper()}"
        )

        print(
            f"{status_tag('info')} "
            f"TARGET PID={proc.get('pid')}"
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

        result = action["action"](proc)

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
    section("PH4NTXM OPSEC PROCESS DIAGNOSTICS")

    process_data = list_processes()

    section("PROCESS ENUMERATION")

    if process_data["ok"]:

        processes = process_data["data"].get(
            "processes",
            []
        )

        kv(
            "PROCESSES",
            str(len(processes)),
            "active"
        )

        print()

        for proc in processes[:20]:

            kv(
                proc.get("name", "UNKNOWN"),
                format_process(proc),
                "active"
            )

    else:
        kv(
            "PROCESSES",
            process_data["error"],
            "bad"
        )

    analysis = analyze_processes(process_data)

    section("SUSPICIOUS PROCESSES")

    if analysis["ok"]:

        suspicious = analysis["data"].get(
            "suspicious",
            []
        )

        if suspicious:

            for proc in suspicious[:20]:

                reasons = proc.get(
                    "reasons",
                    []
                )

                displayed_reasons = [
                    reason
                    for reason in reasons
                    if reason != "detached_shell"
                ]

                reason_str = (
                    ", ".join(displayed_reasons)
                    if displayed_reasons
                    else "DETACHED SHELL"
                )

                print(
                    f"{status_tag(process_status(proc))} "
                    f"TARGET: "
                    f"{format_process(proc)}"
                )

                print(
                    f"    "
                    f"{gray('REASONS:')} "
                    f"{reason_str.upper()}"
                )

        else:
            print(f"{green('[OK]')} FINDING: NONE")

    else:
        kv(
            "ANALYSIS",
            analysis["error"],
            "bad"
        )

    assessment = assess_system(analysis)

    section("SYSTEM ASSESSMENT")

    if assessment["ok"]:

        score = assessment["data"]["score"]

        verdict_text, verdict_status = verdict(score)

        kv(
            "SCORE",
            str(score),
            verdict_status
        )

        kv(
            "VERDICT",
            verdict_text,
            verdict_status
        )

        section("FINDINGS")

        findings = assessment["data"].get(
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

    else:
        kv(
            "ASSESSMENT",
            assessment["error"],
            "bad"
        )

    if analysis["ok"]:
        remediation_menu(suspicious)

    print()
    separator()
    print()

if __name__ == "__main__":
    main()
