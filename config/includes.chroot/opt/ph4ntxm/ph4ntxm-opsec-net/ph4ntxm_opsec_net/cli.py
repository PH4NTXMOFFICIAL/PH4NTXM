# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import sys
import os
from ph4ntxm_opsec_net.checks import (
    get_default_routes,
    analyze_routes,
    get_dns_servers,
    analyze_dns,
    detect_dns_backend,
    detect_ipv6_exposure,
    get_network_namespace,
    is_local_ip,
    get_active_connections,
    analyze_connections,
    assess_session,
)

from ph4ntxm_opsec_net.remediation import REMEDIATIONS
from ph4ntxm_opsec_net.remediation import lockdown_enabled

RESET = "\033[0m"
PH4NTXM_CYAN = "\033[38;2;0;171;255m"
PH4NTXM_MAGENTA = "\033[38;2;255;61;251m"
GREEN = "\033[38;2;68;209;122m"
AMBER = "\033[38;2;255;176;32m"
RED = "\033[38;2;255;77;90m"
GRAY = "\033[38;2;165;175;195m"
LINE_WIDTH = 78


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
    print(f"{status_tag(status)} {gray(f'{key}:'):<30} {value}")


def format_finding(finding):
    mapping = {
        "dns_external_resolver": ("External DNS resolver detected", "warn"),
        "active_connections_present": ("Active connections present", "info"),
        "suspicious_connections_present": (
            "Suspicious connection heuristic match",
            "warn",
        ),
        "namespace_shared": ("Using host network namespace (intentional)", "info"),
        "namespace_visibility_restricted": (
            "Network namespace visibility restricted",
            "info",
        ),
        "ipv6_enabled": ("IPv6 enabled", "warn"),
        "no_routes_detected": ("No default routes detected (offline)", "info"),
        "possible_reverse_shell": ("Shell-like public connection (heuristic)", "bad"),
        "unauthorized_dns_traffic": ("Unauthorized DNS traffic (leak)", "bad"),
        "unexpected_public_connection": ("Unexpected public connection", "bad"),
    }

    text, severity = mapping.get(
        finding, (finding.replace("_", " ").capitalize(), "warn")
    )

    return text, severity


def format_connection(conn):
    parts = []

    if conn.get("remote"):
        parts.append(f"Remote={conn['remote']}")

    if conn.get("process"):
        parts.append(f"Process={conn['process']}")

    if conn.get("pid"):
        parts.append(f"PID={conn['pid']}")

    if conn.get("uid") is not None:
        parts.append(f"UID={conn['uid']}")

    if conn.get("ptr"):
        parts.append(f"PTR={conn['ptr']}")

    if conn.get("exe"):
        parts.append(f"Executable={conn['exe']}")

    return " ".join(parts)


def verdict(score):
    if score >= 85:
        return "No high-severity findings", "good"

    if score >= 60:
        return "Review recommended", "warn"

    return "Attention required", "bad"


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

    lockdown_findings = {
        "active_connections_present",
        "suspicious_connections_present",
        "dns_external_resolver",
        "unauthorized_dns_traffic",
        "unexpected_public_connection",
    }

    for idx, finding in enumerate(remediable, start=1):

        remediation = REMEDIATIONS[finding].copy()

        if finding in lockdown_findings:

            enabled = lockdown_enabled()

            remediation["label"] = (
                "Disable Network Lockdown" if enabled else "Enable Network Lockdown"
            )

        indexed[str(idx)] = remediation

        print(f"{cyan(f'[{idx}]')} " f"{remediation['label']}")

        print(f"    " f"{gray(remediation['description'])}")

    print()

    choice = input(gray("Select targets " "[1 = Apply | Q = Quit]: ")).strip().lower()

    if not choice or choice == "q":
        return

    selections = [item.strip() for item in choice.split(",")]

    print()

    for sel in selections:

        remediation = indexed.get(sel)

        if not remediation:

            print(f"{red('[Fail]')} " f"Invalid selection: {sel}")

            print()

            continue

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

                print(f"{status_tag('info')} " f"{message}")

        else:

            error = result.get("error") or "Unknown Error"

            print(f"{red('[Fail]')} " f"{error}")

        print()


def main():
    section("PH4NTXM OpSec Network")

    route_data = get_default_routes()
    route_analysis = analyze_routes(route_data)

    section("Routes")

    if route_analysis["ok"]:

        for route in route_analysis["data"]["routes"]:
            kv(
                {"ipv4": "IPv4", "ipv6": "IPv6"}.get(route["family"], route["family"]),
                f"{route['interface'] or 'Unknown'} {route['gateway'] or '-'}",
                "good",
            )

    else:
        kv("Routes", red(route_analysis.get("error", "Failed")), "bad")

    dns_data = get_dns_servers()
    dns_analysis = analyze_dns(route_analysis, dns_data)

    section("DNS")

    if dns_analysis["ok"]:

        for server in dns_analysis["data"]["servers"]:

            is_private = is_local_ip(server)

            kv("Resolver", server, "good" if is_private else "active")

        backend = detect_dns_backend()

        if backend["ok"]:
            kv("Backend", backend["data"]["backend"], "active")

    else:
        kv("DNS", red(dns_analysis.get("error", "Failed")), "bad")

    ipv6 = detect_ipv6_exposure()
    namespace = get_network_namespace()

    section("Network State")

    if ipv6["ok"]:
        kv(
            "IPv6",
            "Enabled" if ipv6["data"]["enabled"] else "Disabled",
            "warn" if ipv6["data"]["enabled"] else "good",
        )
    else:
        kv("IPv6", ipv6.get("error", "Check Failed"), "bad")

    if namespace["ok"]:
        if namespace["data"].get("available"):
            kv(
                "Isolation",
                "Isolated" if namespace["data"]["isolated"] else "Shared",
                "good" if namespace["data"]["isolated"] else "active",
            )
        else:
            kv("Isolation", "Visibility Restricted", "info")

    connection_data = get_active_connections()
    connection_analysis = analyze_connections(connection_data)

    section("Active Connections")

    if connection_data["ok"]:

        if connection_data["data"]["connections"]:

            for conn in connection_data["data"]["connections"]:

                conn_status = "active"

                for suspicious in connection_analysis["data"].get("suspicious", []):
                    if conn.get("ip") == suspicious.get("ip") and conn.get(
                        "pid"
                    ) == suspicious.get("pid"):
                        conn_status = "bad"
                        break

                print(
                    f"{status_tag(conn_status)} " f"Finding: {format_connection(conn)}"
                )

        else:
            print(f"{green('[OK]')} Finding: No active connections found.")

    else:
        kv("Connections", red(connection_data.get("error", "Failed")), "bad")

    assessment = assess_session(
        route_analysis, dns_analysis, connection_analysis, ipv6, namespace
    )

    section("Session Assessment")

    if assessment["ok"]:

        score = assessment["data"]["score"]

        v_text, v_status = verdict(score)

        kv("Score", str(score), v_status)
        kv("Verdict", v_text, v_status)

        findings = assessment["data"].get("findings", [])

        section("Findings")

        if findings:

            for f in findings:
                text, severity = format_finding(f)
                print(f"{status_tag(severity)} Finding: {text}")

        else:
            print(f"{green('[OK]')} Finding: None")

    else:
        kv("Assessment", red(assessment.get("error", "Failed")), "bad")

    if assessment["ok"]:

        remediation_menu(assessment["data"].get("findings", []))

    separator()
    print()


if __name__ == "__main__":
    main()
