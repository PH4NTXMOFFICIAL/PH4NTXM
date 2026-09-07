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
    print(f"{status_tag(status)} {gray(f'{key}:'):<30} {value}")

def format_finding(finding):
    mapping = {
        "dns_external_resolver": ("EXTERNAL DNS RESOLVER DETECTED", "warn"),
        "active_connections_present": ("ACTIVE CONNECTIONS PRESENT", "info"),
        "suspicious_connections_present": ("SUSPICIOUS CONNECTION HEURISTIC MATCH", "warn"),
        "namespace_shared": ("USING HOST NETWORK NAMESPACE (INTENTIONAL)", "info"),
        "namespace_visibility_restricted": ("NETWORK NAMESPACE VISIBILITY RESTRICTED", "info"),
        "ipv6_enabled": ("IPV6 ENABLED", "warn"),
        "no_routes_detected": ("NO DEFAULT ROUTES DETECTED (OFFLINE)", "info"),
        "possible_reverse_shell": ("SHELL-LIKE PUBLIC CONNECTION (HEURISTIC)", "bad"),
        "unauthorized_dns_traffic": ("UNAUTHORIZED DNS TRAFFIC (LEAK)", "bad"),
        "unexpected_public_connection": ("UNEXPECTED PUBLIC CONNECTION", "bad"),
    }

    text, severity = mapping.get(
        finding,
        (finding.replace("_", " ").upper(), "warn")
    )

    return text, severity

def format_connection(conn):
    parts = []

    if conn.get("remote"):
        parts.append(f"REMOTE={conn['remote']}")

    if conn.get("process"):
        parts.append(f"PROC={conn['process']}")

    if conn.get("pid"):
        parts.append(f"PID={conn['pid']}")

    if conn.get("uid") is not None:
        parts.append(f"UID={conn['uid']}")

    if conn.get("ptr"):
        parts.append(f"PTR={conn['ptr']}")

    if conn.get("exe"):
        parts.append(f"EXE={conn['exe']}")

    return " ".join(parts)

def verdict(score):
    if score >= 85:
        return "NO HIGH-SEVERITY FINDINGS", "good"

    if score >= 60:
        return "REVIEW RECOMMENDED", "warn"

    return "ATTENTION REQUIRED", "bad"

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
                "Disable Network Lockdown"
                if enabled
                else "Enable Network Lockdown"
            )

        indexed[str(idx)] = remediation

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
            "[1 = APPLY | Q = QUIT]: "
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

        remediation = indexed.get(sel)

        if not remediation:

            print(
                f"{red('[FAIL]')} "
                f"INVALID SELECTION: {sel}"
            )

            print()

            continue

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
                    f"{message.upper()}"
                )

        else:

            error = (
                result.get("error")
                or "Unknown error"
            )

            print(
                f"{red('[FAIL]')} "
                f"{error.upper()}"
            )

        print()

def main():
    section("PH4NTXM OPSEC NETWORK DIAGNOSTICS")

    route_data = get_default_routes()
    route_analysis = analyze_routes(route_data)

    section("ROUTES")

    if route_analysis["ok"]:

        for route in route_analysis["data"]["routes"]:
            kv(
                route["family"].upper(),
                f"{route['interface'] or 'UNKNOWN'} {route['gateway'] or '-'}",
                "good"
            )

    else:
        kv("ROUTES", red(route_analysis.get("error", "FAILED")), "bad")

    dns_data = get_dns_servers()
    dns_analysis = analyze_dns(route_analysis, dns_data)

    section("DNS")

    if dns_analysis["ok"]:

        for server in dns_analysis["data"]["servers"]:

            is_private = is_local_ip(server)

            kv(
                "RESOLVER",
                server.upper(),
                "good" if is_private else "active"
            )

        backend = detect_dns_backend()

        if backend["ok"]:
            kv(
                "BACKEND",
                backend["data"]["backend"].upper(),
                "active"
            )

    else:
        kv("DNS", red(dns_analysis.get("error", "FAILED")), "bad")

    ipv6 = detect_ipv6_exposure()
    namespace = get_network_namespace()

    section("NETWORK STATE")

    if ipv6["ok"]:
        kv(
            "IPV6",
            "ENABLED" if ipv6["data"]["enabled"] else "DISABLED",
            "warn" if ipv6["data"]["enabled"] else "good"
        )
    else:
        kv("IPV6", ipv6.get("error", "CHECK FAILED"), "bad")

    if namespace["ok"]:
        if namespace["data"].get("available"):
            kv(
                "ISOLATION",
                "ISOLATED" if namespace["data"]["isolated"] else "SHARED",
                "good" if namespace["data"]["isolated"] else "active"
            )
        else:
            kv("ISOLATION", "VISIBILITY RESTRICTED", "info")

    connection_data = get_active_connections()
    connection_analysis = analyze_connections(connection_data)

    section("ACTIVE CONNECTIONS")

    if connection_data["ok"]:

        if connection_data["data"]["connections"]:

            for conn in connection_data["data"]["connections"]:

                conn_status = "active"

                for suspicious in connection_analysis["data"].get("suspicious", []):
                    if (
                        conn.get("ip") == suspicious.get("ip")
                        and conn.get("pid") == suspicious.get("pid")
                    ):
                        conn_status = "bad"
                        break

                print(
                    f"{status_tag(conn_status)} "
                    f"FINDING: {format_connection(conn)}"
                )

        else:
            print(f"{green('[OK]')} FINDING: NO ACTIVE CONNECTIONS FOUND.")

    else:
        kv(
            "CONNECTIONS",
            red(connection_data.get("error", "FAILED")),
            "bad"
        )

    assessment = assess_session(
        route_analysis,
        dns_analysis,
        connection_analysis,
        ipv6,
        namespace
    )

    section("SESSION ASSESSMENT")

    if assessment["ok"]:

        score = assessment["data"]["score"]

        v_text, v_status = verdict(score)

        kv("SCORE", str(score), v_status)
        kv("VERDICT", v_text, v_status)

        findings = assessment["data"].get("findings", [])

        section("FINDINGS")

        if findings:

            for f in findings:
                text, severity = format_finding(f)
                print(f"{status_tag(severity)} FINDING: {text}")

        else:
            print(f"{green('[OK]')} FINDING: NONE")

    else:
        kv(
            "ASSESSMENT",
            red(assessment.get("error", "FAILED")),
            "bad"
        )

    if assessment["ok"]:

        remediation_menu(
            assessment["data"].get(
                "findings",
                []
            )
        )

    separator()
    print()

if __name__ == "__main__":
    main()
