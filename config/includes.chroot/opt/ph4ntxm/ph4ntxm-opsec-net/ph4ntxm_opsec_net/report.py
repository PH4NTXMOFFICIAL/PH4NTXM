# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from datetime import datetime, timezone

from ph4ntxm_opsec_net.checks import (
    get_default_routes,
    analyze_routes,
    get_dns_servers,
    analyze_dns,
    detect_dns_backend,
    detect_ipv6_exposure,
    get_network_namespace,
    get_active_connections,
    analyze_connections,
    assess_session,
)
from ph4ntxm_opsec_net.remediation import lockdown_enabled


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


def connection_status(connection, suspicious):
    if any(
        connection.get("ip") == item.get("ip")
        and connection.get("pid") == item.get("pid")
        for item in suspicious
    ):
        return "bad"
    return "info"


def collect_report(progress=None):
    try:
        with open("/run/ph4ntxm/mode", "r", encoding="ascii") as handle:
            mode = handle.read().strip()
    except OSError:
        mode = None

    if progress is not None:
        progress("Reading default routes")
    route_data = get_default_routes()
    route_analysis = analyze_routes(route_data)

    if progress is not None:
        progress("Reading DNS configuration")
    dns_data = get_dns_servers()
    dns_analysis = analyze_dns(route_analysis, dns_data)
    dns_backend = detect_dns_backend()

    if progress is not None:
        progress("Reading IPv6 and network namespace evidence")
    ipv6 = detect_ipv6_exposure()
    namespace = get_network_namespace()

    if progress is not None:
        progress("Reading active connections and process details")
    connection_data = get_active_connections()
    connection_analysis = analyze_connections(connection_data)
    assessment = assess_session(
        route_analysis, dns_analysis, connection_analysis, ipv6, namespace, mode=mode
    )
    collected = {
        "route_data": route_data,
        "route_analysis": route_analysis,
        "dns_data": dns_data,
        "dns_analysis": dns_analysis,
        "dns_backend": dns_backend,
        "ipv6": ipv6,
        "namespace": namespace,
        "connection_data": connection_data,
        "connection_analysis": connection_analysis,
        "assessment": assessment,
    }
    unavailable = []
    if not mode:
        unavailable.append("The active PH4NTXM mode is unavailable.")
    names = {
        "route_data": "Default routes",
        "route_analysis": "Route analysis",
        "dns_data": "DNS servers",
        "dns_analysis": "DNS analysis",
        "dns_backend": "DNS backend",
        "ipv6": "IPv6 state",
        "namespace": "Network namespace",
        "connection_data": "Active connections",
        "connection_analysis": "Connection analysis",
        "assessment": "Network assessment",
    }
    for name, outcome in collected.items():
        if not outcome["ok"]:
            error = outcome.get("error") or "No error details were returned."
            unavailable.append(f"{names[name]} could not be collected: {error}")
    for missing in route_data["data"].get("unavailable", []):
        family = {"ipv4": "IPv4", "ipv6": "IPv6"}.get(missing["family"], missing["family"])
        error = missing.get("error") or "No error details were returned."
        unavailable.append(f"{family} route evidence is unavailable: {error}")
    if namespace["ok"] and not namespace["data"].get("available"):
        unavailable.append("Network namespace visibility is restricted.")
    if connection_data["ok"]:
        count = sum(
            connection.get("info_only", False)
            for connection in connection_data["data"].get("connections", [])
        )
        if count:
            noun = "connection" if count == 1 else "connections"
            unavailable.append(f"Process details are incomplete for {count} {noun}.")
    lockdown_state = bool(lockdown_enabled())
    return {
        "mode": mode,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        **collected,
        "lockdown_enabled": lockdown_state,
        "unavailable": unavailable,
    }


def plain_report(report):
    lines = [
        "PH4NTXM OpSec Network",
        f"Collected: {report['collected_at']}",
        f"Active mode: {report.get('mode') or 'Unavailable'}",
        f"Network lockdown: {'Enabled' if report['lockdown_enabled'] else 'Disabled'}",
    ]
    assessment = report["assessment"]
    if assessment["ok"]:
        score = assessment["data"]["score"]
        lines.extend([f"Score: {score}/100", f"Verdict: {verdict(score)[0]}"])
    lines.extend(["", "Findings"])
    if assessment["ok"]:
        findings = assessment["data"].get("findings", [])
        lines.extend(format_finding(item)[0] for item in findings)
        if not findings:
            lines.append("None")
    else:
        lines.append(assessment.get("error") or "Assessment unavailable")
    lines.extend(["", "Default routes"])
    routes = report["route_analysis"]["data"].get("routes", [])
    lines.extend(f"{route['family']}: {route['raw']}" for route in routes)
    if not routes:
        lines.append("No default routes detected")
    lines.extend(["", "DNS"])
    lines.extend(report["dns_data"]["data"].get("servers", []))
    lines.append(f"Backend: {report['dns_backend']['data'].get('backend', 'Unavailable')}")
    lines.extend(["", "IPv6 and network namespace"])
    if report["ipv6"]["ok"]:
        lines.append(f"IPv6: {'Enabled' if report['ipv6']['data']['enabled'] else 'Disabled'}")
    else:
        lines.append("IPv6: Unavailable")
    namespace = report["namespace"]["data"]
    lines.append(f"Current namespace: {namespace.get('namespace', 'Unavailable')}")
    lines.append(f"Init namespace: {namespace.get('init_namespace') or 'Unavailable'}")
    lines.extend(["", "Active connections"])
    connections = report["connection_data"]["data"].get("connections", [])
    for connection in connections:
        lines.append(
            f"{connection.get('protocol', 'Unknown')} {connection.get('state', 'Unknown')} "
            f"Local={connection.get('local', 'Unavailable')} {format_connection(connection)}"
        )
        if connection.get("raw"):
            lines.append(connection["raw"])
    if not connections:
        lines.append("No active connections detected")
    if report["unavailable"]:
        lines.extend(["", "Unavailable evidence", *report["unavailable"]])
    return "\n".join(lines)
