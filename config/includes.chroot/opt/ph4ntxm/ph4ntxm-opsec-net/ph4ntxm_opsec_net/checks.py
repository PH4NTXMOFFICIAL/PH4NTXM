import ipaddress
import os
import socket
import subprocess

SEVERITY = {
    "active_connections_present": 0,
    "suspicious_connections_present": 20,
    "unauthorized_dns_traffic": 20,
    "ipv6_enabled": 10,
    "dns_external_resolver": 20,
    "unexpected_public_connection": 15,
    "namespace_shared": 0,
}

SHELL_INTERPRETERS = (
    "bash",
    "sh",
    "zsh",
    "python",
    "perl",
    "ruby",
    "nc",
    "socat",
    "ncat",
)

TRUSTED_PATH_PREFIXES = (
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
    "/bin/",
    "/sbin/",
    "/opt/",
)

LOOPBACK_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)

RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

LINK_LOCAL_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
)

ENABLE_PTR_LOOKUP = os.environ.get("PH4NTXM_PTR_LOOKUP") == "1"
IP = "/usr/sbin/ip"
SS = "/usr/bin/ss"
SYSCTL = "/usr/sbin/sysctl"

def result(ok, data=None, error=None, findings=None):
    return {"ok": ok, "data": data or {}, "error": error, "findings": findings or []}

def run(command, timeout=5):
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode != 0:
            return result(False, error=proc.stderr.strip())
        return result(True, data={"stdout": proc.stdout.strip()})
    except subprocess.TimeoutExpired:
        return result(False, error="command timeout")
    except Exception as exc:
        return result(False, error=str(exc))

def normalize_ip(ip):
    try:
        return str(ipaddress.ip_address(ip.split("%", 1)[0]))
    except Exception:
        return None

def is_loopback_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in LOOPBACK_NETWORKS)
    except Exception:
        return False

def is_local_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in RFC1918_NETWORKS + LINK_LOCAL_NETWORKS) or addr.is_loopback
    except Exception:
        return False

def is_rfc1918(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in RFC1918_NETWORKS)
    except Exception:
        return False

def extract_ip(remote):
    if not remote:
        return None
    remote = remote.strip()
    if remote.startswith("["):
        try:
            return normalize_ip(remote.split("]")[0][1:])
        except Exception:
            return None
    try:
        host, _ = remote.rsplit(":", 1)
        return normalize_ip(host)
    except Exception:
        return normalize_ip(remote)

def resolve_ptr(ip):
    try:
        address = ipaddress.ip_address(ip)
        if address.is_loopback or address.is_unspecified:
            return None
        return socket.gethostbyaddr(str(address))[0]
    except Exception:
        return None

def get_default_routes():
    routes = []
    for family, cmd in (("ipv4", [IP, "route"]), ("ipv6", [IP, "-6", "route"])):
        output = run(cmd)
        if not output["ok"]:
            continue
        for line in output["data"]["stdout"].splitlines():
            line = line.strip()
            if line.startswith("default"):
                routes.append({"family": family, "raw": line})
    return result(True, data={"routes": routes})

def analyze_routes(route_data):
    if not route_data["ok"]:
        return route_data
    analyzed = []
    for route in route_data["data"]["routes"]:
        interface = gateway = None
        parts = route["raw"].split()
        for i, p in enumerate(parts):
            if p == "dev" and i + 1 < len(parts):
                interface = parts[i + 1]
            if p == "via" and i + 1 < len(parts):
                gateway = parts[i + 1]
        analyzed.append({"family": route["family"], "interface": interface, "gateway": gateway, "raw": route["raw"]})
    return result(True, data={"routes": analyzed})

def get_dns_servers():
    servers = []
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("nameserver"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip = normalize_ip(parts[1])
                if ip:
                    servers.append(ip)
        return result(True, data={"servers": sorted(set(servers))})
    except Exception as e:
        return result(False, error=str(e))

def detect_dns_backend():
    try:
        target = os.readlink("/etc/resolv.conf")
        return result(True, data={"backend": target})
    except Exception:
        return result(True, data={"backend": "static"})

def analyze_dns(route_analysis, dns_data):
    if not route_analysis["ok"] or not dns_data["ok"]:
        return result(False, error="missing route or dns data")

    findings = []
    dns_servers = dns_data["data"]["servers"]
    external = False

    for s in dns_servers:
        if is_loopback_ip(s):
            findings.append(f"local_stub_resolver:{s}")
        elif is_rfc1918(s):
            findings.append(f"private_resolver:{s}")
        elif is_local_ip(s):
            findings.append(f"local_network_resolver:{s}")
        else:
            external = True
            findings.append(f"external_resolver:{s}")

    if external:
        findings.append("dns_external_resolver")
    if not dns_servers:
        findings.append("no_dns_servers_detected")

    return result(True, data={"servers": dns_servers}, findings=findings)

def detect_ipv6_exposure():
    output = run([SYSCTL, "-n", "net.ipv6.conf.all.disable_ipv6"])
    if not output["ok"]:
        return output
    disabled = output["data"]["stdout"].strip() == "1"
    return result(True, data={"enabled": not disabled}, findings=["ipv6_enabled"] if not disabled else [])

def get_network_namespace():
    try:
        current = os.readlink("/proc/self/ns/net")
        init = os.readlink("/proc/1/ns/net")
        isolated = current != init
        return result(True, data={"namespace": current, "isolated": isolated, "available": True}, findings=[] if isolated else ["namespace_shared"])
    except OSError:
        return result(True, data={"namespace": "unavailable", "isolated": False, "available": False})

def get_active_connections():
    output = run([SS, "-tupnH"])
    if not output["ok"]:
        return output

    connections = []
    for line in output["data"]["stdout"].splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue

        remote = parts[5]
        process = pid = exe = uid = None
        info_only = False

        if "users:(" in line:
            try:
                process = line.split('"')[1]
            except Exception:
                info_only = True

        if "pid=" in line:
            try:
                pid = line.split("pid=")[1].split(",")[0]
            except Exception:
                info_only = True

        if pid:
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except Exception:
                info_only = True
            try:
                uid = os.stat(f"/proc/{pid}").st_uid
            except Exception:
                info_only = True
        else:
            info_only = True

        ip = extract_ip(remote)

        if not ip:
            continue

        connections.append({
            "ip": ip,
            "remote": remote,
            "process": process,
            "pid": pid,
            "exe": exe,
            "uid": uid,
            "info_only": info_only,
            "ptr": resolve_ptr(ip) if ip and ENABLE_PTR_LOOKUP else None,
        })

    return result(True, data={"connections": connections})

def analyze_connections(connection_data):
    if not connection_data["ok"]:
        return connection_data

    suspicious = []
    connections = connection_data["data"]["connections"]

    if not connections:
        return result(True, data={"connections": connections, "suspicious": suspicious}, findings=[])

    for conn in connections:
        ip = conn.get("ip")
        if not ip or is_loopback_ip(ip):
            continue

        reasons = []
        exe = conn.get("exe") or ""
        process = conn.get("process") or ""
        info_only = conn.get("info_only", False)

        try:
            is_public = ipaddress.ip_address(ip).is_global
        except Exception:
            is_public = False

        exe_l = exe.lower()
        proc_l = process.lower()
        exe_name = os.path.basename(exe_l.replace(" (deleted)", ""))
        proc_name = proc_l.rsplit("/", 1)[-1]

        if not info_only:
            if exe.startswith("/tmp/") or exe.startswith("/dev/shm/"):
                reasons.append("ephemeral_executable")
            if exe and not exe.startswith(TRUSTED_PATH_PREFIXES):
                reasons.append("untrusted_executable_path")
            if " (deleted)" in exe:
                reasons.append("deleted_executable")
            if "memfd:" in exe:
                reasons.append("memfd_execution")
            if exe_name in SHELL_INTERPRETERS or proc_name in SHELL_INTERPRETERS:
                if is_public:
                    reasons.append("possible_reverse_shell")

        if reasons:
            suspicious.append({**conn, "reasons": reasons})

    return result(True, data={"connections": connections, "suspicious": suspicious}, findings=[r for c in suspicious for r in c.get("reasons", [])])

def assess_session(route_analysis, dns_analysis, connection_analysis, ipv6, namespace):
    if not all([route_analysis["ok"], dns_analysis["ok"], connection_analysis["ok"], ipv6["ok"], namespace["ok"]]):
        return result(False, error="missing data")

    score = 100
    findings = []

    if any("external_resolver" in f for f in dns_analysis.get("findings", [])):
        score -= SEVERITY["dns_external_resolver"]
        findings.append("dns_external_resolver")

    if not route_analysis["data"]["routes"]:
        findings.append("no_routes_detected")

    if ipv6["data"]["enabled"]:
        try:
            with open("/run/ph4ntxm/mode", "r", encoding="ascii") as handle:
                mode = handle.read().strip()
        except OSError:
            mode = None
        if mode == "lonewolf":
            score -= SEVERITY["ipv6_enabled"]
            findings.append("ipv6_enabled")

    if connection_analysis["data"].get("connections"):
        findings.append("active_connections_present")

    if connection_analysis["data"].get("suspicious"):
        score -= SEVERITY["suspicious_connections_present"]
        findings.append("suspicious_connections_present")
        findings.extend(connection_analysis.get("findings", []))

    if namespace["data"].get("available") and not namespace["data"]["isolated"]:
        score -= SEVERITY["namespace_shared"]
        findings.append("namespace_shared")
    elif not namespace["data"].get("available"):
        findings.append("namespace_visibility_restricted")

    return result(True, data={"score": max(0, score), "findings": sorted(set(findings))})
