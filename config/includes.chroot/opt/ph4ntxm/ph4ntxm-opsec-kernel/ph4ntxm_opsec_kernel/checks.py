import os
import platform
import socket
import subprocess

SYSCTL = "/usr/sbin/sysctl"
LSMOD = "/usr/sbin/lsmod"
MODINFO = "/usr/sbin/modinfo"

SEVERITY = {
    "suspicious_modules_present": 15,
    "suspicious_module_name": 5,
    "kernel_lockdown_disabled": 0,
    "module_signature_enforcement_disabled": 0,
    "modules_loading_enabled": 0,
    "kptr_restrict_disabled": 20,
    "dmesg_restrict_disabled": 10,
    "unrestricted_bpf": 10,
    "ptrace_scope_weak": 10,
    "randomize_va_space_disabled": 20,
    "perf_event_paranoid_weak": 10,
    "unprivileged_userns_enabled_warn": 0,
    "unprivileged_userfaultfd_enabled": 10,
    "kexec_enabled": 0,
    "crashkernel_not_armed": 10,
    "kexec_loader_unlocked": 10,
    "sysrq_enabled": 20,
    "rp_filter_disabled": 0,
    "rp_filter_profile_mismatch": 10,
    "bpf_jit_harden_disabled": 0,
    "tcp_timestamps_disabled": 0,
    "tcp_sack_disabled": 0,
    "tcp_timestamps_profile_mismatch": 10,
    "tcp_sack_profile_mismatch": 10,
    "ipv6_enabled_warn": 10,
    "tcp_syncookies_disabled": 10,
    "accept_redirects_enabled": 10,
    "send_redirects_enabled": 10,
    "accept_source_route_enabled": 20,
}

TRUSTED_MODULE_PATHS = (
    "/lib/modules/",
    "/usr/lib/modules/",
    "/etc/modules/",
    "/opt/modules/",
)

SUSPICIOUS_MODULE_NAMES = (
    "rootkit",
    "diamorphine",
    "reptile",
    "ftrace_hook",
    "override",
    "inject",
)

SYSCTL_KEYS = (
    "kernel.kptr_restrict",
    "kernel.dmesg_restrict",
    "kernel.unprivileged_bpf_disabled",
    "kernel.kexec_load_disabled",
    "kernel.yama.ptrace_scope",
    "kernel.unprivileged_userns_clone",
    "kernel.randomize_va_space",
    "kernel.perf_event_paranoid",
    "kernel.sysrq",
    "vm.unprivileged_userfaultfd",
    "net.ipv4.tcp_syncookies",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.default.send_redirects",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.default.accept_source_route",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
    "net.ipv4.tcp_timestamps",
    "net.ipv4.tcp_sack",
    "net.core.bpf_jit_harden",
    "net.ipv6.conf.all.disable_ipv6",
    "net.ipv6.conf.default.disable_ipv6",
)

def result(ok, data=None, error=None, warnings=None, evidence=None):
    return {
        "ok": ok,
        "data": data or {},
        "error": error,
        "warnings": warnings or [],
        "evidence": evidence or [],
    }

def run(command, timeout=5):
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

        if proc.returncode != 0:
            return result(False, error=proc.stderr.strip())

        return result(True, data={"stdout": proc.stdout.strip()})

    except subprocess.TimeoutExpired:
        return result(False, error="command timeout")

    except Exception as exc:
        return result(False, error=str(exc))

def get_kernel_info():
    try:
        return result(
            True,
            data={
                "kernel": platform.release(),
                "architecture": platform.machine(),
                "hostname": socket.gethostname(),
            },
        )

    except Exception as exc:
        return result(False, error=str(exc))

def get_loaded_modules():
    modules = []

    output = run([LSMOD])

    if not output["ok"]:
        return output

    lines = output["data"]["stdout"].splitlines()

    for line in lines[1:]:

        parts = line.split()

        if len(parts) < 3:
            continue

        name, size, used_by = parts[:3]

        path_output = run([MODINFO, "-n", name])

        path = (
            path_output["data"]["stdout"].strip()
            if path_output["ok"]
            else None
        )

        modules.append({
            "name": name,
            "size": size,
            "used_by": used_by,
            "path": path,
        })

    return result(True, data={"modules": modules})

def analyze_modules(module_data):
    if not module_data["ok"]:
        return module_data

    suspicious = []

    for module in module_data["data"].get("modules", []):

        reasons = []

        name = (module.get("name") or "").lower()
        path = module.get("path") or ""

        if any(token in name for token in SUSPICIOUS_MODULE_NAMES):
            reasons.append("suspicious_module_name")

        if path:

            if not path.startswith(TRUSTED_MODULE_PATHS):
                reasons.append("untrusted_module_path")

            if path.startswith("/tmp/") or path.startswith("/dev/shm/"):
                reasons.append("ephemeral_module")

        if reasons:
            suspicious.append({
                "name": module.get("name"),
                "size": module.get("size"),
                "used_by": module.get("used_by"),
                "path": module.get("path"),
                "reasons": reasons,
            })

    return result(True, data={"suspicious": suspicious})

def read_sysctl(key):
    output = run([SYSCTL, "-n", key])

    if not output["ok"]:
        return None

    return output["data"]["stdout"].strip()

def get_sysctl_state():
    values = {
        key: read_sysctl(key)
        for key in SYSCTL_KEYS
    }

    return result(True, data={"values": values})

def analyze_sysctl_state(sysctl_state):
    if not sysctl_state["ok"]: return sysctl_state
    findings = []
    values = sysctl_state["data"].get("values", {})

    if values.get("kernel.kptr_restrict") == "0": findings.append("kptr_restrict_disabled")
    if values.get("kernel.dmesg_restrict") == "0": findings.append("dmesg_restrict_disabled")
    if values.get("kernel.unprivileged_bpf_disabled") == "0": findings.append("unrestricted_bpf")
    if values.get("kernel.yama.ptrace_scope") == "0": findings.append("ptrace_scope_weak")
    if values.get("kernel.randomize_va_space") == "0": findings.append("randomize_va_space_disabled")
    if values.get("kernel.perf_event_paranoid") is not None and values.get("kernel.perf_event_paranoid") not in ("2", "3", "4"): findings.append("perf_event_paranoid_weak")
    if values.get("vm.unprivileged_userfaultfd") is not None and values.get("vm.unprivileged_userfaultfd") != "0": findings.append("unprivileged_userfaultfd_enabled")
    if values.get("kernel.unprivileged_userns_clone") == "1": findings.append("unprivileged_userns_enabled_warn")
    if values.get("kernel.sysrq") is not None and values.get("kernel.sysrq") != "0": findings.append("sysrq_enabled")
    if values.get("net.core.bpf_jit_harden") == "0": findings.append("bpf_jit_harden_disabled")
    if values.get("net.ipv4.tcp_syncookies") == "0": findings.append("tcp_syncookies_disabled")
    mode = read_file("/run/ph4ntxm/mode")
    expected = {
        "linux": {"timestamps": "1", "sack": "1", "rp_filter": "2", "ipv6": "0"},
        "windows": {"timestamps": "0", "sack": "1", "rp_filter": "2", "ipv6": "0"},
        "lonewolf": {"timestamps": "0", "sack": "1", "rp_filter": "1", "ipv6": "1"},
    }.get(mode)

    if expected is not None:
        if values.get("net.ipv4.tcp_timestamps") is not None and values.get("net.ipv4.tcp_timestamps") != expected["timestamps"]:
            findings.append("tcp_timestamps_profile_mismatch")
        if values.get("net.ipv4.tcp_sack") is not None and values.get("net.ipv4.tcp_sack") != expected["sack"]:
            findings.append("tcp_sack_profile_mismatch")
        rp_filter_values = (
            values.get("net.ipv4.conf.all.rp_filter"),
            values.get("net.ipv4.conf.default.rp_filter"),
        )
        if None not in rp_filter_values and (expected["rp_filter"] not in rp_filter_values or rp_filter_values[0] != rp_filter_values[1]):
            findings.append("rp_filter_profile_mismatch")
        ipv6_values = (
            values.get("net.ipv6.conf.all.disable_ipv6"),
            values.get("net.ipv6.conf.default.disable_ipv6"),
        )
        if None not in ipv6_values and (expected["ipv6"] not in ipv6_values or ipv6_values[0] != ipv6_values[1]):
            findings.append("ipv6_enabled_warn")

    if values.get("kernel.kexec_load_disabled") == "0": findings.append("kexec_enabled")
    if values.get("net.ipv4.tcp_timestamps") == "0": findings.append("tcp_timestamps_disabled")
    if values.get("net.ipv4.tcp_sack") == "0": findings.append("tcp_sack_disabled")
    if "0" in (values.get("net.ipv4.conf.all.rp_filter"), values.get("net.ipv4.conf.default.rp_filter")):
        findings.append("rp_filter_disabled")

    if "1" in (values.get("net.ipv4.conf.all.accept_redirects"), values.get("net.ipv4.conf.default.accept_redirects")):
        findings.append("accept_redirects_enabled")

    if "1" in (values.get("net.ipv4.conf.all.send_redirects"), values.get("net.ipv4.conf.default.send_redirects")):
        findings.append("send_redirects_enabled")

    if "1" in (values.get("net.ipv4.conf.all.accept_source_route"), values.get("net.ipv4.conf.default.accept_source_route")):
        findings.append("accept_source_route_enabled")

    return result(True, data={"findings": findings})

def read_file(path):
    try:
        with open(path, "r") as handle:
            return handle.read().strip()

    except Exception:
        return None

def get_kernel_hardening():
    lockdown = read_file("/sys/kernel/security/lockdown")

    lockdown_mode = None

    if lockdown:
        for part in lockdown.split():
            if part.startswith("[") and part.endswith("]"):
                lockdown_mode = part.strip("[]")
                break

    modules_disabled = read_file("/proc/sys/kernel/modules_disabled")
    crashkernel_loaded = read_file("/sys/kernel/kexec_crash_loaded")
    kexec_load_disabled = read_file("/proc/sys/kernel/kexec_load_disabled")

    module_sig_enforce = read_file(
        "/proc/sys/kernel/module_sig_enforce"
    )

    return result(
        True,
        data={
            "lockdown": lockdown_mode,
            "modules_disabled": modules_disabled == "1",
            "module_sig_enforce": module_sig_enforce == "1",
            "crashkernel_loaded": crashkernel_loaded == "1",
            "kexec_loader_locked": kexec_load_disabled == "1",
        }
    )

def assess_kernel(module_analysis, sysctl_analysis, hardening):
    findings = []
    score = 100

    if module_analysis["ok"]:

        suspicious = module_analysis["data"].get(
            "suspicious",
            []
        )

        if suspicious:
            findings.append("suspicious_modules_present")

        for module in suspicious:
            findings.extend(module.get("reasons", []))

    if sysctl_analysis["ok"]:
        findings.extend(
            sysctl_analysis["data"].get("findings", [])
        )

    if hardening["ok"]:
        data = hardening["data"]

        if data.get("lockdown") in (None, "none"):
            findings.append("kernel_lockdown_disabled")

        if not data.get("module_sig_enforce"):
            findings.append("module_signature_enforcement_disabled")

        if not data.get("modules_disabled"):
            findings.append("modules_loading_enabled")

        if not data.get("crashkernel_loaded"):
            findings.append("crashkernel_not_armed")
        elif not data.get("kexec_loader_locked"):
            findings.append("kexec_loader_unlocked")

    findings = list(dict.fromkeys(findings))

    for finding in findings:
        score -= SEVERITY.get(finding, 0)

    score = max(0, min(score, 100))

    return result(
        True,
        data={
            "score": score,
            "findings": findings,
        }
    )
