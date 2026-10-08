# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from datetime import datetime, timezone

from ph4ntxm_opsec_kernel.checks import (
    get_kernel_info,
    get_loaded_modules,
    analyze_modules,
    get_sysctl_state,
    analyze_sysctl_state,
    get_kernel_hardening,
    assess_kernel,
    read_file,
)


def verdict(score):
    if score >= 85:
        return "No high-severity findings", "good"

    if score >= 60:
        return "Review recommended", "warn"

    return "Attention required", "bad"


def format_finding(finding):
    mapping = {
        "suspicious_modules_present": ("Suspicious modules detected", "bad"),
        "suspicious_module_name": ("Suspicious module name", "warn"),
        "kernel_lockdown_disabled": (
            "Kernel lockdown unavailable (intentional)",
            "info",
        ),
        "module_signature_enforcement_disabled": (
            "Module signature enforcement disabled (intentional)",
            "info",
        ),
        "modules_loading_enabled": (
            "Module loading is still enabled (intentional)",
            "info",
        ),
        "kptr_restrict_disabled": ("Kernel pointer restrictions disabled", "bad"),
        "dmesg_restrict_disabled": ("Kernel dmesg restriction disabled", "warn"),
        "unrestricted_bpf": ("Unrestricted BPF enabled", "warn"),
        "ptrace_scope_weak": ("Weak ptrace restrictions", "warn"),
        "randomize_va_space_disabled": (
            "ASLR (address space randomization) disabled",
            "bad",
        ),
        "perf_event_paranoid_weak": ("Weak perf_event restrictions", "warn"),
        "unprivileged_userns_enabled_warn": (
            "Unprivileged userns clone enabled (intentional)",
            "info",
        ),
        "unprivileged_userfaultfd_enabled": (
            "Unprivileged userfaultfd enabled",
            "warn",
        ),
        "kexec_enabled": ("kexec loader available", "info"),
        "crashkernel_not_armed": ("Crashkernel fallback not armed", "warn"),
        "kexec_loader_unlocked": (
            "Crashkernel armed but kexec loader unlocked",
            "warn",
        ),
        "sysrq_enabled": ("Keyboard SysRq enabled", "warn"),
        "rp_filter_disabled": ("Reverse path filter disabled", "info"),
        "rp_filter_profile_mismatch": (
            "Reverse path filter does not match active mode",
            "warn",
        ),
        "bpf_jit_harden_disabled": ("BPF JIT hardening disabled (intentional)", "info"),
        "tcp_timestamps_disabled": (
            "TCP timestamps disabled by active profile",
            "info",
        ),
        "tcp_sack_disabled": ("TCP SACK disabled by active profile", "info"),
        "tcp_timestamps_profile_mismatch": (
            "TCP timestamps do not match active mode",
            "warn",
        ),
        "tcp_sack_profile_mismatch": ("TCP SACK does not match active mode", "warn"),
        "tcp_syncookies_disabled": ("TCP SYN cookies disabled", "warn"),
        "accept_redirects_enabled": ("ICMP redirects accepted", "warn"),
        "send_redirects_enabled": ("ICMP redirects sending enabled", "warn"),
        "accept_source_route_enabled": ("IP source routing enabled", "warn"),
        "ipv6_enabled_warn": ("IPv6 state does not match active mode", "warn"),
    }

    text, severity = mapping.get(
        finding, (finding.replace("_", " ").capitalize(), "warn")
    )

    return text, severity


def module_status(module):
    reasons = module.get("reasons", [])

    if "ephemeral_module" in reasons:
        return "bad"

    if reasons:
        return "warn"

    return "active"


def format_module(module):
    parts = []

    if module.get("size"):
        parts.append(f"Size={module['size']}")

    if module.get("used_by"):
        parts.append(f"Used by={module['used_by']}")

    if module.get("path"):
        parts.append(f"Path={module['path']}")

    return " ".join(parts)


def hardening_status(key, value, mode, unsupported=()):
    hardened = {
        "kernel.kptr_restrict": ("1", "2"),
        "kernel.dmesg_restrict": ("1",),
        "kernel.yama.ptrace_scope": ("1", "2", "3"),
        "kernel.unprivileged_bpf_disabled": ("1", "2"),
        "kernel.unprivileged_userns_clone": ("0",),
        "kernel.kexec_load_disabled": ("1",),
        "kernel.randomize_va_space": ("2",),
        "kernel.perf_event_paranoid": ("2", "3", "4"),
        "kernel.sysrq": ("0",),
        "vm.unprivileged_userfaultfd": ("0",),
        "net.ipv4.tcp_syncookies": ("1",),
        "net.ipv4.conf.all.accept_redirects": ("0",),
        "net.ipv4.conf.default.accept_redirects": ("0",),
        "net.ipv4.conf.all.send_redirects": ("0",),
        "net.ipv4.conf.default.send_redirects": ("0",),
        "net.ipv4.conf.all.accept_source_route": ("0",),
        "net.ipv4.conf.default.accept_source_route": ("0",),
        "net.core.bpf_jit_harden": ("1", "2"),
        "net.ipv6.conf.all.disable_ipv6": ("1",),
        "net.ipv6.conf.default.disable_ipv6": ("1",),
    }

    profile_values = {
        "linux": {
            "net.ipv4.conf.all.rp_filter": ("2",),
            "net.ipv4.conf.default.rp_filter": ("2",),
            "net.ipv4.tcp_timestamps": ("1",),
            "net.ipv4.tcp_sack": ("1",),
            "net.ipv6.conf.all.disable_ipv6": ("0",),
            "net.ipv6.conf.default.disable_ipv6": ("0",),
        },
        "windows": {
            "net.ipv4.conf.all.rp_filter": ("2",),
            "net.ipv4.conf.default.rp_filter": ("2",),
            "net.ipv4.tcp_timestamps": ("0",),
            "net.ipv4.tcp_sack": ("1",),
            "net.ipv6.conf.all.disable_ipv6": ("0",),
            "net.ipv6.conf.default.disable_ipv6": ("0",),
        },
        "lonewolf": {
            "net.ipv4.conf.all.rp_filter": ("1",),
            "net.ipv4.conf.default.rp_filter": ("1",),
            "net.ipv4.tcp_timestamps": ("0",),
            "net.ipv4.tcp_sack": ("1",),
            "net.ipv6.conf.all.disable_ipv6": ("1",),
            "net.ipv6.conf.default.disable_ipv6": ("1",),
        },
    }

    allowed = profile_values.get(mode, {}).get(key, hardened.get(key))

    if not allowed:
        return None

    if value is None:
        return "info" if key in unsupported else "warn"

    return "good" if str(value) in allowed else "warn"


def collect_report(progress=None):
    mode = read_file("/run/ph4ntxm/mode")

    if progress is not None:
        progress("Reading kernel information")
    kernel_info = get_kernel_info()

    if progress is not None:
        progress("Reading loaded modules")
    modules = get_loaded_modules()
    module_analysis = analyze_modules(modules)

    if progress is not None:
        progress("Reading sysctl settings")
    sysctl_state = get_sysctl_state()
    sysctl_analysis = analyze_sysctl_state(sysctl_state, mode=mode)

    if progress is not None:
        progress("Reading kernel hardening")
    hardening = get_kernel_hardening()
    assessment = assess_kernel(module_analysis, sysctl_analysis, hardening)

    collected = {
        "kernel_info": kernel_info,
        "modules": modules,
        "module_analysis": module_analysis,
        "sysctl_state": sysctl_state,
        "sysctl_analysis": sysctl_analysis,
        "hardening": hardening,
        "assessment": assessment,
    }
    unavailable = []
    information = []

    if mode not in ("linux", "windows", "lonewolf"):
        unavailable.append("The active PH4NTXM mode is unavailable.")

    result_labels = {
        "kernel_info": "Kernel information",
        "modules": "Loaded modules",
        "module_analysis": "Module analysis",
        "sysctl_state": "Sysctl settings",
        "sysctl_analysis": "Sysctl analysis",
        "hardening": "Kernel hardening",
        "assessment": "Kernel assessment",
    }
    for name, outcome in collected.items():
        if not outcome["ok"]:
            error = outcome.get("error") or "No error details were returned."
            unavailable.append(f"{result_labels[name]} could not be collected: {error}")

    if modules["ok"]:
        missing_paths = sum(
            not module.get("path")
            for module in modules["data"].get("modules", [])
        )
        if missing_paths:
            noun = "module" if missing_paths == 1 else "modules"
            unavailable.append(
                f"Module paths are unavailable for {missing_paths} loaded {noun}."
            )

    if sysctl_state["ok"]:
        unsupported = sysctl_state["data"].get("unsupported", [])
        missing_sysctls = sum(
            value is None and key not in unsupported
            for key, value in sysctl_state["data"].get("values", {}).items()
        )
        information.extend(
            f"{key} interface is not exposed." for key in unsupported
        )
        if missing_sysctls:
            noun = "setting is" if missing_sysctls == 1 else "settings are"
            unavailable.append(f"{missing_sysctls} sysctl {noun} unavailable.")

    if hardening["ok"]:
        hardening_labels = {
            "lockdown": "Kernel lockdown",
            "modules_disabled": "Module loading restrictions",
            "module_sig_enforce": "Module signature enforcement",
            "crashkernel_loaded": "Crashkernel",
            "kexec_loader_locked": "Kexec loader restrictions",
        }
        raw_values = hardening["data"].get("raw_values", {})
        unsupported = hardening["data"].get("unsupported", [])
        for key, label in hardening_labels.items():
            if raw_values.get(key) is None:
                if key in unsupported:
                    information.append(f"{label} interface is not exposed.")
                else:
                    unavailable.append(f"{label} evidence is unavailable.")

    return {
        "mode": mode,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        **collected,
        "unavailable": unavailable,
        "information": information,
    }
