# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from ph4ntxm_opsec_kernel.checks import (
    get_kernel_info,
    get_loaded_modules,
    analyze_modules,
    get_sysctl_state,
    analyze_sysctl_state,
    get_kernel_hardening,
    assess_kernel,
)

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


def hardening_status(key, value, mode):
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
        return "warn"

    return "good" if str(value) in allowed else "warn"


def render_lockdown(value):
    normalized = str(value).strip().lower()
    normalized = normalized.replace("[", "").replace("]", "")

    if not normalized or normalized == "none":
        return amber("None"), "warn"

    return green(normalized.capitalize()), "good"


def render_modules_disabled(value):
    return (green("Enabled"), "good") if value else (amber("Disabled"), "warn")


def render_module_sig_enforce(value):
    return (green("Enabled"), "good") if value else (amber("Disabled"), "warn")


def main():
    section("PH4NTXM OpSec Kernel")

    kernel_info = get_kernel_info()

    section("Kernel")

    if kernel_info["ok"]:

        data = kernel_info["data"]

        kv("Kernel", data.get("kernel", "unknown"), "active")
        kv("Hostname", data.get("hostname", "unknown"), "active")
        kv("Architecture", data.get("architecture", "unknown"), "active")

    else:
        kv("Kernel", kernel_info["error"], "bad")

    modules = get_loaded_modules()

    section("Loaded Modules")

    if modules["ok"]:

        loaded = modules["data"].get("modules", [])

        kv("Loaded Modules", str(len(loaded)), "active")

        print()

        for module in loaded[:20]:
            kv(module.get("name", "Unknown"), format_module(module), "active")

    else:
        kv("Modules", modules["error"], "bad")

    module_analysis = analyze_modules(modules)

    section("Module Analysis")

    if module_analysis["ok"]:

        suspicious = module_analysis["data"].get("suspicious", [])

        if suspicious:

            for module in suspicious[:20]:

                reasons = ", ".join(module.get("reasons", []))

                kv(
                    module.get("name", "Unknown"),
                    f"{format_module(module)} [{reasons}]",
                    module_status(module),
                )

        else:
            kv("Status", green("None"), "good")

    else:
        kv("Analysis", module_analysis["error"], "bad")

    sysctl_state = get_sysctl_state()
    sysctl_analysis = analyze_sysctl_state(sysctl_state)
    try:
        with open("/run/ph4ntxm/mode", "r") as handle:
            mode = handle.read().strip()
    except OSError:
        mode = None

    section("sysctl")

    if sysctl_state["ok"]:

        values = sysctl_state["data"].get("values", {})

        for key, value in values.items():
            kv(
                key,
                "Unavailable" if value is None else str(value),
                hardening_status(key, value, mode),
            )

    else:
        kv("sysctl", sysctl_state["error"], "bad")

    hardening = get_kernel_hardening()

    section("Hardening")

    if hardening["ok"]:

        data = hardening["data"]

        lockdown_rendered, lockdown_status = render_lockdown(data.get("lockdown"))

        kv("Lockdown", lockdown_rendered, lockdown_status)

        modules_rendered, modules_status = render_modules_disabled(
            data.get("modules_disabled")
        )

        kv("Module Loading Disabled", modules_rendered, modules_status)

        sig_rendered, sig_status = render_module_sig_enforce(
            data.get("module_sig_enforce")
        )

        kv("Module Signature Enforcement", sig_rendered, sig_status)

        kv(
            "Crashkernel",
            "Armed" if data.get("crashkernel_loaded") else "Not Armed",
            "good" if data.get("crashkernel_loaded") else "warn",
        )
        kv(
            "kexec Loader",
            "Locked" if data.get("kexec_loader_locked") else "Unlocked",
            "good" if data.get("kexec_loader_locked") else "warn",
        )

    else:
        kv("Hardening", hardening["error"], "bad")

    assessment = assess_kernel(module_analysis, sysctl_analysis, hardening)

    section("Kernel Assessment")

    if assessment["ok"]:

        score = assessment["data"].get("score", 0)

        verdict_text, verdict_status = verdict(score)

        kv("Score", str(score), verdict_status)
        kv("Verdict", verdict_text, verdict_status)

        section("Findings")

        all_findings = assessment["data"].get("findings", [])

        issues = []
        for f in all_findings:
            text, severity = format_finding(f)
            if severity != "good":
                issues.append((text, severity))

        if issues:
            for text, severity in issues:
                print(f"{status_tag(severity)} Finding: {text}")
        else:
            print(f"{green('[OK]')} Finding: None")

    else:
        kv("Assessment", assessment["error"], "bad")

    print()
    separator()
    print()


if __name__ == "__main__":
    main()
