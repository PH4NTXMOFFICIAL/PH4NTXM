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

def verdict(score):
    if score >= 85:
        return "NO HIGH-SEVERITY FINDINGS", "good"

    if score >= 60:
        return "REVIEW RECOMMENDED", "warn"

    return "ATTENTION REQUIRED", "bad"

def format_finding(finding):
    mapping = {
        "suspicious_modules_present": ("SUSPICIOUS MODULES DETECTED", "bad"),
        "suspicious_module_name": ("SUSPICIOUS MODULE NAME", "warn"),
        "kernel_lockdown_disabled": ("KERNEL LOCKDOWN UNAVAILABLE (INTENTIONAL)", "info"),
        "module_signature_enforcement_disabled": ("MODULE SIGNATURE ENFORCEMENT DISABLED (INTENTIONAL)", "info"),
        "modules_loading_enabled": ("MODULE LOADING IS STILL ENABLED (INTENTIONAL)", "info"),
        "kptr_restrict_disabled": ("KERNEL POINTER RESTRICTIONS DISABLED", "bad"),
        "dmesg_restrict_disabled": ("KERNEL DMESG RESTRICTION DISABLED", "warn"),
        "unrestricted_bpf": ("UNRESTRICTED BPF ENABLED", "warn"),
        "ptrace_scope_weak": ("WEAK PTRACE RESTRICTIONS", "warn"),
        "randomize_va_space_disabled": ("ASLR (ADDRESS SPACE RANDOMIZATION) DISABLED", "bad"),
        "perf_event_paranoid_weak": ("WEAK PERF_EVENT RESTRICTIONS", "warn"),
        "unprivileged_userns_enabled_warn": ("UNPRIVILEGED USERNS CLONE ENABLED (INTENTIONAL)", "info"),
        "unprivileged_userfaultfd_enabled": ("UNPRIVILEGED USERFAULTFD ENABLED", "warn"),
        "kexec_enabled": ("KEXEC LOADER AVAILABLE", "info"),
        "crashkernel_not_armed": ("CRASHKERNEL FALLBACK NOT ARMED", "warn"),
        "kexec_loader_unlocked": ("CRASHKERNEL ARMED BUT KEXEC LOADER UNLOCKED", "warn"),
        "sysrq_enabled": ("KEYBOARD SYSRQ ENABLED", "warn"),
        "rp_filter_disabled": ("REVERSE PATH FILTER DISABLED", "info"),
        "rp_filter_profile_mismatch": ("REVERSE PATH FILTER DOES NOT MATCH ACTIVE MODE", "warn"),
        "bpf_jit_harden_disabled": ("BPF JIT HARDENING DISABLED (INTENTIONAL)", "info"),
        "tcp_timestamps_disabled": ("TCP TIMESTAMPS DISABLED BY ACTIVE PROFILE", "info"),
        "tcp_sack_disabled": ("TCP SACK DISABLED BY ACTIVE PROFILE", "info"),
        "tcp_timestamps_profile_mismatch": ("TCP TIMESTAMPS DO NOT MATCH ACTIVE MODE", "warn"),
        "tcp_sack_profile_mismatch": ("TCP SACK DOES NOT MATCH ACTIVE MODE", "warn"),
        "tcp_syncookies_disabled": ("TCP SYNCOOKIES DISABLED", "warn"),
        "accept_redirects_enabled": ("ICMP REDIRECTS ACCEPTED", "warn"),
        "send_redirects_enabled": ("ICMP REDIRECTS SENDING ENABLED", "warn"),
        "accept_source_route_enabled": ("IP SOURCE ROUTING ENABLED", "warn"),
        "ipv6_enabled_warn": ("IPV6 STATE DOES NOT MATCH ACTIVE MODE", "warn"),
    }

    text, severity = mapping.get(
        finding,
        (finding.replace("_", " ").upper(), "warn")
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
        parts.append(f"SIZE={module['size']}")

    if module.get("used_by"):
        parts.append(f"USED_BY={module['used_by']}")

    if module.get("path"):
        parts.append(f"PATH={module['path']}")

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
        return amber("NONE"), "warn"

    return green(normalized.upper()), "good"

def render_modules_disabled(value):
    return (
        (green("ENABLED"), "good")
        if value
        else (amber("DISABLED"), "warn")
    )

def render_module_sig_enforce(value):
    return (
        (green("ENABLED"), "good")
        if value
        else (amber("DISABLED"), "warn")
    )

def main():
    section("PH4NTXM OPSEC KERNEL DIAGNOSTICS")

    kernel_info = get_kernel_info()

    section("KERNEL")

    if kernel_info["ok"]:

        data = kernel_info["data"]

        kv("KERNEL", data.get("kernel", "unknown"), "active")
        kv("HOSTNAME", data.get("hostname", "unknown"), "active")
        kv("ARCHITECTURE", data.get("architecture", "unknown"), "active")

    else:
        kv("KERNEL", kernel_info["error"], "bad")

    modules = get_loaded_modules()

    section("LOADED MODULES")

    if modules["ok"]:

        loaded = modules["data"].get("modules", [])

        kv("LOADED MODULES", str(len(loaded)), "active")

        print()

        for module in loaded[:20]:
            kv(
                module.get("name", "UNKNOWN"),
                format_module(module),
                "active"
            )

    else:
        kv("MODULES", modules["error"], "bad")

    module_analysis = analyze_modules(modules)

    section("MODULE ANALYSIS")

    if module_analysis["ok"]:

        suspicious = module_analysis["data"].get(
            "suspicious",
            []
        )

        if suspicious:

            for module in suspicious[:20]:

                reasons = ", ".join(
                    module.get("reasons", [])
                )

                kv(
                    module.get("name", "UNKNOWN"),
                    f"{format_module(module)} [{reasons}]",
                    module_status(module)
                )

        else:
            kv("STATUS", green("NONE"), "good")

    else:
        kv("ANALYSIS", module_analysis["error"], "bad")

    sysctl_state = get_sysctl_state()
    sysctl_analysis = analyze_sysctl_state(sysctl_state)
    try:
        with open("/run/ph4ntxm/mode", "r") as handle:
            mode = handle.read().strip()
    except OSError:
        mode = None

    section("SYSCTL")

    if sysctl_state["ok"]:

        values = sysctl_state["data"].get("values", {})

        for key, value in values.items():
            kv(
                key,
                "UNAVAILABLE" if value is None else str(value),
                hardening_status(key, value, mode)
            )

    else:
        kv("SYSCTL", sysctl_state["error"], "bad")

    hardening = get_kernel_hardening()

    section("HARDENING")

    if hardening["ok"]:

        data = hardening["data"]

        lockdown_rendered, lockdown_status = render_lockdown(
            data.get("lockdown")
        )

        kv("LOCKDOWN", lockdown_rendered, lockdown_status)

        modules_rendered, modules_status = render_modules_disabled(
            data.get("modules_disabled")
        )

        kv(
            "MODULES_DISABLED",
            modules_rendered,
            modules_status
        )

        sig_rendered, sig_status = render_module_sig_enforce(
            data.get("module_sig_enforce")
        )

        kv(
            "MODULE_SIG_ENFORCE",
            sig_rendered,
            sig_status
        )

        kv(
            "CRASHKERNEL",
            "ARMED" if data.get("crashkernel_loaded") else "NOT ARMED",
            "good" if data.get("crashkernel_loaded") else "warn",
        )
        kv(
            "KEXEC LOADER",
            "LOCKED" if data.get("kexec_loader_locked") else "UNLOCKED",
            "good" if data.get("kexec_loader_locked") else "warn",
        )

    else:
        kv("HARDENING", hardening["error"], "bad")

    assessment = assess_kernel(
        module_analysis,
        sysctl_analysis,
        hardening
    )

    section("KERNEL ASSESSMENT")

    if assessment["ok"]:

        score = assessment["data"].get("score", 0)

        verdict_text, verdict_status = verdict(score)

        kv("SCORE", str(score), verdict_status)
        kv("VERDICT", verdict_text, verdict_status)

        section("FINDINGS")

        all_findings = assessment["data"].get("findings", [])

        issues = []
        for f in all_findings:
            text, severity = format_finding(f)
            if severity != "good":
                issues.append((text, severity))

        if issues:
            for text, severity in issues:
                print(f"{status_tag(severity)} FINDING: {text}")
        else:
            print(f"{green('[OK]')} FINDING: NONE")

    else:
        kv("ASSESSMENT", assessment["error"], "bad")

    print()
    separator()
    print()

if __name__ == "__main__":
    main()
