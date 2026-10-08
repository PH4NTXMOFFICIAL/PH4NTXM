# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from ph4ntxm_opsec_kernel.report import (
    collect_report,
    verdict,
    format_finding,
    hardening_status,
    module_status,
    format_module,
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

    report = collect_report()
    kernel_info = report["kernel_info"]

    section("Kernel")

    if kernel_info["ok"]:

        data = kernel_info["data"]

        kv("Kernel", data.get("kernel", "unknown"), "active")
        kv("Hostname", data.get("hostname", "unknown"), "active")
        kv("Architecture", data.get("architecture", "unknown"), "active")

    else:
        kv("Kernel", kernel_info["error"], "bad")

    modules = report["modules"]

    section("Loaded Modules")

    if modules["ok"]:

        loaded = modules["data"].get("modules", [])

        kv("Loaded Modules", str(len(loaded)), "active")

        print()

        for module in loaded[:20]:
            kv(module.get("name", "Unknown"), format_module(module), "active")

    else:
        kv("Modules", modules["error"], "bad")

    module_analysis = report["module_analysis"]

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

    sysctl_state = report["sysctl_state"]
    mode = report["mode"]

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

    hardening = report["hardening"]

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

    assessment = report["assessment"]

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
