# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

from ph4ntxm_opsec_ui import (
    Application,
    ReportWindow,
    STATUS_LABELS,
    add_class,
    data_row,
    finding_row,
    label,
    scroll,
    section,
    set_status,
)
from ph4ntxm_opsec_kernel.report import (
    collect_report,
    format_finding,
    hardening_status,
    module_status,
    verdict,
)


def hardening_rows(report):
    data = report["hardening"]["data"]
    raw = data.get("raw_values", {})
    unsupported = data.get("unsupported", [])
    rows = [
        (
            "lockdown",
            "Kernel lockdown",
            (data.get("lockdown") or "None").capitalize(),
            "good" if data.get("lockdown") not in (None, "none") else "info",
        ),
        (
            "modules_disabled",
            "Module loading",
            "Disabled" if data.get("modules_disabled") else "Enabled",
            "good" if data.get("modules_disabled") else "info",
        ),
        (
            "module_sig_enforce",
            "Module signatures",
            "Enforced" if data.get("module_sig_enforce") else "Not enforced",
            "good" if data.get("module_sig_enforce") else "info",
        ),
        (
            "crashkernel_loaded",
            "Crashkernel fallback",
            "Armed" if data.get("crashkernel_loaded") else "Not armed",
            "good" if data.get("crashkernel_loaded") else "warn",
        ),
        (
            "kexec_loader_locked",
            "Kexec loader",
            "Locked" if data.get("kexec_loader_locked") else "Unlocked",
            (
                "good"
                if data.get("kexec_loader_locked")
                else "warn" if data.get("crashkernel_loaded") else "info"
            ),
        ),
    ]
    return [
        (
            name,
            (
                value
                if raw.get(key) is not None
                else "Not exposed" if key in unsupported else "Unavailable"
            ),
            (
                status
                if raw.get(key) is not None
                else "info" if key in unsupported else "warn"
            ),
        )
        for key, name, value, status in rows
    ]


def report_findings(report):
    data = report["hardening"]["data"]
    raw = data.get("raw_values", {})
    unsupported = data.get("unsupported", [])
    evidence_fields = {
        "kernel_lockdown_disabled": (
            "lockdown",
            "Kernel lockdown state could not be verified",
        ),
        "module_signature_enforcement_disabled": (
            "module_sig_enforce",
            "Module signature enforcement could not be verified",
        ),
        "modules_loading_enabled": (
            "modules_disabled",
            "Module loading restrictions could not be verified",
        ),
        "crashkernel_not_armed": (
            "crashkernel_loaded",
            "Crashkernel arming could not be verified",
        ),
        "kexec_loader_unlocked": (
            "kexec_loader_locked",
            "Kexec loader locking could not be verified",
        ),
    }
    findings = []
    for finding in report["assessment"]["data"].get("findings", []):
        text, status = format_finding(finding)
        evidence = evidence_fields.get(finding)
        if evidence and raw.get(evidence[0]) is None:
            if evidence[0] in unsupported:
                continue
            text, status = evidence[1], "warn"
        findings.append((text, status))
    return findings


def hardening_label(name, value, status):
    if value == "Not exposed":
        return "Info"
    if value == "Unavailable":
        return "Unavailable"
    if status == "info" and name in (
        "Kernel lockdown", "Module loading", "Module signatures"
    ):
        return "Intentional"
    return STATUS_LABELS[status]


class KernelWindow(ReportWindow):
    def __init__(self, application):
        super().__init__(
            application,
            "PH4NTXM OpSec Kernel",
            "Kernel security inspection",
            "ph4ntxm-opsec-kernel",
        )

    def build_pages(self):
        self.overview = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.stack.add_titled(scroll(self.overview), "overview", "Overview")
        self.build_modules()
        self.sysctls = Gtk.ListStore(str, str, str)
        view = self.table(
            self.sysctls,
            (("Setting", 0, 420), ("Value", 1, 100), ("Assessment", 2, 130)),
        )
        self.stack.add_titled(scroll(view), "sysctl", "sysctl")
        self.hardening = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.stack.add_titled(scroll(self.hardening), "hardening", "Hardening")

    def clear_pages(self):
        self.clear(self.hardening)
        self.modules.clear()
        self.sysctls.clear()
        self.stack.child_set_property(
            self.stack.get_child_by_name("modules"), "title", "Modules"
        )
        self.module_details.set_text("Loaded modules will appear after the check")

    def collect_report(self, progress):
        return collect_report(progress)

    def build_modules(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text("Search modules or paths")
        self.search.connect("search-changed", self.filter_modules)
        self.review_only = Gtk.CheckButton(label="Review only")
        self.review_only.set_tooltip_text(
            "Show flagged modules and modules with unavailable paths"
        )
        self.review_only.connect("toggled", self.filter_modules)
        controls.pack_start(self.search, True, True, 0)
        controls.pack_end(self.review_only, False, False, 0)
        page.pack_start(controls, False, False, 0)
        self.modules = Gtk.ListStore(str, str, str, str, str, str)
        self.filtered_modules = self.modules.filter_new()
        self.filtered_modules.set_visible_func(self.module_visible)
        self.sorted_modules = Gtk.TreeModelSort(model=self.filtered_modules)
        for column in (2, 3):
            self.sorted_modules.set_sort_func(column, self.compare_numbers, column)
        view = self.table(
            self.sorted_modules,
            (
                ("Module", 0, 160),
                ("Status", 1, 110),
                ("Size (bytes)", 2, 110),
                ("Users", 3, 70),
                ("Module path", 4, 300),
            ),
        )
        view.get_selection().connect("changed", self.select_module)
        view.set_tooltip_column(4)
        page.pack_start(scroll(view), True, True, 0)
        self.module_details = label(
            "Select a module to see its full path and findings", "data-value", True
        )
        self.module_details.set_max_width_chars(90)
        page.pack_start(self.module_details, False, False, 0)
        self.stack.add_titled(page, "modules", "Modules")

    def module_visible(self, model, iterator, _):
        row = model[iterator]
        query = self.search.get_text().strip().casefold()
        return (not self.review_only.get_active() or row[1] != "Loaded") and (
            not query or query in " ".join((row[0], row[4], row[5])).casefold()
        )

    def filter_modules(self, _):
        self.filtered_modules.refilter()

    def compare_numbers(self, model, first, second, column):
        values = [model[iterator][column] for iterator in (first, second)]
        first_value, second_value = [
            int(value) if value.isdecimal() else -1 for value in values
        ]
        return (first_value > second_value) - (first_value < second_value)

    def select_module(self, selection):
        model, iterator = selection.get_selected()
        if iterator is None:
            self.module_details.set_text(
                "Select a module to see its full path and findings"
            )
            return
        row = model[iterator]
        details = f"{row[0]} · {row[1]}\n{row[4]}"
        if row[5]:
            details += f"\n{row[5]}"
        self.module_details.set_text(details)

    def populate(self, report):
        assessment = report["assessment"]
        findings = report_findings(report) if assessment["ok"] else []
        issues = [(text, level) for text, level in findings if level in ("warn", "bad")]
        information = [(text, level) for text, level in findings if level == "info"]
        information.extend((text, "info") for text in report.get("information", []))
        score = assessment["data"].get("score", 0)
        title, status = (
            verdict(score) if assessment["ok"] else ("Assessment unavailable", "warn")
        )
        if report["unavailable"]:
            title = "Evidence incomplete" if status == "good" else title
            status = "warn" if status == "good" else status
        if issues and status == "good":
            title, status = "Review recommended", "warn"
        if any(level == "bad" for _, level in issues):
            title, status = "Attention required", "bad"
        count = len(issues)
        detail = (
            f"{count} review finding{'s' if count != 1 else ''} · "
            f"{len(information)} informational"
        )
        if report["unavailable"]:
            detail += " · Limited evidence"
        self.set_summary(
            title,
            score=score if assessment["ok"] else None,
            status=status,
            detail=detail,
            updated=report["collected_at"],
        )

        facts = section("Kernel")
        kernel = report["kernel_info"]
        if kernel["ok"]:
            for name, key in (
                ("Kernel release", "kernel"),
                ("Architecture", "architecture"),
                ("Hostname", "hostname"),
            ):
                facts.pack_start(
                    data_row(name, kernel["data"].get(key, "Unavailable")),
                    False,
                    False,
                    0,
                )
        else:
            facts.pack_start(
                label(
                    kernel["error"] or "Kernel information is unavailable",
                    "data-label",
                    True,
                ),
                False,
                False,
                0,
            )
        self.overview.pack_start(facts, False, False, 0)
        self.add_findings(
            "Review findings", issues, "No review findings in the collected evidence"
        )
        if report["unavailable"]:
            self.add_findings(
                "Unavailable evidence",
                [(text, "warn") for text in report["unavailable"]],
            )
        self.add_findings(
            "Profile information", information, "No informational findings"
        )

        suspicious = {
            item["name"]: item
            for item in report["module_analysis"]["data"].get("suspicious", [])
        }
        loaded = report["modules"]["data"].get("modules", [])
        for module in loaded:
            analysis = suspicious.get(module["name"], module)
            severity = module_status(analysis)
            state = STATUS_LABELS.get(severity, "Loaded")
            if severity == "active" and not module.get("path"):
                state = "Unavailable"
            reasons = "; ".join(
                format_finding(reason)[0] for reason in analysis.get("reasons", [])
            )
            self.modules.append(
                (
                    module["name"],
                    state,
                    str(module.get("size") or ""),
                    str(module.get("used_by") or ""),
                    module.get("path") or "Path unavailable",
                    reasons,
                )
            )
        self.stack.child_set_property(
            self.stack.get_child_by_name("modules"), "title", f"Modules ({len(loaded)})"
        )
        if not report["modules"]["ok"]:
            self.module_details.set_text(
                report["modules"]["error"] or "Loaded modules are unavailable"
            )
        elif not loaded:
            self.module_details.set_text("No loaded modules were reported")
        else:
            self.module_details.set_text(
                "Select a module to see its full path and findings"
            )

        values = report["sysctl_state"]["data"].get("values", {})
        unsupported = report["sysctl_state"]["data"].get("unsupported", [])
        for key, value in values.items():
            status = hardening_status(key, value, report["mode"], unsupported)
            state = (
                "Info" if key in unsupported else "Unavailable"
                if value is None
                else (
                    "Matches" if status == "good" else STATUS_LABELS.get(status, "Info")
                )
            )
            if (key == "kernel.unprivileged_userns_clone" and value == "1") or (
                key == "net.core.bpf_jit_harden" and value == "0"
            ):
                state = "Intentional"
            self.sysctls.append(
                (
                    key,
                    str(value)
                    if value is not None
                    else "Not exposed" if key in unsupported else "Unavailable",
                    state,
                )
            )

        hardening = section("Kernel hardening")
        if report["hardening"]["ok"]:
            for name, value, status in hardening_rows(report):
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
                row.pack_start(data_row(name, value), True, True, 0)
                pill = add_class(
                    Gtk.Label(label=hardening_label(name, value, status)), "status-pill"
                )
                set_status(pill, status)
                row.pack_end(pill, False, False, 0)
                hardening.pack_start(row, False, False, 0)
        else:
            hardening.pack_start(
                label(
                    report["hardening"]["error"] or "Hardening state is unavailable",
                    "data-label",
                    True,
                ),
                False,
                False,
                0,
            )
        hardening.pack_start(
            label(
                "Intentional settings follow PH4NTXM's operating policy. "
                "Review findings and unavailable evidence are listed in Overview.",
                "subtitle",
            ),
            False,
            False,
            6,
        )
        self.hardening.pack_start(hardening, False, False, 0)

    def add_findings(self, title, findings, empty=None):
        box = section(title)
        for text, level in findings:
            box.pack_start(finding_row(text, level), False, False, 0)
        if not findings and empty:
            box.pack_start(label(empty, "data-label"), False, False, 0)
        self.overview.pack_start(box, False, False, 0)

    def copy_text(self, report):
        lines = [
            "PH4NTXM OpSec Kernel",
            f"Mode: {report['mode'] or 'Unavailable'}",
            f"Collected: {report['collected_at']}",
            "",
        ]
        for key, value in report["kernel_info"]["data"].items():
            lines.append(f"{key.capitalize()}: {value}")
        lines.extend(
            (
                "",
                f"Assessment score: "
                f"{report['assessment']['data'].get('score', 'Unavailable')}",
                "Findings:",
            )
        )
        for text, severity in report_findings(report):
            lines.append(f"[{STATUS_LABELS[severity]}] {text}")
        lines.extend(
            (
                "",
                "Unavailable evidence:",
                *(report["unavailable"] or ["None recorded"]),
                "",
                "Loaded modules:",
            )
        )
        for module in self.modules:
            lines.append(" | ".join(module))
        lines.extend(("", "sysctl:"))
        for setting in self.sysctls:
            lines.append(" | ".join(setting))
        lines.extend(("", "Hardening:"))
        if report["hardening"]["ok"]:
            for name, value, status in hardening_rows(report):
                lines.append(
                    f"{name}: {value} [{hardening_label(name, value, status)}]"
                )
        return "\n".join(lines)


def main():
    return Application(KernelWindow, "org.ph4ntxm.OpSecKernel").run()


if __name__ == "__main__":
    raise SystemExit(main())
