# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import json
import sys

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

from ph4ntxm_opsec_ui import (
    Application,
    ReportWindow,
    add_class,
    data_row,
    finding_row,
    label,
    run_backend,
    scroll,
    section,
)
from ph4ntxm_opsec_proc.cli import format_finding, process_status, verdict
from ph4ntxm_opsec_proc.remediation import PROCESS_ACTIONS

BACKEND = "/usr/local/bin/ph4ntxm-opsec-proc-backend"
STATUS_LABELS = {"good": "OK", "warn": "Review", "bad": "Critical", "info": "Info"}


class ProcessWindow(ReportWindow):
    def __init__(self, application):
        super().__init__(
            application,
            "PH4NTXM OpSec Process",
            "Process security inspection",
            "ph4ntxm-opsec-proc",
        )

    def build_pages(self):
        self.processes_by_pid = {}
        self.selected_process = None
        self.overview = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.stack.add_titled(scroll(self.overview), "overview", "Overview")
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text("Search processes, PIDs or executable paths")
        self.search.connect("search-changed", self.filter_processes)
        self.review_only = Gtk.CheckButton(label="Review only")
        self.review_only.set_tooltip_text(
            "Show flagged processes and unavailable process identities"
        )
        self.review_only.connect("toggled", self.filter_processes)
        controls.pack_start(self.search, True, True, 0)
        controls.pack_end(self.review_only, False, False, 0)
        page.pack_start(controls, False, False, 0)
        self.processes = Gtk.ListStore(int, str, str, str, str, str, str, str)
        self.filtered_processes = self.processes.filter_new()
        self.filtered_processes.set_visible_func(self.process_visible)
        self.sorted_processes = Gtk.TreeModelSort(model=self.filtered_processes)
        view = self.table(
            self.sorted_processes,
            (
                ("PID", 0, 80),
                ("Process", 1, 170),
                ("UID", 2, 70),
                ("State", 3, 60),
                ("Assessment", 4, 100),
                ("Executable", 5, 330),
            ),
        )
        view.set_tooltip_column(5)
        view.get_selection().connect("changed", self.select_process)
        page.pack_start(scroll(view), True, True, 0)
        self.details = label(
            "Select a process to inspect its evidence", "data-value", True
        )
        details_scroll = scroll(self.details)
        details_scroll.set_min_content_height(64)
        details_scroll.set_max_content_height(120)
        page.pack_start(details_scroll, False, True, 0)
        action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.process_action_buttons = {}
        for name in ("terminate", "terminate_tree", "freeze"):
            action = PROCESS_ACTIONS[name]
            button = Gtk.Button(label=action["label"])
            add_class(button, "danger" if action["severity"] == "bad" else "primary")
            button.set_tooltip_text(action["description"])
            button.set_sensitive(False)
            button.connect("clicked", self.apply_action, name)
            self.process_action_buttons[name] = button
            self.action_buttons.append(button)
            action_row.pack_start(button, False, False, 0)
        page.pack_start(action_row, False, False, 0)
        self.stack.add_titled(page, "processes", "Processes")

    def collect_report(self, progress):
        progress("Authorizing process inspection")
        report = run_backend([BACKEND, "report"], privileged=True)
        if not isinstance(report, dict) or "processes" not in report:
            error = report.get("error") if isinstance(report, dict) else None
            raise RuntimeError(error or "The process report could not be collected")
        if not report.get("privileged"):
            raise RuntimeError("Administrator access is required for this report")
        return report

    def clear_pages(self):
        self.clear(self.overview)
        self.processes.clear()
        self.processes_by_pid = {}
        self.selected_process = None
        self.details.set_text("Process evidence will appear after the check")
        for button in self.process_action_buttons.values():
            button.set_sensitive(False)

    def process_visible(self, model, iterator, _):
        row = model[iterator]
        query = self.search.get_text().strip().casefold()
        return (not self.review_only.get_active() or row[4] != "Loaded") and (
            not query
            or query
            in " ".join((str(row[0]), row[1], row[5], row[6], row[7])).casefold()
        )

    def filter_processes(self, _):
        self.filtered_processes.refilter()

    def select_process(self, selection):
        model, iterator = selection.get_selected()
        self.selected_process = None
        if iterator is None:
            self.details.set_text("Select a process to inspect its evidence")
        else:
            row = model[iterator]
            self.selected_process = self.processes_by_pid.get(row[0])
            self.details.set_text(
                f"PID {row[0]} · {row[1]} · {row[4]}\n"
                f"Executable: {row[5]}\nCommand: {row[6] or 'Unavailable'}\n"
                f"Findings: {row[7] or 'None in the collected evidence'}"
            )
        self.update_actions()

    def update_actions(self):
        allowed = []
        if self.report and self.selected_process:
            allowed = self.report.get("actions", {}).get(
                str(self.selected_process["pid"]), []
            )
        for name, button in self.process_action_buttons.items():
            button.set_sensitive(not self.running and name in allowed)

    def set_busy(self, busy, phase=None):
        super().set_busy(busy, phase)
        if not busy:
            self.update_actions()

    def populate(self, report):
        analysis = report["analysis"]
        assessment = report["assessment"]
        loaded = report["processes"]["data"].get("processes", [])
        suspicious = {
            proc["pid"]: proc for proc in analysis["data"].get("suspicious", [])
        }
        findings = [
            format_finding(name)
            for name in assessment["data"].get("findings", [])
        ]
        score = assessment["data"].get("score") if assessment["ok"] else None
        title, status = (
            verdict(score) if score is not None else ("Assessment unavailable", "warn")
        )
        if any(severity == "bad" for _, severity in findings):
            title, status = "Attention required", "bad"
        elif any(severity == "warn" for _, severity in findings) and status == "good":
            title, status = "Review recommended", "warn"
        if report["unavailable"] and status == "good":
            title, status = "Evidence incomplete", "warn"
        self.set_summary(
            title,
            score=score,
            status=status,
            detail=f"{len(loaded)} processes · {len(suspicious)} flagged processes",
            updated=report["collected_at"],
        )
        finding_box = section("Process findings")
        finding_box.pack_start(
            data_row("Report access", "Administrator" if report["privileged"] else "Regular user"),
            False,
            False,
            0,
        )
        for text, severity in findings:
            finding_box.pack_start(finding_row(text, severity), False, False, 0)
        if not findings:
            finding_box.pack_start(
                label("No findings in the collected evidence", "data-label"),
                False,
                False,
                0,
            )
        self.overview.pack_start(finding_box, False, False, 0)
        if report["unavailable"]:
            evidence = section("Unavailable evidence")
            for text in report["unavailable"]:
                evidence.pack_start(finding_row(text, "warn"), False, False, 0)
            self.overview.pack_start(evidence, False, False, 0)
        mismatches = assessment["data"].get("visibility_mismatch_pids", [])
        if mismatches:
            evidence = section("Process visibility")
            evidence.pack_start(
                label(
                    "Visibility mismatch PIDs: " + ", ".join(map(str, mismatches)),
                    "data-value",
                    True,
                ),
                False,
                False,
                0,
            )
            self.overview.pack_start(evidence, False, False, 0)
        for proc in loaded:
            analyzed = suspicious.get(proc["pid"], proc)
            self.processes_by_pid[proc["pid"]] = analyzed
            severity = process_status(analyzed)
            state = STATUS_LABELS.get(severity, "Loaded")
            if proc.get("start_time_ticks") is None:
                state = "Unavailable"
            reasons = "; ".join(
                format_finding(name)[0] for name in analyzed.get("reasons", [])
            )
            self.processes.append(
                (
                    proc["pid"],
                    proc.get("name") or "Unavailable",
                    (
                        str(proc["uid"])
                        if proc.get("uid") is not None
                        else "Unavailable"
                    ),
                    proc.get("state") or "Unavailable",
                    state,
                    proc.get("exe") or "Unavailable",
                    proc.get("cmdline") or "",
                    reasons,
                )
            )
        self.stack.child_set_property(
            self.stack.get_child_by_name("processes"),
            "title",
            f"Processes ({len(loaded)})",
        )
        self.update_actions()

    def apply_action(self, _, name):
        if self.running or self.closed or not self.selected_process or not self.report:
            return
        proc = self.selected_process
        if name not in self.report.get("actions", {}).get(str(proc["pid"]), []):
            return
        ticks = proc.get("start_time_ticks")
        if ticks is None:
            self.show_message(
                "Action unavailable", "Process identity is unavailable", error=True
            )
            return
        action = PROCESS_ACTIONS[name]
        message = (
            f"{action['description']}\n\nPID: {proc['pid']}\n"
            f"Process: {proc.get('name') or 'Unavailable'}\n"
            f"Executable: {proc.get('exe') or 'Unavailable'}"
        )
        if not self.confirm_action(action["label"], message, action["label"]):
            return
        command = [BACKEND, "action", name, str(proc["pid"]), str(ticks)]
        self.run_action(
            lambda: run_backend(command, privileged=True),
            self.action_complete,
            action["label"],
        )

    def action_complete(self, outcome):
        ok = bool(outcome.get("ok"))
        message = (
            outcome.get("message") or "The process action completed"
            if ok
            else outcome.get("error") or "The process action could not be completed"
        )
        self.show_message("Process action", message, error=not ok)
        if not self.closed:
            self.refresh()

    def copy_text(self, report):
        return "PH4NTXM OpSec Process\n" + json.dumps(
            report, indent=2, ensure_ascii=False
        )


def main():
    return Application(ProcessWindow, "org.ph4ntxm.OpSecProcess").run(sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
