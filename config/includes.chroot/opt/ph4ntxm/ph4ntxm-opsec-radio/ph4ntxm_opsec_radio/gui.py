# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import sys

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk

from ph4ntxm_opsec_radio.report import (
    assessment_summary,
    available_actions,
    format_finding,
    report_text,
)
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


class RadioWindow(ReportWindow):
    def __init__(self, application):
        super().__init__(
            application,
            "PH4NTXM OpSec Radio",
            "Inspect wireless exposure and control active radios",
            "ph4ntxm-opsec-radio",
        )

    def build_pages(self):
        self.overview = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.radio_checks = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.cached_wifi = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.actions = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.stack.add_titled(scroll(self.overview), "overview", "Overview")
        self.stack.add_titled(scroll(self.radio_checks), "radios", "Radio Checks")
        self.stack.add_titled(scroll(self.cached_wifi), "cache", "Cached Wi-Fi")
        self.stack.add_titled(scroll(self.actions), "actions", "Actions")

    def clear_pages(self):
        for box in (self.overview, self.radio_checks, self.cached_wifi, self.actions):
            self.clear(box)
        self.action_buttons.clear()

    def collect_report(self, progress):
        progress("Authenticating and checking radio exposure")
        outcome = run_backend(
            ["/usr/local/bin/ph4ntxm-opsec-radio-backend", "report"],
            privileged=True,
        )
        if not outcome.get("ok"):
            raise RuntimeError(outcome.get("error") or "Radio report failed.")
        if not (
            isinstance(outcome.get("checks"), list)
            and isinstance(outcome.get("assessment"), dict)
            and isinstance(outcome.get("unavailable"), list)
            and isinstance(outcome.get("collected_at"), str)
        ):
            raise RuntimeError("The radio backend returned an invalid report.")
        return outcome

    def populate(self, report):
        score = report["assessment"]["data"]["score"]
        title, status = assessment_summary(report)
        unavailable = report["unavailable"]
        self.set_summary(
            title,
            score=score,
            status=status,
            updated=report["collected_at"],
        )

        summary = section("Radio assessment")
        completed = sum(item["result"]["ok"] for item in report["checks"])
        summary.pack_start(
            data_row("Checks completed", f"{completed}/{len(report['checks'])}"),
            False,
            False,
            0,
        )
        summary.pack_start(
            data_row("Available actions", len(available_actions(report))),
            False,
            False,
            0,
        )
        self.overview.pack_start(summary, False, False, 0)
        findings = section("Findings to review")
        issue_count = 0
        for item in report["checks"]:
            outcome = item["result"]
            if not outcome["ok"]:
                continue
            for finding in outcome.get("findings", []):
                text, severity = format_finding(finding)
                if severity != "good":
                    findings.pack_start(finding_row(text, severity), False, False, 0)
                    issue_count += 1
        for missing in unavailable:
            findings.pack_start(finding_row(missing, "warn"), False, False, 0)
            issue_count += 1
        if not issue_count:
            findings.pack_start(
                finding_row("No findings require review", "good"), False, False, 0
            )
        self.overview.pack_start(findings, False, False, 0)

        for item in report["checks"]:
            box = section(item["title"])
            outcome = item["result"]
            if not outcome["ok"]:
                box.pack_start(
                    finding_row(outcome.get("error") or "Check unavailable", "warn"),
                    False,
                    False,
                    0,
                )
            else:
                for finding in outcome.get("findings", []):
                    text, severity = format_finding(finding)
                    box.pack_start(finding_row(text, severity), False, False, 0)
                for key, value in outcome.get("data", {}).items():
                    box.pack_start(data_row(key, value), False, False, 0)
            page = (
                self.cached_wifi
                if item["name"] == "check_nearby_scan"
                else self.radio_checks
            )
            page.pack_start(box, False, False, 0)
        cache_note = section("About cached observations")
        cache_note.pack_start(
            label(
                "Wi-Fi observations come from NetworkManager's local cache. "
                "Checking this report does not request an active scan. "
                "Cached networks can remain visible after Wi-Fi is disabled.",
                "subtitle",
            ),
            False,
            False,
            0,
        )
        self.cached_wifi.pack_start(cache_note, False, False, 0)
        self.populate_actions(report)

    def populate_actions(self, report):
        note = section("Selected radio controls")
        note.pack_start(
            label(
                "Choose an action to review its effect. Applying an action requires "
                "administrator authentication and checks the current radio state.",
                "subtitle",
            ),
            False,
            False,
            0,
        )
        self.actions.pack_start(note, False, False, 0)
        actions = available_actions(report)
        if not actions:
            note.pack_start(
                finding_row(
                    "No actions are available for the current findings", "info"
                ),
                False,
                False,
                0,
            )
        for action in actions:
            box = section(action["label"])
            box.pack_start(label(action["description"]), False, False, 0)
            box.pack_start(label(action["consequence"], "subtitle"), False, False, 0)
            button = add_class(Gtk.Button(label=action["label"]), "primary")
            button.set_halign(Gtk.Align.START)
            button.connect("clicked", self.apply_action, action["name"])
            self.action_buttons.append(button)
            box.pack_start(button, False, False, 0)
            self.actions.pack_start(box, False, False, 0)

    def apply_action(self, _button, name):
        if self.running or self.closed or self.report is None:
            return
        action = next(
            (item for item in available_actions(self.report) if item["name"] == name),
            None,
        )
        if action is None:
            return
        if not self.confirm_action(
            action["label"],
            action["description"] + ".\n\n" + action["consequence"],
            "Apply",
        ):
            return
        self.run_action(
            lambda: run_backend(
                ["/usr/local/bin/ph4ntxm-opsec-radio-backend", name],
                privileged=True,
            ),
            self.action_complete,
            "Applying " + action["label"],
        )

    def action_complete(self, outcome):
        if outcome.get("ok"):
            self.show_message(
                "Radio action complete",
                outcome.get("message") or "The selected radio action was applied.",
            )
        else:
            self.show_message(
                "Radio action failed",
                outcome.get("error") or "The selected radio action failed.",
                error=True,
            )
        self.refresh()

    def copy_text(self, report):
        return report_text(report)


def main():
    application = Application(RadioWindow, "org.ph4ntxm.OpSecRadio")
    return application.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
