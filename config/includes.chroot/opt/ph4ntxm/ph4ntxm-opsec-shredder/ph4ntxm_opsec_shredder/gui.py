# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from datetime import datetime, timezone
import os
import sys
import threading

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk

from ph4ntxm_opsec_ui import (
    Application,
    ReportWindow,
    add_class,
    data_row,
    finding_row,
    label,
    scroll,
    section,
)
from ph4ntxm_opsec_shredder import shredder as sh
from ph4ntxm_opsec_shredder.report import (
    STORAGE_LIMITATIONS,
    collect_report,
    execution_summary,
    plain_report,
)


class ShredderWindow(ReportWindow):
    def __init__(self, application):
        if os.geteuid() == 0:
            raise PermissionError("Run PH4NTXM OpSec Shredder as a regular user")
        self.overwriting = False
        self.current_marks = []
        self.last_run = None
        self.pass_count = sh.DEFAULT_PASSES
        self.job_thread = None
        super().__init__(
            application,
            "PH4NTXM OpSec Shredder",
            "Marked paths and best-effort overwrite with deletion",
            "ph4ntxm-opsec-shredder",
        )
        self.connect("delete-event", self.on_delete_event)

    def build_pages(self):
        self.overview = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.stack.add_titled(scroll(self.overview), "overview", "Overview")

        marks = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        queue = section("Marked paths")
        queue.pack_start(label("Marking and unmarking update the queue. Overwrite and deletion begin after final confirmation.", "subtitle"), False, False, 0)
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.add_files = Gtk.Button(label="Mark Files…")
        self.add_files.connect("clicked", lambda _: self.choose_paths(Gtk.FileChooserAction.OPEN))
        self.add_folders = Gtk.Button(label="Mark Folders…")
        self.add_folders.connect("clicked", lambda _: self.choose_paths(Gtk.FileChooserAction.SELECT_FOLDER))
        self.remove_marks = Gtk.Button(label="Unmark Selected")
        self.remove_marks.connect("clicked", self.on_unmark_selected)
        self.clear_marks = Gtk.Button(label="Unmark All")
        self.clear_marks.connect("clicked", self.on_unmark_all)
        for button in (self.add_files, self.add_folders, self.remove_marks, self.clear_marks):
            controls.pack_start(button, False, False, 0)
            self.action_buttons.append(button)
        queue.pack_start(controls, False, False, 0)
        self.mark_model = Gtk.ListStore(str, str, str, str)
        self.mark_table = self.table(
            self.mark_model,
            [("Path", 0, 390), ("Type", 1, 120), ("State", 2, 100), ("Evidence", 3, 350)],
        )
        self.mark_table.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)
        self.mark_table.get_selection().connect("changed", lambda _: self.update_controls())
        mark_scroll = scroll(self.mark_table)
        mark_scroll.set_min_content_height(160)
        queue.pack_start(mark_scroll, True, True, 0)
        marks.pack_start(queue, True, True, 0)
        overwrite = section("Overwrite and deletion")
        overwrite.pack_start(label("Folders are processed recursively. Symbolic link targets are not followed.", "subtitle"), False, False, 0)
        pass_controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        pass_controls.pack_start(label("Overwrite passes", "data-label"), False, False, 0)
        self.passes = Gtk.SpinButton.new_with_range(1, sh.MAX_PASSES, 1)
        self.passes.set_value(sh.DEFAULT_PASSES)
        self.passes.set_numeric(True)
        self.passes.connect("value-changed", self.on_passes_changed)
        pass_controls.pack_start(self.passes, False, False, 0)
        self.shred_button = add_class(Gtk.Button(label="Overwrite and Delete Marked Paths…"), "danger")
        self.shred_button.connect("clicked", self.on_shred)
        self.action_buttons.append(self.shred_button)
        pass_controls.pack_end(self.shred_button, False, False, 0)
        overwrite.pack_start(pass_controls, False, False, 0)
        overwrite.pack_start(label(STORAGE_LIMITATIONS, "subtitle"), False, False, 0)
        marks.pack_start(overwrite, False, False, 0)
        self.stack.add_titled(scroll(marks), "marks", "Marked paths")

        execution = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        progress_section = section("Execution progress")
        self.operation_state = label("No overwrite job has run", "section-title")
        self.current_target = label("", "data-value", True)
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_show_text(True)
        self.progress_bar.set_text("Waiting for a confirmed job")
        progress_section.pack_start(self.operation_state, False, False, 0)
        progress_section.pack_start(self.current_target, False, False, 0)
        progress_section.pack_start(self.progress_bar, False, False, 0)
        progress_section.pack_start(label("Progress applies to overwrite passes for the current file. The execution report records final deletion results.", "subtitle"), False, False, 0)
        execution.pack_start(progress_section, False, False, 0)
        results = section("Execution report")
        self.result_model = Gtk.ListStore(str, str, str)
        self.result_table = self.table(self.result_model, [("Result", 0, 120), ("Path", 1, 390), ("Details", 2, 390)])
        result_scroll = scroll(self.result_table)
        result_scroll.set_min_content_height(160)
        results.pack_start(result_scroll, True, True, 0)
        execution.pack_start(results, True, True, 0)
        self.stack.add_titled(scroll(execution), "execution", "Execution")
        self.update_controls()

    def collect_report(self, progress):
        return collect_report(progress, passes=self.pass_count, last_run=self.last_run)

    def clear_pages(self):
        self.current_marks = []
        self.mark_model.clear()
        self.update_controls()

    def populate(self, report):
        self.current_marks = report["marked_paths"]
        count = len(self.current_marks)
        if count:
            title = f"{count} marked target{'s' if count != 1 else ''}"
            status = "warn"
            detail = f"{self.pass_count} overwrite passes selected · Review all targets before destruction"
        elif report.get("last_run"):
            title, status, detail = execution_summary(report["last_run"])
        else:
            title, status, detail = "No paths marked", "info", "Choose files or folders to prepare the queue"
        self.set_summary(title, status=status, detail=detail, updated=report["collected_at"])
        queue = section("Marked queue")
        queue.pack_start(data_row("Marked targets", str(count)), False, False, 0)
        pass_row = add_class(Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18), "data-row")
        pass_row.pack_start(label("Overwrite passes", "data-label"), False, False, 0)
        self.overview_passes = label(str(self.pass_count), "data-value", True)
        self.overview_passes.set_xalign(1)
        pass_row.pack_end(self.overview_passes, True, True, 0)
        queue.pack_start(pass_row, False, False, 0)
        queue.pack_start(label("Add and review targets in Marked paths. Unmarking removes a queue entry and leaves the file in place.", "subtitle"), False, False, 0)
        self.overview.pack_start(queue, False, False, 0)
        limitations = section("Storage limits")
        limitations.pack_start(label(STORAGE_LIMITATIONS, "data-label"), False, False, 0)
        self.overview.pack_start(limitations, False, False, 0)
        for target in report["targets"]:
            self.mark_model.append([target["path"], target["kind"], target["state"], target["detail"]])
        if report.get("last_run"):
            title, status, detail = execution_summary(report["last_run"])
            previous = section("Last execution")
            previous.pack_start(finding_row(title, status), False, False, 0)
            previous.pack_start(label(detail, "subtitle"), False, False, 0)
            for result in report["last_run"]["results"]:
                if result[0] == "error":
                    text = f"{result[1]}: {result[2] if len(result) > 2 else 'Overwrite or deletion failed'}"
                    previous.pack_start(finding_row(text, "bad", "Failed"), False, False, 0)
            self.overview.pack_start(previous, False, False, 0)
        self.update_controls()
        self.overview.show_all()

    def set_busy(self, busy, phase=None):
        super().set_busy(busy, phase)
        self.update_controls()
        self.close_button.set_sensitive(not self.overwriting)

    def update_controls(self):
        if not hasattr(self, "shred_button"):
            return
        idle = not self.running and not self.overwriting
        self.add_files.set_sensitive(idle)
        self.add_folders.set_sensitive(idle)
        self.remove_marks.set_sensitive(idle and bool(self.selected_marks()))
        self.clear_marks.set_sensitive(idle and bool(self.current_marks))
        self.shred_button.set_sensitive(idle and bool(self.current_marks))
        self.passes.set_sensitive(idle)

    def selected_marks(self):
        model, paths = self.mark_table.get_selection().get_selected_rows()
        return [model[path][0] for path in paths]

    def on_passes_changed(self, spin):
        self.pass_count = spin.get_value_as_int()
        if self.report is not None:
            self.report["passes"] = self.pass_count
            self.overview_passes.set_text(str(self.pass_count))
            if self.current_marks:
                self.summary.set_text(
                    f"{self.pass_count} overwrite passes selected · Review all targets before destruction"
                )

    def choose_paths(self, action):
        if self.running or self.overwriting:
            return
        folder = action == Gtk.FileChooserAction.SELECT_FOLDER
        dialog = Gtk.FileChooserDialog(
            title="Mark folders" if folder else "Mark files",
            transient_for=self,
            action=action,
        )
        dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Mark", Gtk.ResponseType.OK)
        dialog.set_select_multiple(True)
        response = dialog.run()
        paths = dialog.get_filenames() if response == Gtk.ResponseType.OK else []
        dialog.destroy()
        if paths:
            self.run_action(lambda: self.mark_paths(paths), self.on_queue_update, "Updating marked paths")

    def mark_paths(self, paths):
        errors = []
        marked = 0
        for path in paths:
            if sh.mark(path):
                marked += 1
            else:
                errors.append(f"{path}: Could not mark the path; it may be missing, protected, already marked, or the queue could not be saved")
        return {"ok": not errors, "message": f"Marked {marked} target(s)", "errors": errors}

    def on_unmark_selected(self, button):
        paths = self.selected_marks()
        if self.running or self.overwriting or not paths:
            return
        self.run_action(lambda: self.unmark_paths(paths), self.on_queue_update, "Removing selected marks")

    def unmark_paths(self, paths):
        errors = []
        removed = 0
        for path in paths:
            if sh.unmark(path):
                removed += 1
            else:
                errors.append(f"{path}: The mark could not be removed; it may have changed or the queue could not be saved")
        return {"ok": not errors, "message": f"Unmarked {removed} target(s)", "errors": errors}

    def on_unmark_all(self, button):
        if self.running or self.overwriting or not self.current_marks:
            return
        self.run_action(self.clear_queue, self.on_queue_update, "Clearing marked paths")

    def clear_queue(self):
        if sh.unmark_all():
            return {"ok": True, "message": "All marks removed"}
        return {"ok": False, "error": "The marked queue could not be cleared"}

    def on_queue_update(self, outcome):
        if not outcome["ok"]:
            errors = outcome.get("errors") or [outcome.get("error") or "The marked queue could not be updated"]
            self.show_message("Marked paths update failed", "\n".join(errors), error=True)
        self.refresh()

    def confirm_targets(self, targets, passes):
        dialog = Gtk.Dialog(title="Confirm overwrite and deletion", transient_for=self, modal=True)
        dialog.set_default_size(720, 520)
        dialog.set_resizable(True)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        confirm = dialog.add_button("Overwrite and Delete", Gtk.ResponseType.OK)
        add_class(confirm, "danger")
        dialog.set_default_response(Gtk.ResponseType.CANCEL)
        content = dialog.get_content_area()
        content.set_border_width(18)
        content.set_spacing(12)
        content.pack_start(label(f"Destroy {len(targets)} marked target(s) using {passes} overwrite pass(es)?", "section-title"), False, False, 0)
        content.pack_start(label("This operation overwrites file contents and deletes the listed paths. Folders include their contents. Symbolic link targets are not followed.", "data-label"), False, False, 0)
        target_view = Gtk.TextView()
        target_view.set_editable(False)
        target_view.set_cursor_visible(False)
        target_view.set_monospace(True)
        target_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        target_view.get_buffer().set_text("\n".join(targets))
        target_scroll = scroll(target_view)
        target_scroll.set_min_content_height(220)
        content.pack_start(target_scroll, True, True, 0)
        content.pack_start(label(STORAGE_LIMITATIONS, "subtitle"), False, False, 0)
        dialog.show_all()
        response = dialog.run()
        dialog.destroy()
        return response == Gtk.ResponseType.OK

    def on_shred(self, button):
        if self.running or self.overwriting:
            return
        targets = sh.list_marks()
        if targets != self.current_marks:
            self.show_message("Marked targets changed", "Review the updated marked queue before confirming overwrite and deletion.")
            self.refresh()
            return
        if not targets:
            return
        passes = self.passes.get_value_as_int()
        if not self.confirm_targets(targets, passes):
            return
        self.start_shred(targets, passes)

    def start_shred(self, targets, passes):
        self.overwriting = True
        self.result_model.clear()
        self.operation_state.set_text("Overwrite and deletion in progress")
        self.current_target.set_text("Preparing confirmed targets")
        self.progress_bar.set_fraction(0)
        self.progress_bar.set_text("Preparing confirmed targets")
        self.stack.set_visible_child_name("execution")
        self.set_busy(True, "Overwriting confirmed targets")
        application = self.get_application()
        application.hold()
        started_at = datetime.now(timezone.utc).isoformat()

        def execute():
            try:
                results = sh.shred_all(
                    passes=passes,
                    progress_callback=self.backend_progress,
                    expected_marks=targets,
                )
            except Exception as error:
                results = [("error", "System", str(error))]
            outcome = {
                "ok": not any(result[0] == "error" for result in results),
                "targets": list(targets),
                "passes": passes,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "results": results,
            }
            GLib.idle_add(self.finish_shred, outcome, application)

        self.job_thread = threading.Thread(target=execute, daemon=False)
        try:
            self.job_thread.start()
        except Exception as error:
            application.release()
            self.overwriting = False
            self.set_busy(False, "Overwrite job could not start")
            self.show_message("Overwrite job could not start", str(error), error=True)

    def backend_progress(self, path, percent):
        GLib.idle_add(self.show_progress, path, percent)

    def show_progress(self, path, percent):
        if not self.closed and self.overwriting:
            self.current_target.set_text(path)
            self.progress_bar.set_fraction(max(0, min(percent, 100)) / 100)
            self.progress_bar.set_text(f"{percent}% overwrite passes for current file")
        return GLib.SOURCE_REMOVE

    def finish_shred(self, outcome, application):
        self.overwriting = False
        self.last_run = outcome
        if not self.closed:
            self.set_busy(False)
            title, status, detail = execution_summary(outcome)
            self.operation_state.set_text(title)
            self.current_target.set_text(detail)
            self.progress_bar.set_fraction(1)
            self.progress_bar.set_text("Job finished")
            states = {"shredded": "Completed", "shredded_dir": "Completed", "missing": "Missing", "error": "Failed"}
            for result in outcome["results"]:
                detail = result[2] if len(result) > 2 else "Overwrite and deletion finished" if result[0] in ("shredded", "shredded_dir") else "Path no longer exists"
                self.result_model.append([states.get(result[0], result[0]), result[1], detail])
            self.refresh()
        application.release()
        return GLib.SOURCE_REMOVE

    def on_delete_event(self, window, event):
        if self.overwriting:
            self.show_message("Overwrite job is still running", "Wait for the execution report before closing this window. The current overwrite job cannot be safely cancelled.")
            return True
        return False

    def close(self):
        if self.overwriting:
            self.show_message("Overwrite job is still running", "Wait for the execution report before closing this window. The current overwrite job cannot be safely cancelled.")
            return
        super().close()

    def copy_text(self, report):
        return plain_report(report)


def main():
    if os.geteuid() == 0:
        print("Run PH4NTXM OpSec Shredder as a regular user", file=sys.stderr)
        return 1
    return Application(ShredderWindow, "org.ph4ntxm.OpSecShredder").run(sys.argv)


if __name__ == "__main__":
    main()
