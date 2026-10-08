# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from datetime import datetime
from pathlib import Path
import json
import os
import subprocess
import sys
import threading

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, Gio, GLib, Gtk, Pango

CSS_FILE = "/usr/share/ph4ntxm/ph4ntxm-ui.css"
MODE_FILE = "/run/ph4ntxm/mode"
MODE_LABELS = {"linux": "Linux", "windows": "Windows", "lonewolf": "Lone Wolf"}
STATUS_CLASSES = {
    "good": "status-active",
    "warn": "status-warning",
    "bad": "status-danger",
    "info": "status-disabled",
}
STATUS_LABELS = {"good": "OK", "warn": "Review", "bad": "Critical", "info": "Info"}


def read_session_mode():
    try:
        mode = Path(MODE_FILE).read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return None
    return mode if mode in MODE_LABELS else None


def add_class(widget, name):
    widget.get_style_context().add_class(name)
    return widget


def label(text, style=None, selectable=False):
    widget = Gtk.Label(label=str(text), xalign=0)
    widget.set_line_wrap(True)
    widget.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
    widget.set_max_width_chars(76)
    widget.set_selectable(selectable)
    if style:
        add_class(widget, style)
    return widget


def set_status(widget, status):
    context = widget.get_style_context()
    for name in STATUS_CLASSES.values():
        context.remove_class(name)
    context.add_class(STATUS_CLASSES.get(status, "status-disabled"))


def section(title):
    box = add_class(
        Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8), "section"
    )
    box.pack_start(label(title, "section-title"), False, False, 0)
    return box


def scroll(child):
    widget = Gtk.ScrolledWindow()
    widget.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    widget.set_shadow_type(Gtk.ShadowType.NONE)
    widget.add(child)
    return widget


def finding_row(text, status, state=None):
    row = add_class(
        Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12), "data-row"
    )
    row.pack_start(label(text, "data-label", True), True, True, 0)
    pill = add_class(Gtk.Label(label=state or STATUS_LABELS[status]), "status-pill")
    pill.set_valign(Gtk.Align.START)
    set_status(pill, status)
    row.pack_end(pill, False, False, 0)
    return row


def data_row(name, value):
    row = add_class(
        Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18), "data-row"
    )
    row.pack_start(label(name, "data-label"), False, False, 0)
    value_label = label(value, "data-value", True)
    value_label.set_xalign(1)
    value_label.set_justify(Gtk.Justification.RIGHT)
    row.pack_end(value_label, True, True, 0)
    return row


def run_backend(command, timeout=180, privileged=False):
    environment = dict(os.environ)
    if privileged:
        command = ["/usr/bin/sudo", "-A", "--", *command]
        environment["SUDO_ASKPASS"] = "/usr/local/bin/ph4ntxm-askpass"
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=environment,
        check=False,
    )
    if completed.returncode != 0:
        try:
            result = json.loads(completed.stdout)
        except (ValueError, TypeError):
            result = None
        if isinstance(result, dict) and result.get("ok") is False:
            return result
        raise RuntimeError(
            completed.stderr.strip() or "The requested operation could not complete"
        )
    result = json.loads(completed.stdout)
    if not isinstance(result, dict):
        raise ValueError("The operation returned an invalid report")
    return result


class ReportWindow(Gtk.ApplicationWindow):
    def __init__(self, application, title, subtitle, icon):
        super().__init__(application=application, title=title)
        self.set_wmclass(icon, title.replace(" ", "-"))
        self.set_icon_name(icon)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.set_resizable(True)
        display = Gdk.Display.get_default()
        monitor = display.get_primary_monitor() or display.get_monitor(0)
        workarea = monitor.get_workarea()
        width = min(960, workarea.width - 40) if workarea.width > 40 else 960
        height = min(700, workarea.height - 40) if workarea.height > 40 else 700
        self.set_default_size(width, height)
        self.set_size_request(min(640, width), -1)
        if Path(CSS_FILE).is_file():
            provider = Gtk.CssProvider()
            provider.load_from_path(CSS_FILE)
            Gtk.StyleContext.add_provider_for_screen(
                self.get_screen(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
        add_class(self, "ph4ntxm-window")
        self.window_title = title
        self.window_subtitle = subtitle
        self.report = None
        self.running = False
        self.closed = False
        self.action_buttons = []
        self.connect("destroy", self.on_destroy)
        self.build()
        GLib.idle_add(self.refresh)

    def build(self):
        self.root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add(self.root)
        self.header = add_class(
            Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18), "top-panel"
        )
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        title_box.pack_start(label(self.window_title, "title"), False, False, 0)
        title_box.pack_start(label(self.window_subtitle, "subtitle"), False, False, 0)
        self.header.pack_start(title_box, True, True, 0)
        self.mode = add_class(Gtk.Label(), "status-pill")
        self.set_mode()
        self.header.pack_end(self.mode, False, False, 0)
        self.root.pack_start(self.header, False, False, 0)
        self.content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.content.set_border_width(18)
        self.root.pack_start(self.content, True, True, 0)
        summary = add_class(
            Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16), "section"
        )
        self.dot = add_class(Gtk.Label(label="●"), "status-dot")
        summary.pack_start(self.dot, False, False, 0)
        summary_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.verdict = label("Checking", "title")
        self.verdict.set_max_width_chars(36)
        self.summary = label("Collecting current state", "subtitle")
        summary_text.pack_start(self.verdict, False, False, 0)
        summary_text.pack_start(self.summary, False, False, 0)
        summary.pack_start(summary_text, True, True, 0)
        self.score_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        self.score_box.set_no_show_all(True)
        self.score = label("—", "title")
        self.score.set_xalign(1)
        self.score_box.pack_start(self.score, False, False, 0)
        self.score_caption = label("Assessment score", "subtitle")
        self.score_box.pack_start(self.score_caption, False, False, 0)
        summary.pack_end(self.score_box, False, False, 0)
        self.content.pack_start(summary, False, False, 0)
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_transition_duration(120)
        self.stack.set_hhomogeneous(False)
        self.stack.set_vhomogeneous(True)
        self.switcher = Gtk.StackSwitcher(stack=self.stack)
        self.switcher.set_spacing(8)
        self.switcher.get_style_context().remove_class("linked")
        self.switcher.set_halign(Gtk.Align.CENTER)
        self.content.pack_start(self.switcher, False, False, 0)
        self.page_scroll = scroll(self.stack)
        self.page_scroll.set_min_content_width(0)
        self.page_scroll.set_min_content_height(0)
        self.content.pack_start(self.page_scroll, True, True, 0)
        self.build_pages()
        self.footer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.spinner = Gtk.Spinner()
        self.spinner.set_no_show_all(True)
        self.activity = label("Preparing checks", "subtitle")
        self.footer.pack_start(self.spinner, False, False, 0)
        self.footer.pack_start(self.activity, True, True, 0)
        self.copy = Gtk.Button(label="Copy Report")
        self.copy.connect("clicked", self.copy_report)
        self.check_again = add_class(Gtk.Button(label="Check Again"), "primary")
        self.check_again.connect("clicked", self.refresh)
        self.close_button = Gtk.Button(label="Close")
        self.close_button.connect("clicked", lambda _: self.close())
        self.footer.pack_end(self.close_button, False, False, 0)
        self.footer.pack_end(self.check_again, False, False, 0)
        self.footer.pack_end(self.copy, False, False, 0)
        self.content.pack_end(self.footer, False, False, 0)

    def build_pages(self):
        self.overview = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.stack.add_titled(scroll(self.overview), "overview", "Overview")

    def clear(self, box):
        for child in box.get_children():
            child.destroy()

    def clear_pages(self):
        pass

    def collect_report(self, progress):
        raise NotImplementedError

    def populate(self, report):
        raise NotImplementedError

    def copy_text(self, report):
        return json.dumps(report, indent=2)

    def table(self, model, columns):
        view = Gtk.TreeView(model=model)
        view.set_headers_visible(True)
        view.set_enable_search(True)
        view.get_selection().set_mode(Gtk.SelectionMode.SINGLE)
        for title, index, width in columns:
            cell = Gtk.CellRendererText()
            cell.set_property("ellipsize", Pango.EllipsizeMode.END)
            column = Gtk.TreeViewColumn(title, cell, text=index)
            column.set_resizable(True)
            column.set_sizing(Gtk.TreeViewColumnSizing.FIXED)
            column.set_fixed_width(width)
            column.set_expand(index == columns[-1][1])
            column.set_sort_column_id(index)
            view.append_column(column)
        view.connect("key-press-event", self.copy_selection)
        return view

    def copy_selection(self, view, event):
        if (
            event.keyval not in (Gdk.KEY_c, Gdk.KEY_C)
            or not event.state & Gdk.ModifierType.CONTROL_MASK
        ):
            return False
        model, iterator = view.get_selection().get_selected()
        if iterator is not None:
            text = "\t".join(str(value) for value in model[iterator])
            Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(text, -1)
        return True

    def show_score(self, text):
        self.score.set_text(text)
        self.score.show()
        self.score_caption.show()
        self.score_box.show()

    def set_mode(self):
        mode = read_session_mode()
        self.mode.set_text(f"Mode  {MODE_LABELS.get(mode, 'Unavailable')}")
        set_status(self.mode, "good" if mode is not None else "warn")

    def set_summary(
        self, title, score=None, status="info", detail="", updated=None
    ):
        self.verdict.set_text(title)
        self.summary.set_text(detail)
        set_status(self.dot, status)
        if score is None:
            self.score_box.hide()
        else:
            self.show_score(f"{score} / 100")
        self.set_mode()
        if updated:
            stamp = datetime.fromisoformat(updated).astimezone().strftime("%H:%M:%S")
            self.activity.set_text(f"Checked {stamp} · On-demand report")

    def set_busy(self, busy, phase=None):
        self.running = busy
        self.check_again.set_sensitive(not busy)
        self.copy.set_sensitive(not busy and self.report is not None)
        for button in self.action_buttons:
            button.set_sensitive(not busy)
        if busy:
            self.spinner.show()
            self.spinner.start()
        else:
            self.spinner.stop()
            self.spinner.hide()
        if phase:
            self.activity.set_text(phase)

    def refresh(self, _=None):
        if self.running or self.closed:
            return GLib.SOURCE_REMOVE
        self.report = None
        self.set_busy(True, "Collecting current state")
        self.set_summary("Checking", detail="Collecting current state")
        self.clear(self.overview)
        self.clear_pages()
        self.stack.show_all()
        threading.Thread(target=self.collect, daemon=True).start()
        return GLib.SOURCE_REMOVE

    def collect(self):
        try:
            report = self.collect_report(self.progress)
        except Exception as error:
            GLib.idle_add(self.finish, None, str(error))
        else:
            GLib.idle_add(self.finish, report, None)

    def progress(self, phase):
        if self.closed:
            raise InterruptedError("Window closed")
        GLib.idle_add(self.update_activity, phase)

    def update_activity(self, phase):
        if not self.closed and self.running:
            self.activity.set_text(phase)
        return GLib.SOURCE_REMOVE

    def finish(self, report, error):
        if self.closed:
            return GLib.SOURCE_REMOVE
        self.set_busy(False)
        self.clear(self.overview)
        if not error:
            try:
                if not isinstance(report, dict):
                    raise ValueError("The operation returned an invalid report")
                self.report = report
                self.populate(report)
            except Exception as failure:
                error = str(failure)
        if error:
            self.report = None
            self.clear(self.overview)
            self.clear_pages()
            self.set_busy(False)
            self.set_summary(
                "Check unavailable",
                status="warn",
                detail="The report could not be completed. Check again to retry.",
            )
            self.activity.set_text("Check failed")
            box = section("Unavailable evidence")
            box.pack_start(label(error, "data-label", True), False, False, 0)
            self.overview.pack_start(box, False, False, 0)
        else:
            self.copy.set_sensitive(True)
        self.stack.show_all()
        return GLib.SOURCE_REMOVE

    def run_action(self, worker, complete, phase):
        if self.running or self.closed:
            return
        self.set_busy(True, phase)

        def execute():
            try:
                result = worker()
            except Exception as error:
                result = {"ok": False, "error": str(error)}
            GLib.idle_add(self.finish_action, result, complete)

        threading.Thread(target=execute, daemon=True).start()

    def finish_action(self, result, complete):
        if not self.closed:
            self.set_busy(False)
            complete(result)
        return GLib.SOURCE_REMOVE

    def confirm_action(self, title, message, button_label="Apply"):
        dialog = Gtk.MessageDialog(
            transient_for=self,
            modal=True,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.NONE,
            text=title,
        )
        dialog.format_secondary_text(message)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        action = dialog.add_button(button_label, Gtk.ResponseType.OK)
        add_class(action, "danger")
        dialog.set_default_response(Gtk.ResponseType.CANCEL)
        response = dialog.run()
        dialog.destroy()
        return response == Gtk.ResponseType.OK

    def show_message(self, title, message, error=False):
        dialog = Gtk.MessageDialog(
            transient_for=self,
            modal=True,
            message_type=Gtk.MessageType.ERROR if error else Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.CLOSE,
            text=title,
        )
        dialog.format_secondary_text(message)
        dialog.run()
        dialog.destroy()

    def copy_report(self, _):
        if self.report is not None:
            Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD).set_text(
                self.copy_text(self.report), -1
            )
            self.activity.set_text("Report copied to clipboard")

    def on_destroy(self, _):
        self.closed = True


class Application(Gtk.Application):
    def __init__(self, window_class, application_id):
        super().__init__(application_id=application_id, flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.window_class = window_class
        self.window = None

    def do_activate(self):
        if self.window is None:
            self.window = self.window_class(self)
        self.window.show_all()
        self.window.present()

    def run(self, argv=None):
        return super().run(sys.argv if argv is None else argv)
