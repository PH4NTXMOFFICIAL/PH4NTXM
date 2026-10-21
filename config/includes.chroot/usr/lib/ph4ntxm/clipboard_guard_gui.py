# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import os
import sys

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("GdkX11", "3.0")
from gi.repository import Gdk, GdkX11, Gio, GLib, Gtk, Pango

from clipboard_guard import GLibScheduler, Guard, GuardError
from clipboard_guard_x11 import X11Backend


CSS_FILE = "/usr/share/ph4ntxm/ph4ntxm-ui.css"
ICON = "ph4ntxm-clipboard-guard"


def add_class(widget, name):
    widget.get_style_context().add_class(name)
    return widget


def label(text, style=None):
    widget = Gtk.Label(label=text, xalign=0)
    widget.set_line_wrap(True)
    widget.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
    widget.set_max_width_chars(82)
    return add_class(widget, style) if style else widget


def icon_name():
    theme = Gtk.IconTheme.get_default()
    return ICON if theme and theme.has_icon(ICON) else "xfce4-clipman-plugin"


class ClipboardGuardWindow(Gtk.ApplicationWindow):
    def __init__(self, application):
        super().__init__(application=application, title="PH4NTXM Clipboard Guard")
        self.application = application
        width, height = 760, 520
        display = Gdk.Display.get_default()
        monitor = (
            (display.get_primary_monitor() or display.get_monitor(0))
            if display
            else None
        )
        if monitor:
            area = monitor.get_workarea()
            width = min(width, max(420, area.width - 40))
            height = min(height, max(340, area.height - 40))
        self.set_default_size(width, height)
        self.set_size_request(min(520, width), min(360, height))
        self.set_position(Gtk.WindowPosition.CENTER)
        self.set_icon_name(icon_name())
        self.set_wmclass("ph4ntxm-clipboard-guard", "PH4NTXM Clipboard Guard")
        add_class(self, "ph4ntxm-window")
        if os.path.isfile(CSS_FILE):
            provider = Gtk.CssProvider()
            provider.load_from_path(CSS_FILE)
            Gtk.StyleContext.add_provider_for_screen(
                self.get_screen(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )
        self.connect("destroy", self.on_destroy)
        self.build()
        self.update()

    def build(self):
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.add(root)
        header = add_class(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4), "top-panel")
        header.pack_start(label("PH4NTXM Clipboard Guard", "title"), False, False, 0)
        header.pack_start(label("Timed clipboard expiration", "subtitle"), False, False, 0)
        root.pack_start(header, False, False, 0)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        content.set_border_width(16)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.add(content)
        root.pack_start(scroll, True, True, 0)
        status = add_class(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5), "section")
        self.status_label = label("", "section-title")
        self.status_message = label("", "subtitle")
        status.pack_start(self.status_label, False, False, 0)
        status.pack_start(self.status_message, False, False, 0)
        content.pack_start(status, False, False, 0)
        content.pack_start(
            label(
                "Clipboard Guard watches clipboard ownership without reading or retaining copied contents.",
                "subtitle",
            ),
            False,
            False,
            0,
        )
        settings = add_class(Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12), "section")
        interval = Gtk.Box(spacing=12)
        interval.pack_start(label("Clear after"), False, False, 0)
        self.seconds = Gtk.SpinButton.new_with_range(1, 86400, 1)
        self.seconds.set_numeric(True)
        self.seconds.set_value(self.application.guard.seconds)
        interval.pack_start(self.seconds, False, False, 0)
        interval.pack_start(label("seconds"), False, False, 0)
        settings.pack_start(interval, False, False, 0)
        self.primary = Gtk.CheckButton(label="Also expire selected text used by middle-click paste")
        primary_label = self.primary.get_child()
        primary_label.set_line_wrap(True)
        primary_label.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
        primary_label.set_max_width_chars(64)
        self.primary.set_active(self.application.guard.include_primary)
        settings.pack_start(self.primary, False, False, 0)
        settings.pack_start(
            label(
                "Existing and new copies expire after the selected interval. Each new copy starts a new timer.",
                "subtitle",
            ),
            False,
            False,
            0,
        )
        content.pack_start(settings, False, False, 0)
        actions = Gtk.Box(spacing=10)
        self.enable_button = add_class(Gtk.Button(label="Enable Protection"), "primary")
        self.enable_button.connect("clicked", self.on_enable)
        self.disable_button = Gtk.Button(label="Disable Protection")
        self.disable_button.connect("clicked", self.on_disable)
        self.clear_button = Gtk.Button(label="Clear Now")
        self.clear_button.connect("clicked", self.on_clear)
        actions.pack_start(self.enable_button, False, False, 0)
        actions.pack_start(self.disable_button, False, False, 0)
        actions.pack_end(self.clear_button, False, False, 0)
        content.pack_start(actions, False, False, 0)
        content.pack_start(
            label(
                "Enable Protection or Clear Now disables Xfce clipboard persistence for this session and stops standalone Clipman if active. Other managers must be closed manually. Existing cached clipboard content may be lost. Copies already retained by applications cannot be revoked.",
                "subtitle",
            ),
            False,
            False,
            0,
        )
        content.pack_start(
            label(
                "Closing this window leaves enabled protection running. Disable protection here to stop it.",
                "subtitle",
            ),
            False,
            False,
            0,
        )
        footer = Gtk.Box(spacing=10)
        close = Gtk.Button(label="Close")
        close.connect("clicked", self.on_close)
        footer.pack_end(close, False, False, 0)
        content.pack_end(footer, False, False, 0)

    def update(self):
        guard = self.application.guard
        enabled = guard.enabled
        error = self.application.error
        style = self.status_label.get_style_context()
        for name in ("status-active", "status-disabled", "status-warning"):
            style.remove_class(name)
        if error:
            self.status_label.set_text("Protection needs attention")
            style.add_class("status-warning")
            self.status_message.set_text(error)
        else:
            self.status_label.set_text("Protection enabled" if enabled else "Protection disabled")
            style.add_class("status-active" if enabled else "status-disabled")
            self.status_message.set_text(guard.message)
        self.enable_button.set_sensitive(not enabled)
        self.disable_button.set_sensitive(enabled)
        self.seconds.set_sensitive(not enabled)
        self.primary.set_sensitive(not enabled)
        if enabled:
            self.seconds.set_value(guard.seconds)
            self.primary.set_active(guard.include_primary)

    def on_enable(self, button):
        self.seconds.update()
        self.application.perform(
            self.application.guard.start,
            self.seconds.get_value_as_int(),
            self.primary.get_active(),
        )

    def on_disable(self, button):
        self.application.stopping = True
        try:
            self.application.perform(self.application.guard.stop)
        finally:
            self.application.stopping = False

    def on_clear(self, button):
        self.application.perform(
            self.application.guard.clear_now,
            self.application.guard.include_primary
            if self.application.guard.enabled
            else self.primary.get_active(),
        )

    def on_close(self, button):
        self.destroy()

    def on_destroy(self, widget):
        if self.application.window is self:
            self.application.window = None


class ClipboardGuardApplication(Gtk.Application):
    def __init__(self):
        super().__init__(
            application_id="org.ph4ntxm.ClipboardGuard",
            flags=Gio.ApplicationFlags.FLAGS_NONE,
        )
        self.window = None
        self.guard = None
        self.held = False
        self.stopping = False
        self.shutting_down = False
        self.error = None

    def do_startup(self):
        Gtk.Application.do_startup(self)
        self.guard = Guard(
            GLibScheduler(GLib), lambda: X11Backend(GLib), self.guard_changed
        )

    def do_activate(self):
        self.present_window()

    def present_window(self):
        if self.window is None:
            self.window = ClipboardGuardWindow(self)
            self.window.show_all()
        self.window.update()
        self.window.present()

    def perform(self, operation, *args):
        self.error = None
        try:
            operation(*args)
        except GuardError as error:
            self.error = str(error)
        self.guard_changed()

    def guard_changed(self, *args):
        if self.shutting_down or self.guard is None:
            return
        enabled = self.guard.enabled
        if self.guard.error:
            self.error = self.guard.error
            if not self.stopping:
                self.present_window()
        if enabled and not self.held:
            self.hold()
            self.held = True
        elif not enabled and self.held:
            self.release()
            self.held = False
        if self.window is not None:
            self.window.update()

    def do_shutdown(self):
        self.shutting_down = True
        try:
            if self.guard is not None:
                self.guard.stop()
        finally:
            if self.held:
                self.release()
                self.held = False
            Gtk.Application.do_shutdown(self)


def main():
    if os.getuid() == 0 or os.geteuid() == 0:
        print("PH4NTXM Clipboard Guard must run as the desktop user.", file=sys.stderr)
        return 1
    ready, _arguments = Gtk.init_check(None)
    if (
        not ready
        or not isinstance(Gdk.Display.get_default(), GdkX11.X11Display)
        or os.environ.get("XDG_SESSION_TYPE", "").lower() == "wayland"
        or os.environ.get("WAYLAND_DISPLAY")
    ):
        print("PH4NTXM Clipboard Guard requires the native X11 desktop.", file=sys.stderr)
        return 1
    application = ClipboardGuardApplication()
    try:
        registered = application.register(None)
    except GLib.Error:
        registered = False
    if not registered or application.get_dbus_connection() is None:
        print("PH4NTXM Clipboard Guard requires the desktop session bus.", file=sys.stderr)
        application.quit()
        return 1
    return application.run(sys.argv)
