#!/usr/bin/python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from pathlib import Path
import contextlib
import io
import json
import os
import queue
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import browser_controller as controller


def request(urls=None, imports=None, private=False):
    return {"urls": urls or [], "imports": imports or [], "private_window": private}


class FakeSession:
    def __init__(self):
        self.items = []
        self.running = False
        self.closed = False
        self.calls = []
        self.results = []
        self.before_start = None
        self.profile = object()

    def add(self, paths):
        self.calls.append(("add", list(paths)))
        self.items.extend({"path": "/workspace/imports/" + Path(path).name} for path in paths)

    def snapshot(self):
        return {"running": self.running, "state": "running" if self.running else "ready"}

    def start(self, **kwargs):
        self.calls.append(("start", kwargs))
        if self.before_start:
            self.before_start()
        self.running = True

    def open_urls(self, urls, **kwargs):
        self.calls.append(("open", list(urls), kwargs))

    def stop(self):
        self.calls.append(("stop",))
        self.running = False

    def outputs(self):
        if self.running:
            raise ValueError("Review requires stopped browser")
        return self.results

    def close(self):
        self.calls.append(("close",))
        self.stop()
        self.closed = True


class FakeGtk:
    def __init__(self):
        self.events = queue.Queue()
        self.widgets = []
        self.window = None
        self.quit = False
        self.responses = []
        self.after_question = None
        self.settings = {"gtk-theme-name": "PH4NTXM-Ghost", "gtk-icon-theme-name": "Lyra-blue-dark", "gtk-font-name": "Sans 10"}
        environment = self

        class Widget:
            def __init__(self, *args, **kwargs):
                self.events = {}
                self.visible = True
                self.sensitive = True
                self.text = kwargs.get("label", "")
                self.tooltip = None
                self.ellipsize = None
                self.focus_on_click = True
                self.can_focus = False
                self.focused = False
                environment.widgets.append(self)

            def connect(self, name, callback):
                self.events[name] = callback

            def get_screen(self):
                return self

            def get_system_visual(self):
                return "preferred-visual"

            def set_visual(self, visual):
                self.visual = visual

            def get_primary_monitor(self):
                return 0

            def get_monitor_workarea(self, *_):
                return types.SimpleNamespace(width=1280, height=900)

            def get_allocation(self):
                return types.SimpleNamespace(width=1084, height=680)

            def get_id(self):
                return 42

            def get_content_area(self):
                return self

            def show_all(self):
                if self is environment.window:
                    for widget in list(environment.widgets):
                        if "realize" in widget.events:
                            assert widget.visual == "root-x11-visual"
                            assert widget.can_focus
                            assert all(not button.focus_on_click for button in environment.widgets if button.text in ("Import Files", "Downloads", "Resume"))
                            widget.events["realize"](widget)

            def set_can_focus(self, value):
                self.can_focus = value

            def grab_focus(self):
                assert self.can_focus
                self.focused = True

            def set_focus_on_click(self, value):
                self.focus_on_click = value

            def set_sensitive(self, value):
                self.sensitive = value

            def set_visible(self, value):
                self.visible = value

            def set_text(self, value):
                self.text = value
                if "notify::label" in self.events:
                    self.events["notify::label"](self, None)

            def get_text(self):
                return self.text

            def set_tooltip_text(self, value):
                self.tooltip = value

            def set_ellipsize(self, value):
                self.ellipsize = value

            def __getattr__(self, name):
                return lambda *args, **kwargs: None

        class Window(Widget):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                environment.window = self

        class Dialog(Widget):
            def run(self):
                response = environment.responses.pop(0) if environment.responses else 0
                if environment.after_question is not None:
                    callback, environment.after_question = environment.after_question, None
                    environment.idle_add(callback)
                return response

            def add_button(self, *args):
                return Widget()

        self.Gtk = types.SimpleNamespace(
            Window=Window, Box=Widget, Button=Widget, Socket=Widget, Label=Widget,
            MessageDialog=Dialog, Dialog=Dialog, WindowPosition=types.SimpleNamespace(CENTER=0),
            Orientation=types.SimpleNamespace(VERTICAL=0),
            MessageType=types.SimpleNamespace(QUESTION=1, ERROR=2),
            ButtonsType=types.SimpleNamespace(NONE=0, CLOSE=1),
            ResponseType=types.SimpleNamespace(CANCEL=0, ACCEPT=1),
            Settings=types.SimpleNamespace(get_default=lambda: types.SimpleNamespace(get_property=self.settings.get)),
            main=self.main, main_quit=self.main_quit,
        )
        self.GLib = types.SimpleNamespace(idle_add=self.idle_add, timeout_add=lambda *args: None)

    def idle_add(self, callback, *args):
        self.events.put((callback, args))

    def main(self):
        deadline = time.monotonic() + 5
        while not self.quit:
            if time.monotonic() > deadline:
                raise TimeoutError("The fake GTK lifecycle did not complete")
            try:
                callback, args = self.events.get(timeout=0.1)
            except queue.Empty:
                continue
            callback(*args)

    def main_quit(self):
        self.quit = True

    def modules(self):
        gi = types.ModuleType("gi")
        versions = {}

        def require_version(namespace, version):
            versions[namespace] = version

        class Repository(types.ModuleType):
            def __getattribute__(self, name):
                if name in ("Gtk", "Gdk", "GdkX11") and versions.get(name) != "3.0":
                    raise ValueError("GTK and Gdk must select version 3.0 before import")
                return super().__getattribute__(name)

        gi.require_version = require_version
        repository = Repository("gi.repository")
        repository.Gtk = self.Gtk
        repository.GLib = self.GLib
        repository.Gdk = types.SimpleNamespace()
        repository.GdkX11 = types.SimpleNamespace()
        repository.Pango = types.SimpleNamespace(EllipsizeMode=types.SimpleNamespace(END=3, MIDDLE=2))
        return {"gi": gi, "gi.repository": repository}


class FakeBroker:
    def listen(self, handler):
        self.handler = handler

    def close(self):
        pass


class ControllerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_selected_file_cli_and_strict_protocol(self):
        file = self.root / "selected file.html"
        file.write_text("selected")
        options = controller.parse_arguments(["-private-window", "https://example.org", file.as_uri(), "about:blank"])
        self.assertEqual(options["imports"], [str(file)])
        self.assertTrue(options["private_window"])
        self.assertEqual(options["urls"], ["https://example.org", "about:blank"])
        self.assertEqual(controller.selected_file(file.as_uri().replace("file:///", "file://localhost/")), str(file))
        for value in ("file://remote/tmp/file", "file:///tmp/%00", "file:///tmp/%FF", "file:///tmp/%xx", "file:///tmp/a?query", "file:///tmp/a#fragment", "file:///tmp/%2e%2e/file", "file:relative", "-profile", "--help", "about:config", "https://host/\nheader"):
            with self.subTest(value=value), self.assertRaises((ValueError, OSError)):
                controller.parse_arguments([value])
        link = self.root / "symlink"
        link.symlink_to(file)
        with self.assertRaises(controller.ControllerError):
            controller.parse_arguments([str(link)])
        valid = request(["https://example.org"], [str(file)], True)
        self.assertEqual(controller.decode_request(json.dumps(valid).encode()), valid)
        for value in (b'{"urls":[],"urls":[],"imports":[],"private_window":false}', b'{"urls":[],"imports":[],"private_window":1}', json.dumps({**valid, "op": "export"}).encode(), json.dumps(request(imports=["relative"])).encode(), json.dumps(request(urls=["file:///home/private"])).encode(), b"x" * (controller.MAX_MESSAGE + 1)):
            with self.subTest(value=value[:80]), self.assertRaises(ValueError):
                controller.decode_request(value)
        with self.assertRaises(controller.ControllerError):
            controller.validate_request(request(urls=["https://example.org"] * 17, imports=[str(file)] * 16))

    def test_pipe_acknowledgement_requires_fifo_and_not_inherited(self):
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        self.assertEqual(controller.ready_descriptor(write), write)
        self.assertFalse(os.get_inheritable(write))
        controller.acknowledge(write)
        self.assertEqual(os.read(read, 64), b"accepted\n")
        descriptor = os.open(self.root / "regular", os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, descriptor)
        with self.assertRaises(controller.ControllerError):
            controller.ready_descriptor(descriptor)

    def test_socket_single_controller_relay_permissions_and_cleanup(self):
        primary = controller.Broker(self.root)
        self.addCleanup(primary.close)
        calls = []
        primary.listen(lambda value: calls.append(value) or {"ok": True})
        secondary = controller.Broker(self.root)
        self.addCleanup(secondary.close)
        self.assertTrue(primary.primary)
        self.assertFalse(secondary.primary)
        value = request(["https://example.org"], private=True)
        secondary.forward(value, timeout=2)
        self.assertEqual(calls, [value])
        self.assertEqual(stat.S_IMODE(primary.path.lstat().st_mode), 0o600)
        primary.path.chmod(0o666)
        with self.assertRaises(controller.ControllerError):
            secondary.forward(value, timeout=2)
        primary.path.chmod(0o600)
        primary.close()
        self.assertFalse(primary.path.exists())
        reopened = controller.Broker(self.root)
        self.addCleanup(reopened.close)
        self.assertTrue(reopened.primary)

    def test_peer_uid_and_lock_mutations_are_rejected(self):
        peer = types.SimpleNamespace(getsockopt=lambda *args: struct.pack("3i", 1, os.getuid() + 1, 1))
        with self.assertRaises(controller.ControllerError):
            controller.same_peer(peer)
        lock = self.root / "ph4ntxm-browser-airlock.lock"
        target = self.root / "target"
        target.write_text("untouched")
        lock.symlink_to(target)
        with self.assertRaises(OSError):
            controller.Broker(self.root)
        self.assertEqual(target.read_text(), "untouched")

    def test_imported_urls_once_live_forward_and_same_profile_resume(self):
        session = FakeSession()
        factory = unittest.mock.Mock(return_value=session)
        state = controller.BrowserState(types.SimpleNamespace(Session=factory))
        state.open(request(["https://first.example"], ["/tmp/a b.html"], True), {"screen_width": 1000}, 42)
        self.assertEqual(session.calls[0][0], "add")
        self.assertEqual(session.calls[1][1]["urls"], ["https://first.example", "file:///workspace/imports/a%20b.html"])
        state.open(request(["https://second.example"]), {}, 42)
        self.assertEqual(session.calls[-1][0], "open")
        self.assertEqual(state.review(), [])
        profile = session.profile
        state.open(request(), {}, 42)
        factory.assert_called_once()
        self.assertIs(session.profile, profile)
        self.assertEqual(sum(call[0] == "start" for call in session.calls), 2)

    def lifecycle(self, session, environment, ready=None):
        backend = types.SimpleNamespace(Session=lambda: session)
        with (
            patch.dict("sys.modules", environment.modules()),
            patch.object(controller, "root_visual", return_value="root-x11-visual"),
        ):
            return controller.desktop(backend, FakeBroker(), request(["https://initial.example"]), ready)

    def test_startup_cancel_stops_cleans_and_never_acknowledges(self):
        environment = FakeGtk()
        session = FakeSession()
        def starting():
            environment.idle_add(environment.window.close_requested)
            time.sleep(0.03)
        session.before_start = starting
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        self.assertEqual(self.lifecycle(session, environment, write), 0)
        self.assertTrue(session.closed)
        self.assertEqual(os.read(read, 64), b"")
        settings = next(call[1]["settings"] for call in session.calls if call[0] == "start")
        self.assertEqual({key: settings[key] for key in environment.settings}, environment.settings)
        self.assertEqual(environment.window.status.ellipsize, 3)
        self.assertEqual(environment.window.status.tooltip, environment.window.status.text)

    def test_close_cancel_then_resume_retains_profile_and_final_discard_cleans(self):
        environment = FakeGtk()
        environment.responses = [0, 1]
        session = FakeSession()
        session.results = [{"id": "download.pdf", "name": "download.pdf", "size": 12}]
        def starting():
            environment.idle_add(environment.window.close_requested)
            time.sleep(0.02)
        session.before_start = starting
        def resume():
            self.assertFalse(session.closed)
            self.assertFalse(session.running)
            environment.window.open_request(request())
        environment.after_question = resume
        profile = session.profile
        self.assertEqual(self.lifecycle(session, environment), 0)
        self.assertTrue(session.closed)
        self.assertIs(session.profile, profile)
        self.assertEqual(sum(call[0] == "start" for call in session.calls), 2)

    def test_poll_preserves_display_exit_reason_and_tooltip(self):
        environment = FakeGtk()
        session = FakeSession()
        reason = "The isolated display stopped while the browser worker was still running. Exit status: 0."
        session.snapshot = lambda: {"running": session.running, "state": "running" if session.running else "failed", "message": reason}
        def reviewed():
            if environment.window.busy:
                environment.idle_add(reviewed)
                return
            self.assertFalse(environment.window.running)
            self.assertIn(reason, environment.window.status.text)
            self.assertEqual(environment.window.status.tooltip, environment.window.status.text)
            environment.window.close_requested()
        def stopped():
            if environment.window.busy:
                environment.idle_add(stopped)
                return
            session.running = False
            environment.window.poll()
            environment.idle_add(reviewed)
        session.before_start = lambda: environment.idle_add(stopped)
        self.assertEqual(self.lifecycle(session, environment), 0)
        self.assertTrue(session.closed)

    def test_start_failure_reports_nonzero_and_closes_ack_pipe(self):
        environment = FakeGtk()
        session = FakeSession()
        def starting():
            raise ValueError("Failed isolation")
        session.before_start = starting
        read, write = os.pipe()
        self.addCleanup(os.close, read)
        with contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(self.lifecycle(session, environment, write), 1)
        self.assertIn("Failed isolation", errors.getvalue())
        self.assertEqual(os.read(read, 64), b"")
        self.assertTrue(session.closed)

    def test_review_limit_can_discard_after_verified_stop_but_stop_failure_blocks(self):
        environment = FakeGtk()
        environment.responses = [1]
        session = FakeSession()
        def outputs():
            self.assertFalse(session.running)
            raise ValueError("The workspace exceeds its 256-entry review limit.")
        session.outputs = outputs
        def starting():
            environment.idle_add(environment.window.close_requested)
            time.sleep(0.02)
        session.before_start = starting
        self.assertEqual(self.lifecycle(session, environment), 0)
        self.assertTrue(session.closed)
        session = FakeSession()
        session.running = True
        state = controller.BrowserState(types.SimpleNamespace(Session=lambda: session))
        state.session = session
        def stop_failed():
            raise ValueError("The isolated application has not stopped.")
        session.stop = stop_failed
        with self.assertRaisesRegex(ValueError, "has not stopped"):
            state.prepare_close()
        self.assertFalse(session.closed)
        self.assertTrue(session.running)

    def test_relay_during_start_is_serial_and_initial_urls_not_replayed(self):
        environment = FakeGtk()
        session = FakeSession()
        broker = FakeBroker()
        relay_results = []
        def starting():
            if len([call for call in session.calls if call[0] == "start"]) != 1:
                return
            def relay():
                relay_results.append(broker.handler(request(["https://second.example"])))
                environment.idle_add(environment.window.close_requested)
            threading.Thread(target=relay, daemon=True).start()
            time.sleep(0.03)
        session.before_start = starting
        with (
            patch.dict("sys.modules", environment.modules()),
            patch.object(controller, "root_visual", return_value="root-x11-visual"),
        ):
            result = controller.desktop(types.SimpleNamespace(Session=lambda: session), broker, request(["https://first.example"]), None)
        self.assertEqual(result, 0)
        self.assertEqual(relay_results, [{"ok": True, "error": ""}])
        self.assertEqual([call[1]["urls"] for call in session.calls if call[0] == "start"], [["https://first.example"]])
        self.assertEqual([call[1] for call in session.calls if call[0] == "open"], [["https://second.example"]])


if __name__ == "__main__":
    unittest.main()
