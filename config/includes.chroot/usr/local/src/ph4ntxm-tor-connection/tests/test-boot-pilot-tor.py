# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import ast
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


SOURCE = next(
    (
        base / "config/includes.chroot/usr/local/bin/ph4ntxm-boot-pilot"
        for base in Path(__file__).resolve().parents
        if (base / "config/includes.chroot/usr/local/bin/ph4ntxm-boot-pilot").is_file()
    ),
    Path("/usr/local/bin/ph4ntxm-boot-pilot"),
)


class Widget:
    def __init__(self, *args, **kwargs):
        self.text = kwargs.get("label", "")
        self.active = False
        self.visible = False
        self.sensitive = True
        self.handlers = {}
        self.children = []
        self.classes = set()
        self.destroyed = False
        self.stopped = set()
        self.group = None

    def connect(self, signal, callback):
        self.handlers.setdefault(signal, []).append(callback)

    def emit(self, signal, *args):
        for callback in self.handlers.get(signal, []):
            callback(self, *args)

    def set_text(self, text):
        self.text = text
        self.emit("changed")

    def get_text(self, *args):
        return self.text

    def get_bounds(self):
        return 0, len(self.text)

    def get_buffer(self):
        if not hasattr(self, "buffer"):
            self.buffer = Widget()
        return self.buffer

    def get_content_area(self):
        return self

    def get_style_context(self):
        return self

    def get_accessible(self):
        return self

    def add_class(self, value):
        self.classes.add(value)

    def remove_class(self, value):
        self.classes.discard(value)

    def add_button(self, *args):
        return Widget()

    def pack_start(self, widget, *args):
        self.children.append(widget)

    pack_end = pack_start

    def add(self, widget):
        self.children.append(widget)

    def get_children(self):
        return self.children

    def remove(self, widget):
        self.children.remove(widget)

    def set_sensitive(self, value):
        self.sensitive = value

    def get_sensitive(self):
        return self.sensitive

    def set_visible(self, value):
        self.visible = value

    def get_visible(self):
        return self.visible

    def set_active(self, value):
        changed = []
        if value and self.group:
            for other in self.group:
                if other is not self and other.active:
                    other.active = False
                    changed.append(other)
        if self.active != value:
            self.active = value
            changed.append(self)
        for widget in changed:
            widget.emit("toggled")

    def get_active(self):
        return self.active

    def set_label(self, value):
        self.text = value

    def show_all(self):
        self.visible = True

    def destroy(self):
        self.emit("destroy")
        self.destroyed = True
        self.visible = False

    def stop_emission_by_name(self, signal):
        self.stopped.add(signal)

    def __getattr__(self, name):
        if name.startswith("set_") or name in {
            "present", "grab_focus", "start", "stop", "hide", "show"
        }:
            return lambda *args: None
        raise AttributeError(name)


class Radio(Widget):
    def __init__(self):
        super().__init__()
        self.active = True
        self.group = [self]

    @classmethod
    def new_with_label_from_widget(cls, other, label):
        widget = cls()
        widget.active = False
        widget.group = other.group
        widget.group.append(widget)
        return widget


class Enum:
    def __getattr__(self, name):
        return name


gtk = types.SimpleNamespace(
    Window=Widget, Dialog=Widget, Box=Widget, RadioButton=Radio,
    Label=Widget, TextView=Widget, ScrolledWindow=Widget, Entry=Widget,
    Orientation=Enum(), Align=Enum(), WrapMode=Enum(),
    PolicyType=Enum(), ShadowType=Enum(), InputPurpose=Enum(),
    ResponseType=Enum(),
)
glib = types.SimpleNamespace(idle_add=Mock(), timeout_add=Mock())
repo = types.SimpleNamespace(Gtk=gtk, Gdk=Enum(), GLib=glib, Pango=types.SimpleNamespace(WrapMode=Enum()))
with patch.dict(sys.modules, {
    "gi": types.SimpleNamespace(require_version=lambda *args: None),
    "gi.repository": repo,
}):
    code = ast.parse(SOURCE.read_text())
    code.body = [node for node in code.body if not (
        isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name) and node.value.func.id == "harden_process"
    )]
    module = {"__name__": "boot_pilot_fixture"}
    exec(compile(code, str(SOURCE), "exec"), module)


Dialog = module["TorConnectionDialog"]
BootPilot = module["BootPilot"]


def snapshot(mode="pending", generation="fixture-generation", phase=None):
    return {
        "ok": True, "generation": generation, "mode": mode,
        "phase": phase or ("waiting" if mode == "pending" else "connecting"),
        "bridge_count": 1 if mode == "obfs4" else 0, "error": "",
    }


def parent(mode="pending"):
    return types.SimpleNamespace(
        tor_state=snapshot(mode), tor_action_active=False,
        tor_dialog=None, apply_tor_connection=Mock(),
    )


class TorDialogTests(unittest.TestCase):
    def dialog(self, mode="pending"):
        pilot = parent(mode)
        dialog = Dialog(pilot)
        pilot.tor_dialog = dialog
        return pilot, dialog

    def test_pending_has_no_selection_and_never_applies_automatically(self):
        pilot, dialog = self.dialog()
        self.assertIsNone(dialog.selected_mode())
        self.assertFalse(dialog.apply_button.get_sensitive())
        dialog.password_entry.set_text("secret")
        dialog.begin_apply()
        pilot.apply_tor_connection.assert_not_called()

    def test_cancel_clears_password_and_confidential_bridges(self):
        pilot, dialog = self.dialog()
        dialog.bridge.set_active(True)
        dialog.buffer.set_text("obfs4 confidential-cert")
        dialog.password_entry.set_text("secret")
        dialog.on_response(dialog, "CANCEL")
        self.assertEqual(dialog.password_entry.get_text(), "")
        self.assertEqual(dialog.bridge_text(), "")
        self.assertIsNone(pilot.tor_dialog)
        pilot.apply_tor_connection.assert_not_called()

    def test_direct_and_bridge_payloads_require_a_fresh_password(self):
        for mode in ("direct", "obfs4"):
            with self.subTest(mode=mode):
                pilot, dialog = self.dialog()
                (dialog.direct if mode == "direct" else dialog.bridge).set_active(True)
                if mode == "obfs4":
                    dialog.buffer.set_text("obfs4 private")
                self.assertFalse(dialog.apply_button.get_sensitive())
                dialog.password_entry.set_text("one secret")
                self.assertTrue(dialog.apply_button.get_sensitive())
                dialog.begin_apply()
                pilot.apply_tor_connection.assert_called_once_with(
                    dialog, mode, "obfs4 private" if mode == "obfs4" else "", "one secret"
                )
                self.assertEqual(dialog.password_entry.get_text(), "")
                self.assertEqual(dialog.bridge_text(), "")
                self.assertFalse(dialog.apply_button.get_sensitive())
                self.assertFalse(dialog.cancel_button.get_sensitive())
                self.assertTrue(dialog.on_delete(dialog, None))
                dialog.on_response(dialog, "CANCEL")
                self.assertFalse(dialog.closed)
                dialog.finish_result({"ok": False, "error": "Authorization failed"})
                self.assertFalse(dialog.apply_button.get_sensitive())
                self.assertTrue(dialog.cancel_button.get_sensitive())
                if mode == "obfs4":
                    dialog.password_entry.set_text("another secret")
                    self.assertFalse(dialog.apply_button.get_sensitive())

    def test_existing_obfs4_requires_repasting_and_success_closes(self):
        _, dialog = self.dialog("obfs4")
        self.assertEqual(dialog.selected_mode(), "obfs4")
        self.assertEqual(dialog.bridge_text(), "")
        dialog.password_entry.set_text("secret")
        self.assertFalse(dialog.apply_button.get_sensitive())
        dialog.buffer.set_text("obfs4 private")
        dialog.begin_apply()
        dialog.finish_result({"ok": True})
        self.assertTrue(dialog.destroyed)
        self.assertEqual(dialog.bridge_text(), "")

    def test_repeated_open_close_resets_fields(self):
        pilot = parent()
        for _ in range(6):
            dialog = Dialog(pilot)
            pilot.tor_dialog = dialog
            self.assertIsNone(dialog.selected_mode())
            self.assertEqual(dialog.bridge_text(), "")
            self.assertEqual(dialog.password_entry.get_text(), "")
            dialog.bridge.set_active(True)
            dialog.buffer.set_text("obfs4 confidential")
            dialog.password_entry.set_text("secret")
            dialog.destroy()
            self.assertIsNone(pilot.tor_dialog)

    def test_changed_snapshot_invalidates_form(self):
        pilot, dialog = self.dialog()
        dialog.direct.set_active(True)
        dialog.password_entry.set_text("secret")
        dialog.update_state(snapshot("obfs4", "new-generation"))
        self.assertTrue(dialog.stale)
        self.assertFalse(dialog.apply_button.get_sensitive())
        self.assertEqual(dialog.password_entry.get_text(), "")
        dialog.begin_apply()
        pilot.apply_tor_connection.assert_not_called()

    def test_selection_change_clears_authorization(self):
        _, dialog = self.dialog()
        dialog.bridge.set_active(True)
        dialog.buffer.set_text("obfs4 confidential")
        dialog.password_entry.set_text("secret")
        dialog.direct.set_active(True)
        self.assertEqual(dialog.password_entry.get_text(), "")
        self.assertEqual(dialog.bridge_text(), "")
        self.assertFalse(dialog.apply_button.get_sensitive())

    def test_bridge_input_limits(self):
        _, dialog = self.dialog()
        dialog.bridge.set_active(True)
        dialog.password_entry.set_text("secret")
        for text in ("x" * 8193, "\n".join(["x"] * 9), ""):
            dialog.buffer.set_text(text)
            self.assertFalse(dialog.apply_button.get_sensitive())
        dialog.buffer.set_text("x" * 8192)
        self.assertTrue(dialog.apply_button.get_sensitive())
        dialog.buffer.set_text("")
        position = types.SimpleNamespace(get_offset=lambda: 0)
        dialog.on_insert(dialog.buffer, position, "x" * 8193, 8193)
        self.assertIn("insert-text", dialog.buffer.stopped)
        dialog.buffer.set_text("\n".join(["x", ""] * 8))
        self.assertTrue(dialog.apply_button.get_sensitive())
        dialog.buffer.set_text("é" * 4096)
        self.assertTrue(dialog.apply_button.get_sensitive())
        dialog.buffer.set_text("é" * 4097)
        self.assertFalse(dialog.apply_button.get_sensitive())
        dialog.buffer.set_text("obfs4 invalid\x00control")
        self.assertTrue(dialog.apply_button.get_sensitive())
        dialog.buffer.set_text("obfs4 invalid\x7fcontrol")
        self.assertTrue(dialog.apply_button.get_sensitive())


class TorControlTests(unittest.TestCase):
    def test_fresh_auth_uses_only_stdin(self):
        command = module["TOR_CONTROL"]
        for _ in range(2):
            wire = "password\n" + json.dumps({"generation": "generation", "mode": "obfs4", "bridges": "secret cert"}) + "\n"
            result = types.SimpleNamespace(returncode=0, stdout='{"ok": true}')
            with patch.object(subprocess, "run", return_value=result) as run:
                self.assertEqual(module["tor_control"]("apply", wire), {"ok": True})
            args, options = run.call_args
            self.assertEqual(args[0], ["/usr/bin/sudo", "-k", "-S", "-p", "", "--", command, "apply"])
            self.assertEqual(options["input"], wire)
            self.assertNotIn("password", str(args))
            self.assertNotIn("env", options)
            self.assertEqual(options["stderr"], subprocess.DEVNULL)

    def test_password_and_json_cross_real_subprocess_pipe(self):
        with tempfile.TemporaryDirectory(prefix="ph4-tor-ui-") as directory:
            helper = Path(directory) / "control"
            sudo = Path(directory) / "sudo"
            helper.write_text(
                "#!/usr/bin/python3\nimport json, sys\n"
                "request = json.load(sys.stdin)\n"
                "assert request == {'generation': 'generation', 'mode': 'obfs4', 'bridges': 'secret cert'}\n"
                "print(json.dumps({'ok': True}))\n"
            )
            sudo.write_text(
                "#!/usr/bin/python3\nimport os, sys\n"
                "assert sys.argv[1:6] == ['-k', '-S', '-p', '', '--']\n"
                "password = b''\n"
                "while not password.endswith(b'\\n'):\n"
                "    byte = os.read(0, 1)\n"
                "    if not byte: sys.exit(1)\n"
                "    password += byte\n"
                "if password != b'password\\n': sys.exit(1)\n"
                "os.execv(sys.argv[6], sys.argv[6:])\n"
            )
            helper.chmod(0o700)
            sudo.chmod(0o700)
            wire = "password\n" + json.dumps({"generation": "generation", "mode": "obfs4", "bridges": "secret cert"}) + "\n"
            with patch.dict(module, {"TOR_CONTROL": str(helper), "SUDO": str(sudo)}):
                for _ in range(2):
                    self.assertEqual(module["tor_control"]("apply", wire), {"ok": True})
                self.assertFalse(module["tor_control"]("apply", "wrong\n{}\n")["ok"])

    def test_snapshot_is_unprivileged_and_strips_extra_secrets(self):
        state = dict(snapshot(), bridges="secret cert")
        with patch.object(
            subprocess,
            "run",
            return_value=types.SimpleNamespace(returncode=0, stdout=json.dumps(state)),
        ) as run:
            result = module["tor_control"]()
        self.assertEqual(run.call_args.args[0], [module["TOR_CONTROL"], "snapshot"])
        self.assertNotIn("bridges", result)
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_malformed_response_auth_failure_and_timeout(self):
        for value in ("[]", "{}", '{"ok":true}', "secret-cert"):
            with patch.object(subprocess, "run", return_value=types.SimpleNamespace(returncode=0, stdout=value)):
                self.assertFalse(module["tor_control"]()["ok"])
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("sudo", 90)):
            self.assertIn("Check its status", module["tor_control"]("apply", "secret\n{}\n")["error"])
        with patch.object(subprocess, "run", return_value=types.SimpleNamespace(returncode=1, stdout="")):
            self.assertFalse(module["tor_control"]("apply", "secret\n{}\n")["ok"])


class TorRefreshTests(unittest.TestCase):
    def test_pending_feature_is_pending_and_error_is_specific(self):
        check = module["tor_connection_feature"](snapshot())
        self.assertEqual(check["state"], "pending")
        state = dict(snapshot("obfs4", phase="error"), error="Tor configuration verification failed")
        check = module["tor_connection_feature"](state)
        self.assertEqual(check["state"], "fail")
        self.assertIn("configuration verification", check["detail"])
        self.assertEqual(module["tor_connection_feature"](snapshot("direct"), True)["detail"], "Direct Tor")

    def test_normal_modes_do_not_call_snapshot(self):
        defaults = {
            "completed": lambda *_: True, "read": lambda *args: "64" if args[0].endswith("ip_default_ttl") else "nameserver 127.0.0.1",
            "nonempty": lambda *_: True, "privileged_read": lambda *_: "MODE=linux", "session_mac_ready": lambda *_: True,
            "normal_packet_transformation_engine_state": lambda *_: (True, True, True), "active": lambda *_: True,
            "tor_control": Mock(side_effect=AssertionError("normal mode called Tor helper")),
        }
        with patch.dict(module, defaults):
            checks = module["network_features"]("linux")
        self.assertFalse(any(check["label"] == "Tor Connection" for check in checks))
        defaults["tor_control"].assert_not_called()

    def test_pending_gates_tor_and_dns_without_false_failures(self):
        defaults = {
            "completed": lambda *_: True,
            "read": lambda *args: "1" if "disable_ipv6" in args[0] else "nameserver 127.0.0.1",
            "privileged_read": lambda *_: "MODE=lonewolf", "session_mac_ready": lambda *_: True,
            "active": lambda unit: unit == "ph4ntxm-lonewolf-firewall-guard.service",
            "firewall_ready": lambda *_: True, "listener": lambda *_: False,
            "run": lambda *_: (0, "ActiveState=inactive\nSubState=dead"), "state_values": lambda *_: None,
        }
        with patch.dict(module, defaults):
            checks = module["network_features"]("lonewolf", snapshot())
        for label in ("Tor Connection", "Tor Routing", "DNS Protection"):
            self.assertEqual(next(check for check in checks if check["label"] == label)["state"], "pending")
        self.assertEqual(module["overall"]([{"checks": checks}])[0], "warn")

    def test_old_boot_result_cannot_replace_applied_choice(self):
        pilot = types.SimpleNamespace(
            boot_refresh_active=True, closed=False, tor_request_revision=4,
            refresh=Mock(), tor_state=snapshot("obfs4"),
        )
        result = BootPilot.apply_boot_state(pilot, [], (False, ""), snapshot("direct"), 3)
        self.assertFalse(result)
        self.assertEqual(pilot.tor_state["mode"], "obfs4")
        pilot.refresh.assert_called_once()

    def test_apply_worker_encodes_request_and_does_not_autolaunch_browser(self):
        pilot = types.SimpleNamespace(
            tor_action_active=False, tor_request_revision=0,
            boot_refresh_callback=Mock(), boot_refresh_pending=True,
            tor_action_error="", tor_connection_ready=True,
            boot_settled=True, browser_ready=True,
            update_browser_controls=Mock(), update_tor_panel=Mock(),
            apply_tor_result=Mock(),
        )
        dialog = types.SimpleNamespace(generation="generation")
        def thread(**options):
            options["target"]()
            return Mock()
        control = Mock(return_value={"ok": True})
        glib.idle_add.reset_mock()
        with (
            patch.dict(module, {"read": lambda *_: "lonewolf", "tor_control": control}),
            patch.object(module["threading"], "Thread", side_effect=thread),
        ):
            BootPilot.apply_tor_connection(pilot, dialog, "obfs4", "confidential cert", "password")
        self.assertTrue(pilot.tor_action_active)
        self.assertFalse(pilot.browser_ready)
        self.assertFalse(pilot.boot_settled)
        self.assertIsNone(pilot.boot_refresh_callback)
        action, wire = control.call_args.args
        self.assertEqual(action, "apply")
        password, payload = wire.split("\n", 1)
        self.assertEqual(password, "password")
        self.assertEqual(json.loads(payload), {"generation": "generation", "mode": "obfs4", "bridges": "confidential cert"})
        self.assertEqual(glib.idle_add.call_args.args, (pilot.apply_tor_result, dialog, "obfs4", {"ok": True}))

    def test_forced_modal_destroy_does_not_drop_parent_result_or_refresh(self):
        pilot, dialog = parent(), None
        dialog = Dialog(pilot)
        pilot.tor_dialog = dialog
        dialog.submitting = True
        dialog.destroy()
        pilot.tor_action_active = True
        pilot.tor_request_revision = 1
        pilot.closed = False
        pilot.update_tor_panel = Mock()
        pilot.refresh = Mock()
        BootPilot.apply_tor_result(pilot, dialog, "obfs4", {"ok": True})
        self.assertFalse(pilot.tor_action_active)
        self.assertEqual(pilot.tor_state["mode"], "obfs4")
        self.assertEqual(pilot.tor_state["phase"], "configuring")
        self.assertIn("accepted", pilot.tor_action_error)
        pilot.refresh.assert_called_once()

    def test_snapshot_refresh_remains_in_existing_worker(self):
        pilots = types.SimpleNamespace(
            closed=False, boot_refresh_callback=None, boot_refresh_active=False,
            tor_request_revision=0, apply_boot_state=Mock(),
        )
        fake_thread = Mock()
        def thread(**options):
            options["target"]()
            return fake_thread
        for mode, calls in (("linux", 0), ("windows", 0), ("lonewolf", 1)):
            pilots.boot_refresh_active = False
            control = Mock(return_value=snapshot())
            with patch.dict(module, {
                "read": lambda *args: mode, "tor_control": control,
                "collect": lambda *_: [], "browser_launch_status": lambda *_: (True, ""),
            }), patch.object(module["threading"], "Thread", side_effect=thread):
                BootPilot.refresh(pilots)
            self.assertEqual(control.call_count, calls)


if __name__ == "__main__":
    unittest.main()
