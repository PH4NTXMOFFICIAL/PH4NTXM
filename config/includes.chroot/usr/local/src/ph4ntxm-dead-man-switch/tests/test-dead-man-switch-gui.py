#!/usr/bin/python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import threading
import time
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[4]
GUI = ROOT / "local/bin/ph4ntxm-dead-man-switch"
loader = importlib.machinery.SourceFileLoader("dead_man_gui", str(GUI))
spec = importlib.util.spec_from_loader(loader.name, loader)
gui = importlib.util.module_from_spec(spec)
loader.exec_module(gui)


def snapshot(state="disarmed", remaining=0, generation="a" * 32):
    active = state in {"armed", "warning", "triggered", "degraded"}
    return {
        "ok": True,
        "state": state,
        "generation": generation,
        "duration_seconds": 900 if active else 0,
        "remaining_seconds": remaining,
        "deadline_boottime_ns": time.clock_gettime_ns(time.CLOCK_BOOTTIME) + remaining * 1000000000 if active else 0,
        "message": "Synthetic timer status",
    }


class HelperTests(unittest.TestCase):
    def test_authentication_and_generation_for_every_action(self):
        for action, generation, minutes in (
            ("arm", "", 15),
            ("arm", "a" * 32, 1),
            ("renew", "b" * 32, 1440),
            ("disarm", "c" * 32, None),
        ):
            with self.subTest(action=action, minutes=minutes):
                call = gui.HelperCall(action, generation, minutes)
                with patch.object(call, "run_process", return_value=(0, b'{"ok":true}')) as run:
                    self.assertEqual(call.run(), {"ok": True})
                command, environment = run.call_args.args
                self.assertEqual(command, ["/usr/bin/sudo", "-A", "-k", "--", gui.CONTROL, action])
                self.assertEqual(environment["SUDO_ASKPASS"], "/usr/local/bin/ph4ntxm-askpass")
                expected = {"generation": generation}
                if action != "disarm":
                    expected["minutes"] = minutes
                self.assertEqual(json.loads(call.input), expected)
                self.assertNotIn("password", json.loads(call.input))

    def test_invalid_requests_never_start_a_process(self):
        for action, generation, minutes in (
            ("snapshot", "", None),
            ("arm", "invalid", 15),
            ("renew", "a" * 32, True),
            ("arm", "", 0),
            ("arm", "", 1441),
        ):
            with self.subTest(action=action, minutes=minutes):
                with self.assertRaises(ValueError):
                    gui.HelperCall(action, generation, minutes)

    def test_malformed_and_duplicate_json_is_not_success(self):
        call = gui.HelperCall("arm", "", 15)
        for output in (b'{"ok":true,"ok":false}', b'{"ok":1}', b'[]', b'not json', b'\xff'):
            with self.subTest(output=output), patch.object(call, "run_process", return_value=(0, output)):
                self.assertFalse(call.run()["ok"])

    def test_cancel_before_start(self):
        call = gui.HelperCall("arm", "", 15)
        call.cancel()
        with patch.object(gui.subprocess, "Popen") as popen:
            self.assertFalse(call.run()["ok"])
            popen.assert_not_called()

    def test_bounded_output_and_timeout_cleanup(self):
        environment = dict(os.environ)
        call = gui.HelperCall("arm", "", 15)
        with patch.object(gui, "MAX_OUTPUT", 256):
            with self.assertRaises(ValueError):
                call.run_process(["/usr/bin/python3", "-c", "import sys; sys.stdin.buffer.read(); sys.stdout.write('x'*4096)"], environment)
        self.assertIsNone(call.process)
        with patch.object(gui, "HELPER_TIMEOUT", 0.1):
            with self.assertRaises(TimeoutError):
                call.run_process(["/usr/bin/python3", "-c", "import time; time.sleep(10)"], environment)
        self.assertIsNone(call.process)

    def test_pending_cancellation_reaps_process(self):
        call = gui.HelperCall("arm", "", 15)
        errors = []

        def worker():
            try:
                call.run_process(["/usr/bin/python3", "-c", "import time; time.sleep(10)"], dict(os.environ))
            except InterruptedError:
                errors.append("cancelled")

        thread = threading.Thread(target=worker)
        thread.start()
        for _ in range(100):
            with call.lock:
                process = call.process
            if process is not None:
                break
            time.sleep(0.01)
        self.assertIsNotNone(process)
        call.cancel()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertIsNotNone(process.poll())
        self.assertIsNone(call.process)
        self.assertEqual(errors, ["cancelled"])


class UiLogicTests(unittest.TestCase):
    def test_controls_respect_expiry_busy_and_backend_state(self):
        self.assertEqual(gui.controls(snapshot()), {"arm": True, "renew": False, "disarm": False})
        for state in ("armed", "warning"):
            self.assertEqual(gui.controls(snapshot(state, 30)), {"arm": False, "renew": True, "disarm": True})
            self.assertFalse(any(gui.controls(snapshot(state, 0)).values()))
            self.assertFalse(any(gui.controls(snapshot(state, 30), busy=True).values()))
        self.assertFalse(any(gui.controls(snapshot("triggered", 0)).values()))
        degraded = snapshot("degraded", 30)
        degraded["ok"] = False
        self.assertEqual(gui.controls(degraded), {"arm": False, "renew": False, "disarm": True})

    def test_invalid_snapshot_is_rejected(self):
        for key, value in (
            ("ok", 1), ("state", "off"), ("generation", "xyz"),
            ("duration_seconds", True), ("remaining_seconds", -1),
            ("remaining_seconds", 86401), ("deadline_boottime_ns", 0),
        ):
            candidate = snapshot("armed", 60)
            candidate[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                gui.validate_snapshot(candidate)

    def test_status_failure_preserves_known_active_deadline(self):
        previous = snapshot("armed", 50)
        failed = gui.unavailable_snapshot(previous)
        self.assertFalse(failed["ok"])
        self.assertTrue(gui.is_active(failed))
        self.assertEqual(failed["generation"], previous["generation"])
        self.assertEqual(failed["deadline_boottime_ns"], previous["deadline_boottime_ns"])
        self.assertIn(failed["remaining_seconds"], (49, 50))
        self.assertFalse(gui.is_active(gui.unavailable_snapshot(snapshot())))

    def test_close_cancels_pending_request_and_refreshes_without_disarming(self):
        events = []
        application = types.SimpleNamespace(
            job=types.SimpleNamespace(cancel=lambda: events.append("cancel")),
            refresh=lambda: events.append("refresh"),
            complete_close=lambda: events.append("exit"),
            window=types.SimpleNamespace(hide=lambda: events.append("hide")),
            notice="",
        )
        with patch.object(gui, "HelperCall", side_effect=AssertionError("Closing must not mutate the timer")):
            gui.DeadManApplication.close_window(application)
        self.assertEqual(events, ["hide", "cancel", "refresh"])
        self.assertTrue(application.closing)
        self.assertIn("checked again", application.notice)

    def test_close_without_pending_request_exits_without_mutation(self):
        events = []
        application = types.SimpleNamespace(
            job=None, window=types.SimpleNamespace(hide=lambda: events.append("hide")),
            refresh=lambda: events.append("refresh"), complete_close=lambda: events.append("exit"),
        )
        with patch.object(gui, "HelperCall", side_effect=AssertionError("Closing must not mutate the timer")):
            gui.DeadManApplication.close_window(application)
        self.assertEqual(events, ["hide", "refresh", "exit"])

    def test_close_waits_for_cancelled_helper_cleanup_before_exit(self):
        events = []
        job = object()
        application = types.SimpleNamespace(
            job=job, notice="", stopping=False, closing=True,
            refresh=lambda: events.append("refresh"), complete_close=lambda: events.append("exit"),
        )
        gui.DeadManApplication.finish(application, job, {"ok": False, "error": "Cancelled"})
        self.assertIsNone(application.job)
        self.assertEqual(events, ["refresh", "exit"])

    def test_finish_reads_current_backend_truth_even_when_request_failed(self):
        job = object()
        application = types.SimpleNamespace(job=job, notice="", stopping=False, closing=False)
        application.refresh = lambda: setattr(application, "snapshot", snapshot("armed", 899))
        self.assertFalse(gui.DeadManApplication.finish(application, job, {"ok": False, "error": "Cancelled"}))
        self.assertIsNone(application.job)
        self.assertEqual(application.snapshot["state"], "armed")
        self.assertEqual(application.notice, "Cancelled")

    def test_status_poll_is_unprivileged_and_cannot_notify_or_present(self):
        events = []
        application = types.SimpleNamespace(
            stopping=False, snapshot=gui.unavailable_snapshot(),
            window=types.SimpleNamespace(update=lambda: events.append("update")),
            present_controls=lambda: self.fail("Polling must not open controls"),
        )
        with (
            patch.object(gui.subprocess, "Popen") as popen,
            patch.object(gui.Gio.Notification, "new", side_effect=AssertionError("No notifications")),
            patch.object(gui.Gtk, "StatusIcon", side_effect=AssertionError("No tray icon")),
        ):
            for state, remaining in (("disarmed", 0), ("armed", 100), ("warning", 60), ("degraded", 50), ("triggered", 0)):
                with patch.object(gui, "read_snapshot", return_value=snapshot(state, remaining)):
                    self.assertTrue(gui.DeadManApplication.refresh(application))
            popen.assert_not_called()
        self.assertEqual(events, ["update"] * 5)
        source = GUI.read_text()
        self.assertNotIn("Gio.Notification", source)
        self.assertNotIn("StatusIcon", source)
        self.assertNotIn("send_notification", source)
        self.assertNotIn("--monitor", source)

    def test_degraded_reader_response_keeps_last_known_active_deadline(self):
        previous = snapshot("armed", 100)
        application = types.SimpleNamespace(
            stopping=False, snapshot=previous, window=None,
        )
        with patch.object(gui, "read_snapshot", return_value=gui.unavailable_snapshot()):
            gui.DeadManApplication.refresh(application)
        self.assertEqual(application.snapshot["generation"], previous["generation"])
        self.assertEqual(application.snapshot["deadline_boottime_ns"], previous["deadline_boottime_ns"])
        self.assertFalse(application.snapshot["ok"])

    def test_countdown_format(self):
        self.assertEqual(gui.format_remaining(0), "00:00")
        self.assertEqual(gui.format_remaining(60), "01:00")
        self.assertEqual(gui.format_remaining(900), "15:00")
        self.assertEqual(gui.format_remaining(86400), "24:00:00")


if __name__ == "__main__":
    unittest.main()
