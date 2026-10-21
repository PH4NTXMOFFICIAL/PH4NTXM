#!/usr/bin/python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import copy
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch


def source_root():
    for ancestor in Path(__file__).resolve().parents:
        candidate = ancestor / "config/includes.chroot"
        if (candidate / "usr/lib/ph4ntxm/session_guard_client.py").is_file():
            return candidate
    return Path("/")


ROOT = source_root()
sys.path.insert(0, str(ROOT / "usr/lib/ph4ntxm"))
import session_guard_client as client


def load(name, filename):
    loader = importlib.machinery.SourceFileLoader(
        name, str(ROOT / "usr/local/bin" / filename)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


gui = load("session_guard_gui", "ph4ntxm-session-guard")
monitor = load("session_guard_monitor", "ph4ntxm-session-guard-monitor")


def snapshot(enabled=True, incidents=None):
    return {
        "ok": True,
        "schema": 1,
        "available": True,
        "enabled": enabled,
        "generation": "a" * 32,
        "mode": "linux",
        "sequence": 1,
        "last_poll_boottime": time.clock_gettime(time.CLOCK_BOOTTIME),
        "poll_interval": 10,
        "checks": [
            {
                "code": "identity",
                "title": "Session identity consistency",
                "healthy": False,
                "status": "failed",
                "detail": "Session identity changed.",
            }
        ],
        "incidents": incidents if incidents is not None else [
            {
                "id": "b" * 32,
                "code": "identity",
                "severity": "warning",
                "title": "Session identity consistency",
                "detail": "Session identity changed.",
                "mode": "linux",
                "active": True,
                "first_seen_boottime": 123.5,
                "resolved_boottime": None,
            }
        ],
    }


def bare_monitor():
    current = monitor.SessionGuardMonitor.__new__(monitor.SessionGuardMonitor)
    current.stopping = False
    current.quitting = False
    current.snapshot_job = None
    current.notification_jobs = set()
    current.lockdown_job = None
    current.result_job = None
    current.tracker = client.EpisodeTracker()
    current.last_enabled_snapshot = None
    current.unavailable_id = None
    current.unavailable_since = None
    current.start = unittest.mock.Mock()
    return current


class ClientTests(unittest.TestCase):
    def test_status_is_public_and_validated(self):
        call = client.HelperCall()
        with patch.object(
            call, "run_process", return_value=(0, json.dumps(snapshot()).encode())
        ) as run:
            self.assertTrue(call.run()["enabled"])
        self.assertEqual(run.call_args.args[0], [client.CONTROL, "status"])
        self.assertEqual(run.call_args.args[1], 5)
        self.assertIsNone(run.call_args.args[2])

    def test_password_is_fresh_stdin_only_for_every_mutation(self):
        for action in ("enable", "disable", "enable"):
            with self.subTest(action=action):
                call = client.HelperCall(action, "a" * 32, "test password")
                captured = {}

                def run(command, timeout, input_data):
                    captured.update(command=command, timeout=timeout, input=bytes(input_data))
                    return 0, b'{"ok":true}'

                with patch.object(call, "run_process", side_effect=run):
                    self.assertTrue(call.run()["ok"])
                self.assertEqual(
                    captured["command"],
                    ["/usr/bin/sudo", "-k", "-S", "-p", "", "--", client.CONTROL, action],
                )
                self.assertEqual(captured["input"].splitlines()[0], b"test password")
                self.assertEqual(
                    json.loads(captured["input"].splitlines()[1]),
                    {"generation": "a" * 32},
                )
                self.assertLessEqual(captured["timeout"], 30)
                self.assertIsNone(call.input)
                self.assertNotIn("test password", repr(captured["command"]))

    def test_invalid_authorization_never_spawns(self):
        for action, generation, password in (
            ("enable", "invalid", "password"),
            ("disable", "a" * 32, "bad\npassword"),
            ("disable", "a" * 32, ""),
            ("lockdown", "a" * 32, "password"),
        ):
            with self.subTest(action=action, generation=generation), self.assertRaises(ValueError):
                client.HelperCall(action, generation, password)

    def test_bad_response_and_nonzero_exit_are_not_success(self):
        for code, output in (
            (0, b'{"ok":true,"ok":false}'),
            (0, b'{"ok":1}'),
            (0, b"[]"),
            (1, b'{"ok":true}'),
            (0, b"\xff"),
        ):
            call = client.HelperCall("enable", "a" * 32, "password")
            with (
                self.subTest(code=code, output=output),
                patch.object(call, "run_process", return_value=(code, output)),
            ):
                self.assertFalse(call.run()["ok"])
                self.assertIsNone(call.input)

    def test_snapshot_rejects_unsafe_and_unbounded_fields(self):
        mutations = [
            ("poll_interval", 5),
            ("poll_interval", 10.0),
            ("mode", []),
            ("enabled", 1),
            ("generation", "bad"),
            ("last_poll_boottime", float("nan")),
            ("incidents", snapshot()["incidents"] * 65),
        ]
        for key, value in mutations:
            data = snapshot()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                client.validate_snapshot(data)
        data = snapshot()
        data["incidents"][0]["detail"] = "x" * 2049
        with self.assertRaises(ValueError):
            client.validate_snapshot(data)
        data = snapshot()
        data["incidents"][0]["title"] = "Unsafe\u202etitle\x00"
        self.assertNotIn("\u202e", client.validate_snapshot(data)["incidents"][0]["title"])

    def test_status_freshness_including_disabled_and_future_clock(self):
        for enabled in (False, True):
            for age in (-0.1, 0, 30, 30.01):
                data = snapshot(enabled=enabled)
                data["last_poll_boottime"] = 100 - age
                with (
                    self.subTest(enabled=enabled, age=age),
                    patch.object(client.time, "clock_gettime", return_value=100),
                ):
                    if 0 <= age <= 30:
                        self.assertTrue(client.validate_snapshot(data)["ok"])
                    else:
                        with self.assertRaises(ValueError):
                            client.validate_snapshot(data)

    def test_unknown_mode_only_when_disabled(self):
        data = snapshot(enabled=False)
        data["mode"] = "unknown"
        self.assertEqual(client.validate_snapshot(data)["mode"], "unknown")
        data["enabled"] = True
        with self.assertRaises(ValueError):
            client.validate_snapshot(data)

    def test_lockdown_requires_success_and_protected_status(self):
        for code, enabled in ((1, True), (0, False), (0, True), (0, None)):
            call = client.LockdownCall()
            with (
                self.subTest(code=code, enabled=enabled),
                patch.object(call, "run_process", return_value=(code, b"")) as run,
                patch.object(client, "lockdown_state", return_value=enabled),
            ):
                self.assertEqual(call.run()["ok"], code == 0 and enabled is True)
            self.assertEqual(
                run.call_args.args[0],
                ["/usr/bin/sudo", "-n", "/usr/local/sbin/ph4ntxm-firewall-control", "enable"],
            )

    def test_disable_lockdown_needs_fresh_password_and_verified_false(self):
        for code, state in ((0, False), (0, True), (0, None), (1, False)):
            with self.subTest(code=code, state=state):
                call = client.LockdownCall("disable", "test password")
                secret = call.input
                captured = {}

                def run(command, timeout, input_data, maximum):
                    captured.update(command=command, input=bytes(input_data))
                    return code, b""

                with (
                    patch.object(call, "run_process", side_effect=run),
                    patch.object(client, "lockdown_state", return_value=state),
                ):
                    self.assertEqual(call.run()["ok"], code == 0 and state is False)
                self.assertEqual(
                    captured["command"],
                    ["/usr/bin/sudo", "-k", "-S", "-p", "", "--",
                     "/usr/local/sbin/ph4ntxm-firewall-control", "disable"],
                )
                self.assertEqual(captured["input"], b"test password\n")
                self.assertNotIn("test password", repr(captured["command"]))
                self.assertIsNone(call.input)
                self.assertEqual(secret, bytearray(len(secret)))
        for password in (None, "", "wrong\nline", "nul\x00", "x" * 513):
            with self.assertRaises(ValueError):
                client.LockdownCall("disable", password)

    def test_lockdown_status_still_updates_when_monitoring_status_fails(self):
        call = client.HelperCall()
        with (
            patch.object(call, "run_process", return_value=(1, b'{"ok":false}')),
            patch.object(client, "lockdown_state", return_value=True),
        ):
            result = call.run()
        self.assertFalse(result["ok"])
        self.assertIs(result["lockdown_enabled"], True)

    def test_status_reader_rejects_symlink_writable_and_false(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            path.write_text('{"enabled":true}')
            path.chmod(0o666)
            self.assertFalse(client.lockdown_enabled(str(path)))
            path.chmod(0o644)
            link = Path(directory) / "link"
            link.symlink_to(path)
            self.assertFalse(client.lockdown_enabled(str(link)))
            path.write_text('{"enabled":false}')
            self.assertFalse(client.lockdown_enabled(str(path)))

    def test_timeout_output_limit_and_cancellation_reap_child(self):
        call = client.BoundedProcess()
        with self.assertRaises(TimeoutError):
            call.run_process(["/usr/bin/python3", "-c", "import time; time.sleep(10)"], 0.05)
        self.assertIsNone(call.process)
        with self.assertRaises(ValueError):
            call.run_process(["/usr/bin/python3", "-c", "print('x'*8192)"], 2, maximum=32)
        self.assertIsNone(call.process)
        call.cancel()
        with (
            patch.object(client.subprocess, "Popen") as popen,
            self.assertRaises(InterruptedError),
        ):
            call.run_process(["/usr/bin/true"], 1)
        popen.assert_not_called()


class MonitorTests(unittest.TestCase):
    def test_unknown_or_disabled_backend_loss_is_quiet(self):
        current = bare_monitor()
        marker = object()
        current.snapshot_job = marker
        current.finish_snapshot(marker, {"ok": False})
        current.start.assert_not_called()
        current.snapshot_job = marker
        current.finish_snapshot(marker, snapshot(enabled=False, incidents=[]))
        current.snapshot_job = marker
        current.finish_snapshot(marker, {"ok": False})
        current.start.assert_not_called()
        self.assertIsNone(current.unavailable_id)

    def test_enabled_backend_loss_warns_once_and_recovery_allows_new_episode(self):
        current = bare_monitor()
        marker = object()
        healthy = snapshot(incidents=[])
        healthy["last_poll_boottime"] = 100
        current.snapshot_job = marker
        current.finish_snapshot(marker, healthy)
        with patch.object(monitor.time, "clock_gettime", return_value=130):
            current.snapshot_job = marker
            current.finish_snapshot(marker, {"ok": False})
        current.start.assert_not_called()
        with patch.object(monitor.time, "clock_gettime", return_value=131):
            current.snapshot_job = marker
            current.finish_snapshot(marker, {"ok": False})
        self.assertEqual(current.start.call_count, 1)
        first = next(iter(current.notification_jobs))
        self.assertEqual(first.incidents[0]["code"], "backend-unavailable")
        first_id = current.unavailable_id
        current.finish_notification(first, {"ok": True, "action": "dismiss"})
        with patch.object(monitor.time, "clock_gettime", return_value=140):
            current.snapshot_job = marker
            current.finish_snapshot(marker, {"ok": False})
        self.assertEqual(current.start.call_count, 1)
        self.assertEqual(current.unavailable_id, first_id)
        healthy["last_poll_boottime"] = 150
        current.snapshot_job = marker
        current.finish_snapshot(marker, healthy)
        self.assertIsNone(current.unavailable_id)
        self.assertEqual(current.tracker.current, {})
        with patch.object(monitor.time, "clock_gettime", return_value=181):
            current.snapshot_job = marker
            current.finish_snapshot(marker, {"ok": False})
        self.assertEqual(current.start.call_count, 2)
        self.assertNotEqual(current.unavailable_id, first_id)
        current.snapshot_job = marker
        current.finish_snapshot(marker, snapshot(enabled=False, incidents=[]))
        self.assertIsNone(current.last_enabled_snapshot)
        self.assertIsNone(current.unavailable_id)
        self.assertEqual(current.tracker.current, {})

    def test_first_failed_poll_notifies_and_unchanged_does_not_repeat(self):
        current = bare_monitor()
        job = object()
        current.snapshot_job = job
        current.finish_snapshot(job, snapshot())
        self.assertEqual(len(current.notification_jobs), 1)
        notice = next(iter(current.notification_jobs))
        self.assertIsInstance(notice, monitor.NotificationCall)
        self.assertEqual(len(notice.incidents), 1)
        current.finish_notification(notice, {"ok": True, "action": "dismiss"})
        current.snapshot_job = job
        current.finish_snapshot(job, snapshot())
        self.assertEqual(current.notification_jobs, set())
        self.assertEqual(current.start.call_count, 1)

    def test_delivery_failure_retries_next_poll_without_duplicate_inflight(self):
        current = bare_monitor()
        marker = object()
        current.snapshot_job = marker
        current.finish_snapshot(marker, snapshot())
        first = next(iter(current.notification_jobs))
        current.snapshot_job = marker
        current.finish_snapshot(marker, snapshot())
        self.assertEqual(current.start.call_count, 1)
        current.finish_notification(first, {"ok": False})
        self.assertEqual(current.start.call_count, 1)
        self.assertEqual(current.tracker.seen, set())
        self.assertEqual(current.tracker.inflight, set())
        current.snapshot_job = marker
        current.finish_snapshot(marker, snapshot())
        self.assertEqual(current.start.call_count, 2)
        retry = next(iter(current.notification_jobs))
        current.finish_notification(retry, {"ok": True, "action": "dismiss"})
        current.snapshot_job = marker
        current.finish_snapshot(marker, snapshot())
        self.assertEqual(current.start.call_count, 2)

    def test_new_incident_notifies_while_previous_notification_waits(self):
        current = bare_monitor()
        marker = object()
        current.snapshot_job = marker
        current.finish_snapshot(marker, snapshot())
        following = snapshot()
        extra = copy.deepcopy(following["incidents"][0])
        extra["id"] = "c" * 32
        following["incidents"].append(extra)
        current.snapshot_job = marker
        current.finish_snapshot(marker, following)
        self.assertEqual(len(current.notification_jobs), 2)
        self.assertEqual(current.start.call_count, 2)
        self.assertEqual(current.start.call_args.args[0].incidents[0]["id"], "c" * 32)

    def test_notification_limit_stays_bounded_without_losing_unseen_episode(self):
        current = bare_monitor()
        current.notification_jobs.update({object(), object(), object()})
        current.tracker.update(snapshot())
        current.show_notification()
        current.start.assert_not_called()
        self.assertEqual(len(current.tracker.seen), 0)
        current.notification_jobs.pop()
        current.show_notification()
        self.assertEqual(len(current.notification_jobs), 3)
        self.assertEqual(len(current.tracker.inflight), 1)

    def test_shutdown_waits_for_started_lockdown_and_cancels_only_observers(self):
        current = bare_monitor()
        current.application = types.SimpleNamespace(quit=unittest.mock.Mock())
        current.poll_source = 0
        current.initial_source = 0
        current.snapshot_job = unittest.mock.Mock()
        current.lockdown_job = unittest.mock.Mock()
        current.notification_jobs.add(unittest.mock.Mock())
        lockdown = current.lockdown_job
        current.close()
        current.snapshot_job.cancel.assert_called_once()
        lockdown.cancel.assert_not_called()
        current.application.quit.assert_not_called()
        current.snapshot_job = None
        current.notification_jobs.clear()
        current.finish_lockdown(lockdown, {"ok": True})
        current.application.quit.assert_called_once()
        current.start.assert_not_called()

    def test_resolved_incident_stays_resolved_and_new_episode_notifies(self):
        tracker = client.EpisodeTracker()
        tracker.update(snapshot())
        self.assertEqual(len(tracker.take()), 1)
        self.assertEqual(tracker.take(), {})
        resolved = snapshot()
        resolved["incidents"][0].update(active=False, resolved_boottime=150.0)
        tracker.update(resolved)
        self.assertEqual(tracker.take(), {})
        following = snapshot()
        following["incidents"][0]["id"] = "c" * 32
        tracker.update(following)
        self.assertEqual(len(tracker.take()), 1)
        tracker.update(snapshot(enabled=False))
        self.assertEqual(tracker.take(), {})

    def test_only_literal_successful_lockdown_action_invokes_helper(self):
        for response, ok in (
            ("", True),
            ("dismiss", True),
            ("lockdown", False),
            ("Lockdown", True),
            ("lockdown", True),
        ):
            current = bare_monitor()
            job = monitor.NotificationCall({})
            current.notification_jobs.add(job)
            with self.subTest(response=response, ok=ok):
                current.finish_notification(job, {"ok": ok, "action": response})
                self.assertEqual(current.lockdown_job is not None, ok and response == "lockdown")

    def test_notification_has_explicit_actions_and_bounded_wait(self):
        call = monitor.NotificationCall({("a" * 32, "b" * 32): snapshot()["incidents"][0]})
        with patch.object(call, "run_process", return_value=(0, b"dismiss\n")) as run:
            self.assertEqual(call.run()["action"], "dismiss")
        command = run.call_args.args[0]
        self.assertIn("--action=lockdown=Enable Lockdown", command)
        self.assertIn("--action=details=View Details", command)
        self.assertIn("--action=dismiss=Dismiss", command)
        self.assertIn("--wait", command)
        self.assertEqual(run.call_args.args[1], 20)

    def test_both_timers_are_exact_ten_seconds(self):
        self.assertEqual(client.POLL_INTERVAL_MS, 10000)
        for filename in ("ph4ntxm-session-guard", "ph4ntxm-session-guard-monitor"):
            source = (ROOT / "usr/local/bin" / filename).read_text()
            self.assertIn("GLib.timeout_add(POLL_INTERVAL_MS, self.poll)", source)
            self.assertNotIn("timeout_add_seconds", source)

    def test_gui_does_not_claim_change_until_fresh_status_matches(self):
        window = gui.SessionGuardWindow.__new__(gui.SessionGuardWindow)
        window.snapshot_job = object()
        window.awaiting_action = "enable"
        window.snapshot = None
        window.notice = types.SimpleNamespace(set_text=unittest.mock.Mock())
        with (
            patch.object(gui.SessionGuardWindow, "apply_snapshot"),
            patch.object(gui.SessionGuardWindow, "update_controls"),
        ):
            window.finish_snapshot(window.snapshot_job, snapshot(enabled=False))
        self.assertIn("could not be verified", window.notice.set_text.call_args.args[0])
        self.assertIsNone(window.awaiting_action)


class LockdownControlTests(unittest.TestCase):
    def window(self):
        window = gui.SessionGuardWindow.__new__(gui.SessionGuardWindow)
        window.closed = False
        window.action_job = None
        window.confirming = False
        window.awaiting_action = None
        window.snapshot = {"available": True}
        window.snapshot_job = None
        window.lockdown_state = None
        for name in (
            "monitoring_button", "lockdown_button", "disable_lockdown_button",
            "refresh_button", "spinner", "notice",
        ):
            setattr(window, name, unittest.mock.Mock())
        window.start_job = unittest.mock.Mock()
        return window

    def test_check_details_only_explain_pending_or_failed(self):
        self.assertEqual(
            gui.check_text({"title": "Firewall", "status": "healthy", "detail": "Healthy."}),
            "Firewall: Healthy",
        )
        for status in ("pending", "failed"):
            self.assertIn(" — reason", gui.check_text(
                {"title": "Firewall", "status": status, "detail": "reason"}
            ))

    def test_lockdown_buttons_follow_verified_state_and_busy(self):
        window = self.window()
        for state in (True, False, None):
            window.lockdown_state = state
            window.update_controls()
            window.lockdown_button.set_sensitive.assert_called_with(state is not True)
            window.disable_lockdown_button.set_sensitive.assert_called_with(state is True)
        window.action_job = object()
        window.update_controls()
        window.lockdown_button.set_sensitive.assert_called_with(False)
        window.disable_lockdown_button.set_sensitive.assert_called_with(False)

    def test_cancel_and_unknown_state_do_not_disable_lockdown(self):
        window = self.window()
        window.lockdown_state = True
        with patch.object(gui.SessionGuardWindow, "request_password", return_value=None):
            window.on_disable_lockdown()
        window.start_job.assert_not_called()
        self.assertIsNone(window.action_job)
        window.lockdown_state = None
        with patch.object(gui.SessionGuardWindow, "request_password") as prompt:
            window.on_disable_lockdown()
        prompt.assert_not_called()
        window.start_job.assert_not_called()

    def test_disable_dispatches_only_after_password_and_refreshes_after_result(self):
        window = self.window()
        window.lockdown_state = True
        with patch.object(gui.SessionGuardWindow, "request_password", return_value="test password"):
            window.on_disable_lockdown()
        job = window.action_job
        self.assertIsInstance(job, client.LockdownCall)
        self.assertEqual(job.action, "disable")
        window.start_job.assert_called_once()
        for result in ({"ok": False, "error": "Failed"}, {"ok": True, "message": "Verified"}):
            window.action_job = job
            with patch.object(gui.SessionGuardWindow, "refresh") as refresh:
                window.finish_action(job, result)
            refresh.assert_called_once()
            self.assertIsNone(window.lockdown_state)
        job.input[:] = b"\x00" * len(job.input)
        job.input = None


if __name__ == "__main__":
    unittest.main()
