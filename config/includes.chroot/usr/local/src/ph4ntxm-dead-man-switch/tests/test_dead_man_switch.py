# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import contextlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[4] / "lib/ph4ntxm/dead_man_switch.py"
SPEC = importlib.util.spec_from_file_location("dead_man_switch_under_test", MODULE_PATH)
dms = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dms)
BOOT_ID = "12345678-1234-1234-1234-123456789abc"
OTHER_BOOT_ID = "abcdefab-1234-1234-1234-123456789abc"


class FakeClock:
    def __init__(self):
        self.now = 100 * dms.NS

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += int(seconds * dms.NS)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "runtime"
        self.store = dms.StateStore(str(self.path), os.getuid(), os.getgid())
        self.clock = FakeClock()
        self.dispatch = mock.Mock(return_value=True)
        self.engine = self.new_engine()
        self.engine.tick()

    def new_engine(self):
        return dms.TimerEngine(self.store, self.clock, self.dispatch, BOOT_ID)

    def state(self):
        with self.store.directory() as directory_fd:
            return self.store.read(directory_fd, BOOT_ID)

    def arm(self, minutes=15):
        return self.engine.mutate("arm", {"generation": self.state()["generation"], "minutes": minutes})

    def test_start_is_disarmed_without_dispatch(self):
        state = self.state()
        self.assertEqual(state["status"], "disarmed")
        self.assertEqual(state["generation"], "")
        self.assertEqual(state["duration_seconds"], 900)
        self.dispatch.assert_not_called()

    def test_arm_sets_duration_and_changes_generation(self):
        self.clock.advance(0.25)
        result = self.arm(2)
        self.assertEqual(result["remaining_seconds"], 120)
        self.assertEqual(result["deadline_boottime_ns"], self.clock() + 120 * dms.NS)
        self.assertRegex(result["generation"], r"^[0-9a-f]{32}$")
        self.engine.tick()
        self.assertEqual(self.state()["status"], "armed")

    def test_renew_replaces_deadline_and_rejects_replay(self):
        armed = self.arm()
        self.clock.advance(5)
        result = self.engine.mutate("renew", {"generation": armed["generation"], "minutes": 1})
        self.assertEqual(result["deadline_boottime_ns"], self.clock() + 60 * dms.NS)
        self.assertNotEqual(armed["generation"], result["generation"])
        with self.assertRaises(dms.ActionError):
            self.engine.mutate("renew", {"generation": armed["generation"], "minutes": 1})
        self.assertEqual(self.state()["generation"], result["generation"])

    def test_disarm_requires_latest_generation(self):
        armed = self.arm()
        with self.assertRaises(dms.ActionError):
            self.engine.mutate("disarm", {"generation": ""})
        result = self.engine.mutate("disarm", {"generation": armed["generation"]})
        self.assertEqual(result["state"], "disarmed")
        self.assertEqual(result["deadline_boottime_ns"], 0)
        self.assertNotEqual(result["generation"], armed["generation"])
        self.dispatch.assert_not_called()

    def test_invalid_transitions_fail(self):
        with self.assertRaises(dms.ActionError):
            self.engine.mutate("renew", {"generation": "", "minutes": 15})
        self.arm()
        with self.assertRaises(dms.ActionError):
            self.engine.mutate("arm", {"generation": self.state()["generation"], "minutes": 15})

    def test_warning_boundary_and_rounding(self):
        self.arm(2)
        self.clock.advance(59.9)
        self.engine.tick()
        self.assertEqual(dms.snapshot_for(self.state(), self.clock())["state"], "armed")
        self.clock.advance(0.1)
        snapshot = dms.snapshot_for(self.state(), self.clock())
        self.assertEqual(snapshot["state"], "warning")
        self.assertEqual(snapshot["remaining_seconds"], 60)

    def test_daemon_restart_keeps_deadline_and_generation(self):
        before = self.arm()
        self.clock.advance(10)
        result = self.new_engine().tick()
        self.assertEqual(result["deadline_boottime_ns"], before["deadline_boottime_ns"])
        self.assertEqual(result["generation"], before["generation"])
        self.assertEqual(result["remaining_seconds"], 890)

    def test_suspend_jump_expires_on_next_tick(self):
        self.arm()
        self.clock.advance(3600)
        result = self.new_engine().tick()
        self.assertEqual(result["state"], "triggered")
        self.dispatch.assert_called_once_with()
        self.assertTrue(self.state()["dispatched"])

    def test_exact_deadline_expiry_wins_renew_and_disarm(self):
        for action in ("renew", "disarm"):
            with self.subTest(action=action):
                self.setUp()
                armed = self.arm(1)
                self.clock.advance(60)
                payload = {"generation": armed["generation"]}
                if action == "renew":
                    payload["minutes"] = 15
                with self.assertRaises(dms.ActionError):
                    self.engine.mutate(action, payload)
                self.assertEqual(self.state()["status"], "triggered")
                self.dispatch.assert_called_once_with()

    def test_expiry_wins_if_deadline_passes_during_state_read(self):
        armed = self.arm(1)
        self.clock.advance(59)
        original = self.store.load_locked

        def delayed_read(*args, **kwargs):
            result = original(*args, **kwargs)
            self.clock.advance(1)
            return result

        with mock.patch.object(self.store, "load_locked", side_effect=delayed_read):
            with self.assertRaises(dms.ActionError):
                self.engine.mutate("disarm", {"generation": armed["generation"]})
        self.dispatch.assert_called_once_with()

    def test_suspend_between_heartbeat_checks_cannot_write_invalid_renewal(self):
        armed = self.arm()
        calls = 0

        def paused_clock():
            nonlocal calls
            calls += 1
            if calls == 3:
                self.clock.advance(9)
            return self.clock()

        self.engine.clock = paused_clock
        with self.assertRaises(dms.ActionError):
            self.engine.mutate("renew", {"generation": armed["generation"], "minutes": 15})
        self.assertEqual(self.state()["deadline_boottime_ns"], armed["deadline_boottime_ns"])
        self.assertEqual(self.state()["generation"], armed["generation"])
        self.engine.tick()
        self.assertEqual(self.state()["status"], "armed")

    def test_trigger_persisted_before_dispatch(self):
        self.arm(1)
        self.clock.advance(60)

        def observed_dispatch():
            self.assertEqual(self.state()["status"], "triggered")
            self.assertFalse(self.state()["dispatched"])
            return True

        self.engine.dispatch = observed_dispatch
        self.engine.tick()

    def test_failed_dispatch_retries_after_restart_without_cancellation(self):
        self.dispatch.return_value = False
        armed = self.arm(1)
        self.clock.advance(60)
        self.engine.tick()
        self.assertFalse(self.state()["dispatched"])
        self.assertEqual(self.state()["status"], "triggered")
        self.dispatch.return_value = True
        with self.assertRaises(dms.ActionError):
            self.new_engine().mutate("disarm", {"generation": armed["generation"]})
        self.assertTrue(self.state()["dispatched"])
        self.assertEqual(self.dispatch.call_count, 2)
        self.new_engine().tick()
        self.assertEqual(self.dispatch.call_count, 2)

    def test_stale_heartbeat_preserves_timer_information(self):
        armed = self.arm()
        self.clock.advance(9)
        result = dms.snapshot_for(self.state(), self.clock())
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["remaining_seconds"], 891)
        self.assertEqual(result["deadline_boottime_ns"], armed["deadline_boottime_ns"])
        with self.assertRaises(dms.ActionError):
            self.engine.mutate("disarm", {"generation": armed["generation"]})

    def test_controller_does_not_refresh_daemon_heartbeat(self):
        heartbeat = self.state()["heartbeat_boottime_ns"]
        self.clock.advance(2)
        self.arm()
        self.assertEqual(self.state()["heartbeat_boottime_ns"], heartbeat)

    def test_boot_mismatch_never_dispatches(self):
        self.arm(1)
        self.clock.advance(1000)
        other = dms.TimerEngine(self.store, self.clock, self.dispatch, OTHER_BOOT_ID)
        with self.assertRaises(dms.StateError):
            other.tick()
        self.dispatch.assert_not_called()

    def test_missing_initialized_state_never_resets(self):
        self.arm(1)
        (self.path / dms.STATE_FILE).unlink()
        with self.assertRaises(dms.StateError):
            self.new_engine().tick()
        self.assertFalse((self.path / dms.STATE_FILE).exists())
        self.dispatch.assert_not_called()

    def test_public_snapshot_reports_missing_initialized_state_as_degraded(self):
        (self.path / dms.STATE_FILE).unlink()
        with mock.patch.object(dms, "StateStore", return_value=self.store):
            with mock.patch.object(dms, "boot_id", return_value=BOOT_ID):
                result = dms.read_snapshot()
        self.assertEqual(result["state"], "degraded")
        self.assertFalse(result["ok"])

    def test_public_snapshot_defaults_to_disarmed_before_initialization(self):
        (self.path / dms.STATE_FILE).unlink()
        (self.path / dms.LOCK_FILE).unlink()
        with mock.patch.object(dms, "StateStore", return_value=self.store):
            with mock.patch.object(dms, "boot_id", return_value=BOOT_ID):
                result = dms.read_snapshot()
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "disarmed")
        self.assertEqual(result["generation"], "")

    def test_malformed_state_never_dispatches_or_resets(self):
        raw = b'{"status":"armed","deadline_boottime_ns":1}\n'
        (self.path / dms.STATE_FILE).write_bytes(raw)
        with self.assertRaises(dms.StateError):
            self.engine.tick()
        self.assertEqual((self.path / dms.STATE_FILE).read_bytes(), raw)
        self.dispatch.assert_not_called()

    def test_state_file_symlink_is_rejected_without_touching_target(self):
        target = Path(self.temporary.name) / "outside"
        target.write_text("untouched")
        (self.path / dms.STATE_FILE).unlink()
        (self.path / dms.STATE_FILE).symlink_to(target)
        with self.assertRaises(OSError):
            self.engine.tick()
        self.assertEqual(target.read_text(), "untouched")
        self.dispatch.assert_not_called()

    def test_state_fifo_is_rejected_without_blocking(self):
        (self.path / dms.STATE_FILE).unlink()
        os.mkfifo(self.path / dms.STATE_FILE, 0o644)
        with self.assertRaises(dms.StateError):
            self.engine.tick()
        self.dispatch.assert_not_called()

    def test_lock_symlink_is_rejected(self):
        (self.path / dms.LOCK_FILE).unlink()
        (self.path / dms.LOCK_FILE).symlink_to(self.path / dms.STATE_FILE)
        with self.assertRaises(OSError):
            self.engine.tick()
        self.dispatch.assert_not_called()

    def test_unsafe_directory_permissions_are_rejected(self):
        self.path.chmod(0o777)
        with self.assertRaises(dms.StateError):
            self.engine.tick()
        self.dispatch.assert_not_called()

    def test_state_permissions_and_hardlinks_are_rejected(self):
        path = self.path / dms.STATE_FILE
        path.chmod(0o666)
        with self.assertRaises(dms.StateError):
            self.engine.tick()
        path.chmod(0o644)
        os.link(path, Path(self.temporary.name) / "hardlink")
        with self.assertRaises(dms.StateError):
            self.engine.tick()
        self.dispatch.assert_not_called()

    def test_second_daemon_is_rejected(self):
        with self.store.daemon_lock():
            with self.assertRaises(dms.StateError):
                with self.store.daemon_lock():
                    self.fail("Second daemon acquired the lock")

    def test_public_snapshot_reads_without_lock_or_mutation(self):
        armed = self.arm()
        with mock.patch.object(dms, "StateStore", return_value=self.store):
            with mock.patch.object(dms, "boot_id", return_value=BOOT_ID):
                with mock.patch.object(dms, "boottime_ns", self.clock):
                    with mock.patch.object(self.store, "locked", side_effect=AssertionError):
                        self.assertEqual(dms.read_snapshot()["generation"], armed["generation"])
        self.dispatch.assert_not_called()

    def test_watchdog_failure_preserves_armed_deadline_for_restart(self):
        armed = self.arm()
        with mock.patch.object(dms, "watchdog_ping", side_effect=dms.StateError("notify failed")):
            with self.assertRaises(dms.StateError):
                self.engine.run()
        self.assertEqual(self.state()["deadline_boottime_ns"], armed["deadline_boottime_ns"])
        self.assertEqual(self.state()["generation"], armed["generation"])
        restarted = self.new_engine().tick()
        self.assertEqual(restarted["deadline_boottime_ns"], armed["deadline_boottime_ns"])
        self.dispatch.assert_not_called()

    def test_malformed_state_iteration_signals_ready_without_reset_or_dispatch(self):
        raw = b"invalid state"
        (self.path / dms.STATE_FILE).write_bytes(raw)
        with mock.patch.object(dms, "watchdog_ping") as ping:
            with mock.patch.object(self.engine, "report"):
                with mock.patch.object(dms.time, "sleep", side_effect=KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        self.engine.run()
        ping.assert_called_once_with(ready=True)
        self.assertEqual((self.path / dms.STATE_FILE).read_bytes(), raw)
        self.dispatch.assert_not_called()

    def test_public_snapshot_always_returns_degraded_dict_for_invalid_state(self):
        (self.path / dms.STATE_FILE).write_bytes(b"bad")
        with mock.patch.object(dms, "StateStore", return_value=self.store):
            with mock.patch.object(dms, "boot_id", return_value=BOOT_ID):
                result = dms.read_snapshot()
        self.assertIsInstance(result, dict)
        self.assertEqual(result["state"], "degraded")
        self.assertFalse(result["ok"])


class InputTests(unittest.TestCase):
    def payload(self, raw):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, raw)
        finally:
            os.close(write_fd)
        try:
            return dms.read_payload(read_fd)
        finally:
            os.close(read_fd)

    def test_duplicate_unknown_and_extra_fields_are_rejected(self):
        with self.assertRaises(dms.ActionError):
            self.payload(b'{"generation":"","generation":"","minutes":15}')
        for payload in ({"generation": "", "minutes": 15, "extra": 1}, {"generation": ""}, []):
            with self.subTest(payload=payload):
                with self.assertRaises(dms.ActionError):
                    dms.validate_payload("arm", payload)
        with self.assertRaises(dms.ActionError):
            dms.validate_payload("disarm", {"generation": "", "minutes": 15})

    def test_only_integer_minutes_in_range_are_accepted(self):
        for value in (True, False, 0, 1441, -1, 1.0, "15", None, {}, []):
            with self.subTest(value=value):
                with self.assertRaises(dms.ActionError):
                    dms.validate_payload("arm", {"generation": "", "minutes": value})
        for value in (1, 15, 1440):
            dms.validate_payload("arm", {"generation": "", "minutes": value})

    def test_invalid_generations_are_rejected(self):
        for value in (None, 1, [], {}, "A" * 32, "a" * 31, "a" * 33, "a" * 32 + "\n"):
            with self.subTest(value=value):
                with self.assertRaises(dms.ActionError):
                    dms.validate_payload("disarm", {"generation": value})

    def test_malformed_oversized_and_trailing_json_are_rejected(self):
        for raw in (b"", b"x", b"{}{}", b"\xff", b" " * (dms.MAX_INPUT_BYTES + 1)):
            with self.subTest(raw=raw[:20]):
                with self.assertRaises(dms.ActionError):
                    self.payload(raw)
        self.assertEqual(self.payload(b'{"generation":"","minutes":15}\n')["minutes"], 15)

    def test_stdin_has_a_total_timeout(self):
        read_fd, write_fd = os.pipe()
        try:
            with mock.patch.object(dms, "INPUT_TIMEOUT_SECONDS", 0.001):
                with self.assertRaises(dms.ActionError):
                    dms.read_payload(read_fd)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_root_access_is_required_before_any_engine_work(self):
        with mock.patch.object(dms.os, "geteuid", return_value=1000):
            with mock.patch.object(dms, "TimerEngine") as engine:
                with contextlib.redirect_stdout(__import__("io").StringIO()) as output:
                    self.assertEqual(dms.main(["arm"]), 1)
                self.assertFalse(json.loads(output.getvalue())["ok"])
                engine.assert_not_called()

    def test_dispatch_uses_fixed_command_clean_environment_and_timeout(self):
        with mock.patch.object(dms.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.assertTrue(dms.dispatch_panic())
            args, kwargs = run.call_args
            self.assertEqual(args[0], dms.PANIC_COMMAND)
            self.assertEqual(kwargs["timeout"], 3)
            self.assertEqual(set(kwargs["env"]), {"PATH", "LANG", "LC_ALL"})
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        for failure in (OSError(), subprocess.TimeoutExpired(dms.PANIC_COMMAND, 3)):
            with mock.patch.object(dms.subprocess, "run", side_effect=failure):
                self.assertFalse(dms.dispatch_panic())


class WatchdogTests(unittest.TestCase):
    def test_initial_notification_combines_ready_and_watchdog(self):
        payload = b"READY=1\nWATCHDOG=1"
        with mock.patch.dict(dms.os.environ, {"NOTIFY_SOCKET": "/run/systemd/notify"}, clear=True):
            with mock.patch.object(dms.socket, "socket") as factory:
                notifier = factory.return_value.__enter__.return_value
                notifier.send.return_value = len(payload)
                dms.watchdog_ping(ready=True)
        notifier.send.assert_called_once_with(payload)

    def test_pathname_socket_protocol_and_bounded_timeout(self):
        with mock.patch.dict(dms.os.environ, {"NOTIFY_SOCKET": "/run/systemd/notify"}, clear=True):
            with mock.patch.object(dms.socket, "socket") as factory:
                notifier = factory.return_value.__enter__.return_value
                notifier.send.return_value = len(b"WATCHDOG=1")
                dms.watchdog_ping()
        factory.assert_called_once_with(dms.socket.AF_UNIX, dms.socket.SOCK_DGRAM | dms.socket.SOCK_CLOEXEC)
        notifier.settimeout.assert_called_once_with(0.2)
        notifier.connect.assert_called_once_with("/run/systemd/notify")
        notifier.send.assert_called_once_with(b"WATCHDOG=1")
        factory.return_value.__exit__.assert_called_once()

    def test_abstract_socket_conversion(self):
        with mock.patch.dict(dms.os.environ, {"NOTIFY_SOCKET": "@systemd-notify"}, clear=True):
            with mock.patch.object(dms.socket, "socket") as factory:
                notifier = factory.return_value.__enter__.return_value
                notifier.send.return_value = len(b"WATCHDOG=1")
                dms.watchdog_ping()
        notifier.connect.assert_called_once_with("\0systemd-notify")

    def test_missing_environment_is_harmless_without_socket(self):
        with mock.patch.dict(dms.os.environ, {}, clear=True):
            with mock.patch.object(dms.socket, "socket") as factory:
                dms.watchdog_ping()
                factory.assert_not_called()

    def test_invalid_or_failed_notification_stops_the_daemon_loop(self):
        for failure in (OSError("send failure"), TimeoutError("send timeout")):
            with self.subTest(failure=failure):
                with mock.patch.dict(dms.os.environ, {"NOTIFY_SOCKET": "/run/systemd/notify"}, clear=True):
                    with mock.patch.object(dms.socket, "socket") as factory:
                        factory.return_value.__enter__.return_value.send.side_effect = failure
                        with self.assertRaises(dms.StateError):
                            dms.watchdog_ping()
        with mock.patch.dict(dms.os.environ, {"NOTIFY_SOCKET": "vsock:1:2"}, clear=True):
            with self.assertRaises(dms.StateError):
                dms.watchdog_ping()
        store = mock.Mock()
        store.daemon_lock.return_value = contextlib.nullcontext()
        engine = dms.TimerEngine(store, FakeClock(), mock.Mock(), BOOT_ID)
        with mock.patch.object(engine, "tick") as tick:
            with mock.patch.object(dms, "watchdog_ping", side_effect=dms.StateError("failed")):
                with mock.patch.object(dms.time, "sleep") as sleep:
                    with self.assertRaises(dms.StateError):
                        engine.run()
        tick.assert_called_once_with()
        sleep.assert_not_called()

    def test_short_send_is_a_failure(self):
        with mock.patch.dict(dms.os.environ, {"NOTIFY_SOCKET": "/run/systemd/notify"}, clear=True):
            with mock.patch.object(dms.socket, "socket") as factory:
                notifier = factory.return_value.__enter__.return_value
                notifier.send.return_value = 0
                with self.assertRaises(dms.StateError):
                    dms.watchdog_ping()

    def test_ping_follows_each_completed_or_degraded_tick_before_sleep(self):
        for failure in (None, dms.StateError("degraded")):
            with self.subTest(failure=failure):
                store = mock.Mock()
                store.daemon_lock.return_value = contextlib.nullcontext()
                engine = dms.TimerEngine(store, FakeClock(), mock.Mock(), BOOT_ID)
                events = []

                def tick():
                    events.append("tick")
                    if failure:
                        raise failure

                def ping(ready=False):
                    self.assertTrue(ready)
                    events.append("ping")

                def sleep(seconds):
                    self.assertEqual(seconds, dms.HEARTBEAT_SECONDS)
                    events.append("sleep")
                    raise KeyboardInterrupt

                with mock.patch.object(engine, "tick", side_effect=tick):
                    with mock.patch.object(engine, "report"):
                        with mock.patch.object(dms, "watchdog_ping", side_effect=ping):
                            with mock.patch.object(dms.time, "sleep", side_effect=sleep):
                                with self.assertRaises(KeyboardInterrupt):
                                    engine.run()
                self.assertEqual(events, ["tick", "ping", "sleep"])

    def test_ready_is_sent_once_after_first_tick(self):
        store = mock.Mock()
        store.daemon_lock.return_value = contextlib.nullcontext()
        engine = dms.TimerEngine(store, FakeClock(), mock.Mock(), BOOT_ID)
        events = []

        def tick():
            events.append("tick")

        def ping(ready=False):
            events.append("ready" if ready else "ping")

        def sleep(seconds):
            events.append("sleep")
            if len(events) == 6:
                raise KeyboardInterrupt

        with mock.patch.object(engine, "tick", side_effect=tick):
            with mock.patch.object(dms, "watchdog_ping", side_effect=ping) as notifier:
                with mock.patch.object(dms.time, "sleep", side_effect=sleep):
                    with self.assertRaises(KeyboardInterrupt):
                        engine.run()
        self.assertEqual(events, ["tick", "ready", "sleep", "tick", "ping", "sleep"])
        self.assertEqual(notifier.call_args_list, [mock.call(ready=True), mock.call(ready=False)])


if __name__ == "__main__":
    unittest.main()
