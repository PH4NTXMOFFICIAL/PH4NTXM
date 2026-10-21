#!/usr/bin/python3 -I
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import importlib.util
import sys
import unittest
from pathlib import Path


module_path = (
    Path(sys.argv.pop(1))
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-")
    else Path("/usr/lib/ph4ntxm/clipboard_guard.py")
)
if module_path.is_dir():
    module_path /= "clipboard_guard.py"
sys.path.insert(0, str(module_path.parent))
spec = importlib.util.spec_from_file_location("clipboard_guard", module_path)
core = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = core
spec.loader.exec_module(core)


class FakeScheduler:
    def __init__(self):
        self.next_id = 1
        self.pending = {}
        self.callbacks = {}
        self.cancelled = []
        self.intervals = {}

    def after(self, seconds, callback):
        identifier = self.next_id
        self.next_id += 1
        self.pending[identifier] = callback
        self.callbacks[identifier] = callback
        self.intervals[identifier] = seconds
        return identifier

    def cancel(self, identifier):
        self.cancelled.append(identifier)
        self.pending.pop(identifier, None)

    def fire(self, identifier, stale=False):
        callback = self.callbacks[identifier] if stale else self.pending.pop(identifier)
        return callback()


class FakeBackend:
    def __init__(self, initial=None):
        self.initial = initial or {}
        self.callback = None
        self.calls = []
        self.closed = 0
        self.start_error = None
        self.expire_error = None
        self.clear_error = None
        self.expire_results = []
        self.clear_result = {"cleared": ["CLIPBOARD"], "events": []}

    def start(self, include_primary, callback):
        self.calls.append(("start", include_primary))
        self.callback = callback
        if self.start_error:
            raise self.start_error
        return dict(self.initial)

    def expire(self, name, owner, timestamp):
        self.calls.append(("expire", name, owner, timestamp))
        if self.expire_error:
            raise self.expire_error
        return (
            self.expire_results.pop(0)
            if self.expire_results
            else {"cleared": True, "events": [], "retry": False}
        )

    def clear_now(self, include_primary):
        self.calls.append(("clear_now", include_primary))
        if self.clear_error:
            raise self.clear_error
        return self.clear_result

    def close(self):
        self.calls.append(("close",))
        self.closed += 1

    def event(self, name, owner, timestamp):
        self.callback({"selection": name, "owner": owner, "timestamp": timestamp})


class BackendFactory:
    def __init__(self, *backends):
        self.backends = list(backends)
        self.created = []
        self.error = None

    def __call__(self):
        if self.error:
            raise self.error
        if not self.backends:
            raise AssertionError("Unexpected backend construction")
        backend = self.backends.pop(0)
        self.created.append(backend)
        return backend


class ClipboardGuardTest(unittest.TestCase):
    def make_guard(self, initial=None, backends=None):
        self.scheduler = FakeScheduler()
        self.backend = FakeBackend(initial)
        self.factory = BackendFactory(*(backends or [self.backend]))
        self.changes = []
        self.guard = core.Guard(self.scheduler, self.factory, lambda *args: self.changes.append(args))
        return self.guard

    def timer(self):
        self.assertEqual(len(self.scheduler.pending), 1)
        return next(iter(self.scheduler.pending))

    def expire_calls(self):
        return [call for call in self.backend.calls if call[0] == "expire"]

    def test_defaults_do_not_open_display_or_schedule_polling(self):
        guard = self.make_guard()
        self.assertFalse(guard.enabled)
        self.assertEqual(guard.seconds, 60)
        self.assertFalse(guard.include_primary)
        self.assertEqual(self.factory.created, [])
        self.assertEqual(self.scheduler.pending, {})

    def test_existing_owner_receives_full_timeout_without_reading_content(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(60, False)
        identifier = self.timer()
        self.assertEqual(self.scheduler.intervals[identifier], 60)
        self.assertTrue(guard.enabled)
        self.assertFalse(self.scheduler.fire(identifier))
        self.assertEqual(self.expire_calls(), [("expire", "CLIPBOARD", 41, 100)])
        self.assertEqual(self.scheduler.pending, {})
        self.assertTrue(guard.enabled)
        self.assertTrue(self.changes)

    def test_new_owner_starts_timer(self):
        guard = self.make_guard()
        guard.start(25, False)
        self.assertEqual(self.scheduler.pending, {})
        self.backend.event("CLIPBOARD", 42, 200)
        identifier = self.timer()
        self.assertEqual(self.scheduler.intervals[identifier], 25)
        self.scheduler.fire(identifier)
        self.assertEqual(self.expire_calls(), [("expire", "CLIPBOARD", 42, 200)])

    def test_same_owner_new_timestamp_renews_full_timeout(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(30, False)
        old_timer = self.timer()
        self.backend.event("CLIPBOARD", 41, 200)
        new_timer = self.timer()
        self.assertNotEqual(old_timer, new_timer)
        self.assertIn(old_timer, self.scheduler.cancelled)
        self.assertEqual(self.scheduler.intervals[new_timer], 30)
        self.scheduler.fire(new_timer)
        self.assertEqual(self.expire_calls(), [("expire", "CLIPBOARD", 41, 200)])

    def test_stale_timer_cannot_expire_new_copy(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        old_timer = self.timer()
        self.backend.event("CLIPBOARD", 42, 200)
        new_timer = self.timer()
        self.assertFalse(self.scheduler.fire(old_timer, stale=True))
        self.assertEqual(self.expire_calls(), [])
        self.assertIn(new_timer, self.scheduler.pending)
        self.scheduler.fire(new_timer)
        self.assertEqual(self.expire_calls(), [("expire", "CLIPBOARD", 42, 200)])

    def test_lost_owner_cancels_timer(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        old_timer = self.timer()
        self.backend.event("CLIPBOARD", 0, 200)
        self.assertEqual(self.scheduler.pending, {})
        self.assertIn(old_timer, self.scheduler.cancelled)
        self.scheduler.fire(old_timer, stale=True)
        self.assertEqual(self.expire_calls(), [])

    def test_primary_is_not_covered_unless_requested(self):
        guard = self.make_guard({"PRIMARY": (99, 100)})
        guard.start(10, False)
        self.backend.event("PRIMARY", 100, 200)
        self.assertEqual(self.scheduler.pending, {})
        self.assertEqual(self.backend.calls, [("start", False)])

    def test_primary_and_clipboard_have_independent_timers(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100), "PRIMARY": (99, 200)})
        guard.start(10, True)
        self.assertEqual(len(self.scheduler.pending), 2)
        original = set(self.scheduler.pending)
        self.backend.event("CLIPBOARD", 42, 300)
        retained = original.intersection(self.scheduler.pending)
        self.assertEqual(len(retained), 1)
        for identifier in list(self.scheduler.pending):
            self.scheduler.fire(identifier)
        self.assertCountEqual(
            self.expire_calls(),
            [("expire", "PRIMARY", 99, 200), ("expire", "CLIPBOARD", 42, 300)],
        )
        self.assertEqual(self.scheduler.pending, {})

    def test_disable_cancels_timers_and_leaves_content(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100), "PRIMARY": (99, 200)})
        guard.start(10, True)
        original = list(self.scheduler.pending)
        guard.stop()
        self.assertFalse(guard.enabled)
        self.assertEqual(self.backend.closed, 1)
        self.assertEqual(self.scheduler.pending, {})
        self.assertEqual(self.expire_calls(), [])
        self.assertFalse(any(call[0] == "clear_now" for call in self.backend.calls))
        for identifier in original:
            self.scheduler.fire(identifier, stale=True)
        self.assertEqual(self.expire_calls(), [])

    def test_manager_appearance_disables_and_explains_failure(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        self.backend.event("MANAGER", 88, 200)
        self.assertFalse(guard.enabled)
        self.assertTrue(guard.error)
        self.assertTrue(guard.message)
        self.assertEqual(self.scheduler.pending, {})
        self.assertEqual(self.backend.closed, 1)
        self.assertEqual(self.expire_calls(), [])

    def test_manager_without_owner_does_not_disable(self):
        guard = self.make_guard()
        guard.start(10, False)
        self.backend.event("MANAGER", 0, 200)
        self.assertTrue(guard.enabled)
        self.assertEqual(self.backend.closed, 0)

    def test_start_failure_closes_backend_and_reports_error(self):
        guard = self.make_guard()
        self.backend.start_error = core.GuardError("Clipboard manager is active")
        try:
            guard.start(10, False)
        except core.GuardError:
            pass
        self.assertFalse(guard.enabled)
        self.assertTrue(guard.error)
        self.assertIn("manager", guard.message.lower())
        self.assertEqual(self.backend.closed, 1)
        self.assertEqual(self.scheduler.pending, {})
        self.assertTrue(self.changes)

    def test_factory_failure_reports_error_without_scheduling(self):
        guard = self.make_guard()
        self.factory.error = core.GuardError("X11 backend is unavailable")
        try:
            guard.start(10, False)
        except core.GuardError:
            pass
        self.assertFalse(guard.enabled)
        self.assertTrue(guard.error)
        self.assertTrue(guard.message)
        self.assertEqual(self.factory.created, [])
        self.assertEqual(self.scheduler.pending, {})

    def test_expire_failure_disables_and_reports_error(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        self.backend.expire_error = core.GuardError("X11 selection clear failed")
        self.assertFalse(self.scheduler.fire(self.timer()))
        self.assertFalse(guard.enabled)
        self.assertTrue(guard.error)
        self.assertTrue(guard.message)
        self.assertEqual(self.backend.closed, 1)
        self.assertEqual(self.scheduler.pending, {})

    def test_backend_error_event_disables(self):
        guard = self.make_guard()
        guard.start(10, False)
        self.backend.callback({"error": "X11 display disconnected"})
        self.assertFalse(guard.enabled)
        self.assertTrue(guard.error)
        self.assertTrue(guard.message)
        self.assertEqual(self.backend.closed, 1)

    def test_new_copy_reported_during_expire_keeps_its_timer(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        self.backend.expire_results.append(
            {
                "cleared": False,
                "events": [{"selection": "CLIPBOARD", "owner": 42, "timestamp": 200}],
                "retry": False,
            }
        )
        old_timer = self.timer()
        self.assertFalse(self.scheduler.fire(old_timer))
        new_timer = self.timer()
        self.assertNotEqual(new_timer, old_timer)
        self.assertEqual(self.scheduler.intervals[new_timer], 10)
        self.scheduler.fire(new_timer)
        self.assertEqual(
            self.expire_calls(),
            [("expire", "CLIPBOARD", 41, 100), ("expire", "CLIPBOARD", 42, 200)],
        )

    def test_same_owner_renewal_during_expire_keeps_its_timer(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        self.backend.expire_results.append(
            {
                "cleared": False,
                "events": [{"selection": "CLIPBOARD", "owner": 41, "timestamp": 200}],
                "retry": False,
            }
        )
        self.scheduler.fire(self.timer())
        self.scheduler.fire(self.timer())
        self.assertEqual(
            self.expire_calls(),
            [("expire", "CLIPBOARD", 41, 100), ("expire", "CLIPBOARD", 41, 200)],
        )

    def test_expiry_own_zero_owner_event_preserves_cleared_message(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        self.backend.expire_results.append(
            {
                "cleared": True,
                "events": [{"selection": "CLIPBOARD", "owner": 0, "timestamp": 200}],
                "retry": False,
            }
        )
        self.assertFalse(self.scheduler.fire(self.timer()))
        self.assertTrue(guard.enabled)
        self.assertFalse(guard.error)
        self.assertEqual(guard.message, "Clipboard cleared.")
        self.assertEqual(self.scheduler.pending, {})

    def test_retry_race_schedules_only_one_followup(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        self.backend.expire_results.append({"cleared": False, "events": [], "retry": True})
        self.scheduler.fire(self.timer())
        retry_timer = self.timer()
        self.assertGreater(self.scheduler.intervals[retry_timer], 0)
        self.scheduler.fire(retry_timer)
        self.assertEqual(len(self.expire_calls()), 2)
        self.assertEqual(self.scheduler.pending, {})

    def test_no_retry_after_owner_lost(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        self.backend.expire_results.append(
            {
                "cleared": False,
                "events": [{"selection": "CLIPBOARD", "owner": 0, "timestamp": 200}],
                "retry": True,
            }
        )
        self.scheduler.fire(self.timer())
        self.assertEqual(self.scheduler.pending, {})

    def test_clear_now_while_enabled_cancels_cleared_selection_timer(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        guard.clear_now(False)
        self.assertTrue(guard.enabled)
        self.assertIn(("clear_now", False), self.backend.calls)
        self.assertEqual(self.backend.closed, 0)
        self.assertEqual(self.scheduler.pending, {})

    def test_clear_now_preserves_new_copy_from_same_call(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        self.backend.clear_result = {
            "cleared": ["CLIPBOARD"],
            "events": [{"selection": "CLIPBOARD", "owner": 42, "timestamp": 200}],
        }
        guard.clear_now(False)
        self.scheduler.fire(self.timer())
        self.assertEqual(self.expire_calls(), [("expire", "CLIPBOARD", 42, 200)])

    def test_clear_now_while_disabled_uses_ephemeral_backend(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.clear_now(False)
        self.assertFalse(guard.enabled)
        self.assertEqual(
            self.backend.calls,
            [("start", False), ("clear_now", False), ("close",)],
        )
        self.assertEqual(self.backend.closed, 1)
        self.assertEqual(self.scheduler.pending, {})

    def test_clear_now_failure_while_enabled_stops_monitoring(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        self.backend.clear_error = core.GuardError("Clipboard manager appeared")
        try:
            guard.clear_now(False)
        except core.GuardError:
            pass
        self.assertFalse(guard.enabled)
        self.assertTrue(guard.error)
        self.assertEqual(self.backend.closed, 1)
        self.assertEqual(self.scheduler.pending, {})

    def test_clear_now_manager_event_keeps_failure_visible(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        self.backend.clear_result = {
            "cleared": ["CLIPBOARD"],
            "events": [{"selection": "MANAGER", "owner": 88, "timestamp": 200}],
        }
        with self.assertRaises(core.GuardError):
            guard.clear_now(False)
        self.assertFalse(guard.enabled)
        self.assertTrue(guard.error)
        self.assertIn("manager", guard.message.lower())
        self.assertEqual(self.backend.closed, 1)
        self.assertEqual(self.scheduler.pending, {})

    def test_clear_now_uses_active_coverage(self):
        guard = self.make_guard()
        guard.start(10, True)
        guard.clear_now(False)
        self.assertIn(("clear_now", True), self.backend.calls)
        self.assertTrue(guard.enabled)

    def test_stale_timer_cannot_cross_disable_and_reenable(self):
        first = FakeBackend({"CLIPBOARD": (41, 100)})
        second = FakeBackend({"CLIPBOARD": (41, 100)})
        guard = self.make_guard(backends=[first, second])
        guard.start(10, False)
        old_timer = self.timer()
        guard.stop()
        guard.start(10, False)
        new_timer = self.timer()
        self.scheduler.fire(old_timer, stale=True)
        self.assertFalse(any(call[0] == "expire" for call in second.calls))
        self.assertIn(new_timer, self.scheduler.pending)
        self.scheduler.fire(new_timer)
        self.assertIn(("expire", "CLIPBOARD", 41, 100), second.calls)

    def test_clear_now_failure_while_disabled_closes_backend(self):
        guard = self.make_guard()
        self.backend.clear_error = core.GuardError("Clipboard manager is active")
        try:
            guard.clear_now(False)
        except core.GuardError:
            pass
        self.assertFalse(guard.enabled)
        self.assertTrue(guard.error)
        self.assertEqual(self.backend.closed, 1)
        self.assertEqual(self.scheduler.pending, {})

    def test_configuration_rejects_non_integer_timeout(self):
        for value in (True, False, None, 1.0, "60", [], {}):
            with self.subTest(value=value):
                guard = self.make_guard()
                with self.assertRaises(core.GuardError):
                    guard.start(value, False)
                self.assertFalse(guard.enabled)
                self.assertEqual(self.factory.created, [])

    def test_configuration_rejects_timeout_outside_bounds(self):
        for value in (-1, 0, 86401):
            with self.subTest(value=value):
                guard = self.make_guard()
                with self.assertRaises(core.GuardError):
                    guard.start(value, False)
                self.assertFalse(guard.enabled)
                self.assertEqual(self.factory.created, [])

    def test_configuration_requires_real_boolean_primary(self):
        for value in (None, 0, 1, "yes", [], {}):
            with self.subTest(value=value):
                guard = self.make_guard()
                with self.assertRaises(core.GuardError):
                    guard.start(60, value)
                self.assertFalse(guard.enabled)
                self.assertEqual(self.factory.created, [])

    def test_clear_now_rejects_invalid_coverage_without_opening_backend(self):
        for value in (None, 0, 1, "yes", [], {}):
            with self.subTest(value=value):
                guard = self.make_guard()
                with self.assertRaises(core.GuardError):
                    guard.clear_now(value)
                self.assertFalse(guard.enabled)
                self.assertEqual(self.factory.created, [])

    def test_enabled_guard_requires_disable_before_configuration_change(self):
        guard = self.make_guard({"CLIPBOARD": (41, 100)})
        guard.start(10, False)
        old_timer = self.timer()
        with self.assertRaises(core.GuardError):
            guard.start(20, True)
        self.assertTrue(guard.enabled)
        self.assertEqual(guard.seconds, 10)
        self.assertFalse(guard.include_primary)
        self.assertIn(old_timer, self.scheduler.pending)
        self.assertEqual(self.backend.closed, 0)

    def test_timeout_bounds_are_accepted(self):
        for value in (1, 86400):
            with self.subTest(value=value):
                guard = self.make_guard({"CLIPBOARD": (41, 100)})
                guard.start(value, False)
                self.assertTrue(guard.enabled)
                self.assertEqual(self.scheduler.intervals[self.timer()], value)
                guard.stop()


if __name__ == "__main__":
    unittest.main()
