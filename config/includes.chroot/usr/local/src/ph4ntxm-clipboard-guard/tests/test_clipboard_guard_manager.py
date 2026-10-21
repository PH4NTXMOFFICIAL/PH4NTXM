#!/usr/bin/python3 -I
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import importlib.util
import os
import select
import signal
import stat
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch


module_path = (
    Path(sys.argv.pop(1))
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-")
    else Path("/usr/lib/ph4ntxm/clipboard_guard_manager.py")
)
if module_path.is_dir():
    module_path /= "clipboard_guard_manager.py"
core_path = (
    Path(sys.argv.pop(1))
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-")
    else module_path.parent
)
sys.path.insert(0, str(core_path))
sys.path.insert(0, str(module_path.parent))
spec = importlib.util.spec_from_file_location("clipboard_guard_manager", module_path)
manager = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = manager
spec.loader.exec_module(manager)


def metadata(mode, uid=0, dev=10, inode=20):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_dev=dev, st_ino=inode)


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now


class FakePoll:
    def __init__(self, clock, process_fd):
        self.clock = clock
        self.steps = [(0.0, [(process_fd, select.POLLIN)])]
        self.registrations = []
        self.timeouts = []

    def register(self, descriptor, flags):
        self.registrations.append((descriptor, flags))

    def poll(self, timeout):
        self.timeouts.append(timeout)
        if self.steps:
            elapsed, events = self.steps.pop(0)
        else:
            elapsed, events = timeout / 1000, []
        self.clock.now += elapsed
        return events


class ClipmanManagerTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.pid = 4242
        self.binary_fd = 19
        self.process_fd = 23
        self.binary = metadata(stat.S_IFREG | 0o755)
        self.process = metadata(stat.S_IFDIR | 0o555, uid=1000)
        self.clock = FakeClock()
        self.poller = FakePoll(self.clock, self.process_fd)
        self.getuid = self.mock(manager.os, "getuid", return_value=1000)
        self.geteuid = self.mock(manager.os, "geteuid", return_value=1000)
        self.open = self.mock(manager.os, "open", return_value=self.binary_fd)
        self.fstat = self.mock(manager.os, "fstat", return_value=self.binary)
        self.stat = self.mock(
            manager.os,
            "stat",
            side_effect=[self.process, self.binary, self.process, self.binary],
        )
        self.pidfd_open = self.mock(manager.os, "pidfd_open", return_value=self.process_fd)
        self.send_signal = self.mock(manager.signal, "pidfd_send_signal")
        self.close = self.mock(manager.os, "close")
        self.mock(manager.os, "scandir", side_effect=AssertionError("Process enumeration is forbidden"))
        self.mock(manager.time, "monotonic", side_effect=self.clock.monotonic)
        self.mock(manager.select, "poll", return_value=self.poller)

    def mock(self, target, name, **options):
        return self.stack.enter_context(patch.object(target, name, **options))

    def pause(self):
        return manager.pause_clipman(self.pid)

    def test_only_authoritative_pid_is_verified_and_stopped(self):
        self.assertEqual(self.pause(), 1)
        self.pidfd_open.assert_called_once_with(self.pid, 0)
        self.send_signal.assert_called_once_with(self.process_fd, signal.SIGTERM, None, 0)
        self.assertEqual(
            self.stat.call_args_list,
            [
                call(f"/proc/{self.pid}", follow_symlinks=False),
                call(f"/proc/{self.pid}/exe"),
                call(f"/proc/{self.pid}", follow_symlinks=False),
                call(f"/proc/{self.pid}/exe"),
            ],
        )
        self.assertCountEqual(self.close.call_args_list, [call(self.binary_fd), call(self.process_fd)])

    def test_trusted_binary_is_opened_without_following_final_symlink(self):
        self.assertEqual(self.pause(), 1)
        self.open.assert_called_once_with(
            "/usr/bin/xfce4-clipman", os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        self.fstat.assert_called_once_with(self.binary_fd)

    def test_invalid_pid_is_rejected_without_inspection(self):
        for value in (True, False, 0, -1, None, "4242", 4242.0, 2147483648, 10**100):
            with self.subTest(value=value):
                with self.assertRaises(manager.GuardError):
                    manager.pause_clipman(value)
        self.open.assert_not_called()
        self.send_signal.assert_not_called()

    def test_root_invocation_is_rejected(self):
        self.getuid.return_value = 0
        self.geteuid.return_value = 0
        with self.assertRaises(manager.GuardError):
            self.pause()
        self.open.assert_not_called()
        self.send_signal.assert_not_called()

    def test_elevated_effective_uid_is_rejected(self):
        self.geteuid.return_value = 0
        with self.assertRaises(manager.GuardError):
            self.pause()
        self.open.assert_not_called()
        self.send_signal.assert_not_called()

    def test_untrusted_binary_is_rejected(self):
        for info in (
            metadata(stat.S_IFREG | 0o775),
            metadata(stat.S_IFREG | 0o757),
            metadata(stat.S_IFREG | 0o755, uid=1000),
            metadata(stat.S_IFLNK | 0o777),
            metadata(stat.S_IFDIR | 0o755),
        ):
            with self.subTest(info=info):
                self.fstat.return_value = info
                with self.assertRaises(manager.GuardError):
                    self.pause()
        self.stat.assert_not_called()
        self.pidfd_open.assert_not_called()
        self.send_signal.assert_not_called()

    def test_other_user_process_is_not_stopped(self):
        self.stat.side_effect = [metadata(stat.S_IFDIR | 0o555, uid=1001)]
        self.assertEqual(self.pause(), 0)
        self.pidfd_open.assert_not_called()
        self.send_signal.assert_not_called()

    def test_other_executable_is_not_stopped(self):
        self.stat.side_effect = [self.process, metadata(stat.S_IFREG | 0o755, inode=21)]
        self.assertEqual(self.pause(), 0)
        self.pidfd_open.assert_not_called()
        self.send_signal.assert_not_called()

    def test_same_inode_on_other_device_is_not_stopped(self):
        self.stat.side_effect = [self.process, metadata(stat.S_IFREG | 0o755, dev=11)]
        self.assertEqual(self.pause(), 0)
        self.send_signal.assert_not_called()

    def test_pid_reuse_with_different_owner_is_not_stopped(self):
        self.stat.side_effect = [
            self.process,
            self.binary,
            metadata(stat.S_IFDIR | 0o555, uid=1001),
        ]
        self.assertEqual(self.pause(), 0)
        self.pidfd_open.assert_called_once_with(self.pid, 0)
        self.send_signal.assert_not_called()
        self.assertIn(call(self.process_fd), self.close.call_args_list)

    def test_exec_change_after_pidfd_open_is_not_stopped(self):
        self.stat.side_effect = [
            self.process,
            self.binary,
            self.process,
            metadata(stat.S_IFREG | 0o755, inode=21),
        ]
        self.assertEqual(self.pause(), 0)
        self.send_signal.assert_not_called()
        self.assertIn(call(self.process_fd), self.close.call_args_list)

    def test_disappeared_process_is_not_stopped(self):
        self.stat.side_effect = FileNotFoundError()
        self.assertEqual(self.pause(), 0)
        self.pidfd_open.assert_not_called()
        self.send_signal.assert_not_called()

    def test_process_exiting_before_pidfd_open_is_harmless(self):
        self.pidfd_open.side_effect = ProcessLookupError()
        self.assertEqual(self.pause(), 0)
        self.send_signal.assert_not_called()
        self.assertEqual(self.close.call_args_list, [call(self.binary_fd)])

    def test_process_exiting_after_pidfd_open_is_harmless(self):
        self.stat.side_effect = [self.process, self.binary, FileNotFoundError()]
        self.assertEqual(self.pause(), 0)
        self.send_signal.assert_not_called()
        self.assertCountEqual(self.close.call_args_list, [call(self.binary_fd), call(self.process_fd)])

    def test_process_exiting_before_signal_is_harmless(self):
        self.send_signal.side_effect = ProcessLookupError()
        self.assertEqual(self.pause(), 0)
        self.assertEqual(self.poller.registrations, [])

    def test_permission_failure_during_inspection_is_reported(self):
        self.stat.side_effect = PermissionError()
        with self.assertRaises(manager.GuardError):
            self.pause()
        self.send_signal.assert_not_called()
        self.assertEqual(self.close.call_args_list, [call(self.binary_fd)])

    def test_pidfd_permission_failure_is_reported(self):
        self.pidfd_open.side_effect = PermissionError()
        with self.assertRaises(manager.GuardError):
            self.pause()
        self.send_signal.assert_not_called()
        self.assertEqual(self.close.call_args_list, [call(self.binary_fd)])

    def test_signal_permission_failure_is_reported_and_handles_closed(self):
        self.send_signal.side_effect = PermissionError()
        with self.assertRaises(manager.GuardError):
            self.pause()
        self.assertCountEqual(self.close.call_args_list, [call(self.binary_fd), call(self.process_fd)])

    def test_process_exit_hangup_counts_as_stopped(self):
        self.poller.steps = [(0.0, [(self.process_fd, select.POLLHUP)])]
        self.assertEqual(self.pause(), 1)

    def test_process_handle_error_is_not_reported_as_success(self):
        for flag in (select.POLLERR, select.POLLNVAL):
            with self.subTest(flag=flag):
                self.stat.side_effect = [self.process, self.binary, self.process, self.binary]
                self.poller.steps = [(0.0, [(self.process_fd, flag)])]
                with self.assertRaises(manager.GuardError):
                    self.pause()

    def test_termination_wait_uses_one_global_deadline(self):
        self.poller.steps = [(0.6, []), (0.4, [])]
        with self.assertRaises(manager.GuardError):
            self.pause()
        self.assertEqual(len(self.poller.timeouts), 2)
        self.assertLessEqual(self.poller.timeouts[0], 1000)
        self.assertLessEqual(self.poller.timeouts[1], 400)
        self.assertLessEqual(self.clock.now, 1.0)
        self.send_signal.assert_called_once()
        self.assertCountEqual(self.close.call_args_list, [call(self.binary_fd), call(self.process_fd)])

    def test_unknown_poll_descriptors_do_not_confirm_termination(self):
        self.poller.steps = [(0.2, [(999, select.POLLIN)]), (0.0, [(self.process_fd, select.POLLIN)])]
        self.assertEqual(self.pause(), 1)
        self.assertEqual(len(self.poller.timeouts), 2)

    def test_missing_clipman_does_not_touch_unknown_manager(self):
        self.open.side_effect = FileNotFoundError()
        self.assertEqual(self.pause(), 0)
        self.stat.assert_not_called()
        self.pidfd_open.assert_not_called()
        self.send_signal.assert_not_called()

    def test_xfce_replacement_disables_only_clipboard_in_child_environment(self):
        with patch.object(manager.subprocess, "run") as run:
            self.assertEqual(manager.disable_xfce_clipboard(self.pid), 1)
        arguments, options = run.call_args
        self.assertEqual(arguments[0], [f"/proc/self/fd/{self.binary_fd}", "--replace", "--daemon"])
        self.assertEqual(options["env"]["XFSETTINGSD_NO_CLIPBOARD"], "1")
        self.assertEqual(options["pass_fds"], (self.binary_fd,))
        self.assertEqual(options["timeout"], 2)
        self.assertTrue(options["check"])
        self.send_signal.assert_not_called()
        self.open.assert_called_once_with(manager.XFSETTINGS_BINARY, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)

    def test_xfce_other_process_never_launches_replacement(self):
        self.stat.side_effect = [self.process, metadata(stat.S_IFREG | 0o755, inode=21)]
        with patch.object(manager.subprocess, "run") as run:
            self.assertEqual(manager.disable_xfce_clipboard(self.pid), 0)
        run.assert_not_called()

    def test_xfce_untrusted_binary_never_launches_replacement(self):
        self.fstat.return_value = metadata(stat.S_IFREG | 0o777)
        with patch.object(manager.subprocess, "run") as run:
            with self.assertRaises(manager.GuardError):
                manager.disable_xfce_clipboard(self.pid)
        run.assert_not_called()

    def test_xfce_failed_replacement_is_reported(self):
        for failure in (manager.subprocess.TimeoutExpired("xfsettingsd", 2), manager.subprocess.CalledProcessError(1, "xfsettingsd")):
            with self.subTest(failure=failure):
                self.stat.side_effect = [self.process, self.binary]
                with patch.object(manager.subprocess, "run", side_effect=failure):
                    with self.assertRaises(manager.GuardError):
                        manager.disable_xfce_clipboard(self.pid)
        self.send_signal.assert_not_called()


if __name__ == "__main__":
    unittest.main()
