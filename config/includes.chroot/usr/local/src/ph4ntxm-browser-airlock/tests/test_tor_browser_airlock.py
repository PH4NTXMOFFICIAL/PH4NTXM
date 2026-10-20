#!/usr/bin/python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

MODULE = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else Path("/opt/ph4ntxm/ph4ntxm-opsec-ui/ph4ntxm_opsec_ui/tor_browser_check.py")
PACKAGE = Path(sys.argv.pop(1)) if len(sys.argv) > 1 else MODULE.parent.parent
sys.path.insert(0, str(PACKAGE))
spec = importlib.util.spec_from_file_location("ph4ntxm_opsec_ui.tor_browser_airlock_test", MODULE)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)
HELD_SESSION_LOCK = observer.held_session_lock


class TorBrowserAirlockTests(unittest.TestCase):
    def setUp(self):
        self.previous_umask = os.umask(0o077)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.runtime = self.root / "runtime"
        self.public_temp = self.root / "tmp"
        self.proc = self.root / "proc"
        for path in (self.runtime, self.public_temp, self.proc):
            path.mkdir(mode=0o700)
        self.uid = os.getuid()
        self.patches = [
            patch.object(observer, "TEMP_DIRECTORY", self.public_temp),
            patch.object(observer, "PROC_DIRECTORY", self.proc),
            patch.object(observer, "held_session_lock", return_value=True),
        ]
        original = Path.lstat

        def metadata(path, *args, **kwargs):
            if path == self.public_temp:
                return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o1777)
            return original(path, *args, **kwargs)

        self.patches.append(patch.object(Path, "lstat", metadata))
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()
        os.umask(self.previous_umask)

    def profile(self, name="ph4ntxm-browser-airlock.a1b2c3d4", base=None, process=42):
        directory = (base or self.public_temp) / name
        profile = directory / "home/.tor-browser/profile"
        profile.mkdir(mode=0o700, parents=True)
        lock = profile / ".parentlock"
        lock.write_bytes(b"")
        info = lock.stat()
        record = "1: POSIX ADVISORY WRITE %d %x:%x:%d 0 EOF\n" % (
            process, os.major(info.st_dev), os.minor(info.st_dev), info.st_ino,
        )
        locks = self.proc / "locks"
        with locks.open("a") as stream:
            stream.write(record)
        task = self.proc / str(process)
        task.mkdir()
        (task / "status").write_text("Uid:\t" + "\t".join([str(self.uid)] * 4) + "\n")
        (task / "cmdline").write_bytes(b"firefox\x00")
        (task / "exe").symlink_to(observer.BROWSER / "firefox.real")
        return directory / "home", profile

    def test_controller_and_legacy_locks_are_recognized(self):
        for name in ("ph4ntxm-browser-airlock.lock", "ph4ntxm-tor-browser.lock"):
            with self.subTest(name=name):
                path = self.runtime / name
                path.write_bytes(b"")
                info = path.stat()
                identity = "%x:%x:%d" % (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
                (self.proc / "locks").write_text("1: FLOCK ADVISORY WRITE 42 " + identity + " 0 EOF\n")
                self.assertTrue(HELD_SESSION_LOCK(self.runtime, self.uid))
                (self.proc / "locks").write_text("")
                self.assertFalse(HELD_SESSION_LOCK(self.runtime, self.uid))
                path.unlink()

    def test_locked_airlock_profile_is_discovered_without_process_environ(self):
        home, profile = self.profile()
        result = observer.locked_runtime_session(self.runtime, self.uid)
        self.assertEqual(result["home"], home)
        self.assertEqual(result["profile"], profile)
        self.assertTrue(result["lock_held"])

    def test_legacy_runtime_profile_discovery_remains_valid(self):
        home, profile = self.profile("ph4ntxm-tor-browser.a1B2c3", self.runtime)
        result = observer.locked_runtime_session(self.runtime, self.uid)
        self.assertEqual(result["home"], home)
        self.assertEqual(result["profile"], profile)

    def test_only_exact_private_session_roots_are_accepted(self):
        for home in (
            self.public_temp / "ph4ntxm-browser-airlock.a1b2c3d4/home",
            self.runtime / "ph4ntxm-tor-browser.a1B2c3/home",
        ):
            self.assertTrue(observer.valid_session_home(home, self.runtime))
        for home in (
            self.public_temp / "other.a1b2c3d4/home",
            self.public_temp / "ph4ntxm-browser-airlock.short/home",
            self.root / "ph4ntxm-browser-airlock.a1b2c3d4/home",
            self.public_temp / "ph4ntxm-browser-airlock.a1b2c3d4/other",
        ):
            self.assertFalse(observer.valid_session_home(home, self.runtime))

    def test_home_symlink_and_writable_home_are_not_trusted(self):
        home, _ = self.profile()
        home.chmod(0o777)
        with self.assertRaises(ValueError):
            observer.locked_runtime_session(self.runtime, self.uid)
        home.chmod(0o700)
        moved = home.with_name("saved")
        home.rename(moved)
        home.symlink_to(moved)
        with self.assertRaises(ValueError):
            observer.locked_runtime_session(self.runtime, self.uid)

    def test_missing_lock_and_duplicate_profiles_are_not_reported_as_one_browser(self):
        self.profile()
        with patch.object(observer, "held_session_lock", return_value=False):
            self.assertIsNone(observer.locked_runtime_session(self.runtime, self.uid))
        self.profile("ph4ntxm-browser-airlock.z9y8x7w6", process=43)
        with self.assertRaises(ValueError):
            observer.locked_runtime_session(self.runtime, self.uid)


if __name__ == "__main__":
    unittest.main()
