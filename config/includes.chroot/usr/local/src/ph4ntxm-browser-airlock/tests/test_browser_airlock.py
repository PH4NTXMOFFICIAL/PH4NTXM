#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import importlib.util
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location("browser_airlock_review", ROOT / "browser_airlock.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class BrowserBackendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="browser-airlock-review-")
        self.root = Path(self.temporary.name)
        self.session = app.Session.__new__(app.Session)
        self.session.directory = self.root / "private"
        self.session.directory.mkdir(mode=0o700)
        self.session.workspace = self.session.directory / "workspace"
        self.session.workspace.mkdir(mode=0o700)
        self.session.imports = self.session.workspace / "imports"
        self.session.imports.mkdir(mode=0o700)
        self.session.downloads = self.session.workspace / "downloads"
        self.session.downloads.mkdir(mode=0o700)
        self.session.home = self.session.directory / "home"
        self.session.home.mkdir(mode=0o700)
        self.session.items = []
        self.session.unit = None
        self.session.cgroup = ""
        self.session.running = False
        self.session.closed = False
        self.session.plan = object()
        self.memory = patch.object(app, "memory_budget", return_value=512 * 1024 * 1024)
        self.memory.start()

    def tearDown(self):
        self.memory.stop()
        self.temporary.cleanup()

    def source(self, name="input.txt", data=b"chosen import"):
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_readiness_reports_safe_bounded_probe_failure_and_closes_filter(self):
        errors = (
            (subprocess.CalledProcessError(1, ["bwrap"], stderr=b"bwrap: /proc: permission denied\n\x1b[31m" + b"x" * 500), "bwrap: /proc: permission denied"),
            (subprocess.CalledProcessError(2, ["bwrap"], stderr="bad\u202efile\nname"), "bad file name"),
            (subprocess.CalledProcessError(3, ["bwrap"]), "status 3"),
            (subprocess.TimeoutExpired(["bwrap"], 15), "timed out after 15 seconds"),
        )
        for error, expected in errors:
            with self.subTest(error=type(error).__name__, expected=expected):
                with patch.object(app.os, "getuid", return_value=1000), patch.object(app, "trusted"), patch.object(app, "bootstrap_permissions"), patch.object(app, "runtime_directory"), patch.object(app, "ram_directory"), patch.object(app, "environment", return_value={}), patch.object(app, "filter_fd", return_value=71), patch.object(app, "sandbox", return_value=["bwrap"]), patch.object(app, "command", side_effect=[None, error]), patch.object(app.os, "close") as close:
                    with self.assertRaises(app.AppError) as caught:
                        app.check_ready()
                    message = str(caught.exception)
                    self.assertIn("No application was opened.", message)
                    self.assertIn(expected, message)
                    self.assertLess(len(message), 400)
                    self.assertTrue(all(not app.unicodedata.category(character).startswith("C") for character in message))
                    close.assert_called_once_with(71)

    def test_oom_termination_cannot_be_reported_as_a_clean_stop(self):
        state = {"state": "finished", "message": "Stopped", "exit_code": 0}
        memory = {"memory.max": 640 * 1024 * 1024, "memory.events": {"max": 308, "oom": 1, "oom_kill": 1}}
        result = app.memory_outcome(state, memory)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["reason"], "memory-limit")
        self.assertIn("640 MiB", result["message"])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(state["state"], "finished")
        result = app.memory_outcome(state, {"memory.events": {"oom_kill": 1}})
        self.assertEqual(result["reason"], "out-of-memory")
        self.assertNotIn("memory limit", result["message"])

    def test_last_failure_survives_resume_and_clean_stop_in_the_same_session(self):
        failure = app.memory_outcome({"state": "finished", "exit_code": 0}, {"memory.events": {"oom_kill": 1}})
        app.record_state(self.session.directory, failure)
        remembered = self.session.directory / "last-failure.json"
        original = remembered.read_bytes()
        for value in ({"state": "running", "memory_limit": 1024 ** 3}, {"state": "finished", "exit_code": 0}):
            app.record_state(self.session.directory, value)
            self.assertEqual(remembered.read_bytes(), original)
            self.assertEqual(app.read_json(self.session.directory / "state.json"), value)
        self.assertEqual(stat.S_IMODE(remembered.stat().st_mode), 0o600)
        newer = {"state": "failed", "message": "Display exited", "exit_code": 1}
        app.record_state(self.session.directory, newer)
        self.assertEqual(app.read_json(remembered), newer)
        self.assertFalse((self.root / "last-failure.json").exists())

    def test_memory_pressure_without_a_kill_preserves_clean_stop(self):
        state = {"state": "finished", "message": "Stopped", "exit_code": 0}
        for events in ({}, {"max": 100, "oom": 1, "oom_kill": 0}):
            result = app.memory_outcome(state, {"memory.events": events})
            self.assertEqual(result["state"], "finished")
            self.assertNotIn("reason", result)

    def test_diagnostics_retain_the_final_failure_after_warning_spam(self):
        text = app.diagnostic_text(b"warning " * 1000 + b"\x00\nFINAL_FAILURE", tail=True)
        self.assertTrue(text.endswith("FINAL_FAILURE"))
        self.assertLessEqual(len(text), 240)
        self.assertTrue(all(not app.unicodedata.category(character).startswith("C") for character in text))

    def test_socket_startup_waits_for_readiness_and_identifies_the_failed_endpoint(self):
        path = unittest.mock.Mock()
        process = unittest.mock.Mock()
        process.poll.return_value = None
        path.is_socket.side_effect = [False, True]
        with patch.object(app.time, "monotonic", side_effect=[0, 0, 1]), patch.object(app.time, "sleep"):
            app.wait_socket(path, process, "browser session bus")
        path.is_socket.side_effect = None
        path.is_socket.return_value = False
        with patch.object(app.time, "monotonic", side_effect=[0, 0, 16]), patch.object(app.time, "sleep"):
            with self.assertRaisesRegex(app.AppError, "browser session bus.*15 seconds"):
                app.wait_socket(path, process, "browser session bus")
        process.poll.return_value = 0
        with self.assertRaisesRegex(app.AppError, "Xephyr display stopped"):
            app.wait_socket(path, process, "Xephyr display")

    def test_tor_architecture_tool_is_private_and_does_not_replace_host_wrappers(self):
        with patch.object(app, "trusted") as trusted:
            args = app.tor_bindings(["base"], "/home/private")
        self.assertEqual(trusted.call_args_list, [unittest.mock.call("/usr/bin/getconf-real"), unittest.mock.call("/opt/ph4ntxm/tor-browser/Browser/TorBrowser/Tor/tor")])
        self.assertEqual(args, ["base", "--dir", "/run/ph4ntxm-browser-tools", "--ro-bind", "/usr/bin/getconf-real", "/run/ph4ntxm-browser-tools/getconf", "--ro-bind", "/opt/ph4ntxm/tor-browser/Browser/TorBrowser/Tor/tor", "/home/private/.tor-browser/TorBrowser/Tor/tor"])
        self.assertNotIn("/usr/bin/getconf", args)
        with patch.object(app, "trusted", side_effect=app.AppError("Untrusted executable")):
            with self.assertRaises(app.AppError):
                app.tor_bindings([], "/home/private")

    def test_zero_status_display_exit_is_not_a_clean_browser_close(self):
        state = app.completion_state(None, 0)
        self.assertEqual(state["state"], "failed")
        self.assertEqual(state["exit_code"], 0)
        self.assertIn("display stopped", state["message"])
        self.assertEqual(state["components"], {"browser_worker": None, "display": 0})

    def test_browser_and_display_exit_codes_remain_distinct(self):
        state = app.completion_state(0, None)
        self.assertEqual(state["state"], "finished")
        self.assertIn("browser worker stopped", state["message"])
        for application, display in ((-11, 0), (0, -9), (None, 1)):
            with self.subTest(application=application, display=display):
                state = app.completion_state(application, display)
                self.assertEqual(state["state"], "failed")
                self.assertNotEqual(state["exit_code"], 0)
                self.assertEqual(state["components"], {"browser_worker": application, "display": display})

    def test_embedded_display_has_parent_before_its_only_screen(self):
        settings = {"screen_width": 900, "screen_height": 600}
        args = app.display_command(100, settings, 42)
        self.assertEqual(args[:6], ["/usr/bin/Xephyr", ":100", "-parent", "42", "-screen", "900x600"])
        self.assertEqual(args.count("-screen"), 1)
        self.assertEqual(args.count("-parent"), 1)
        self.assertIn("-no-host-grab", args)
        self.assertEqual(args[args.index("-auth") + 1], "/config/nested.auth")
        self.assertEqual(app.display_command(100, settings, None)[:4], ["/usr/bin/Xephyr", ":100", "-screen", "900x600"])

    def test_live_import_is_atomic_and_not_a_download(self):
        self.session.unit = "running.service"
        source = self.source()
        original = app.os.link

        def publish(staged, target, **kwargs):
            self.assertEqual(Path(staged).read_bytes(), source.read_bytes())
            self.assertFalse(Path(target).exists())
            self.assertEqual(Path(staged).stat().st_mode & 0o777, 0o600)
            return original(staged, target, **kwargs)

        with patch.object(app, "stopped", return_value=False), patch.object(app.os, "link", side_effect=publish):
            self.session.add([source])
            with self.assertRaises(app.AppError):
                self.session.outputs()
        self.assertEqual((self.session.imports / source.name).read_bytes(), source.read_bytes())
        self.assertEqual(self.session.items[0]["path"], "/workspace/imports/input.txt")
        self.assertEqual(list(self.session.directory.glob("import.*")), [])
        self.session.unit = None
        self.assertEqual(self.session.outputs(), [])

    def test_duplicate_batch_preserves_previous_import(self):
        old = self.source("old.txt", b"previous")
        self.session.add([old])
        with self.assertRaises(FileExistsError):
            self.session.add([self.source("new.txt"), old])
        self.assertEqual([item["id"] for item in self.session.items], ["old.txt"])
        self.assertFalse((self.session.imports / "new.txt").exists())
        self.assertEqual((self.session.imports / "old.txt").read_bytes(), b"previous")
        self.assertEqual(list(self.session.directory.glob("import.*")), [])

    def test_import_rejects_symlink_fifo_empty_and_combined_limit(self):
        source = self.source()
        link = self.root / "link"
        link.symlink_to(source)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (link, fifo, self.source("empty", b"")):
            with self.subTest(path=path.name), self.assertRaises((OSError, app.AppError)):
                self.session.add([path])
        with patch.object(app, "MAX_INPUT", 12):
            with self.assertRaises(app.AppError):
                self.session.add([self.source("first", b"12345678"), self.source("second", b"12345678")])
        self.assertEqual(self.session.items, [])
        self.assertEqual(list(self.session.imports.iterdir()), [])

    def test_import_detects_changed_source_before_publication(self):
        source = self.source()
        original = app.os.read
        changed = False

        def read(descriptor, size):
            nonlocal changed
            result = original(descriptor, size)
            if result and not changed:
                changed = True
                source.write_bytes(b"a different source")
            return result

        with patch.object(app.os, "read", side_effect=read), self.assertRaises(app.AppError):
            self.session.add([source])
        self.assertEqual(list(self.session.imports.iterdir()), [])
        self.assertEqual(list(self.session.directory.glob("import.*")), [])

    def test_download_export_preserves_destination_and_source(self):
        (self.session.downloads / "result").write_bytes(b"download result")
        target = self.root / "export"
        self.session.export("result", target)
        self.assertEqual(target.read_bytes(), b"download result")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            self.session.export("result", target)
        linked = self.root / "linked"
        linked.symlink_to(target)
        with self.assertRaises(FileExistsError):
            self.session.export("result", linked)
        self.assertEqual(target.read_bytes(), b"download result")
        self.assertEqual((self.session.downloads / "result").read_bytes(), b"download result")

    def test_export_rejects_directory_replaced_by_symlink(self):
        nested = self.session.downloads / "nested"
        nested.mkdir()
        (nested / "file").write_bytes(b"safe")
        listing = self.session.outputs()
        (nested / "file").unlink()
        nested.rmdir()
        nested.symlink_to(self.root)
        self.source("file", b"must not export")
        with patch.object(self.session, "outputs", return_value=listing), self.assertRaises(OSError):
            self.session.export("nested/file", self.root / "escaped")
        self.assertFalse((self.root / "escaped").exists())

    def test_outputs_exclude_links_and_special_files(self):
        output = self.session.downloads / "report"
        output.write_bytes(b"safe")
        (self.session.downloads / "link").symlink_to(self.source("outside"))
        os.mkfifo(self.session.downloads / "fifo")
        (self.session.downloads / "hard-one").write_bytes(b"hardlink")
        os.link(self.session.downloads / "hard-one", self.session.downloads / "hard-two")
        self.assertEqual([item["id"] for item in self.session.outputs()], ["report"])

    def test_file_total_entry_and_depth_limits(self):
        with patch.object(app, "MAX_FILE", 12), patch.object(app, "MAX_OUTPUT", 20):
            (self.session.downloads / "a").write_bytes(b"x" * 13)
            with self.assertRaises(app.AppError):
                self.session.outputs()
            self.session.clear()
            for name in ("a", "b"):
                (self.session.downloads / name).write_bytes(b"x" * 12)
            with self.assertRaises(app.AppError):
                self.session.outputs()
        self.session.clear()
        with patch.object(app, "MAX_ENTRIES", 2):
            for name in ("a", "b", "c"):
                (self.session.downloads / name).touch()
            with self.assertRaises(app.AppError):
                self.session.outputs()
        self.session.clear()
        nested = self.session.downloads
        for _ in range(9):
            nested = nested / "d"
            nested.mkdir()
        with self.assertRaises(app.AppError):
            self.session.outputs()

    def test_cleanup_does_not_follow_links_and_retains_profile_until_close(self):
        outside = self.source("outside", b"preserve")
        self.session.home.joinpath("profile-state").write_bytes(b"within boot")
        (self.session.downloads / "link").symlink_to(outside)
        nested = self.session.downloads / "unreadable"
        nested.mkdir()
        (nested / "data").write_bytes(b"temporary")
        nested.chmod(0)
        self.session.clear()
        self.assertEqual(outside.read_bytes(), b"preserve")
        self.assertEqual(self.session.home.joinpath("profile-state").read_bytes(), b"within boot")
        self.assertTrue(self.session.imports.is_dir())
        self.assertTrue(self.session.downloads.is_dir())
        self.session.close()
        self.session.close()
        self.assertFalse(self.session.directory.exists())
        self.assertEqual(outside.read_bytes(), b"preserve")

    def test_external_firefox_profile_mount_and_cleanup_preserve_cache(self):
        cache = self.root / "firefox-cache" / "profile"
        cache.mkdir(parents=True, mode=0o700)
        (cache / "state").write_bytes(b"reused until reboot")
        private = self.session.home / "profile"
        private.mkdir(mode=0o700)
        (private / "state").write_bytes(b"wrong profile source")
        arguments = app.profile_binding([], str(cache))
        self.assertEqual(arguments, ["--bind", str(cache), str(cache)])
        self.assertNotIn(str(private), arguments)
        self.assertEqual(app.profile_binding([], None), [])
        self.session.close()
        self.assertFalse(self.session.directory.exists())
        self.assertEqual((cache / "state").read_bytes(), b"reused until reboot")

    def test_cgroup_population_prevents_export_and_cleanup(self):
        self.session.unit = "test.service"
        with patch.object(app, "unit_state", return_value={"ActiveState": "inactive", "ControlGroup": "/browser-review"}), patch.object(Path, "read_text", return_value="populated 1\n"):
            self.assertFalse(app.stopped(self.session.unit))
            with self.assertRaises(app.AppError):
                self.session.outputs()
        with patch.object(app, "stopped", return_value=False), patch.object(app, "environment", return_value={}), patch.object(app.subprocess, "run"):
            with self.assertRaises(app.AppError):
                self.session.close()
        self.assertTrue(self.session.directory.exists())
        self.assertFalse(self.session.closed)
        with patch.object(app, "stopped", return_value=True):
            self.session.stop()
        self.assertFalse(self.session.running)

    def test_missing_service_state_fails_closed(self):
        result = subprocess.CompletedProcess([], 0, stdout="Result=success\n", stderr="")
        with patch.object(app, "environment", return_value={}), patch.object(app.subprocess, "run", return_value=result), self.assertRaises(app.AppError):
            app.unit_state("test.service")

    def test_forwarding_validates_controlled_private_request_and_state(self):
        values = ["https://example.invalid/path?q=one&two=3", "about:blank"]
        self.assertEqual(app.browser_arguments(values, True), ["-private-window", *values])
        for invalid in (["file:///etc/passwd"], ["--private-window"], ["https://example.invalid/\n"], ["about:config"], ["http://"]):
            with self.subTest(invalid=invalid), self.assertRaises(app.AppError):
                app.browser_urls(invalid)
        imported = Path("/workspace/imports/a # résumé.pdf").as_uri()
        self.assertEqual(app.browser_urls([imported]), [imported])
        for invalid in ("file:///workspace/imports/../secret", "file:///workspace/imports/%2Fetc%2Fpasswd", "file://host/workspace/imports/file", "file:///workspace/imports/file?query", "file:///workspace/imports/a%00b"):
            with self.subTest(invalid=invalid), self.assertRaises(app.AppError):
                app.browser_urls([invalid])
        with self.assertRaises(app.AppError):
            app.browser_arguments([], "true")
        with self.assertRaises(app.AppError):
            self.session.open_urls(values)
        self.session.unit = "test.service"
        with patch.object(app, "stopped", return_value=False), patch.object(app, "revalidate_browser") as validate, patch.object(app, "forward_urls") as forward:
            self.session.open_urls(values, True)
            validate.assert_called_once_with(self.session.plan)
            forward.assert_called_once_with(self.session.directory / "bus/bus", values, True)

    def test_sandbox_keeps_host_network_and_hostname_and_isolates_other_namespaces(self):
        browser = app.sandbox(17)
        display = app.sandbox(18, offline=True)
        self.assertNotIn("--unshare-net", browser)
        self.assertIn("--unshare-net", display)
        self.assertNotIn("--hostname", browser)
        self.assertEqual(browser[:2], [str(app.EXEC / "bootstrap"), "17"])
        self.assertNotIn("--proc", browser)
        self.assertNotIn("--unshare-pid", browser)
        cpu = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)
        with patch.object(Path, "lstat", return_value=cpu), patch.object(Path, "resolve", side_effect=FileNotFoundError):
            bindings = app.identity_bindings([])
        self.assertEqual(bindings.count("--ro-bind"), 4)
        self.assertIn("/proc/cpuinfo", bindings)
        self.assertNotIn("/sys/class/dmi/id", bindings)
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        with patch.object(Path, "lstat", side_effect=[cpu, cpu, directory]), patch.object(Path, "resolve", return_value=Path("/sys/devices/virtual/dmi/id")):
            bindings = app.identity_bindings([])
        self.assertIn("/sys/class/dmi/id", bindings)
        for canonical, mode in (("/tmp/dmi", 0o755), ("/sys/devices/virtual/dmi/id", 0o777)):
            unsafe = SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=0)
            with self.subTest(canonical=canonical, mode=mode), patch.object(Path, "lstat", side_effect=[cpu, cpu, unsafe]), patch.object(Path, "resolve", return_value=Path(canonical)), self.assertRaises(app.AppError):
                app.identity_bindings([])
        for option in ("--unshare-user", "--unshare-ipc", "--unshare-uts", "--cap-drop", "--clearenv"):
            self.assertIn(option, browser)
        for name in ("DBUS_SESSION_BUS_ADDRESS", "LD_PRELOAD", "LIBGL_ALWAYS_SOFTWARE", "MOZ_DISABLE_CONTENT_SANDBOX"):
            self.assertNotIn(name, browser)
        settings = app.display_settings({"screen_width": 1200, "screen_height": 800})
        self.assertEqual(settings["screen_width"], 1200)
        for settings in ({"screen_width": 0}, {"screen_width": True}, {"screen_height": 90000}, {"screen_width": 8192, "screen_height": 8192}):
            with self.assertRaises(app.AppError):
                app.display_settings(settings)


if __name__ == "__main__":
    unittest.main(verbosity=2)
