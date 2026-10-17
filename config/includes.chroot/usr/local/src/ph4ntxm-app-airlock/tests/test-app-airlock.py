#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import importlib.util
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "app_airlock.py"
spec = importlib.util.spec_from_file_location("app_airlock_review", SOURCE)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class BackendReview(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="app-airlock-review-")
        self.base = Path(self.temp.name)
        self.session = app.Session.__new__(app.Session)
        self.session.directory = self.base / "private"
        self.session.directory.mkdir(mode=0o700)
        self.session.workspace = self.session.directory / "workspace"
        self.session.workspace.mkdir(mode=0o700)
        self.session.items = []
        self.session.unit = None
        self.session.cgroup = ""
        self.session.running = False
        self.session.closed = False
        self.session.require_stopped = lambda: None
        self.memory = patch.object(app, "memory_budget", return_value=512 * 1024 * 1024)
        self.memory.start()

    def tearDown(self):
        self.memory.stop()
        self.temp.cleanup()

    def source(self, name="input.txt", data=b"hello"):
        file = self.base / name
        file.write_bytes(data)
        return file

    def test_import_export_roundtrip_and_private_mode(self):
        source = self.source()
        self.session.add([source])
        target = self.base / "exported.txt"
        self.session.export("input.txt", target)
        self.assertEqual(target.read_bytes(), b"hello")
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(source.read_bytes(), b"hello")

    def test_batch_duplicate_rolls_back_only_new_copies(self):
        self.session.add([self.source("old.txt")])
        fresh = self.source("fresh.txt")
        with self.assertRaises(FileExistsError):
            self.session.add([fresh, self.base / "old.txt"])
        self.assertEqual([item["id"] for item in self.session.items], ["old.txt"])
        self.assertFalse((self.session.workspace / "fresh.txt").exists())
        self.assertTrue((self.session.workspace / "old.txt").exists())

    def test_import_symlink_and_empty_are_rejected(self):
        source = self.source()
        linked = self.base / "link.txt"
        linked.symlink_to(source)
        with self.assertRaises(OSError):
            self.session.add([linked])
        with self.assertRaises(app.AppError):
            self.session.add([self.source("empty.txt", b"")])
        self.assertEqual(self.session.items, [])

    def test_export_cannot_overwrite_existing_or_symlink(self):
        self.session.add([self.source()])
        existing = self.source("existing.txt", b"original")
        with self.assertRaises(FileExistsError):
            self.session.export("input.txt", existing)
        target = self.base / "link.txt"
        target.symlink_to(existing)
        with self.assertRaises(FileExistsError):
            self.session.export("input.txt", target)
        self.assertEqual(existing.read_bytes(), b"original")

    def test_nested_results_and_symlink_hardlink_fifo_exclusion(self):
        nested = self.session.workspace / "results"
        nested.mkdir()
        (nested / "report.txt").write_bytes(b"result")
        (nested / "host-link").symlink_to("/etc/passwd")
        (nested / "hard-one").write_bytes(b"data")
        os.link(nested / "hard-one", nested / "hard-two")
        os.mkfifo(nested / "pipe")
        results = self.session.outputs()
        self.assertEqual([item["id"] for item in results], ["results/report.txt"])
        target = self.base / "nested-export"
        self.session.export("results/report.txt", target)
        self.assertEqual(target.read_bytes(), b"result")
        with self.assertRaises(app.AppError):
            self.session.export("results/host-link", self.base / "leak")

    def test_entry_depth_and_combined_size_limits(self):
        for index in range(app.MAX_ENTRIES + 1):
            (self.session.workspace / str(index)).touch()
        with self.assertRaises(app.AppError):
            self.session.outputs()
        self.session.clear()
        nested = self.session.workspace
        for _ in range(9):
            nested = nested / "d"
            nested.mkdir()
        with self.assertRaises(app.AppError):
            self.session.outputs()
        self.session.clear()
        with patch.object(app, "MAX_INPUT", 16), patch.object(app, "MAX_OUTPUT", 20):
            (self.session.workspace / "a").write_bytes(b"x" * 12)
            (self.session.workspace / "b").write_bytes(b"x" * 12)
            with self.assertRaises(app.AppError):
                self.session.outputs()

    def test_clear_unlinks_workspace_symlinks_without_following(self):
        outside = self.source("outside.txt", b"preserve")
        (self.session.workspace / "link").symlink_to(outside)
        self.session.clear()
        self.assertEqual(outside.read_bytes(), b"preserve")
        self.assertEqual(self.session.outputs(), [])

    def test_cleanup_repairs_unreadable_workspace_directories(self):
        nested = self.session.workspace / "private-result"
        nested.mkdir()
        (nested / "data").write_bytes(b"test")
        nested.chmod(0)
        self.session.workspace.chmod(0)
        self.session.clear()
        self.assertEqual(self.session.outputs(), [])

    def test_display_credentials_use_selected_display_number(self):
        for number in (100, 101):
            root = self.base / ("config-%d" % number)
            app.configure(root, {}, number)
            self.assertEqual((root / "display").read_text(), ":%d" % number)
            self.assertIn(str(number).encode(), (root / "nested.auth").read_bytes())
            self.assertNotIn("host.auth", [path.name for path in root.iterdir()])

    def test_command_arguments_are_not_run_by_a_host_shell(self):
        self.assertEqual(
            app.application_command("printf '%s' '$(literal);touch /tmp/example'"),
            ["printf", "%s", "$(literal);touch /tmp/example"],
        )
        for value in ("", " ", "'broken", "x" * 4097, "x\x00y"):
            with self.assertRaises(app.AppError):
                app.application_command(value)

    def test_cleanup_handles_deep_trees_without_following_links(self):
        root = self.session.workspace
        for index in range(90):
            (root / "file").write_text("test")
            (root / "link").symlink_to("/etc")
            root = root / "d"
            root.mkdir()
        root.chmod(0)
        self.session.clear()
        self.assertEqual(self.session.outputs(), [])

    def test_desktop_entries_are_enumerated_without_application_allowlist(self):
        directory = self.base / "applications"
        directory.mkdir()
        for name, extra in (
            ("one", ""),
            ("hidden-from-menu", "NoDisplay=true\n"),
            ("disabled", "Hidden=true\n"),
        ):
            (directory / (name + ".desktop")).write_text(
                "[Desktop Entry]\nType=Application\nName="
                + name
                + "\nExec=example %F\n"
                + extra
            )
        with patch.object(app, "APPLICATIONS", directory):
            self.assertEqual(
                {item["id"] for item in app.applications()},
                {"one.desktop", "hidden-from-menu.desktop"},
            )

    def test_desktop_field_expansion_preserves_literal_arguments(self):
        directory = self.base / "applications"
        directory.mkdir()
        (directory / "example.desktop").write_text(
            '[Desktop Entry]\nType=Application\nName=Example App\nIcon=example-icon\nExec=example "--label=%c" %F %% %i\n'
        )
        with patch.object(app, "APPLICATIONS", directory):
            self.assertEqual(
                app.desktop_command("example.desktop", "a file.txt"),
                [
                    "example",
                    "--label=Example App",
                    "/workspace/a file.txt",
                    "%",
                    "--icon",
                    "example-icon",
                ],
            )
            self.assertEqual(
                app.desktop_command("example.desktop"),
                ["example", "--label=Example App", "%", "--icon", "example-icon"],
            )
            with self.assertRaises(app.AppError):
                app.desktop_command("../example.desktop")

    def test_gui_launch_does_not_create_an_extra_terminal(self):
        arguments = ["mousepad", "/workspace/example.txt"]
        self.assertEqual(
            app.launch_command({"arguments": arguments, "terminal": False}), arguments
        )
        command = app.launch_command({"arguments": ["python3", "-V"], "terminal": True})
        self.assertEqual(command[0], "/usr/bin/xterm")
        self.assertEqual(command[-3:], ["-e", "python3", "-V"])
        self.assertTrue(command[command.index("-title") + 1].isascii())
        for launch in (
            ["mousepad"],
            {"arguments": ["mousepad"], "terminal": "false"},
            {"arguments": [], "terminal": False},
        ):
            with self.assertRaises(app.AppError):
                app.launch_command(launch)

    def test_gsettings_are_memory_only_inside_sandbox(self):
        arguments = app.sandbox(17)
        index = arguments.index("GSETTINGS_BACKEND")
        self.assertEqual(
            arguments[index - 1 : index + 2],
            ["--setenv", "GSETTINGS_BACKEND", "memory"],
        )
        self.assertIn("--unshare-all", arguments)
        self.assertNotIn("--share-net", arguments)

    def test_populated_cgroup_remains_running_even_if_unit_inactive(self):
        with patch.object(
            app,
            "unit_state",
            return_value={"ActiveState": "inactive", "ControlGroup": "/fake-review"},
        ), patch.object(Path, "read_text", return_value="populated 1\nfrozen 0\n"):
            self.assertFalse(app.stopped("test.service"))

    def test_close_refuses_cleanup_until_unit_stops(self):
        self.session.unit = "active.service"
        self.session.running = True
        with patch.object(app, "environment", return_value={}), patch.object(
            app, "stopped", return_value=False
        ), patch.object(app, "command", return_value=None):
            with self.assertRaises(app.AppError):
                self.session.close()
        self.assertTrue(self.session.directory.exists())
        self.assertFalse(self.session.closed)

    def test_stop_accepts_collected_inactive_unit(self):
        self.session.unit = "ph4ntxm-app-airlock-gone.service"
        failure = subprocess.CalledProcessError(
            5, ["systemctl", "stop", self.session.unit]
        )
        with patch.object(app, "environment", return_value={}), patch.object(
            app, "stopped", return_value=True
        ), patch.object(app, "command", side_effect=failure):
            self.session.stop()
        self.assertFalse(self.session.running)


if __name__ == "__main__":
    unittest.main(verbosity=2)
