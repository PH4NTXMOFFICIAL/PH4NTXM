#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import contextlib
import importlib.machinery
import importlib.util
import io
import os
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zlib
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import airlock


def stream(pixels=b"\xff\x00\x00", width=1, height=1):
    return (
        airlock.OUTPUT_MAGIC
        + struct.pack("!III", 1, width, height)
        + pixels
        + airlock.END_MAGIC
    )


class AirlockTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def receive(self, data):
        return airlock.receive_pages(io.BytesIO(data), self.root)

    def test_pixels_round_trip(self):
        pixels = bytes(range(256)) * 3
        pages = self.receive(stream(pixels, 16, 16))
        self.assertEqual(pages[0][:2], (16, 16))
        self.assertEqual(zlib.decompress(pages[0][2].read_bytes()), pixels)

    def test_every_truncation_is_rejected(self):
        data = stream()
        for position in range(len(data)):
            with self.subTest(position=position):
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(airlock.AirlockError):
                        airlock.receive_pages(
                            io.BytesIO(data[:position]), Path(directory)
                        )

    def test_invalid_headers_and_dimensions(self):
        for count, width, height in (
            (0, 1, 1),
            (101, 1, 1),
            (1, 0, 1),
            (1, 2401, 1),
            (1, 1, 2**32 - 1),
        ):
            with self.subTest(count=count, width=width, height=height):
                data = airlock.OUTPUT_MAGIC + struct.pack("!III", count, width, height)
                with self.assertRaises(airlock.AirlockError):
                    self.receive(data)
        with self.assertRaises(airlock.AirlockError):
            self.receive(b"%PDF-1.7 malicious guest file")

    def test_trailing_data_is_rejected(self):
        with self.assertRaises(airlock.AirlockError):
            self.receive(stream() + b"unexpected")

    def test_total_pixel_limit(self):
        with mock.patch.object(airlock, "MAX_TOTAL_RGB", 2):
            with self.assertRaises(airlock.AirlockError):
                self.receive(stream())

    def test_compressed_limit(self):
        with mock.patch.object(airlock, "MAX_COMPRESSED", 1):
            with self.assertRaises(airlock.AirlockError):
                self.receive(stream())

    def test_existing_page_is_not_overwritten(self):
        target = self.root / "page-000.rgbz"
        target.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            self.receive(stream())
        self.assertEqual(target.read_bytes(), b"keep")

    def test_input_rejects_symlink_fifo_empty_and_oversize(self):
        source = self.root / "original.pdf"
        source.write_bytes(b"input")
        linked = self.root / "linked.pdf"
        linked.symlink_to(source)
        with self.assertRaises(OSError):
            airlock.read_input(linked)
        fifo = self.root / "pipe.pdf"
        os.mkfifo(fifo)
        with self.assertRaises(airlock.AirlockError):
            airlock.read_input(fifo)
        source.write_bytes(b"")
        with self.assertRaises(airlock.AirlockError):
            airlock.read_input(source)
        with source.open("wb") as handle:
            handle.truncate(airlock.MAX_INPUT + 1)
        with self.assertRaises(airlock.AirlockError):
            airlock.read_input(source)

    def test_input_is_read_as_bytes_without_document_parser(self):
        source = self.root / "document.PDF"
        source.write_bytes(b"not actually a PDF")
        self.assertEqual(airlock.read_input(source), (".pdf", b"not actually a PDF"))

    def test_export_never_overwrites_original_or_symlink(self):
        session = airlock.AirlockSession(self.root)
        try:
            session.pages = airlock.receive_pages(
                io.BytesIO(stream()), session.directory
            )
            original = self.root / "original.pdf"
            original.write_bytes(b"original")
            alias = self.root / "alias.pdf"
            alias.symlink_to(original)
            for destination in (original, alias):
                with self.assertRaises(FileExistsError):
                    session.export(destination)
            self.assertEqual(original.read_bytes(), b"original")
            target = self.root / "export.pdf"
            session.export(target)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            data = target.read_bytes()
            for token in (
                b"/JavaScript",
                b"/OpenAction",
                b"/EmbeddedFiles",
                b"/URI",
                b"/Info",
                b"/Metadata",
            ):
                self.assertNotIn(token, data)
        finally:
            directory = session.directory
            session.close()
        self.assertFalse(directory.exists())

    def test_pdf_can_be_rendered_by_independent_parser(self):
        pages = self.receive(stream())
        target = self.root / "result.pdf"
        with target.open("wb") as handle:
            airlock.write_pdf(pages, handle)
        metadata = subprocess.run(
            ["pdfinfo", str(target)], capture_output=True, check=True
        ).stdout
        self.assertIn(b"Pages:           1", metadata)
        pixels = subprocess.run(
            ["pdftoppm", "-scale-to", "1", "-singlefile", str(target)],
            capture_output=True,
            check=True,
        ).stdout
        self.assertTrue(pixels.endswith(b"\xff\x00\x00"))

    def test_command_keeps_isolation_and_has_no_tcg_fallback(self):
        command = airlock.vm_command(".pdf")
        self.assertEqual(command[command.index("-accel") + 1], "kvm")
        self.assertEqual(command[command.index("-nic") + 1], "none")
        self.assertEqual(command[command.index("-monitor") + 1], "none")
        self.assertIn("--unshare-all", command)
        self.assertIn("--cap-drop", command)
        self.assertIn(airlock.BWRAP_PATH, command)
        self.assertIn("/proc", command)
        self.assertNotIn("--proc", command)
        self.assertNotIn("/usr/bin/bwrap", command)
        self.assertNotIn("-netdev", command)
        self.assertNotIn("-virtfs", command)
        self.assertNotIn("-spice", command)
        self.assertNotIn("tcg", " ".join(command))
        self.assertLess(airlock.memory_mib(".pdf"), airlock.memory_mib(".docx"))

    def test_memory_profiles_match_the_conversion_workload(self):
        self.assertEqual(airlock.memory_mib(".jpg"), 384)
        self.assertEqual(airlock.memory_mib(".pdf"), 512)
        self.assertEqual(airlock.memory_mib(".docx"), 768)
        minimum = airlock.memory_mib(".jpg") + airlock.HOST_RESERVE_MIB
        self.assertEqual(airlock.check_memory(".jpg", minimum), 384)
        with self.assertRaisesRegex(airlock.AirlockError, "available RAM"):
            airlock.check_memory(".jpg", minimum - 1)

    def test_cancel_kills_worker_and_does_not_publish_pages(self):
        session = airlock.AirlockSession(self.root)
        timer = threading.Timer(0.2, session.cancelled.set)
        timer.start()
        start = time.monotonic()
        try:
            with self.assertRaises(airlock.AirlockError):
                session.convert(
                    ".pdf",
                    b"input",
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                )
            self.assertLess(time.monotonic() - start, 3)
            self.assertEqual(session.pages, [])
        finally:
            timer.join()
            session.close()

    def test_timeout_kills_worker(self):
        session = airlock.AirlockSession(self.root)
        try:
            with mock.patch.object(airlock, "TIMEOUT", 0.1):
                with self.assertRaisesRegex(airlock.AirlockError, "five-minute"):
                    session.convert(
                        ".pdf",
                        b"input",
                        [sys.executable, "-c", "import time; time.sleep(30)"],
                    )
        finally:
            session.close()

    def test_complete_protocol_from_failed_process_is_not_exportable(self):
        session = airlock.AirlockSession(self.root)
        code = (
            "import sys, struct; h=sys.stdin.buffer.read(28); sys.stdin.buffer.read(struct.unpack('!8sI16s', h)[1]); sys.stdout.buffer.write(%r); sys.stdout.buffer.flush(); sys.stdin.buffer.read(8); sys.exit(1)"
            % stream()
        )
        try:
            with self.assertRaises(airlock.AirlockError):
                session.convert(".pdf", b"input", [sys.executable, "-c", code])
            self.assertEqual(session.pages, [])
        finally:
            session.close()

    def test_success_does_not_signal_reaped_process(self):
        session = airlock.AirlockSession(self.root)
        code = (
            "import sys, struct; h=sys.stdin.buffer.read(28); sys.stdin.buffer.read(struct.unpack('!8sI16s', h)[1]); sys.stdout.buffer.write(%r); sys.stdout.buffer.flush(); sys.stdin.buffer.read(8)"
            % stream()
        )
        try:
            with mock.patch.object(airlock.os, "killpg", wraps=os.killpg) as kill:
                session.convert(".pdf", b"input", [sys.executable, "-c", code])
                kill.assert_not_called()
            self.assertEqual(len(session.pages), 1)
        finally:
            session.close()

    def test_input_pipe_stays_open_until_converter_exits(self):
        session = airlock.AirlockSession(self.root)
        code = (
            "import sys,struct,select; "
            "h=sys.stdin.buffer.read(28); "
            "sys.stdin.buffer.read(struct.unpack('!8sI16s',h)[1]); "
            "ready=select.select([sys.stdin],[],[],0.1)[0]; "
            "sys.exit(7) if ready else None; "
            "sys.stdout.buffer.write(%r); sys.stdout.buffer.flush(); sys.stdin.buffer.read(8)"
            % stream()
        )
        try:
            session.convert(".pdf", b"input", [sys.executable, "-c", code])
            self.assertEqual(len(session.pages), 1)
        finally:
            session.close()

    def test_only_one_conversion_per_runtime_directory(self):
        first = airlock.AirlockSession(self.root)
        second = airlock.AirlockSession(self.root)
        started = threading.Event()
        real_popen = subprocess.Popen
        errors = []

        def popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            started.set()
            return process

        def worker():
            try:
                first.convert(
                    ".pdf",
                    b"input",
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                )
            except airlock.AirlockError as error:
                errors.append(error)

        try:
            with mock.patch.object(airlock.subprocess, "Popen", popen):
                thread = threading.Thread(target=worker)
                thread.start()
                self.assertTrue(started.wait(3))
                with self.assertRaisesRegex(airlock.AirlockError, "already running"):
                    second.convert(".pdf", b"input", [sys.executable, "-c", "pass"])
                first.cancelled.set()
                thread.join(3)
                self.assertFalse(thread.is_alive())
                self.assertEqual(len(errors), 1)
        finally:
            first.cancelled.set()
            first.close()
            second.close()

    def test_failed_export_leaves_no_destination(self):
        session = airlock.AirlockSession(self.root)
        try:
            session.pages = airlock.receive_pages(
                io.BytesIO(stream()), session.directory
            )
            target = self.root / "failed.pdf"
            with mock.patch.object(
                airlock, "write_pdf", side_effect=OSError("storage full")
            ):
                with self.assertRaises(OSError):
                    session.export(target)
            self.assertFalse(target.exists())
            self.assertEqual(list(self.root.glob(".ph4ntxm-airlock-*")), [])
        finally:
            session.close()

    def test_missing_kvm_never_falls_back(self):
        with mock.patch.object(airlock.os, "geteuid", return_value=1000):
            with mock.patch.object(
                airlock.os, "access", side_effect=lambda path, mode: path != "/dev/kvm"
            ):
                with self.assertRaisesRegex(airlock.AirlockError, "KVM access"):
                    airlock.check_ready()


class LauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[3] / "bin/ph4ntxm-document-airlock"
        loader = importlib.machinery.SourceFileLoader("airlock_launcher", str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cls.launcher = importlib.util.module_from_spec(spec)
        loader.exec_module(cls.launcher)

    def test_document_opens_desktop_without_an_output_argument(self):
        document = "/tmp/document with spaces (1).pdf"
        with mock.patch.object(sys, "argv", ["airlock", "--", document]):
            with mock.patch.object(self.launcher, "desktop") as desktop:
                with mock.patch.object(self.launcher, "read_input") as read_input:
                    self.assertEqual(self.launcher.main(), 0)
        desktop.assert_called_once_with(document)
        read_input.assert_not_called()

    def test_filename_after_separator_is_not_interpreted_as_an_option(self):
        with mock.patch.object(sys, "argv", ["airlock", "--", "--check.pdf"]):
            with mock.patch.object(self.launcher, "desktop") as desktop:
                self.assertEqual(self.launcher.main(), 0)
        desktop.assert_called_once_with("--check.pdf")

    def test_menu_launch_opens_the_file_chooser(self):
        with mock.patch.object(sys, "argv", ["airlock"]):
            with mock.patch.object(self.launcher, "desktop") as desktop:
                self.assertEqual(self.launcher.main(), 0)
        desktop.assert_called_once_with(None)

    def test_explicit_output_keeps_command_line_conversion(self):
        session = mock.Mock()
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys, "argv", ["airlock", "source.pdf", "--output", "result.pdf"]
                )
            )
            read_input = stack.enter_context(
                mock.patch.object(
                    self.launcher, "read_input", return_value=(".pdf", b"document")
                )
            )
            stack.enter_context(
                mock.patch.object(
                    self.launcher, "check_ready", return_value="/run/test"
                )
            )
            stack.enter_context(
                mock.patch.object(self.launcher, "AirlockSession", return_value=session)
            )
            desktop = stack.enter_context(mock.patch.object(self.launcher, "desktop"))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.assertEqual(self.launcher.main(), 0)
        read_input.assert_called_once_with("source.pdf")
        session.convert.assert_called_once_with(".pdf", b"document")
        session.export.assert_called_once_with("result.pdf")
        session.close.assert_called_once_with()
        desktop.assert_not_called()

    def test_output_without_a_document_is_rejected(self):
        with mock.patch.object(sys, "argv", ["airlock", "--output", "result.pdf"]):
            with mock.patch.object(self.launcher, "desktop") as desktop:
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        self.launcher.main()
        self.assertEqual(error.exception.code, 2)
        desktop.assert_not_called()


if __name__ == "__main__":
    unittest.main()
