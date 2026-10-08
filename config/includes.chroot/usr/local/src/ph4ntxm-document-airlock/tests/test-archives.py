#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import fcntl
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import airlock
import archives

REAL_AVAILABLE_MEMORY = airlock.available_memory_mib
REAL_CHECK_STORAGE = archives.check_storage
MISSING = object()


def entry(name="notes.txt", size=4, kind="file", reason=""):
    return {"index": 0, "name": name, "size": size, "kind": kind, "reason": reason}


def listing(entries=None, format="ZIP"):
    return {"format": format, "entries": [entry()] if entries is None else entries}


def listing_data(value=MISSING):
    data = json.dumps(listing() if value is MISSING else value).encode("utf-8")
    return struct.pack("!I", len(data)) + data


def listing_stream(value=MISSING):
    return archives.LIST_MAGIC + listing_data(value) + archives.END_MAGIC


def data_stream(chunks=(b"text",)):
    return archives.DATA_MAGIC + b"".join(struct.pack("!I", len(chunk)) + chunk for chunk in chunks) + struct.pack("!I", 0) + archives.END_MAGIC


def command(response, exit_code=0, wait_ack=True):
    code = (
        "import struct,sys; "
        "magic,size,index=struct.unpack('!8sII',sys.stdin.buffer.read(16)); "
        "assert magic==%r; "
        "assert sys.stdin.buffer.read(size)==b'snapshot'; "
        "sys.stdout.buffer.write(%r); sys.stdout.buffer.flush(); "
        "%s"
        "sys.exit(%d)"
    ) % (archives.INPUT_MAGIC, response, "assert sys.stdin.buffer.read(8)==%r; " % archives.ACK_MAGIC if wait_ack else "", exit_code)
    return [sys.executable, "-c", code]


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sessions = []
        self.memory = mock.patch.object(airlock, "available_memory_mib", return_value=4096)
        self.storage = mock.patch.object(archives, "check_storage")
        self.memory.start()
        self.storage.start()

    def tearDown(self):
        for session in self.sessions:
            session.close()
        self.storage.stop()
        self.memory.stop()
        self.temporary.cleanup()

    def session(self, entries=None):
        session = archives.ArchiveSession(self.root)
        self.sessions.append(session)
        session.source.write_bytes(b"snapshot")
        session.source.chmod(0o600)
        session.entries = [entry()] if entries is None else entries
        return session

    def receive_listing(self, value):
        session = self.session()
        return session.receive_listing(io.BytesIO(listing_data(value)), archives.LIST_MAGIC)

    def test_snapshot_refuses_to_replace_or_remove_previous_copy(self):
        session = self.session()
        incoming = self.root / "incoming.zip"
        incoming.write_bytes(b"new archive")
        with self.assertRaises(FileExistsError):
            session.snapshot(incoming)
        self.assertEqual(session.source.read_bytes(), b"snapshot")

    def test_listing_accepts_supported_formats_and_unknown_size(self):
        for format in ("ZIP", "RAR", "7z", "TAR"):
            with self.subTest(format=format):
                value = listing([entry("folder/notes.txt", None)], format)
                self.assertEqual(self.receive_listing(value), value)
        self.assertEqual(self.receive_listing(listing([]))["entries"], [])

    def test_listing_rejects_malformed_fields(self):
        values = [None, [], {"format": "ZIP"}, listing(format="ISO"), listing(format=[]), listing(entries={}), {**listing(), "extra": True}]
        alterations = (
            {"index": True}, {"index": 1}, {"index": -1}, {"name": 1},
            {"size": True}, {"size": -1}, {"size": 2 ** 63}, {"size": "4"},
            {"kind": "symlink"}, {"kind": []}, {"reason": None},
            {"reason": "x" * 161}, {"reason": "line\nfeed"},
            {"kind": "blocked", "reason": ""},
        )
        values.extend(listing([{**entry(), **alteration}]) for alteration in alterations)
        malformed = entry()
        del malformed["reason"]
        values.extend((listing([malformed]), listing([{**entry(), "extra": 1}]), listing([[]])))
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(archives.ArchiveError):
                    self.receive_listing(value)

    def test_listing_rejects_unsafe_names_and_excess_entries(self):
        names = ("", "/absolute", "../escape", "folder/../escape", "./file", "folder//file", "C:drive.txt", "a\\b", "nul\x00.txt", "line\n.txt", "bidi\u202e.txt", "x" * 1025, "é" * 513, "\ud800")
        for name in names:
            with self.subTest(name=repr(name)):
                with self.assertRaises(archives.ArchiveError):
                    self.receive_listing(listing([entry(name)]))
        values = [{**entry(), "index": index} for index in range(archives.MAX_ENTRIES + 1)]
        with self.assertRaisesRegex(archives.ArchiveError, "entry limit"):
            self.receive_listing(listing(values))

    def test_listing_requires_bounded_complete_json(self):
        session = self.session()
        for size in (0, archives.MAX_METADATA + 1, 2 ** 32 - 1):
            with self.subTest(size=size):
                with self.assertRaises(archives.ArchiveError):
                    session.receive_listing(io.BytesIO(struct.pack("!I", size)), archives.LIST_MAGIC)
        for payload in (b"\xff", b"{broken", b"{}{}", b"true"):
            with self.subTest(payload=payload):
                with self.assertRaises(archives.ArchiveError):
                    session.receive_listing(io.BytesIO(struct.pack("!I", len(payload)) + payload), archives.LIST_MAGIC)
        data = listing_data()
        for position in range(len(data)):
            with self.subTest(position=position):
                with self.assertRaises(archives.ArchiveError):
                    session.receive_listing(io.BytesIO(data[:position]), archives.LIST_MAGIC)
        with self.assertRaises(archives.ArchiveError):
            session.receive_listing(io.BytesIO(data), archives.DATA_MAGIC)

    def test_snapshot_rejects_links_fifo_empty_and_oversize(self):
        source = self.root / "original.zip"
        source.write_bytes(b"archive")
        alias = self.root / "alias.zip"
        alias.symlink_to(source)
        fifo = self.root / "fifo.zip"
        os.mkfifo(fifo)
        for path, error in ((alias, OSError), (fifo, archives.ArchiveError)):
            session = archives.ArchiveSession(self.root)
            self.sessions.append(session)
            with self.subTest(path=path):
                with self.assertRaises(error):
                    session.snapshot(path)
                self.assertFalse(session.source.exists())
        for contents in (b"", b"12345"):
            source.write_bytes(contents)
            session = archives.ArchiveSession(self.root)
            self.sessions.append(session)
            with mock.patch.object(archives, "MAX_INPUT", 4):
                with self.assertRaises(archives.ArchiveError):
                    session.snapshot(source)
            self.assertFalse(session.source.exists())

    def test_snapshot_keeps_private_bytes_and_never_overwrites(self):
        source = self.root / "original.ZIP"
        source.write_bytes(b"original")
        session = archives.ArchiveSession(self.root)
        self.sessions.append(session)
        session.snapshot(source)
        self.assertEqual(session.source.read_bytes(), b"original")
        self.assertEqual(stat.S_IMODE(session.source.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(session.directory.stat().st_mode), 0o700)
        source.write_bytes(b"changed")
        with self.assertRaises(FileExistsError):
            session.snapshot(source)
        self.assertEqual(source.read_bytes(), b"changed")
        directory = session.directory
        session.close()
        session.close()
        self.assertFalse(directory.exists())

    def test_snapshot_change_and_cancellation_leave_no_copy(self):
        source = self.root / "input.zip"
        source.write_bytes(b"input")
        real_fstat = os.fstat
        for first_size, change_time in ((4, False), (6, False), (5, True)):
            session = archives.ArchiveSession(self.root)
            self.sessions.append(session)
            calls = 0

            def fstat(descriptor):
                nonlocal calls
                metadata = real_fstat(descriptor)
                calls += 1
                return SimpleNamespace(
                    st_mode=metadata.st_mode,
                    st_size=first_size if calls == 1 else metadata.st_size,
                    st_mtime_ns=metadata.st_mtime_ns + int(change_time and calls > 1),
                    st_ctime_ns=metadata.st_ctime_ns,
                )

            with self.subTest(first_size=first_size, change_time=change_time):
                with mock.patch.object(archives.os, "fstat", side_effect=fstat):
                    with self.assertRaisesRegex(archives.ArchiveError, "changed"):
                        session.snapshot(source)
                self.assertFalse(session.source.exists())
        session = archives.ArchiveSession(self.root)
        self.sessions.append(session)
        session.cancelled.set()
        with self.assertRaisesRegex(archives.ArchiveError, "cancelled"):
            session.snapshot(source)
        self.assertFalse(session.source.exists())

    def test_ram_guards_read_actual_memory_and_reject_inventory_environment(self):
        with mock.patch.object(airlock, "available_memory_mib", REAL_AVAILABLE_MEMORY):
            with mock.patch.dict(os.environ, {"PH4_REPORTED_RAM": "64", "PH4_USABLE_RAM_BYTES": str(64 * 1024 ** 3)}, clear=True):
                with mock.patch.object(airlock.Path, "read_text", return_value="MemTotal: 999999999 kB\nMemAvailable: 126976 kB\n") as read:
                    self.assertEqual(archives.available_memory_mib(), 124)
                    read.assert_called_once_with(encoding="ascii")
            with mock.patch.dict(os.environ, {"PH4_INVENTORY_MEMINFO": "persona"}, clear=True):
                with mock.patch.object(airlock.Path, "read_text") as read:
                    with self.assertRaisesRegex(archives.ArchiveError, "Actual available RAM"):
                        archives.available_memory_mib()
                    read.assert_not_called()
        minimum = archives.GUEST_RAM_MIB + archives.QEMU_RESERVE_MIB + archives.RESERVE_MIB + 1
        with mock.patch.object(airlock, "available_memory_mib", return_value=minimum):
            archives.check_memory(1)
        with mock.patch.object(airlock, "available_memory_mib", return_value=minimum - 1):
            with self.assertRaisesRegex(archives.ArchiveError, "available RAM"):
                archives.check_memory(1)

    def test_storage_guard_keeps_ram_workspace_reserve(self):
        needed = 5 + 16 * 1024 ** 2
        for available, allowed in ((needed, True), (needed - 1, False)):
            with self.subTest(available=available):
                with mock.patch.object(archives.os, "statvfs", return_value=SimpleNamespace(f_bavail=available, f_frsize=1)):
                    if allowed:
                        REAL_CHECK_STORAGE(self.root, 5)
                    else:
                        with self.assertRaisesRegex(archives.ArchiveError, "space"):
                            REAL_CHECK_STORAGE(self.root, 5)

    def test_ready_preserves_runtime_failure_and_checks_resource_guards(self):
        with mock.patch.object(airlock, "check_ready", side_effect=airlock.AirlockError("Document Airlock KVM unavailable")):
            with self.assertRaisesRegex(archives.ArchiveError, "Archive Airlock KVM unavailable"):
                archives.check_ready()
        with mock.patch.object(airlock, "check_ready", return_value=self.root) as ready:
            self.assertEqual(archives.check_ready(), self.root)
            ready.assert_called_once_with(".pdf")
        with mock.patch.object(airlock, "check_ready", return_value=self.root):
            with mock.patch.object(airlock, "available_memory_mib", return_value=1):
                with self.assertRaises(archives.ArchiveError):
                    archives.check_ready()

    def test_successful_protocol_waits_for_ack_and_reaps_process(self):
        session = self.session()
        real_popen = subprocess.Popen
        processes = []

        def popen(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process

        with mock.patch.object(archives.subprocess, "Popen", side_effect=popen):
            with mock.patch.object(archives.os, "killpg", wraps=os.killpg) as kill:
                result = session.request(archives.LIST_INDEX, session.receive_listing, archives.MAX_METADATA, command(listing_stream()))
                kill.assert_not_called()
        self.assertEqual(result, listing())
        self.assertEqual(processes[0].returncode, 0)
        self.assertTrue(processes[0].stdin.closed)
        self.assertTrue(processes[0].stdout.closed)

    def test_chunks_are_bounded_by_actual_size_and_listed_size(self):
        body = b"a" * archives.CHUNK_SIZE + b"b"
        session = self.session([entry(size=len(body))])
        output = session.extract(0, command(data_stream((body[:-1], body[-1:]))))
        self.assertEqual(output.read_bytes(), body)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        output_parent = output.parent
        session.clear_view()
        self.assertFalse(output_parent.exists())
        cases = (
            ([entry(size=1)], data_stream((b"12",))),
            ([entry(size=5)], data_stream((b"1234",))),
            ([entry(size=None)], archives.DATA_MAGIC + struct.pack("!I", archives.CHUNK_SIZE + 1)),
            ([entry(size=None)], data_stream(())),
        )
        for entries, response in cases:
            with self.subTest(entries=entries, response_size=len(response)):
                session = self.session(entries)
                with self.assertRaises(archives.ArchiveError):
                    session.extract(0, command(response))
                self.assertIsNone(session.view)
                self.assertEqual(list(session.directory.glob("view-*")), [])

    def test_unknown_listed_size_cannot_bypass_viewer_limit(self):
        session = self.session([entry(size=None)])
        with mock.patch.object(archives, "TEXT_LIMIT", 3):
            with self.assertRaisesRegex(archives.ArchiveError, "size limit"):
                session.extract(0, command(data_stream()))
        self.assertIsNone(session.view)

    def test_selection_policy_rejects_non_files_and_unsupported_or_oversize_files(self):
        session = self.session()
        for index in (None, True, -1, 1):
            with self.subTest(index=index):
                with self.assertRaises(archives.ArchiveError):
                    session.selected_entry(index)
        values = (
            entry("folder/", 0, "directory"),
            entry("link.txt", 4, "blocked", "Symbolic link"),
            entry("run.exe", 4),
            entry(size=0),
            entry(size=archives.TEXT_LIMIT + 1),
            entry("report.pdf", airlock.MAX_INPUT + 1),
        )
        for value in values:
            with self.subTest(entry=value):
                session = self.session([value])
                with mock.patch.object(archives.subprocess, "Popen", side_effect=AssertionError("A blocked entry started a reader")) as popen:
                    with self.assertRaises(archives.ArchiveError):
                        session.extract(0)
                    popen.assert_not_called()
                self.assertIsNone(session.view)

    def test_truncated_wrong_ending_trailing_and_failed_process_are_rejected(self):
        response = data_stream()
        cases = [response[:position] for position in (0, 7, 10, 14, len(response) - 1)]
        cases.extend((archives.LIST_MAGIC + response[8:], response[:-8] + b"WRONGEND", response + b"trailing"))
        for data in cases:
            with self.subTest(data=data):
                session = self.session()
                with self.assertRaises(archives.ArchiveError):
                    session.extract(0, command(data, wait_ack=False))
                self.assertIsNone(session.view)
        session = self.session()
        with self.assertRaises(archives.ArchiveError):
            session.extract(0, command(response, 1))
        self.assertIsNone(session.view)

    def test_isolated_error_response_is_strict_and_never_opens_a_view(self):
        payload = json.dumps({"error": "Archive is encrypted"}).encode()
        response = archives.ERROR_MAGIC + struct.pack("!I", len(payload)) + payload + archives.END_MAGIC
        session = self.session()
        with self.assertRaisesRegex(archives.ArchiveError, "encrypted"):
            session.extract(0, command(response))
        self.assertIsNone(session.view)
        for payload in (b"{}", b'{"error":1}', b'{"error":"bad\\nerror"}', b'{"error":"safe","extra":1}'):
            session = self.session()
            response = archives.ERROR_MAGIC + struct.pack("!I", len(payload)) + payload + archives.END_MAGIC
            with self.assertRaises(archives.ArchiveError):
                session.extract(0, command(response))

    def stopped_request(self, mode):
        session = self.session()
        processes = []
        real_popen = subprocess.Popen
        started = threading.Event()
        timer = None

        def popen(*args, **kwargs):
            nonlocal timer
            process = real_popen(*args, **kwargs)
            processes.append(process)
            started.set()
            if mode == "cancel":
                timer = threading.Timer(0.25, session.cancelled.set)
                timer.start()
            return process

        memory_calls = 0

        def available():
            nonlocal memory_calls
            memory_calls += 1
            if memory_calls == 1:
                return 4096
            if mode == "unverified":
                raise airlock.AirlockError("Unverified memory")
            return 1 if mode == "ram" else 4096

        start = time.monotonic()
        timeout = 0.3 if mode == "timeout" else 5
        try:
            with mock.patch.object(archives.subprocess, "Popen", side_effect=popen):
                with mock.patch.object(archives, "TIMEOUT", timeout):
                    with mock.patch.object(airlock, "available_memory_mib", side_effect=available):
                        with self.assertRaises(archives.ArchiveError) as caught:
                            session.request(archives.LIST_INDEX, session.receive_listing, 1, [sys.executable, "-c", "import time; time.sleep(30)"])
            self.assertTrue(started.is_set())
            self.assertLess(time.monotonic() - start, 4)
            self.assertIsNotNone(processes[0].returncode)
            self.assertTrue(processes[0].stdin.closed)
            self.assertTrue(processes[0].stdout.closed)
            return str(caught.exception)
        finally:
            if timer:
                timer.join()
            if processes and processes[0].poll() is None:
                processes[0].kill()
                processes[0].wait()

    def test_cancellation_timeout_and_live_ram_guards_kill_and_reap(self):
        for mode, message in (("cancel", "cancelled"), ("timeout", "time limit"), ("ram", "RAM became too low"), ("unverified", "could not be verified")):
            with self.subTest(mode=mode):
                self.assertIn(message, self.stopped_request(mode))

    def test_runtime_lock_is_shared_with_document_airlock_and_released(self):
        session = self.session()
        lock_path = self.root / "ph4ntxm-airlock.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with mock.patch.object(archives.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(archives.ArchiveError, "already running"):
                    session.request(archives.LIST_INDEX, session.receive_listing, 1, command(listing_stream()))
                popen.assert_not_called()
        self.assertEqual(session.request(archives.LIST_INDEX, session.receive_listing, 1, command(listing_stream())), listing())

    def test_untrusted_lock_or_snapshot_cannot_start_a_reader(self):
        session = self.session()
        lock_path = self.root / "ph4ntxm-airlock.lock"
        lock_path.write_bytes(b"")
        lock_path.chmod(0o644)
        with mock.patch.object(archives.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(archives.ArchiveError, "lock is not trusted"):
                session.request(archives.LIST_INDEX, session.receive_listing, 1, command(listing_stream()))
            popen.assert_not_called()
        lock_path.chmod(0o600)
        session.source.chmod(0o644)
        with mock.patch.object(archives.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(archives.ArchiveError, "copy is not trusted"):
                session.request(archives.LIST_INDEX, session.receive_listing, 1, command(listing_stream()))
            popen.assert_not_called()

    def test_text_preview_rejects_binary_and_invalid_utf8_and_cleans_view(self):
        for data, allowed in ((b"\xef\xbb\xbfhello", True), (b"binary\x00data", False), (b"\xff", False)):
            session = self.session([entry(size=len(data))])
            output = session.directory / "preview.txt"
            output.write_bytes(data)
            with mock.patch.object(session, "extract", return_value=output):
                with mock.patch.object(session, "clear_view") as clear:
                    if allowed:
                        self.assertEqual(session.read_text_entry(0), "hello")
                    else:
                        with self.assertRaises(archives.ArchiveError):
                            session.read_text_entry(0)
                    clear.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
