# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import fcntl
import json
import os
from pathlib import Path, PurePosixPath
import signal
import stat
import struct
import subprocess
import tempfile
import threading
import time

import airlock
from archive_protocol import (
    ACK_MAGIC, ARCHIVE_SUFFIXES, CHUNK_SIZE, DATA_MAGIC,
    END_MAGIC, ERROR_MAGIC, GUEST_RAM_MIB, INPUT_MAGIC, LIST_INDEX, LIST_MAGIC,
    MAX_ENTRIES, MAX_INPUT, MAX_METADATA, MAX_OUTPUT, TIMEOUT,
    safe_name, viewer_kind,
)

RESERVE_MIB = 192
QEMU_RESERVE_MIB = 96
TEXT_LIMIT = 1024 * 1024


class ArchiveError(Exception):
    pass


def read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(min(size - len(data), CHUNK_SIZE))
        if not chunk:
            raise ArchiveError("The isolated reader returned incomplete data.")
        data.extend(chunk)
    return bytes(data)


def available_memory_mib():
    try:
        return airlock.available_memory_mib()
    except (airlock.AirlockError, ValueError, OSError) as exc:
        raise ArchiveError("Actual available RAM could not be verified. Open Archive Airlock from the desktop.") from exc


def check_memory(extra=0):
    required = GUEST_RAM_MIB + QEMU_RESERVE_MIB + RESERVE_MIB + (extra + 1024 * 1024 - 1) // (1024 * 1024)
    if available_memory_mib() < required:
        raise ArchiveError("Not enough available RAM. Close other applications and try again.")


def check_storage(directory, extra):
    space = os.statvfs(directory)
    if space.f_bavail * space.f_frsize < extra + 16 * 1024 * 1024:
        raise ArchiveError("Not enough space in the private RAM workspace.")


def check_ready():
    try:
        runtime = airlock.check_ready(".pdf")
    except (airlock.AirlockError, OSError, ValueError, subprocess.SubprocessError) as exc:
        raise ArchiveError(str(exc).replace("Document Airlock", "Archive Airlock").replace("Conversion", "Archive inspection")) from exc
    check_memory(MAX_METADATA)
    check_storage(runtime, MAX_METADATA)
    return runtime


def validate_listing(value):
    if not isinstance(value, dict) or set(value) != {"format", "entries"}:
        raise ArchiveError("The isolated reader returned invalid archive contents.")
    if value["format"] not in {"ZIP", "RAR", "7z", "TAR"}:
        raise ArchiveError("This archive format is not supported.")
    entries = value["entries"]
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ArchiveError("The archive exceeds the entry limit.")
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {"index", "name", "size", "kind", "reason"}:
            raise ArchiveError("The isolated reader returned invalid file metadata.")
        if type(entry["index"]) is not int or entry["index"] != index:
            raise ArchiveError("The isolated reader returned invalid entry numbers.")
        if entry["kind"] not in {"file", "directory", "blocked"}:
            raise ArchiveError("The isolated reader returned an invalid entry type.")
        if not isinstance(entry["name"], str) or not safe_name(entry["name"]):
            raise ArchiveError("The isolated reader returned an unsafe filename.")
        if entry["size"] is not None and (type(entry["size"]) is not int or not 0 <= entry["size"] < 2 ** 63):
            raise ArchiveError("The isolated reader returned an invalid file size.")
        if not isinstance(entry["reason"], str) or len(entry["reason"]) > 160 or (entry["reason"] and not safe_name(entry["reason"])):
            raise ArchiveError("The isolated reader returned invalid entry details.")
        if entry["kind"] == "blocked" and not entry["reason"]:
            raise ArchiveError("The isolated reader returned incomplete entry details.")
    return value


def viewer_limit(name):
    kind = viewer_kind(name)
    if kind == "document":
        return airlock.MAX_INPUT
    if kind == "text":
        return TEXT_LIMIT
    return MAX_OUTPUT


class ArchiveSession:
    def __init__(self, runtime):
        self.temporary = tempfile.TemporaryDirectory(prefix="ph4ntxm-archive-", dir=runtime)
        self.directory = Path(self.temporary.name)
        self.source = self.directory / "source"
        self.entries = []
        self.cancelled = threading.Event()
        self.view = None

    def close(self):
        self.cancelled.set()
        self.clear_view()
        self.temporary.cleanup()

    def clear_view(self):
        if self.view is not None:
            self.view.cleanup()
            self.view = None

    def snapshot(self, filename):
        if not str(filename).lower().endswith(ARCHIVE_SUFFIXES):
            raise ArchiveError("Choose a ZIP, RAR, 7z or TAR archive.")
        descriptor = os.open(filename, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        created = False
        try:
            with os.fdopen(descriptor, "rb") as source:
                before = os.fstat(source.fileno())
                if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_INPUT:
                    raise ArchiveError("Choose a non-empty regular archive no larger than 128 MiB.")
                if available_memory_mib() < RESERVE_MIB + (before.st_size // (1024 * 1024)) + 1:
                    raise ArchiveError("Not enough available RAM to copy this archive.")
                check_storage(self.directory, before.st_size + MAX_METADATA)
                total = 0
                output = os.open(self.source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                created = True
                with os.fdopen(output, "wb") as destination:
                    while True:
                        if self.cancelled.is_set():
                            raise ArchiveError("Archive inspection cancelled.")
                        chunk = source.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > before.st_size or total > MAX_INPUT:
                            raise ArchiveError("The archive changed while it was being copied.")
                        if total % (1024 * 1024) == 0 and available_memory_mib() < RESERVE_MIB:
                            raise ArchiveError("Not enough available RAM to copy this archive.")
                        destination.write(chunk)
                    after = os.fstat(source.fileno())
                    if total != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        raise ArchiveError("The archive changed while it was being copied.")
        except BaseException:
            if created:
                self.source.unlink(missing_ok=True)
            raise

    def inspect(self, filename, command=None):
        self.snapshot(filename)
        result = self.request(LIST_INDEX, self.receive_listing, MAX_METADATA, command)
        self.entries = result["entries"]
        return result

    def receive_listing(self, stream, magic):
        if magic != LIST_MAGIC:
            raise ArchiveError("The isolated reader returned an invalid contents response.")
        size = struct.unpack("!I", read_exact(stream, 4))[0]
        if not 0 < size <= MAX_METADATA:
            raise ArchiveError("The archive contents exceed the metadata limit.")
        try:
            return validate_listing(json.loads(read_exact(stream, size).decode("utf-8")))
        except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
            raise ArchiveError("The isolated reader returned invalid archive contents.") from exc

    def selected_entry(self, index):
        if type(index) is not int or not 0 <= index < len(self.entries):
            raise ArchiveError("Select a file from the archive first.")
        entry = self.entries[index]
        if entry["kind"] != "file" or not safe_name(entry["name"]):
            raise ArchiveError("This entry cannot be opened.")
        if viewer_kind(entry["name"]) is None:
            raise ArchiveError("This file type has no isolated viewer.")
        if entry["size"] == 0 or (entry["size"] is not None and entry["size"] > viewer_limit(entry["name"])):
            raise ArchiveError("This file is empty or exceeds its viewer's size limit.")
        return entry

    def extract(self, index, command=None):
        entry = self.selected_entry(index)
        limit = viewer_limit(entry["name"])
        if entry["size"] is not None:
            limit = min(limit, entry["size"])
        self.clear_view()
        self.view = tempfile.TemporaryDirectory(prefix="view-", dir=self.directory)
        output = Path(self.view.name) / ("selected" + PurePosixPath(entry["name"]).suffix.lower())

        def receive(stream, magic):
            if magic != DATA_MAGIC:
                raise ArchiveError("The isolated reader returned an invalid file response.")
            total = 0
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                while True:
                    size = struct.unpack("!I", read_exact(stream, 4))[0]
                    if size == 0:
                        break
                    total += size
                    if size > CHUNK_SIZE or total > limit:
                        raise ArchiveError("The extracted file exceeds its viewer's size limit.")
                    if self.cancelled.is_set():
                        raise ArchiveError("Opening the archive file was cancelled.")
                    handle.write(read_exact(stream, size))
                if total == 0 or (entry["size"] is not None and total != entry["size"]):
                    raise ArchiveError("The extracted file does not match its listed size.")
            return output

        try:
            return self.request(index, receive, limit, command)
        except BaseException:
            self.clear_view()
            raise

    def request(self, index, receive, output_limit, command=None):
        if self.cancelled.is_set():
            raise ArchiveError("Archive operation cancelled.")
        check_memory(output_limit)
        check_storage(self.directory, output_limit)
        lock_path = self.directory.parent / "ph4ntxm-airlock.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, "wb") as lock:
            metadata = os.fstat(lock.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                raise ArchiveError("The Airlock session lock is not trusted.")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ArchiveError("Another Airlock operation is already running.") from None
            return self.exchange(index, receive, command)

    def exchange(self, index, receive, command):
        source_fd = os.open(self.source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(source_fd, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077 or not 0 < metadata.st_size <= MAX_INPUT:
                raise ArchiveError("The private archive copy is not trusted.")
            return self.run_process(index, receive, command, source, metadata.st_size)

    def run_process(self, index, receive, command, source, size):
        if command is None:
            command = airlock.vm_command(".pdf", GUEST_RAM_MIB)
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        done = threading.Event()
        sent = threading.Event()
        failure = []

        def stop():
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        def watch():
            deadline = time.monotonic() + TIMEOUT
            while not done.wait(0.2):
                if self.cancelled.is_set():
                    failure.append("Archive operation cancelled.")
                    stop()
                    return
                if time.monotonic() >= deadline:
                    failure.append("The archive exceeded the three-minute time limit.")
                    stop()
                    return
                try:
                    if available_memory_mib() < RESERVE_MIB:
                        failure.append("Available RAM became too low. The isolated reader was stopped.")
                        stop()
                        return
                except ArchiveError:
                    failure.append("Actual available RAM could not be verified.")
                    stop()
                    return

        def send():
            try:
                process.stdin.write(struct.pack("!8sII", INPUT_MAGIC, size, index))
                remaining = size
                while remaining:
                    chunk = source.read(min(remaining, CHUNK_SIZE))
                    if not chunk:
                        break
                    process.stdin.write(chunk)
                    remaining -= len(chunk)
                process.stdin.flush()
                if not remaining:
                    sent.set()
            except (BrokenPipeError, OSError):
                pass
            finally:
                done.wait()
                try:
                    process.stdin.close()
                except OSError:
                    pass

        watcher = threading.Thread(target=watch, daemon=True)
        sender = threading.Thread(target=send, daemon=True)
        watcher.start()
        sender.start()
        try:
            magic = read_exact(process.stdout, 8)
            if magic == ERROR_MAGIC:
                length = struct.unpack("!I", read_exact(process.stdout, 4))[0]
                if not 0 < length <= 4096:
                    raise ArchiveError("The isolated reader returned an invalid error response.")
                error = json.loads(read_exact(process.stdout, length).decode("utf-8"))
                if not isinstance(error, dict) or set(error) != {"error"} or not isinstance(error["error"], str) or not safe_name(error["error"]):
                    raise ArchiveError("The isolated reader could not inspect this archive.")
                if read_exact(process.stdout, 8) != END_MAGIC:
                    raise ArchiveError("The isolated reader returned an invalid stream ending.")
                raise ArchiveError(error["error"])
            result = receive(process.stdout, magic)
            if read_exact(process.stdout, 8) != END_MAGIC:
                raise ArchiveError("The isolated reader returned an invalid stream ending.")
            if not sent.wait(5):
                raise ArchiveError("The archive could not be delivered to the isolated reader.")
            process.stdin.write(ACK_MAGIC)
            process.stdin.flush()
            if process.stdout.read(1):
                raise ArchiveError("The isolated reader returned unexpected trailing data.")
            process.wait(timeout=5)
            if failure or process.returncode != 0 or self.cancelled.is_set():
                raise ArchiveError(failure[0] if failure else "The isolated archive reader stopped unexpectedly.")
            return result
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, ArchiveError) as exc:
            if failure:
                raise ArchiveError(failure[0]) from None
            if isinstance(exc, ArchiveError):
                raise
            raise ArchiveError("The archive could not be read. It may be damaged, encrypted, unsupported or exceed the resource limits.") from exc
        finally:
            done.set()
            watcher.join()
            if process.poll() is None:
                stop()
            process.wait()
            sender.join()
            process.stdout.close()

    def read_text_entry(self, index):
        entry = self.selected_entry(index)
        if viewer_kind(entry["name"]) != "text":
            raise ArchiveError("Select a plain text file.")
        try:
            path = self.extract(index)
            if self.cancelled.is_set():
                raise ArchiveError("Opening the archive file was cancelled.")
            data = path.read_bytes()
            if len(data) > TEXT_LIMIT or b"\x00" in data:
                raise ArchiveError("This is not a supported plain text file.")
            try:
                return data.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ArchiveError("Text preview supports UTF-8 files.") from exc
        finally:
            self.clear_view()

    def open_entry(self, index):
        entry = self.selected_entry(index)
        kind = viewer_kind(entry["name"])
        if kind == "text":
            raise ArchiveError("Use the text preview for this file.")
        try:
            path = self.extract(index)
            if self.cancelled.is_set():
                raise ArchiveError("Opening the archive file was cancelled.")
            if kind == "document":
                command = ["/usr/local/bin/ph4ntxm-document-airlock", "--", str(path)]
            else:
                command = ["/usr/local/bin/ph4ntxm-media", "--kind", "image" if kind == "image" else "video", "--airlock-input", "--", str(path)]
            process = subprocess.Popen(command, start_new_session=True)
            try:
                while process.poll() is None:
                    if self.cancelled.wait(0.2):
                        process.terminate()
                        try:
                            process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                        raise ArchiveError("Opening the archive file was cancelled.")
                if process.returncode:
                    raise ArchiveError("The isolated viewer could not open this file.")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        finally:
            self.clear_view()
