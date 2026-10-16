# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import ctypes
import errno
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import uuid

sys.path.insert(0, "/usr/local/lib/ph4ntxm-document-airlock")
import airlock
import archives
from archive_protocol import viewer_kind
from cleaner_protocol import (
    FORMATS,
    MAX_INPUT,
    MAX_OUTPUT,
    MAX_MEMORY,
    MAX_REPORT,
    suffix_for,
    validate_report,
)

BWRAP = "/usr/local/libexec/ph4ntxm-document-airlock/bwrap"
FILTER = "/usr/local/libexec/ph4ntxm-media/filter"
RUNTIME = "/usr/local/lib/ph4ntxm-metadata-cleaner"
MAX_FILES = 32
MAX_TOTAL = 128 * 1024 * 1024
RESERVE = 192 * 1024 * 1024
CHUNK_SIZE = 64 * 1024


class CleanerError(Exception):
    pass


def user_environment(runtime):
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "XDG_RUNTIME_DIR": str(runtime),
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + str(Path(runtime) / "bus"),
    }


def storage_directory():
    directory = Path("/tmp")
    try:
        info = directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o1777
        ):
            raise CleanerError("A root-owned sticky temporary directory is required.")
        result = subprocess.run(
            ["/usr/bin/findmnt", "-n", "-o", "FSTYPE", "-T", str(directory)],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CleanerError("The private RAM storage could not be verified.") from error
    if result.stdout.strip() != "tmpfs":
        raise CleanerError("Metadata Cleaner temporary storage must reside in RAM.")
    return directory


def check_budget(directory, storage=0, working=False):
    if len(Path("/proc/swaps").read_text(encoding="ascii").splitlines()) > 1:
        raise CleanerError("Disable swap before using Metadata Cleaner.")
    available = airlock.available_memory_mib() * 1024 * 1024
    required = RESERVE + (MAX_MEMORY if working else storage)
    if available < required:
        raise CleanerError(
            "Not enough available RAM: %d MiB required, %d MiB available. Close other applications and retry."
            % ((required + 1048575) // 1048576, available // 1048576)
        )
    space = os.statvfs(directory)
    available = space.f_bavail * space.f_frsize
    required = (max(storage, MAX_MEMORY) if working else storage) + 16 * 1024 * 1024
    if available < required:
        raise CleanerError(
            "Not enough space in the private RAM workspace: %d MiB required, %d MiB available."
            % ((required + 1048575) // 1048576, available // 1048576)
        )


def check_components():
    for value in (
        BWRAP,
        FILTER,
        RUNTIME + "/worker.py",
        RUNTIME + "/cleaner_protocol.py",
        "/usr/bin/systemd-run",
        "/usr/bin/systemctl",
        "/usr/bin/exiftool",
        "/usr/bin/ffmpeg",
    ):
        path = Path(value)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise CleanerError("A trusted metadata runtime component is unavailable.")
        if not value.endswith(".py") and not os.access(path, os.X_OK):
            raise CleanerError(
                "A required metadata runtime component is not executable."
            )


def check_ready():
    try:
        if os.geteuid() == 0:
            raise CleanerError("Run Metadata Cleaner from the normal desktop account.")
        runtime = airlock.runtime_directory()
        check_components()
        result = subprocess.run(
            ["/usr/bin/systemctl", "--user", "show-environment"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            env=user_environment(runtime),
        )
        if result.returncode:
            raise CleanerError("A running desktop user service manager is required.")
        check_budget(storage_directory())
        return runtime
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
        airlock.AirlockError,
    ) as error:
        raise CleanerError(
            str(error)
            .replace("Document Airlock", "Metadata Cleaner")
            .replace("Airlock", "Metadata Cleaner")
        ) from None


def sandbox(source, workspace, suffix, operation):
    args = [
        BWRAP,
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--hostname",
        "metadata-cleaner",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--dir",
        "/proc",
        "--dir",
        "/proc/self",
        "--ro-bind",
        "/proc/self/cgroup",
        "/proc/self/cgroup",
        "--ro-bind",
        "/sys/fs/cgroup",
        "/sys/fs/cgroup",
        "--dev",
        "/dev",
        "--size",
        str(MAX_OUTPUT),
        "--tmpfs",
        "/tmp",
        "--dir",
        "/tmp/home",
        "--setenv",
        "HOME",
        "/tmp/home",
        "--setenv",
        "XDG_CACHE_HOME",
        "/tmp/home/cache",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--dir",
        "/input",
        "--ro-bind",
        str(source),
        "/input/source" + suffix,
        "--bind",
        str(workspace),
        "/work",
        "--chdir",
        "/work",
    ]
    for path in (
        "/etc/mime.types",
        "/etc/ld.so.cache",
        "/etc/alternatives",
        "/etc/fonts",
        "/var/cache/fontconfig",
    ):
        if Path(path).exists():
            args.extend(["--ro-bind", path, path])
    args.extend(["/usr/bin/python3", "-I", RUNTIME + "/worker.py", operation, suffix])
    return args


class CleanerPreview(archives.ArchiveSession):
    def __init__(self, runtime, source, name, copy_file):
        super().__init__(runtime)
        self.original = source
        self.copy_file = copy_file
        self.entries = [{"name": name, "kind": "file", "size": source.stat().st_size}]

    def extract(self, index, command=None):
        entry = self.selected_entry(index)
        self.clear_view()
        self.view = tempfile.TemporaryDirectory(prefix="view-", dir=self.directory)
        output = Path(self.view.name) / (
            "selected" + Path(entry["name"]).suffix.lower()
        )
        self.copy_file(self.original, output, MAX_OUTPUT)
        return output


class CleanerSession:
    def __init__(self, runtime):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="ph4ntxm-metadata-", dir=storage_directory()
        )
        self.directory = Path(self.temporary.name)
        self.runtime = runtime
        self.environment = user_environment(runtime)
        self.items = []
        self.cancelled = threading.Event()
        self.closed = False
        self.cleanup_pending = False
        self.unit = None
        self.process = None
        self.preview = None
        self.mutex = threading.Lock()

    def ensure_open(self):
        if self.closed or self.cleanup_pending or self.cancelled.is_set():
            raise CleanerError("Metadata operation cancelled.")

    def copy_file(self, source, destination, limit):
        self.ensure_open()
        descriptor = os.open(
            source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        )
        created = False
        try:
            with os.fdopen(descriptor, "rb") as incoming:
                before = os.fstat(incoming.fileno())
                if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
                    raise CleanerError(
                        "Select nonempty regular files within the size limit."
                    )
                check_budget(Path(destination).parent, before.st_size)
                output = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                created = True
                total = 0
                with os.fdopen(output, "wb") as outgoing:
                    while True:
                        self.ensure_open()
                        block = incoming.read(CHUNK_SIZE)
                        if not block:
                            break
                        total += len(block)
                        if total > before.st_size:
                            raise CleanerError(
                                "The file changed while it was being copied."
                            )
                        outgoing.write(block)
                    after = os.fstat(incoming.fileno())
                    if total != before.st_size or (
                        before.st_size,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                    ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        raise CleanerError(
                            "The file changed while it was being copied."
                        )
                return total
        except BaseException:
            if created:
                Path(destination).unlink(missing_ok=True)
            raise

    def add_files(self, paths):
        self.ensure_open()
        if not paths or len(self.items) + len(paths) > MAX_FILES:
            raise CleanerError("Select up to 32 files per session.")
        total = sum(item["size"] for item in self.items)
        added = []
        try:
            for value in paths:
                name = Path(value).name
                if len(os.fsencode(name)) > 255 or any(
                    unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in name
                ):
                    raise CleanerError(
                        "Choose files without control characters in their filenames."
                    )
                suffix = suffix_for(name)
                identifier = uuid.uuid4().hex
                source = self.directory / identifier
                size = self.copy_file(value, source, min(MAX_INPUT, MAX_TOTAL - total))
                added.append(
                    {
                        "id": identifier,
                        "name": name,
                        "suffix": suffix,
                        "size": size,
                        "source": source,
                        "result": None,
                        "report": None,
                    }
                )
                total += size
        except BaseException:
            for item in added:
                item["source"].unlink(missing_ok=True)
            raise
        self.items.extend(added)

    def selected(self, identifier):
        self.ensure_open()
        for item in self.items:
            if item["id"] == identifier:
                return item
        raise CleanerError("Select a file from the current session.")

    def remove(self, identifier):
        item = self.selected(identifier)
        item["source"].unlink()
        if item["result"]:
            item["result"].unlink(missing_ok=True)
        self.items.remove(item)

    def stop_unit(self):
        if self.unit is None:
            return
        try:
            result = subprocess.run(
                ["/usr/bin/systemctl", "--user", "stop", self.unit],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=8,
                env=self.environment,
            )
            status = subprocess.run(
                [
                    "/usr/bin/systemctl",
                    "--user",
                    "show",
                    "--property=ActiveState",
                    "--value",
                    self.unit,
                ],
                capture_output=True,
                text=True,
                timeout=5,
                env=self.environment,
            )
            if status.returncode == 0 and status.stdout.strip() not in {
                "inactive",
                "failed",
                "",
            }:
                raise CleanerError(
                    "The metadata worker could not be stopped. Close Metadata Cleaner and retry cleanup."
                )
            if status.returncode and result.returncode:
                error = status.stderr.strip()
                if "not found" not in error and "could not be found" not in error:
                    raise CleanerError(
                        "The metadata worker state could not be verified."
                    )
        except (OSError, subprocess.SubprocessError) as error:
            raise CleanerError("The metadata worker could not be stopped.") from error

    def finish_process(self):
        process = self.process
        self.stop_unit()
        if process is not None and process.poll() is None:
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
        self.stop_unit()
        self.unit = None
        with self.mutex:
            self.process = None
        if process is not None:
            for stream in (process.stdin, process.stdout):
                if stream is not None and not stream.closed:
                    stream.close()

    def publish(self, source, destination):
        parent = os.open(
            destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        name = ".ph4ntxm-cleaned-" + uuid.uuid4().hex
        created = False
        published = False
        try:
            if os.path.lexists(destination):
                raise CleanerError(
                    "The destination already exists. Choose a new filename."
                )
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent,
            )
            created = True
            with (
                os.fdopen(descriptor, "wb") as outgoing,
                open(source, "rb") as incoming,
            ):
                while True:
                    self.ensure_open()
                    block = incoming.read(CHUNK_SIZE)
                    if not block:
                        break
                    outgoing.write(block)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            self.ensure_open()
            library = ctypes.CDLL(None, use_errno=True)
            rename = library.renameat2
            rename.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            rename.restype = ctypes.c_int
            if rename(
                parent, os.fsencode(name), parent, os.fsencode(destination.name), 1
            ):
                value = ctypes.get_errno()
                if value == errno.EEXIST:
                    raise CleanerError(
                        "The destination already exists. Choose a new filename."
                    )
                raise CleanerError(
                    "The storage could not publish the copy safely. Choose another destination."
                )
            published = True
            try:
                os.fsync(parent)
            except OSError as error:
                if error.errno not in {errno.EINVAL, errno.ENOTSUP}:
                    raise CleanerError(
                        "The copy was written, but storage synchronization failed. Verify the copy before removing the device."
                    ) from error
        except OSError as error:
            raise CleanerError(
                "The cleaned copy could not be saved. Check the destination and available space."
            ) from error
        finally:
            if created and not published:
                try:
                    os.unlink(name, dir_fd=parent)
                except OSError:
                    pass
            os.close(parent)

    def process_file(self, identifier, operation):
        item = self.selected(identifier)
        if operation not in {"inspect", "clean"}:
            raise CleanerError("The metadata request is invalid.")
        if operation == "inspect" and item["report"] is not None:
            return item["report"]
        check_budget(self.directory, MAX_INPUT + MAX_OUTPUT * 2, working=True)
        workspace = Path(tempfile.mkdtemp(prefix="job-", dir=self.directory))
        self.unit = "ph4ntxm-metadata-" + uuid.uuid4().hex + ".service"
        args = [
            "/usr/bin/systemd-run",
            "--user",
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--service-type=exec",
            "--unit=" + self.unit,
            "--property=MemoryMax=" + str(MAX_MEMORY),
            "--property=MemorySwapMax=0",
            "--property=TasksMax=64",
            "--property=CPUQuota=100%",
            "--property=RuntimeMaxSec=180",
            "--property=TimeoutStopSec=3",
            "--property=KillMode=control-group",
            "--property=LimitCORE=0",
            "--property=LimitFSIZE=" + str(MAX_OUTPUT),
            "--property=LimitNOFILE=256",
            "--",
            *sandbox(item["source"], workspace, item["suffix"], operation),
        ]
        try:
            process = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self.environment,
                start_new_session=True,
            )
            with self.mutex:
                self.process = process
            os.set_blocking(process.stdout.fileno(), False)
            output = bytearray()
            deadline = time.monotonic() + 190
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map() or process.poll() is None:
                    self.ensure_open()
                    if time.monotonic() >= deadline:
                        raise CleanerError(
                            "The metadata operation exceeded its time limit."
                        )
                    for key, _ in selector.select(0.2):
                        block = os.read(key.fileobj.fileno(), 16384)
                        if not block:
                            selector.unregister(key.fileobj)
                        elif len(output) + len(block) > MAX_REPORT:
                            raise CleanerError("The metadata report exceeds its limit.")
                        else:
                            output.extend(block)
            try:
                report = validate_report(json.loads(output), operation)
            except (ValueError, TypeError, UnicodeError, RecursionError) as error:
                raise CleanerError(
                    str(error)
                    if isinstance(error, ValueError)
                    and not isinstance(error, json.JSONDecodeError)
                    else "The isolated metadata worker could not complete the operation."
                ) from None
            if process.returncode:
                raise CleanerError(
                    "The isolated metadata worker did not finish successfully."
                )
            self.finish_process()
            self.ensure_open()
            if operation == "clean":
                if (
                    report["output_size"]
                    + sum(
                        other["result"].stat().st_size
                        for other in self.items
                        if other is not item and other["result"] is not None
                    )
                    > MAX_TOTAL
                ):
                    raise CleanerError(
                        "Cleaned copies exceed the 128 MiB session limit. Export and remove some files first."
                    )
                result = workspace / ("result" + item["suffix"])
                info = result.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.getuid()
                    or info.st_size != report["output_size"]
                ):
                    raise CleanerError("The cleaned output could not be verified.")
                result.chmod(0o600)
                destination = self.directory / (item["id"] + "-cleaned")
                os.replace(result, destination)
                item["result"] = destination
            item["report"] = report
            return report
        finally:
            try:
                self.finish_process()
                shutil.rmtree(workspace)
            except BaseException:
                self.cleanup_pending = True
                self.cancel()
                self.temporary._finalizer.detach()
                raise

    def review(self, identifier, cleaned=False):
        item = self.selected(identifier)
        if viewer_kind(item["name"]) not in {"image", "media", "document"}:
            raise CleanerError(
                "This file type has no isolated preview. Export and review it separately."
            )
        source = item["result"] if cleaned else item["source"]
        if source is None:
            raise CleanerError("Create a cleaned copy first.")
        self.preview = CleanerPreview(
            self.runtime, source, item["name"], self.copy_file
        )
        try:
            self.preview.open_entry(0)
        finally:
            try:
                self.preview.close()
            except BaseException:
                self.cleanup_pending = True
                self.cancel()
                self.temporary._finalizer.detach()
                raise
            self.preview = None

    def export(self, identifier, destination):
        item = self.selected(identifier)
        if item["result"] is None:
            raise CleanerError("Create a cleaned copy before exporting.")
        destination = Path(destination)
        if suffix_for(destination.name) != item["suffix"]:
            raise CleanerError("Keep the original file extension for the cleaned copy.")
        if destination.parent.resolve().is_relative_to(self.directory.resolve()):
            raise CleanerError("Choose a destination outside the temporary session.")
        self.publish(item["result"], destination)

    def cancel(self):
        self.cancelled.set()
        if self.preview is not None:
            self.preview.cancelled.set()

    def resume(self):
        if (
            not self.closed
            and not self.cleanup_pending
            and self.unit is None
            and self.preview is None
        ):
            self.cancelled.clear()

    def close(self):
        self.cleanup_pending = True
        self.cancel()
        try:
            self.finish_process()
            if self.preview is not None:
                self.preview.close()
                self.preview = None
            self.temporary.cleanup()
        except BaseException:
            self.temporary._finalizer.detach()
            raise
        self.items.clear()
        self.closed = True
