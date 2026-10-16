# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import ctypes
import errno
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import uuid
import zipfile

sys.path.insert(0, "/usr/local/lib/ph4ntxm-document-airlock")
import airlock
import archives
from archive_protocol import (
    CHUNK_SIZE,
    DATA_MAGIC,
    MAX_METADATA,
    safe_name,
    viewer_kind,
)

MAX_FILES = 32
MAX_TOTAL = 64 * 1024 * 1024
MAX_CLEAR = MAX_TOTAL + 128 * 1024
MAX_CIPHER = MAX_CLEAR + 128 * 1024
RESERVE = 192 * 1024 * 1024
CRYPTO_MEMORY = 512 * 1024 * 1024
CRYPTO = "/usr/local/libexec/ph4ntxm-vault/crypto"
BWRAP = "/usr/local/libexec/ph4ntxm-document-airlock/bwrap"
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


class VaultError(Exception):
    pass


class VaultCancelled(VaultError):
    pass


def password_bytes(password, exporting=False):
    if not isinstance(password, str):
        raise VaultError("Enter a vault password.")
    try:
        data = password.encode("utf-8")
    except UnicodeError:
        raise VaultError("The vault password is not valid UTF-8.") from None
    if not data or len(data) > 1024 or (exporting and len(password) < 12):
        raise VaultError(
            "Use at least 12 characters and no more than 1024 UTF-8 bytes for export."
        )
    if (
        len(json.dumps({"password": password}, ensure_ascii=False).encode("utf-8")) + 1
        > 4096
    ):
        raise VaultError("The vault password exceeds the private channel limit.")
    return data


def file_name(name):
    if (
        not isinstance(name, str)
        or name in {"", ".", ".."}
        or not safe_name(name)
        or "/" in name
        or "\\" in name
        or any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in name)
        or len(name.encode("utf-8")) > 255
    ):
        raise VaultError(
            "Choose files with simple filenames of at most 255 UTF-8 bytes."
        )
    return name


def private_file(path):
    info = Path(path).lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise VaultError("The private vault workspace could not be verified.")
    return info


def check_budget(directory, storage=0, crypto=False):
    try:
        if len(Path("/proc/swaps").read_text(encoding="ascii").splitlines()) > 1:
            raise VaultError("Disable swap before using Vault.")
        available = airlock.available_memory_mib() * 1024 * 1024
        space = os.statvfs(directory)
    except (airlock.AirlockError, OSError, ValueError) as error:
        raise VaultError("Actual available RAM could not be verified.") from error
    if available < RESERVE + storage + (CRYPTO_MEMORY if crypto else 0):
        raise VaultError(
            "Not enough available RAM. Close other applications and try again."
        )
    if space.f_bavail * space.f_frsize < storage + 16 * 1024 * 1024:
        raise VaultError("Not enough space in the private RAM workspace.")


def sandbox(source, destination, mode):
    return [
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
        "vault",
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
        "--dev",
        "/dev",
        "--dir",
        "/sys",
        "--dir",
        "/sys/fs",
        "--ro-bind",
        "/sys/fs/cgroup",
        "/sys/fs/cgroup",
        "--tmpfs",
        "/tmp",
        "--chdir",
        "/tmp",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--ro-bind",
        str(source),
        "/input",
        "--bind",
        str(destination),
        "/output",
        CRYPTO,
        mode,
        "/input",
        "/output",
    ]


def user_environment(runtime):
    return {
        **SAFE_ENV,
        "XDG_RUNTIME_DIR": str(runtime),
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + str(Path(runtime) / "bus"),
    }


def check_runtime_components():
    for path in (CRYPTO, BWRAP, "/usr/bin/systemd-run", "/usr/bin/systemctl"):
        try:
            info = Path(path).lstat()
        except OSError as error:
            raise VaultError(
                f"Vault runtime component is unavailable: {path}"
            ) from error
        if not stat.S_ISREG(info.st_mode):
            raise VaultError(f"Vault runtime component is not a regular file: {path}")
        if info.st_uid != 0:
            raise VaultError(f"Vault runtime component is not owned by root: {path}")
        if info.st_mode & 0o022:
            raise VaultError(
                f"Vault runtime component is writable by other users: {path}"
            )
        if not os.access(path, os.X_OK):
            raise VaultError(f"Vault runtime component is not executable: {path}")


def check_ready():
    try:
        runtime = airlock.runtime_directory()
        if os.geteuid() == 0:
            raise VaultError("Run PH4NTXM Vault from the normal desktop account.")
        check_runtime_components()
        result = subprocess.run(
            ["/usr/bin/systemctl", "--user", "show-environment"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            env=user_environment(runtime),
        )
        if result.returncode:
            raise VaultError("A running desktop user service manager is required.")
        check_budget(runtime)
        return runtime
    except (
        airlock.AirlockError,
        OSError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        raise VaultError(
            str(error).replace("Airlock", "Vault").replace("Document Vault", "Vault")
        ) from None


class VaultArchive(archives.ArchiveSession):
    def extract_file(self, index, destination):
        if type(index) is not int or not 0 <= index < len(self.entries):
            raise VaultError("Select a vault file first.")
        entry = self.entries[index]
        size = entry["size"]
        if (
            entry["kind"] != "file"
            or type(size) is not int
            or not 0 < size <= MAX_TOTAL
        ):
            raise VaultError("This vault entry cannot be restored.")

        def receive(stream, magic):
            if magic != DATA_MAGIC:
                raise VaultError("The isolated reader returned invalid file data.")
            total = 0
            descriptor = os.open(
                destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(descriptor, "wb") as output:
                while True:
                    length = struct.unpack("!I", archives.read_exact(stream, 4))[0]
                    if not length:
                        break
                    total += length
                    if length > CHUNK_SIZE or total > size:
                        raise VaultError("The restored file exceeds its listed size.")
                    if self.cancelled.is_set():
                        raise VaultCancelled("Vault operation cancelled.")
                    output.write(archives.read_exact(stream, length))
                if total != size:
                    raise VaultError(
                        "The restored file does not match its listed size."
                    )
            return destination

        try:
            return self.request(index, receive, size)
        except BaseException:
            Path(destination).unlink(missing_ok=True)
            raise


class VaultSession:
    def __init__(self, runtime):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="ph4ntxm-vault-", dir=runtime
        )
        self.directory = Path(self.temporary.name)
        self.environment = user_environment(runtime)
        self.files = self.directory / "files"
        self.files.mkdir(mode=0o700)
        self.items = []
        self.dirty = False
        self.cancelled = threading.Event()
        self.archive = None
        self.review_archive = None
        self.unit = None
        self.process = None
        self.closed = False
        self.mutex = threading.Lock()

    def ensure_open(self):
        if self.closed:
            raise VaultError("This vault is locked. Create or open a vault first.")
        if self.cancelled.is_set():
            raise VaultCancelled("Vault operation cancelled.")

    def copy_file(self, source, destination, limit):
        self.ensure_open()
        descriptor = os.open(
            source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        )
        created = False
        try:
            with os.fdopen(descriptor, "rb") as incoming:
                before = os.fstat(incoming.fileno())
                if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
                    raise VaultError(
                        "Choose nonempty regular files within the vault size limit."
                    )
                check_budget(self.directory, before.st_size)
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
                            raise VaultError(
                                "The selected file changed while it was being copied."
                            )
                        if total % (1024 * 1024) == 0:
                            check_budget(self.directory)
                        outgoing.write(block)
                    after = os.fstat(incoming.fileno())
                    if total != before.st_size or (
                        before.st_size,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                    ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        raise VaultError(
                            "The selected file changed while it was being copied."
                        )
                return total
        except BaseException:
            if created:
                Path(destination).unlink(missing_ok=True)
            raise

    def add_files(self, paths):
        self.ensure_open()
        if not paths or len(paths) + len(self.items) > MAX_FILES:
            raise VaultError("A vault can contain between one and 32 files.")
        names = {item["name"].casefold() for item in self.items}
        total = sum(item["size"] for item in self.items)
        added = []
        try:
            for value in paths:
                self.ensure_open()
                name = file_name(Path(value).name)
                if name.casefold() in names:
                    raise VaultError(
                        "Two files have the same filename. Rename one before adding it."
                    )
                identifier = uuid.uuid4().hex
                destination = self.files / identifier
                size = self.copy_file(value, destination, MAX_TOTAL - total)
                added.append(
                    {
                        "id": identifier,
                        "name": name,
                        "size": size,
                        "viewer": viewer_kind(name),
                        "path": destination,
                    }
                )
                total += size
                names.add(name.casefold())
        except BaseException:
            for item in added:
                item["path"].unlink(missing_ok=True)
            raise
        self.items.extend(added)
        self.dirty = True

    def remove_files(self, identifiers):
        self.ensure_open()
        identifiers = set(identifiers)
        if not identifiers or not identifiers <= {item["id"] for item in self.items}:
            raise VaultError("Select files from the current vault.")
        remaining = []
        for item in self.items:
            if item["id"] in identifiers:
                if item.get("path"):
                    item["path"].unlink(missing_ok=True)
            else:
                remaining.append(item)
        self.items = remaining
        self.dirty = True

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
                raise VaultError(
                    "The vault worker could not be stopped. Close Vault and retry cleanup."
                )
            if status.returncode and result.returncode:
                error = status.stderr.strip()
                if "not found" not in error and "could not be found" not in error:
                    raise VaultError("The vault worker state could not be verified.")
        except (OSError, subprocess.SubprocessError) as error:
            raise VaultError("The vault worker could not be stopped.") from error

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

    def transform(self, source, destination, mode, password):
        self.ensure_open()
        password_bytes(password, mode == "encrypt")
        check_budget(
            self.directory,
            (
                MAX_CLEAR
                if mode == "decrypt"
                else private_file(source).st_size + 128 * 1024
            ),
            crypto=True,
        )
        private_file(source)
        descriptor = os.open(
            destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        os.close(descriptor)
        unit = "ph4ntxm-vault-" + uuid.uuid4().hex + ".service"
        self.unit = unit
        args = [
            "/usr/bin/systemd-run",
            "--user",
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--service-type=exec",
            "--unit=" + unit,
            "--property=MemoryMax=" + str(CRYPTO_MEMORY),
            "--property=MemorySwapMax=0",
            "--property=TasksMax=64",
            "--property=CPUQuota=100%",
            "--property=RuntimeMaxSec=90",
            "--property=TimeoutStopSec=3",
            "--property=KillMode=control-group",
            "--property=LimitCORE=0",
            "--",
            *sandbox(source, destination, mode),
        ]
        secret = bytearray(
            json.dumps(
                {"password": password}, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            + b"\n"
        )
        process = None
        succeeded = False
        try:
            process = subprocess.Popen(
                args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=self.environment,
                start_new_session=True,
            )
            with self.mutex:
                self.process = process
            process.stdin.write(secret)
            process.stdin.close()
            secret[:] = b"\x00" * len(secret)
            os.set_blocking(process.stdout.fileno(), False)
            deadline = time.monotonic() + 100
            output = bytearray()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map() or process.poll() is None:
                    self.ensure_open()
                    if time.monotonic() >= deadline:
                        raise VaultError("The vault operation exceeded its time limit.")
                    check_budget(self.directory)
                    for key, _ in selector.select(0.2):
                        block = os.read(key.fileobj.fileno(), 4097)
                        if not block:
                            selector.unregister(key.fileobj)
                        elif len(output) + len(block) > 4096:
                            raise VaultError(
                                "The vault worker returned an invalid response."
                            )
                        else:
                            output.extend(block)
                    if not selector.get_map() and process.poll() is None:
                        self.cancelled.wait(0.05)
            process.wait(timeout=1)
            self.ensure_open()
            if len(output) > 4096:
                raise VaultError("The vault worker returned an invalid response.")
            try:
                result = json.loads(output.decode("utf-8"))
            except (ValueError, UnicodeError):
                result = {}
            if not isinstance(result, dict):
                result = {}
            if process.returncode != 0 or result != {"ok": True}:
                if mode == "decrypt" and result.get("error") == "unlock_failed":
                    raise VaultError(
                        "The vault password is incorrect, or the vault is damaged or unsupported."
                    )
                raise VaultError(
                    "The isolated vault worker could not complete the operation."
                )
            info = private_file(destination)
            limit = MAX_CLEAR if mode == "decrypt" else MAX_CIPHER
            if not 0 < info.st_size <= limit:
                raise VaultError("The vault output exceeds its size limit.")
            succeeded = True
        finally:
            secret[:] = b"\x00" * len(secret)
            try:
                self.finish_process()
            except BaseException:
                self.temporary._finalizer.detach()
                raise
            if not succeeded:
                Path(destination).unlink(missing_ok=True)

    def open_vault(self, path, password):
        self.ensure_open()
        if self.items or self.archive is not None:
            raise VaultError("Open an encrypted vault in a new RAM session.")
        if Path(path).suffix.lower() != ".ph4vault":
            raise VaultError("Choose a .ph4vault file.")
        encrypted = self.directory / "input.age"
        clear = self.directory / "unlocked.zip"
        reader = None
        try:
            self.copy_file(path, encrypted, MAX_CIPHER)
            self.transform(encrypted, clear, "decrypt", password)
            reader = VaultArchive(archives.check_ready())
            reader.cancelled = self.cancelled
            report = reader.inspect(clear)
            if (
                report["format"] != "ZIP"
                or not 1 <= len(report["entries"]) <= MAX_FILES
            ):
                raise VaultError(
                    "The vault does not contain a supported file collection."
                )
            names = set()
            items = []
            total = 0
            for entry in report["entries"]:
                name = file_name(entry["name"])
                size = entry["size"]
                if (
                    entry["kind"] != "file"
                    or entry["encrypted"]
                    or type(size) is not int
                    or not 0 < size <= MAX_TOTAL
                    or name.casefold() in names
                ):
                    raise VaultError(
                        "The vault contains unsupported or duplicate entries."
                    )
                total += size
                if total > MAX_TOTAL:
                    raise VaultError("Vault contents exceed 64 MiB.")
                names.add(name.casefold())
                items.append(
                    {
                        "id": uuid.uuid4().hex,
                        "name": name,
                        "size": size,
                        "viewer": viewer_kind(name),
                        "index": entry["index"],
                    }
                )
            self.ensure_open()
            self.archive = reader
            self.items = items
            self.dirty = False
        except BaseException:
            if reader is not None:
                try:
                    reader.close()
                except BaseException:
                    self.archive = reader
                    raise
            raise
        finally:
            encrypted.unlink(missing_ok=True)
            clear.unlink(missing_ok=True)

    def item(self, identifier):
        self.ensure_open()
        for item in self.items:
            if item["id"] == identifier:
                return item
        raise VaultError("Select a file from the current vault.")

    def materialize(self, item):
        self.ensure_open()
        if item.get("path"):
            info = private_file(item["path"])
            if info.st_size != item["size"]:
                raise VaultError("A private vault file changed.")
            return item["path"]
        if self.archive is None:
            raise VaultError("The vault file is no longer available.")
        self.archive.cancelled = self.cancelled
        destination = self.files / item["id"]
        self.archive.extract_file(item["index"], destination)
        item["path"] = destination
        return destination

    def bundle(self, items, destination):
        self.ensure_open()
        check_budget(
            self.directory,
            sum(item["size"] * (1 if item.get("path") else 2) for item in items)
            + 128 * 1024,
        )
        try:
            descriptor = os.open(
                destination, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            with (
                os.fdopen(descriptor, "w+b") as bundle,
                zipfile.ZipFile(
                    bundle, "w", compression=zipfile.ZIP_STORED, allowZip64=False
                ) as archive,
            ):
                for item in items:
                    self.ensure_open()
                    source = self.materialize(item)
                    info = zipfile.ZipInfo(
                        item["name"], date_time=(1980, 1, 1, 0, 0, 0)
                    )
                    info.compress_type = zipfile.ZIP_STORED
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    descriptor = os.open(
                        source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                    )
                    with (
                        os.fdopen(descriptor, "rb") as incoming,
                        archive.open(info, "w") as outgoing,
                    ):
                        count = 0
                        while True:
                            self.ensure_open()
                            block = incoming.read(CHUNK_SIZE)
                            if not block:
                                break
                            count += len(block)
                            if count > item["size"]:
                                raise VaultError("A private vault file changed.")
                            outgoing.write(block)
                        if count != item["size"]:
                            raise VaultError("A private vault file changed.")
            if private_file(destination).st_size > MAX_CLEAR:
                raise VaultError("The vault exceeds its output limit.")
        except BaseException:
            Path(destination).unlink(missing_ok=True)
            raise

    def review(self, identifier):
        item = self.item(identifier)
        if not item["viewer"] or item["size"] > archives.viewer_limit(item["name"]):
            raise VaultError(
                "This file has no isolated preview within the viewer's size limit."
            )
        if "index" in item and self.archive is not None:
            reader = self.archive
            index = item["index"]
        else:
            if self.review_archive is not None:
                self.review_archive.close()
                self.review_archive = None
            path = self.directory / "review.zip"
            path.unlink(missing_ok=True)
            try:
                self.bundle([item], path)
                reader = VaultArchive(archives.check_ready())
                self.review_archive = reader
                reader.cancelled = self.cancelled
                reader.inspect(path)
                index = 0
            finally:
                path.unlink(missing_ok=True)
        reader.cancelled = self.cancelled
        if item["viewer"] == "text":
            return reader.read_text_entry(index)
        reader.open_entry(index)
        return None

    def export(self, path, password):
        self.ensure_open()
        password_bytes(password, True)
        if not self.items:
            raise VaultError("Add at least one file before exporting a vault.")
        destination = Path(path)
        if destination.suffix.lower() != ".ph4vault":
            raise VaultError("Choose a .ph4vault filename.")
        if os.path.lexists(destination):
            raise VaultError(
                "The destination already exists. Choose a new vault filename."
            )
        clear = self.directory / "export.zip"
        encrypted = self.directory / "export.age"
        clear.unlink(missing_ok=True)
        encrypted.unlink(missing_ok=True)
        try:
            self.bundle(list(self.items), clear)
            self.transform(clear, encrypted, "encrypt", password)
            self.publish(encrypted, destination)
            self.dirty = False
        finally:
            clear.unlink(missing_ok=True)
            encrypted.unlink(missing_ok=True)

    def publish(self, source, destination):
        parent = os.open(
            destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        name = ".ph4ntxm-vault-" + uuid.uuid4().hex
        created = False
        published = False
        try:
            if os.path.lexists(destination):
                raise VaultError(
                    "The destination already exists. Choose a new vault filename."
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
                    raise VaultError(
                        "The destination already exists. Choose a new vault filename."
                    )
                raise VaultError(
                    "The storage could not publish the vault safely. Choose another destination."
                )
            published = True
            try:
                os.fsync(parent)
            except OSError as error:
                if error.errno not in {errno.EINVAL, errno.ENOTSUP}:
                    raise VaultError(
                        "The vault was written, but storage synchronization failed. Verify the copy before removing the device."
                    ) from error
        except OSError as error:
            raise VaultError(
                "The encrypted vault could not be saved. Check the destination and available space."
            ) from error
        finally:
            if created and not published:
                try:
                    os.unlink(name, dir_fd=parent)
                except OSError:
                    pass
            os.close(parent)

    def close(self):
        self.cancelled.set()
        try:
            self.finish_process()
            for reader in (self.review_archive, self.archive):
                if reader is not None:
                    reader.close()
            self.temporary.cleanup()
        except BaseException:
            self.temporary._finalizer.detach()
            raise
        self.items.clear()
        self.archive = None
        self.review_archive = None
        self.closed = True
