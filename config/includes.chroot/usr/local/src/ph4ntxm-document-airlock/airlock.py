#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import hashlib
import fcntl
import json
import os
import shutil
import signal
import stat
import struct
import subprocess
import tempfile
import threading
import time
import zlib
from pathlib import Path

ASSET_DIR = Path("/usr/local/share/ph4ntxm-document-airlock")
BWRAP_PATH = "/usr/local/libexec/ph4ntxm-document-airlock/bwrap"
INPUT_MAGIC = b"PH4DAI01"
OUTPUT_MAGIC = b"PH4DAO01"
END_MAGIC = b"PH4DONE1"
ACK_MAGIC = b"PH4ACK01"
MAX_INPUT = 64 * 1024 * 1024
MAX_PAGES = 100
MAX_DIMENSION = 2400
MAX_PIXELS = MAX_DIMENSION * MAX_DIMENSION
MAX_TOTAL_RGB = 512 * 1024 * 1024
MAX_COMPRESSED = 128 * 1024 * 1024
TIMEOUT = 300
HOST_RESERVE_MIB = 192
SUFFIXES = {
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".tif",
    ".tiff",
    ".doc",
    ".docx",
    ".odt",
    ".xls",
    ".xlsx",
    ".ods",
    ".ppt",
    ".pptx",
    ".odp",
    ".odg",
    ".rtf",
}
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".tif", ".tiff"}


class AirlockError(Exception):
    pass


def read_exact(stream, size):
    result = bytearray()
    while len(result) < size:
        data = stream.read(min(size - len(result), 1024 * 1024))
        if not data:
            raise AirlockError("The isolated converter returned incomplete data.")
        result.extend(data)
    return bytes(result)


def read_input(path):
    suffix = Path(path).suffix.lower()
    if suffix not in SUFFIXES:
        raise AirlockError("This document type is not supported.")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise AirlockError("Select a regular document file.")
        if not 0 < metadata.st_size <= MAX_INPUT:
            raise AirlockError("Documents must be non-empty and no larger than 64 MiB.")
        data = handle.read(MAX_INPUT + 1)
        if not data or len(data) > MAX_INPUT:
            raise AirlockError("The document size changed or exceeds the input limit.")
    return suffix, data


def memory_mib(suffix):
    if suffix in IMAGE_SUFFIXES:
        return 384
    if suffix == ".pdf":
        return 512
    return 768


def available_memory_mib():
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) // 1024
    return 0


def check_memory(suffix, available=None):
    if available is None:
        available = available_memory_mib()
    ram = memory_mib(suffix)
    if available < ram + HOST_RESERVE_MIB:
        raise AirlockError(
            "Not enough available RAM for this conversion. Close other applications."
        )
    return ram


def verify_assets():
    for parent in (ASSET_DIR, *ASSET_DIR.parents):
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
            raise AirlockError("The Airlock image directory is not trusted.")
        if metadata.st_mode & 0o022:
            raise AirlockError(
                "The Airlock image directory is writable by other users."
            )
    manifest_path = ASSET_DIR / "manifest.json"
    metadata = manifest_path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or metadata.st_size > 4096
    ):
        raise AirlockError("The Airlock image manifest is not trusted.")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != {
        "kernel",
        "initrd",
        "root.squashfs",
    }:
        raise AirlockError("The Airlock image manifest is incomplete.")
    for name, expected in manifest.items():
        path = ASSET_DIR / name
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise AirlockError("An Airlock image component is not trusted.")
        with path.open("rb") as handle:
            actual = hashlib.file_digest(handle, "sha256").hexdigest()
        if actual != expected:
            raise AirlockError(
                "Airlock image verification failed. Rebuild the live image."
            )


def runtime_directory():
    path = Path("/run/user") / str(os.getuid())
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
    ):
        raise AirlockError("A private session runtime directory is required.")
    result = subprocess.run(
        ["/usr/bin/findmnt", "-n", "-o", "FSTYPE", "-T", str(path)],
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    )
    if result.stdout.strip() != "tmpfs":
        raise AirlockError("Airlock temporary storage must reside in RAM.")
    if len(Path("/proc/swaps").read_text(encoding="ascii").splitlines()) > 1:
        raise AirlockError("Disable swap before using Document Airlock.")
    return path


def check_ready(suffix=".pdf"):
    if os.geteuid() == 0:
        raise AirlockError("Run Document Airlock from the normal desktop account.")
    for executable in (
        BWRAP_PATH,
        "/usr/bin/qemu-system-x86_64",
        "/usr/bin/prlimit",
        "/usr/bin/findmnt",
    ):
        if not os.access(executable, os.X_OK):
            raise AirlockError("A required Airlock runtime component is missing.")
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise AirlockError(
            "KVM access is required. Enable virtualization and check the kvm group."
        )
    descriptor = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
    try:
        if fcntl.ioctl(descriptor, 0xAE00) != 12:
            raise AirlockError("The KVM interface is not supported.")
    finally:
        os.close(descriptor)
    ram = check_memory(suffix)
    path = runtime_directory()
    command = vm_command(suffix, ram)
    command = command[: command.index("/usr/bin/qemu-system-x86_64")] + [
        "/usr/bin/true"
    ]
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=5,
    )
    if result.returncode != 0:
        raise AirlockError(
            "Private namespaces are unavailable. Conversion cannot proceed."
        )
    verify_assets()
    return path


def vm_command(suffix, ram=None):
    if ram is None:
        ram = memory_mib(suffix)
    return [
        "/usr/bin/prlimit",
        "--as=" + str((ram + 1024) * 1024 * 1024),
        "--cpu=240",
        "--core=0",
        "--nofile=128",
        "--",
        BWRAP_PATH,
        "--unshare-all",
        "--hostname",
        "ph4ntxm-airlock",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "LANG",
        "C",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/sbin",
        "/sbin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--dir",
        "/proc",
        "--dev",
        "/dev",
        "--dev-bind",
        "/dev/kvm",
        "/dev/kvm",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
        "--chdir",
        "/tmp",
        "/usr/bin/qemu-system-x86_64",
        "-no-user-config",
        "-nodefaults",
        "-machine",
        "q35,usb=off,vmport=off,dump-guest-core=off",
        "-accel",
        "kvm",
        "-cpu",
        "qemu64",
        "-smp",
        "2",
        "-m",
        str(ram),
        "-nic",
        "none",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "none",
        "-parallel",
        "none",
        "-no-reboot",
        "-sandbox",
        "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        "-kernel",
        str(ASSET_DIR / "kernel"),
        "-initrd",
        str(ASSET_DIR / "initrd"),
        "-append",
        "quiet loglevel=0 panic=1 rdinit=/init noswap",
        "-drive",
        "if=none,id=root,format=raw,readonly=on,file="
        + str(ASSET_DIR / "root.squashfs"),
        "-device",
        "virtio-blk-pci,drive=root",
        "-device",
        "virtio-serial-pci",
        "-chardev",
        "stdio,id=airlock,signal=off",
        "-device",
        "virtserialport,chardev=airlock,name=org.ph4ntxm.airlock",
    ]


def receive_pages(stream, directory, acknowledge=None):
    if read_exact(stream, 8) != OUTPUT_MAGIC:
        raise AirlockError(
            "The isolated converter did not return the Airlock protocol."
        )
    count = struct.unpack("!I", read_exact(stream, 4))[0]
    if not 1 <= count <= MAX_PAGES:
        raise AirlockError(
            "The document exceeds the 100-page limit or returned no pages."
        )
    pages = []
    total_rgb = 0
    total_compressed = 0
    for number in range(count):
        width, height = struct.unpack("!II", read_exact(stream, 8))
        if not 1 <= width <= MAX_DIMENSION or not 1 <= height <= MAX_DIMENSION:
            raise AirlockError("The converter returned invalid page dimensions.")
        size = width * height * 3
        total_rgb += size
        if width * height > MAX_PIXELS or total_rgb > MAX_TOTAL_RGB:
            raise AirlockError("The document exceeds the pixel budget.")
        path = directory / ("page-%03d.rgbz" % number)
        with path.open("xb") as handle:
            compressor = zlib.compressobj(level=3)
            remaining = size
            while remaining:
                chunk = read_exact(stream, min(remaining, 64 * 1024))
                remaining -= len(chunk)
                compressed = compressor.compress(chunk)
                total_compressed += len(compressed)
                if total_compressed > MAX_COMPRESSED:
                    raise AirlockError(
                        "The converted document exceeds the 128 MiB output budget."
                    )
                handle.write(compressed)
            compressed = compressor.flush()
            total_compressed += len(compressed)
            if total_compressed > MAX_COMPRESSED:
                raise AirlockError(
                    "The converted document exceeds the 128 MiB output budget."
                )
            handle.write(compressed)
        pages.append((width, height, path))
    if read_exact(stream, 8) != END_MAGIC:
        raise AirlockError("The isolated converter returned an invalid stream ending.")
    if acknowledge is not None:
        acknowledge()
    if stream.read(1):
        raise AirlockError("The isolated converter returned trailing data.")
    return pages


def write_pdf(pages, handle):
    offsets = [0]

    def write(value):
        handle.write(value.encode("ascii"))

    def begin(number):
        offsets.append(handle.tell())
        write("%d 0 obj\n" % number)

    handle.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    begin(1)
    write("<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    begin(2)
    kids = " ".join("%d 0 R" % (3 + index * 3) for index in range(len(pages)))
    write("<< /Type /Pages /Count %d /Kids [%s] >>\nendobj\n" % (len(pages), kids))
    for index, (width, height, path) in enumerate(pages):
        number = 3 + index * 3
        page_width = width * 72 / 150
        page_height = height * 72 / 150
        begin(number)
        write(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] "
            "/Resources << /XObject << /Image %d 0 R >> >> /Contents %d 0 R >>\nendobj\n"
            % (page_width, page_height, number + 1, number + 2)
        )
        begin(number + 1)
        write(
            "<< /Type /XObject /Subtype /Image /Width %d /Height %d "
            "/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length %d >>\nstream\n"
            % (width, height, path.stat().st_size)
        )
        with path.open("rb") as source:
            shutil.copyfileobj(source, handle, length=1024 * 1024)
        write("\nendstream\nendobj\n")
        begin(number + 2)
        content = "q %.2f 0 0 %.2f 0 0 cm /Image Do Q\n" % (page_width, page_height)
        write(
            "<< /Length %d >>\nstream\n%sendstream\nendobj\n" % (len(content), content)
        )
    start = handle.tell()
    write("xref\n0 %d\n0000000000 65535 f \n" % len(offsets))
    for offset in offsets[1:]:
        write("%010d 00000 n \n" % offset)
    write(
        "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
        % (len(offsets), start)
    )


class AirlockSession:
    def __init__(self, runtime):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="ph4ntxm-airlock-", dir=runtime
        )
        self.directory = Path(self.temporary.name)
        self.pages = []
        self.cancelled = threading.Event()

    def close(self):
        self.temporary.cleanup()

    def convert(self, suffix, data, command=None):
        lock_path = self.directory.parent / "ph4ntxm-airlock.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as lock:
            metadata = os.fstat(lock.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                raise AirlockError("The Airlock session lock is not trusted.")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise AirlockError(
                    "Another Document Airlock conversion is already running."
                ) from None
            self._convert(suffix, data, command)

    def _convert(self, suffix, data, command):
        done = threading.Event()
        timed_out = threading.Event()
        process = subprocess.Popen(
            vm_command(suffix) if command is None else command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )

        def stop():
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        def watch():
            deadline = time.monotonic() + TIMEOUT
            while not done.wait(0.1):
                if self.cancelled.is_set() or time.monotonic() >= deadline:
                    timed_out.set()
                    stop()
                    return

        def send():
            try:
                process.stdin.write(
                    struct.pack(
                        "!8sI16s", INPUT_MAGIC, len(data), suffix.encode("ascii")
                    )
                )
                process.stdin.write(data)
                process.stdin.flush()
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

        def acknowledge():
            process.stdin.write(ACK_MAGIC)
            process.stdin.flush()

        try:
            with process.stdout:
                pages = receive_pages(process.stdout, self.directory, acknowledge)
            done.set()
            watcher.join()
            status = process.wait(timeout=5)
            if status != 0 or self.cancelled.is_set() or timed_out.is_set():
                raise AirlockError("Conversion was cancelled, timed out, or failed.")
            self.pages = pages
        except (AirlockError, OSError, subprocess.TimeoutExpired):
            if self.cancelled.is_set():
                raise AirlockError("Conversion cancelled.") from None
            if timed_out.is_set():
                raise AirlockError(
                    "Conversion exceeded the five-minute limit."
                ) from None
            raise AirlockError(
                "Conversion failed. The document may be unsupported or exceed the resource limits."
            ) from None
        finally:
            done.set()
            watcher.join()
            if process.returncode is None:
                stop()
            process.wait()
            sender.join()

    def export(self, destination):
        if not self.pages:
            raise AirlockError("There is no completed conversion to export.")
        if Path(destination).suffix.lower() != ".pdf":
            raise AirlockError("Choose a PDF filename for the converted document.")
        destination = Path(destination)
        descriptor, temporary = tempfile.mkstemp(
            prefix=".ph4ntxm-airlock-", dir=destination.parent
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                write_pdf(self.pages, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, destination, follow_symlinks=False)
        finally:
            os.unlink(temporary)
