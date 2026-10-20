# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import argparse
import configparser
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import uuid
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree as ET

LIB = Path("/usr/local/lib/ph4ntxm-browser-airlock")
EXEC = Path("/usr/local/libexec/ph4ntxm-browser-airlock")
sys.path.insert(0, str(LIB))
from browser_profiles import ProfileError, prepare_browser, revalidate_browser
from browser_display import DisplaySync

MAX_FILES = 32
MAX_INPUT = 64 * 1024 * 1024
MAX_FILE = 512 * 1024 * 1024
MAX_OUTPUT = 1024 * 1024 * 1024
MAX_ENTRIES = 256
RESERVE = 192 * 1024 * 1024
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


class AppError(Exception):
    pass


class SessionStopped(AppError):
    pass


def command(args, **kwargs):
    return subprocess.run(args, check=True, timeout=kwargs.pop("timeout", 10), **kwargs)


def diagnostic_text(value, limit=240, tail=False):
    if isinstance(value, bytes):
        value = (value[-4096:] if tail else value[:4096]).decode("utf-8", errors="replace")
    value = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in (value[-4096:] if tail else value[:4096])
    )
    value = " ".join(value.split())
    return value[-limit:] if tail else value[:limit]


def trusted(path):
    info = Path(path).stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise AppError("A Browser Airlock runtime component could not be verified.")
    if not os.access(path, os.X_OK):
        raise AppError("A Browser Airlock runtime component is unavailable.")


def bootstrap_permissions():
    helper = (EXEC / "bootstrap").stat()
    if helper.st_gid != 0 or stat.S_IMODE(helper.st_mode) != 0o4755:
        raise AppError("The Browser Airlock bootstrap permissions are invalid.")
    for name in ("guard", "bwrap"):
        if (EXEC / name).stat().st_mode & 0o6000:
            raise AppError("The Browser Airlock worker helpers must be unprivileged.")


def runtime_directory():
    path = Path("/run/user") / str(os.getuid())
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise AppError("A private desktop runtime directory is required.")
    return path


def ram_directory(path="/tmp"):
    if (
        command(
            ["/usr/bin/findmnt", "-n", "-o", "FSTYPE", "-T", str(path)],
            capture_output=True,
            text=True,
        ).stdout.strip()
        != "tmpfs"
    ):
        raise AppError("Browser Airlock temporary storage must reside in RAM.")
    if len(Path("/proc/swaps").read_text().splitlines()) > 1:
        raise AppError("Disable swap before using Browser Airlock.")
    return Path(path)


def memory_budget(storage=0):
    if any(key.startswith("PH4_INVENTORY_") for key in os.environ):
        raise AppError("Open Browser Airlock from the desktop to check actual RAM.")
    values = dict(
        re.findall(r"^(\w+):\s+(\d+) kB$", Path("/proc/meminfo").read_text(), re.M)
    )
    available = int(values["MemAvailable"]) * 1024
    limit = min(2 * 1024 * 1024 * 1024, available - RESERVE - storage)
    if limit < 512 * 1024 * 1024:
        raise AppError(
            "Not enough available RAM. Close other applications and try again."
        )
    space = os.statvfs("/tmp")
    if space.f_bavail * space.f_frsize < storage + 16 * 1024 * 1024:
        raise AppError("Not enough free space in temporary RAM storage.")
    return limit


def environment():
    runtime = runtime_directory()
    return {
        **SAFE_ENV,
        "XDG_RUNTIME_DIR": str(runtime),
        "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + str(runtime / "bus"),
    }


def remove_tree(path):
    path = Path(path)
    path.chmod(0o700, follow_symlinks=False)
    current = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    entries = None
    parents = []
    try:
        entries = os.scandir(current)
        while True:
            try:
                entry = next(entries)
            except StopIteration:
                entries.close()
                entries = None
                if not parents:
                    break
                parent = os.open(
                    "..",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=current,
                )
                os.close(current)
                current = parent
                os.rmdir(parents.pop(), dir_fd=current)
                entries = os.scandir(current)
                continue
            if entry.is_dir(follow_symlinks=False):
                os.chmod(entry.name, 0o700, dir_fd=current, follow_symlinks=False)
                child = os.open(
                    entry.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=current,
                )
                parents.append(entry.name)
                entries.close()
                os.close(current)
                current = child
                entries = os.scandir(current)
            else:
                os.unlink(entry.name, dir_fd=current)
    finally:
        if entries is not None:
            entries.close()
        os.close(current)
    path.rmdir()


def file_name(value):
    if (
        not isinstance(value, str)
        or value in {"", ".", ".."}
        or "/" in value
        or "\\" in value
        or len(value.encode("utf-8")) > 240
        or any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in value)
    ):
        raise AppError(
            "Choose a file with a simple filename of at most 240 UTF-8 bytes."
        )
    return value


def process_start(pid):
    return Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()[19]


def filter_fd(offline=False):
    data = command([str(EXEC / "guard"), "offline-filter" if offline else "filter"], capture_output=True).stdout
    if not data or len(data) % 8 or len(data) > 32768:
        raise AppError("The Browser Airlock syscall filter is invalid.")
    descriptor = os.memfd_create(
        "ph4ntxm-browser-airlock-filter", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    )
    try:
        os.write(descriptor, data)
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL,
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def sandbox(descriptor, offline=False):
    args = [
        str(EXEC / "bootstrap"),
        str(descriptor),
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
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
        "--bind",
        "/proc",
        "/proc",
        "--dir",
        "/sys",
        "--dev",
        "/dev",
        "--size",
        str(512 * 1024 * 1024),
        "--tmpfs",
        "/tmp",
        "--size",
        str(16 * 1024 * 1024),
        "--tmpfs",
        "/run",
        "--size",
        str(64 * 1024 * 1024),
        "--tmpfs",
        "/home/ph4ntxm",
        "--dir",
        "/etc",
        "--dir",
        "/workspace",
        "--dir",
        "/workspace/downloads",
        "--dir",
        "/var/cache",
        "--tmpfs",
        "/usr/share/dbus-1/services",
        "--chdir",
        "/workspace",
        "--seccomp",
        str(descriptor),
    ]
    if offline:
        args += ["--unshare-net"]
    for path in (
        "/etc/fonts",
        "/etc/ssl/certs",
        "/etc/ca-certificates",
        "/etc/nsswitch.conf",
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/localtime",
        "/etc/ld.so.cache",
        "/etc/alternatives",
        "/var/cache/fontconfig",
    ):
        if Path(path).exists():
            args += ["--ro-bind", path, path]
    for path in ("/proc/sys", "/proc/irq", "/proc/bus"):
        args += ["--tmpfs", path, "--remount-ro", path]
    for path in ("/proc/kcore", "/proc/keys", "/proc/timer_list", "/proc/sysrq-trigger"):
        if Path(path).exists():
            args += ["--ro-bind", "/dev/null", path]
    for key, value in {
        **SAFE_ENV,
        "HOME": "/home/ph4ntxm",
        "USER": "ph4ntxm",
        "LOGNAME": "ph4ntxm",
        "XDG_RUNTIME_DIR": "/run",
        "XDG_CONFIG_HOME": "/home/ph4ntxm/.config",
        "XDG_CACHE_HOME": "/home/ph4ntxm/.cache",
        "XDG_DATA_HOME": "/home/ph4ntxm/.local/share",
        "XDG_CONFIG_DIRS": "/config/xdg",
        "NO_AT_BRIDGE": "1",
        "GDK_BACKEND": "x11",
        "GSETTINGS_BACKEND": "memory",
        "GIO_USE_VFS": "local",
        "GIO_USE_VOLUME_MONITOR": "unix",
    }.items():
        args += ["--setenv", key, value]
    return args


def identity_bindings(args):
    for source, destinations in (
        ("/run/ph4ntxm/fake_cpuinfo", ("/proc/cpuinfo",)),
        ("/run/ph4ntxm/fake_online", ("/sys/devices/system/cpu/online", "/sys/devices/system/cpu/present", "/sys/devices/system/cpu/possible")),
    ):
        info = Path(source).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AppError("The protected hardware identity is unavailable.")
        for destination in destinations:
            args += ["--ro-bind", source, destination]
    try:
        dmi = Path("/sys/class/dmi/id").resolve(strict=True)
    except FileNotFoundError:
        return args
    info = dmi.lstat()
    if not dmi.is_relative_to("/sys/devices") or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise AppError("The protected DMI identity is unavailable.")
    args += ["--ro-bind", str(dmi), str(dmi), "--dir", "/sys/class/dmi", "--symlink", os.path.relpath(dmi, "/sys/class/dmi"), "/sys/class/dmi/id"]
    return args


def tor_bindings(args, home):
    getconf = "/usr/bin/getconf-real"
    tor = "/opt/ph4ntxm/tor-browser/Browser/TorBrowser/Tor/tor"
    trusted(getconf)
    trusted(tor)
    return args + [
        "--dir", "/run/ph4ntxm-browser-tools",
        "--ro-bind", getconf, "/run/ph4ntxm-browser-tools/getconf",
        "--ro-bind", tor, home + "/.tor-browser/TorBrowser/Tor/tor",
    ]


def profile_binding(args, profile_path):
    if profile_path:
        args += ["--bind", profile_path, profile_path]
    return args


def check_ready():
    if os.getuid() == 0:
        raise AppError("Open Browser Airlock from the normal desktop account.")
    for path in (
        EXEC / "guard",
        EXEC / "bwrap",
        EXEC / "bootstrap",
        "/usr/bin/Xephyr",
        "/usr/bin/xfwm4",
        "/usr/bin/python3",
        "/usr/bin/bash",
        "/usr/bin/dbus-daemon",
        "/usr/bin/systemd-run",
        "/usr/bin/systemctl",
    ):
        trusted(path)
    bootstrap_permissions()
    runtime_directory()
    ram_directory()
    memory_budget()
    command(
        ["/usr/bin/systemctl", "--user", "show-environment"],
        env=environment(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    descriptor = filter_fd()
    try:
        command(
            sandbox(descriptor)
            + [
                str(EXEC / "guard"),
                "run",
                "--",
                "/usr/bin/python3",
                "-I",
                str(LIB / "browser_airlock.py"),
                "--probe",
            ],
            pass_fds=(descriptor,),
            capture_output=True,
            timeout=15,
        )
    except subprocess.CalledProcessError as error:
        diagnostic = diagnostic_text(error.stderr or b"")
        detail = "Isolation probe exited with status %d" % error.returncode
        if diagnostic:
            detail += ": " + diagnostic
        raise AppError(
            "Browser Airlock isolation is unavailable. No application was opened. " + detail
        ) from error
    except subprocess.TimeoutExpired as error:
        raise AppError(
            "Browser Airlock isolation is unavailable. No application was opened. "
            "The isolation probe timed out after 15 seconds."
        ) from error
    finally:
        os.close(descriptor)


def read_json(path):
    with Path(path).open("rb") as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise AppError("The Browser Airlock control record is invalid.")
    return json.loads(data)


def write_json(path, values):
    temporary = Path(str(path) + ".new")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(values, stream)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def record_state(directory, values):
    if values.get("state") == "failed":
        write_json(Path(directory) / "last-failure.json", values)
    write_json(Path(directory) / "state.json", values)


def unit_state(unit):
    result = subprocess.run(
        [
            "/usr/bin/systemctl",
            "--user",
            "show",
            unit,
            "-p",
            "ActiveState",
            "-p",
            "ControlGroup",
            "-p",
            "Result",
        ],
        env=environment(),
        capture_output=True,
        text=True,
        timeout=8,
    )
    values = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    if "ActiveState" not in values or not values["ActiveState"]:
        raise AppError("The Browser Airlock service state could not be verified.")
    return values


def stopped(unit, cgroup=""):
    values = unit_state(unit)
    if values.get("ActiveState", "inactive") not in {"inactive", "failed"}:
        return False
    group = values.get("ControlGroup") or cgroup
    if group:
        path = Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.events"
        try:
            if "populated 1" in path.read_text():
                return False
        except FileNotFoundError:
            pass
    return True


class Session:
    def __init__(self):
        check_ready()
        self.directory = Path(
            tempfile.mkdtemp(prefix="ph4ntxm-browser-airlock.", dir=ram_directory())
        )
        self.workspace = self.directory / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.imports = self.workspace / "imports"
        self.imports.mkdir(mode=0o700)
        self.downloads = self.workspace / "downloads"
        self.downloads.mkdir(mode=0o700)
        self.home = self.directory / "home"
        self.home.mkdir(mode=0o700)
        self.plan = None
        self.items = []
        self.unit = None
        self.cgroup = ""
        self.running = False
        self.closed = False

    def require_stopped(self):
        if self.closed:
            raise AppError("The Browser Airlock session is closed.")
        if self.unit and not stopped(self.unit, self.cgroup):
            raise AppError(
                "Stop the isolated application before changing or exporting files."
            )
        self.running = False

    def add(self, paths):
        if self.closed:
            raise AppError("The Browser Airlock session is closed.")
        if len(self.items) + len(paths) > MAX_FILES:
            raise AppError("Import up to 32 files per browser session.")
        existing = sum(item["size"] for item in self.items)
        added = []
        try:
            for value in paths:
                path = Path(value).expanduser().absolute()
                name = file_name(path.name)
                if str(path).startswith(("/proc/", "/sys/", "/dev/")):
                    raise AppError("Import a regular file.")
                source = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                destination = None
                staged = None
                try:
                    before = os.fstat(source)
                    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_INPUT:
                        raise AppError("Import nonempty regular files of at most 64 MiB.")
                    if existing + before.st_size > MAX_INPUT:
                        raise AppError("Imported files must not exceed 64 MiB combined.")
                    memory_budget(before.st_size)
                    destination, staged_name = tempfile.mkstemp(prefix="import.", dir=self.directory)
                    staged = Path(staged_name)
                    copied = 0
                    while True:
                        data = os.read(source, min(1024 * 1024, before.st_size - copied + 1))
                        if not data:
                            break
                        copied += len(data)
                        if copied > before.st_size:
                            raise AppError("An imported file changed during copying.")
                        view = memoryview(data)
                        while view:
                            count = os.write(destination, view)
                            if count <= 0:
                                raise AppError("An imported file could not be copied.")
                            view = view[count:]
                    after = os.fstat(source)
                    if copied != before.st_size or (
                        after.st_size, after.st_mtime_ns, after.st_ctime_ns,
                    ) != (before.st_size, before.st_mtime_ns, before.st_ctime_ns):
                        raise AppError("An imported file changed during copying.")
                    os.close(destination)
                    destination = None
                    os.link(staged, self.imports / name, follow_symlinks=False)
                    added.append({"id": name, "name": name, "size": copied, "path": "/workspace/imports/" + name})
                    existing += copied
                finally:
                    os.close(source)
                    if destination is not None:
                        os.close(destination)
                    if staged is not None:
                        staged.unlink(missing_ok=True)
            self.items.extend(added)
        except BaseException:
            for item in added:
                (self.imports / item["id"]).unlink(missing_ok=True)
            raise

    def remove(self, identifiers):
        self.require_stopped()
        for identifier in identifiers:
            if identifier not in {item["id"] for item in self.items}:
                raise AppError("The selected imported file is unavailable.")
            path = self.imports / file_name(identifier)
            if path.is_dir() and not path.is_symlink():
                raise AppError("Clear the workspace to remove generated directories.")
            path.unlink(missing_ok=True)
        self.items = [item for item in self.items if item["id"] not in identifiers]

    def start(self, settings=None, urls=(), parent_window=None, private_window=False):
        self.require_stopped()
        urls = browser_urls(urls)
        settings = display_settings(settings)
        if parent_window is not None and (type(parent_window) is not int or not 0 < parent_window < 2 ** 32):
            raise AppError("The browser display parent is invalid.")
        if self.plan is None:
            try:
                self.plan = prepare_browser(self.home)
            except ProfileError as error:
                raise AppError(str(error)) from error
        try:
            revalidate_browser(self.plan)
        except ProfileError as error:
            raise AppError(str(error)) from error
        arguments = list(self.plan.command) + browser_arguments(urls, private_window)
        self.outputs()
        ram_directory()
        limit = memory_budget()
        display = re.fullmatch(r":(\d+)(?:\.\d+)?", os.environ.get("DISPLAY", ""))
        if not display:
            raise AppError("A local X11 desktop is required.")
        host_socket = Path("/tmp/.X11-unix/X" + display.group(1))
        if not host_socket.is_socket():
            raise AppError("The desktop display socket is unavailable.")
        auth = Path(os.environ.get("XAUTHORITY") or str(Path.home() / ".Xauthority"))
        with auth.open("rb") as stream:
            credentials = stream.read(1024 * 1024 + 1)
        if not credentials or len(credentials) > 1024 * 1024:
            raise AppError("The desktop display credentials are unavailable.")
        host_auth = self.directory / "host.auth"
        host_auth.write_bytes(credentials)
        host_auth.chmod(0o600)
        self.unit = "ph4ntxm-browser-airlock-" + uuid.uuid4().hex + ".service"
        for name in (
            "state.json",
            "request.json",
            "state.json.new",
            "last-failure.json.new",
            "request.json.new",
        ):
            (self.directory / name).unlink(missing_ok=True)
        sockets = self.directory / "x11"
        if sockets.exists():
            remove_tree(sockets)
        configuration = self.directory / "config"
        if configuration.exists():
            remove_tree(configuration)
        write_json(
            self.directory / "request.json",
            {
                "command": arguments,
                "environment": self.plan.environment,
                "readonly_paths": list(self.plan.readonly_paths),
                "mode": self.plan.mode,
                "profile_path": self.plan.profile_path,
                "launcher_pid": os.getpid(),
                "launcher_start": process_start(os.getpid()),
                "display": int(display.group(1)),
                "settings": settings or {},
                "parent_window": parent_window,
            },
        )
        try:
            command(
                [
                    "/usr/bin/systemd-run",
                    "--user",
                    "--quiet",
                    "--collect",
                    "--unit=" + self.unit,
                    "-p",
                    "MemoryMax=" + str(limit),
                    "-p",
                    "MemorySwapMax=0",
                    "-p",
                    "TasksMax=512",
                    "-p",
                    "CPUQuota=400%",
                    "-p",
                    "KillMode=control-group",
                    "-p",
                    "TimeoutStopSec=3s",
                    "-p",
                    "RuntimeMaxSec=43200",
                    "-p",
                    "LimitCORE=0",
                    "-p",
                    "LimitFSIZE=" + str(MAX_FILE),
                    "-p",
                    "StandardInput=null",
                    "-p",
                    "StandardOutput=null",
                    "-p",
                    "StandardError=null",
                    "--",
                    "/usr/bin/python3",
                    "-I",
                    str(LIB / "browser_airlock.py"),
                    "--session",
                    str(self.directory),
                ],
                env=environment(),
                capture_output=True,
            )
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                values = unit_state(self.unit)
                self.cgroup = values.get("ControlGroup") or self.cgroup
                state_path = self.directory / "state.json"
                if state_path.exists():
                    values = read_json(state_path)
                    if values["state"] == "running":
                        self.running = True
                        return
                    if values["state"] in {"failed", "finished"}:
                        raise AppError(
                            values.get("message")
                            or "The isolated application exited during startup."
                        )
                if stopped(self.unit, self.cgroup):
                    raise AppError(
                        "The isolated application could not start. Check the Browser Airlock prerequisites."
                    )
                time.sleep(0.1)
            raise AppError("The isolated application did not become ready.")
        except BaseException:
            self.stop()
            raise

    def open_urls(self, urls, private_window=False):
        values = browser_arguments(urls, private_window)
        if not self.unit or stopped(self.unit, self.cgroup):
            raise AppError("The isolated browser is not running.")
        if not values:
            return
        try:
            revalidate_browser(self.plan)
        except ProfileError as error:
            raise AppError(str(error)) from error
        forward_urls(self.directory / "bus/bus", urls, private_window)

    def snapshot(self):
        if self.closed:
            return {
                "running": False,
                "state": "closed",
                "message": "The session is closed.",
                "exit_code": None,
            }
        if not self.unit:
            return {
                "running": False,
                "state": "ready",
                "message": "Private browser workspace ready.",
                "exit_code": None,
            }
        alive = not stopped(self.unit, self.cgroup)
        path = self.directory / "state.json"
        state = (
            read_json(path)
            if path.exists()
            else {
                "state": "starting",
                "message": "Starting the isolated browser.",
                "exit_code": None,
            }
        )
        if not alive and state["state"] not in {"failed", "finished"}:
            state = {
                "state": "finished",
                "message": "The isolated application has stopped.",
                "exit_code": None,
            }
        self.running = alive
        return {**state, "running": alive}

    def stop(self):
        if self.unit and not stopped(self.unit, self.cgroup):
            subprocess.run(
                ["/usr/bin/systemctl", "--user", "stop", self.unit],
                env=environment(),
                capture_output=True,
                timeout=12,
            )
            if not stopped(self.unit, self.cgroup):
                raise AppError(
                    "The isolated application has not stopped. Export remains unavailable."
                )
        self.running = False

    def outputs(self):
        self.require_stopped()
        result = []
        total = 0
        visited = 0

        def visit(descriptor, prefix="", depth=0):
            nonlocal total, visited
            if depth > 8:
                raise AppError("The workspace exceeds its directory depth limit.")
            names = []
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if visited + len(names) >= MAX_ENTRIES:
                        raise AppError(
                            "The workspace exceeds its 256-entry review limit. Clear the workspace to continue."
                        )
                    names.append(entry.name)
            for name in sorted(names):
                file_name(name)
                visited += 1
                if visited > MAX_ENTRIES:
                    raise AppError(
                        "The workspace exceeds its 256-entry review limit. Clear the workspace to continue."
                    )
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                relative = prefix + name
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=descriptor,
                    )
                    try:
                        visit(child, relative + "/", depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    if info.st_size > MAX_FILE:
                        raise AppError(
                            "A workspace file exceeds the 512 MiB export limit."
                        )
                    total += info.st_size
                    if total > MAX_OUTPUT:
                        raise AppError(
                            "Workspace results exceed the 1 GiB combined export limit."
                        )
                    result.append(
                        {"id": relative, "name": relative, "size": info.st_size}
                    )

        descriptor = os.open(
            self.downloads, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        try:
            visit(descriptor)
        finally:
            os.close(descriptor)
        return result

    def export(self, identifier, destination):
        self.require_stopped()
        records = {item["id"]: item for item in self.outputs()}
        if identifier not in records:
            raise AppError(
                "The selected result is unavailable or is not a regular file."
            )
        parts = identifier.split("/")
        descriptors = []
        output = None
        target = Path(destination).expanduser().absolute()
        created = False
        try:
            current = os.open(
                self.downloads,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            descriptors.append(current)
            for part in parts[:-1]:
                current = os.open(
                    file_name(part),
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=current,
                )
                descriptors.append(current)
            source = os.open(
                file_name(parts[-1]),
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=current,
            )
            descriptors.append(source)
            info = os.fstat(source)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_size > MAX_FILE
            ):
                raise AppError("Only bounded regular files can be exported.")
            output = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
            )
            created = True
            remaining = info.st_size
            while remaining:
                data = os.read(source, min(1024 * 1024, remaining))
                if not data:
                    raise AppError("The selected result changed during export.")
                remaining -= len(data)
                view = memoryview(data)
                while view:
                    written = os.write(output, view)
                    if written <= 0:
                        raise AppError("The selected result could not be exported.")
                    view = view[written:]
            if os.read(source, 1):
                raise AppError("The selected result changed during export.")
            os.fsync(output)
        except BaseException:
            if created:
                target.unlink(missing_ok=True)
            raise
        finally:
            if output is not None:
                os.close(output)
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def clear(self):
        self.require_stopped()
        remove_tree(self.workspace)
        self.workspace.mkdir(mode=0o700)
        self.imports.mkdir(mode=0o700)
        self.downloads.mkdir(mode=0o700)
        self.items = []

    def close(self):
        if self.closed:
            return
        self.stop()
        remove_tree(self.directory)
        self.closed = True


def configure(directory, settings, nested=100, username="ph4ntxm", home_path="/home/ph4ntxm"):
    directory.mkdir(mode=0o700)
    home = directory / "home"
    home.mkdir(mode=0o700)
    (home / "user-dirs.dirs").write_text('XDG_DOWNLOAD_DIR="/workspace/downloads"\n')
    gtk = home / "gtk-3.0"
    gtk.mkdir(parents=True)
    ini = configparser.ConfigParser(interpolation=None)
    ini["Settings"] = {
        key: str(settings.get(key, default))[:256]
        for key, default in (
            ("gtk-theme-name", "Adwaita"),
            ("gtk-icon-theme-name", "Adwaita"),
            ("gtk-font-name", "Sans 10"),
        )
    }
    ini["Settings"]["gtk-recent-files-enabled"] = "false"
    with (gtk / "settings.ini").open("w") as stream:
        ini.write(stream)
    channels = home / "xfce4/xfconf/xfce-perchannel-xml"
    channels.mkdir(parents=True)
    root = ET.Element("channel", name="xfwm4", version="1.0")
    general = ET.SubElement(root, "property", name="general", type="empty")
    for name, kind, value in (
        ("theme", "string", ini["Settings"]["gtk-theme-name"]),
        ("use_compositing", "bool", "false"),
        ("workspace_count", "int", "1"),
    ):
        ET.SubElement(general, "property", name=name, type=kind, value=value)
    ET.ElementTree(root).write(
        channels / "xfwm4.xml", encoding="utf-8", xml_declaration=True
    )
    values = [b"", str(nested).encode("ascii"), b"MIT-MAGIC-COOKIE-1", os.urandom(16)]
    (directory / "display").write_text(":%d" % nested)
    (directory / "nested.auth").write_bytes(
        struct.pack(">H", 65535)
        + b"".join(struct.pack(">H", len(v)) + v for v in values)
    )
    (directory / "passwd").write_text(
        "%s:x:%d:%d:Browser Airlock:%s:/bin/bash\n" % (username, os.getuid(), os.getgid(), home_path)
    )
    (directory / "group").write_text("%s:x:%d:\n" % (username, os.getgid()))
    (directory / "machine-id").write_text(uuid.uuid4().hex + "\n")
    (directory / "dbus.conf").write_text(
        "<busconfig><type>session</type><listen>unix:path=/control/bus</listen>"
        '<auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/>'
        '<allow receive_sender="*"/><allow own="*"/></policy></busconfig>\n'
    )


def configured(args, config):
    args += ["--ro-bind", str(config), "/config"]
    for name in ("passwd", "group", "machine-id"):
        args += ["--ro-bind", str(config / name), "/etc/" + name]
    return args


def wait_socket(path, process, endpoint="private display"):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AppError("The " + endpoint + " stopped before becoming ready.")
        if path.is_socket():
            return
        time.sleep(0.04)
    raise AppError("The " + endpoint + " did not become ready within 15 seconds.")


def display_settings(settings):
    if settings is None:
        settings = {}
    if not isinstance(settings, dict):
        raise AppError("The isolated display settings are invalid.")
    result = dict(settings)
    width = result.get("screen_width", 900)
    height = result.get("screen_height", 660)
    if type(width) is not int or type(height) is not int or not 128 <= width <= 8192 or not 128 <= height <= 8192 or width * height > 16777216:
        raise AppError("The isolated display size is invalid.")
    result.update(screen_width=width, screen_height=height)
    return result


def browser_urls(values):
    if not isinstance(values, (list, tuple)) or len(values) > 32:
        raise AppError("Open up to 32 browser links at a time.")
    result = []
    for value in values:
        if not isinstance(value, str) or len(value.encode("utf-8")) > 8192:
            raise AppError("The browser link is invalid.")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise AppError("The browser link contains control characters.")
        parsed = urlsplit(value)
        if parsed.scheme == "file":
            try:
                decoded = unquote(parsed.path, encoding="utf-8", errors="strict")
            except UnicodeError as error:
                raise AppError("The imported file link is invalid.") from error
            if parsed.netloc or parsed.query or parsed.fragment or not decoded.startswith("/workspace/imports/"):
                raise AppError("Open local files through Import Files.")
            name = file_name(decoded[len("/workspace/imports/"):])
            if Path("/workspace/imports", name).as_uri() != value:
                raise AppError("The imported file link is invalid.")
        elif parsed.scheme not in {"http", "https", "about"}:
            raise AppError("Open an HTTP, HTTPS, imported file or browser page link.")
        if parsed.scheme in {"http", "https"} and not parsed.netloc:
            raise AppError("The browser link has no destination.")
        if parsed.scheme == "about" and value not in {"about:blank", "about:newtab", "about:preferences", "about:support"}:
            raise AppError("The browser page is unavailable.")
        result.append(value)
    return result


def browser_arguments(urls, private_window=False):
    if type(private_window) is not bool:
        raise AppError("The browser window request is invalid.")
    return (["-private-window"] if private_window else []) + browser_urls(urls)


def forward_urls(path, urls, private_window=False):
    urls = browser_arguments(urls, private_window)
    from gi.repository import Gio, GLib

    connection = Gio.DBusConnection.new_for_address_sync(
        "unix:path=" + str(path),
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
        None,
        None,
    )
    try:
        def bus_call(method, arguments=None):
            return connection.call_sync(
                "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                method, arguments, None, Gio.DBusCallFlags.NO_AUTO_START, 1000, None,
            ).unpack()[0]

        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            targets = set()
            for name in bus_call("ListNames"):
                match = re.fullmatch(r"org\.mozilla\.([A-Za-z0-9_]+)\.[A-Za-z0-9_]+", name)
                if match:
                    targets.add((bus_call("GetNameOwner", GLib.Variant("(s)", (name,))), match.group(1)))
            if len(targets) > 1:
                raise AppError("More than one isolated browser session is active.")
            if targets:
                owner, application = targets.pop()
                arguments = ["firefox", *urls]
                data = b"/workspace\0"
                offsets = []
                header_size = 4 * (len(arguments) + 1)
                for argument in arguments:
                    offsets.append(header_size + len(data))
                    data += os.fsencode(argument) + b"\0"
                data = struct.pack("<" + "I" * (len(arguments) + 1), len(arguments), *offsets) + data
                connection.call_sync(
                    owner, "/org/mozilla/" + application + "/Remote", "org.mozilla." + application,
                    "OpenURL", GLib.Variant("(ay)", (data,)), None,
                    Gio.DBusCallFlags.NO_AUTO_START, 5000, None,
                )
                return
            time.sleep(0.1)
        raise AppError("The isolated browser is not ready to receive links.")
    finally:
        connection.close_sync(None)


def inside():
    shutil.copytree("/config/home", Path(os.environ["HOME"]) / ".config", dirs_exist_ok=True)
    os.environ.update(
        DISPLAY=Path("/config/display").read_text(),
        XAUTHORITY="/config/nested.auth",
        DBUS_SESSION_BUS_ADDRESS="unix:path=/control/bus",
    )
    children = []
    display = None
    try:
        display = DisplaySync()
        display.poll()
        downloads = Path(os.environ["HOME"]) / "Downloads"
        if not downloads.exists() and not downloads.is_symlink():
            downloads.symlink_to("/workspace/downloads")
        bus = subprocess.Popen(
            ["/usr/bin/dbus-daemon", "--nofork", "--config-file=/config/dbus.conf"],
            stdin=subprocess.DEVNULL,
        )
        children.append(bus)
        wait_socket(Path("/control/bus"), bus, "private session bus")
        xfconf = next(Path("/usr/lib").glob("*/xfce4/xfconf/xfconfd"))
        children.append(subprocess.Popen([str(xfconf)], stdin=subprocess.DEVNULL))
        children.append(
            subprocess.Popen(
                ["/usr/bin/xfwm4", "--compositor=off", "--sm-client-disable"],
                stdin=subprocess.DEVNULL,
            )
        )
        payload = read_json("/config/launch.json")["arguments"]
        application = subprocess.Popen(payload, stdin=subprocess.DEVNULL)
        children.append(application)
        while application.poll() is None:
            display.poll()
            if bus.poll() is not None or children[2].poll() is not None:
                raise AppError("An isolated desktop component stopped.")
            time.sleep(0.2)
        print("Browser Airlock: browser process exited with status %d." % application.returncode, file=sys.stderr, flush=True)
        return application.returncode
    finally:
        if display is not None:
            display.close()
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()


def display_command(nested, settings, parent_window):
    args = ["/usr/bin/Xephyr", ":%d" % nested]
    if parent_window is not None:
        args += ["-parent", str(parent_window)]
    return args + [
        "-screen",
        "%dx%d" % (settings["screen_width"], settings["screen_height"]),
        "-resizeable",
        "-nolisten",
        "tcp",
        "-no-host-grab",
        "-auth",
        "/config/nested.auth",
        "-extension",
        "XTEST",
        "-noreset",
        "-title",
        "PH4NTXM Browser Airlock",
    ]


def completion_state(application_code, display_code):
    codes = {"browser_worker": application_code, "display": display_code}
    exited = {name: value for name, value in codes.items() if value is not None}
    failed_codes = [value for value in exited.values() if value != 0]
    display_stopped = display_code is not None and application_code is None
    failed = bool(failed_codes) or display_stopped or not exited
    code = failed_codes[0] if failed_codes else next(iter(exited.values()), None)
    if display_stopped:
        message = "The isolated display stopped while the browser worker was still running."
    elif application_code is not None and display_code is not None:
        message = "The isolated browser worker and display stopped."
    elif application_code is not None:
        message = "The isolated browser worker stopped."
    else:
        message = "The isolated browser state could not be determined."
    if code is not None:
        message += " Exit status: %d." % code
    return {
        "state": "failed" if failed else "finished",
        "message": message,
        "exit_code": code,
        "components": codes,
    }


def memory_outcome(state, memory):
    state = {**state, "memory": memory}
    events = memory.get("memory.events", {})
    if events.get("oom_kill", 0) <= 0 and events.get("oom_group_kill", 0) <= 0:
        return state
    state["state"] = "failed"
    if events.get("max", 0) > 0 and events.get("oom", 0) > 0:
        state["reason"] = "memory-limit"
        limit = memory.get("memory.max")
        suffix = " (%d MiB)" % (limit // (1024 * 1024)) if type(limit) is int else ""
        state["message"] = "The browser sandbox hit its memory limit" + suffix + ". An out-of-memory kill was recorded."
    else:
        state["reason"] = "out-of-memory"
        state["message"] = "An out-of-memory kill was detected in the browser sandbox."
    return state


def session(directory):
    directory = Path(directory)
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise AppError("The private Browser Airlock directory could not be verified.")
    group = next(
        line.split(":", 2)[2]
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    )
    cgroup = Path("/sys/fs/cgroup") / group.lstrip("/")
    if (cgroup / "memory.max").read_text().strip() == "max" or (
        cgroup / "memory.swap.max"
    ).read_text().strip() != "0":
        raise AppError("The Browser Airlock resource limits are not active.")
    request = read_json(directory / "request.json")
    nested = 101 if request["display"] == 100 else 100
    configure(directory / "config", request["settings"], nested, request["environment"]["USER"], request["environment"]["HOME"])
    sockets = directory / "x11"
    sockets.mkdir(mode=0o700, exist_ok=True)
    descriptor = filter_fd()
    children = []
    controller = None
    offline_descriptor = None
    diagnostics = {}
    readers = []

    def capture(process):
        try:
            while True:
                chunk = os.read(process.stderr.fileno(), 1024)
                if not chunk:
                    break
                diagnostics[process].extend(chunk)
                del diagnostics[process][:-4096]
        finally:
            process.stderr.close()

    def details(limit=480):
        return " ".join(
            diagnostic_text(bytes(value), limit=2048, tail=True) for process, value in diagnostics.items()
            if process.poll() is not None and value
        )[-limit:]

    def spawn(args, filter_descriptor=None):
        number = os.open("/proc/self/fd/%d" % (descriptor if filter_descriptor is None else filter_descriptor), os.O_RDONLY | os.O_CLOEXEC)
        args[1] = str(number)
        args[args.index("--seccomp") + 1] = str(number)
        try:
            process = subprocess.Popen(
                args,
                pass_fds=(number,),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        finally:
            os.close(number)
        diagnostics[process] = bytearray()
        reader = threading.Thread(target=capture, args=(process,), daemon=True)
        reader.start()
        readers.append(reader)
        children.append(process)
        return process

    def terminate(_signal, _frame):
        raise SessionStopped("The isolated session was stopped.")

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    state = {
        "state": "failed",
        "message": "The isolated application could not start.",
        "exit_code": None,
    }
    try:
        controller = os.pidfd_open(request["launcher_pid"], 0)
        if process_start(request["launcher_pid"]) != request["launcher_start"]:
            raise SessionStopped("The controlling application is unavailable.")
        write_json(directory / "config/launch.json", {"arguments": request["command"]})
        host = request["display"]
        offline_descriptor = filter_fd(offline=True)
        display_args = configured(sandbox(offline_descriptor, offline=True), directory / "config") + [
            "--bind",
            str(sockets),
            "/tmp/.X11-unix",
            "--ro-bind",
            "/tmp/.X11-unix/X%d" % host,
            "/tmp/.X11-unix/X%d" % host,
            "--ro-bind",
            str(directory / "host.auth"),
            "/run/host.auth",
            "--setenv",
            "DISPLAY",
            ":%d" % host,
            "--setenv",
            "XAUTHORITY",
            "/run/host.auth",
            str(EXEC / "guard"),
            "run",
            "--",
        ] + display_command(nested, request["settings"], request["parent_window"])
        display = spawn(display_args, offline_descriptor)
        wait_socket(sockets / ("X%d" % nested), display, "Xephyr display")
        control = directory / "bus"
        control.mkdir(mode=0o700, exist_ok=True)
        (control / "bus").unlink(missing_ok=True)
        payload_args = configured(sandbox(descriptor), directory / "config")
        if request["mode"] != "lonewolf":
            payload_args = identity_bindings(payload_args)
        for path in request["readonly_paths"]:
            payload_args += ["--ro-bind", path, path]
        payload_args += ["--bind", str(directory / "home"), request["environment"]["HOME"], "--bind", str(control), "/control"]
        payload_args = profile_binding(payload_args, request["profile_path"])
        if request["mode"] == "lonewolf":
            payload_args = tor_bindings(payload_args, request["environment"]["HOME"])
        for key, value in request["environment"].items():
            payload_args += ["--setenv", key, value]
        payload_args += [
            "--ro-bind",
            str(sockets / ("X%d" % nested)),
            "/tmp/.X11-unix/X%d" % nested,
            "--ro-bind",
            str(directory / "workspace"),
            "/workspace",
            "--bind",
            str(directory / "workspace/downloads"),
            "/workspace/downloads",
            str(EXEC / "guard"),
            "run",
            "--",
            "/usr/bin/python3",
            "-I",
            str(LIB / "browser_airlock.py"),
            "--inside",
        ]
        application = spawn(payload_args)
        wait_socket(control / "bus", application, "browser session bus")
        time.sleep(0.5)
        if application.poll() is not None or display.poll() is not None:
            raise AppError(
                "The isolated desktop could not start. No application was opened outside Airlock."
            )
        record_state(
            directory,
            {
                "state": "running",
                "message": "Isolated browser running. Downloads remain in private RAM.",
                "memory_limit": int((cgroup / "memory.max").read_text().strip()),
                "exit_code": None,
            },
        )
        while application.poll() is None and display.poll() is None:
            if select.select([controller], [], [], 0.2)[0]:
                raise SessionStopped("The controlling application is unavailable.")
        state = completion_state(application.poll(), display.poll())
    except SessionStopped:
        state = {
            "state": "finished",
            "message": "The isolated session was stopped. Results remain in private RAM.",
            "exit_code": None,
        }
    except (AppError, OSError, ValueError, subprocess.SubprocessError) as error:
        state["message"] = str(error)
        if details():
            state["message"] += " " + details()
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        os.close(descriptor)
        if offline_descriptor is not None:
            os.close(offline_descriptor)
        if controller is not None:
            os.close(controller)
        for reader in readers:
            reader.join(timeout=1)
        state["diagnostics"] = details(4096)
        memory = {}
        for name in ("memory.events", "memory.peak", "memory.max"):
            try:
                value = (cgroup / name).read_text().strip()
                if name == "memory.events":
                    memory[name] = {key: int(number) for key, number in (line.split() for line in value.splitlines())}
                else:
                    memory[name] = int(value) if value.isdigit() else value
            except (OSError, ValueError):
                pass
        state = memory_outcome(state, memory)
        record_state(directory, state)
    return 1 if state["state"] == "failed" else 0


def probe():
    assert len([name for name in os.listdir("/proc") if name.isdigit()]) <= 4
    assert not os.listdir("/sys")
    for path in ("/run/user", "/run/dbus/system_bus_socket", "/dev/dri", "/dev/sda", "/etc/shadow", "/tmp/.X11-unix"):
        assert not os.path.exists(path)
    assert ctypes.CDLL(None).prctl(39, 0, 0, 0, 0) == 1
    for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
        try:
            with socket.socket(family):
                pass
        except OSError as error:
            if family != socket.AF_INET6 or error.errno not in {errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT}:
                raise
    for family in (socket.AF_NETLINK, socket.AF_PACKET):
        try:
            socket.socket(family)
        except PermissionError:
            pass
        else:
            raise AppError("The browser socket filter is not active.")
    return 0


def main():
    parser = argparse.ArgumentParser(description="PH4NTXM Browser Airlock runtime")
    parser.add_argument("--session")
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--probe", action="store_true")
    arguments = parser.parse_args()
    if arguments.session:
        return session(arguments.session)
    if arguments.inside:
        return inside()
    if arguments.probe:
        return probe()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
