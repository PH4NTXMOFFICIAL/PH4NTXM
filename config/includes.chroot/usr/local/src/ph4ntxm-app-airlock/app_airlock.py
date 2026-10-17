# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import argparse
import configparser
import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import select
import shlex
import signal
import stat
import struct
import subprocess
import tempfile
import time
import unicodedata
import uuid
from xml.etree import ElementTree as ET

LIB = Path("/usr/local/lib/ph4ntxm-app-airlock")
EXEC = Path("/usr/local/libexec/ph4ntxm-app-airlock")
APPLICATIONS = Path("/usr/share/applications")

MAX_FILES = 32
MAX_INPUT = 64 * 1024 * 1024
MAX_OUTPUT = 128 * 1024 * 1024
MAX_ENTRIES = 256
RESERVE = 192 * 1024 * 1024
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


class AppError(Exception):
    pass


class SessionStopped(AppError):
    pass


def command(args, **kwargs):
    return subprocess.run(args, check=True, timeout=kwargs.pop("timeout", 10), **kwargs)


def trusted(path):
    info = Path(path).stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise AppError("An App Airlock runtime component could not be verified.")
    if not os.access(path, os.X_OK):
        raise AppError("An App Airlock runtime component is unavailable.")


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


def ram_directory():
    if (
        command(
            ["/usr/bin/findmnt", "-n", "-o", "FSTYPE", "-T", "/tmp"],
            capture_output=True,
            text=True,
        ).stdout.strip()
        != "tmpfs"
    ):
        raise AppError("App Airlock temporary storage must reside in RAM.")
    if len(Path("/proc/swaps").read_text().splitlines()) > 1:
        raise AppError("Disable swap before using App Airlock.")
    return Path("/tmp")


def memory_budget(storage=0):
    if any(key.startswith("PH4_INVENTORY_") for key in os.environ):
        raise AppError("Open App Airlock from the desktop to check actual RAM.")
    values = dict(
        re.findall(r"^(\w+):\s+(\d+) kB$", Path("/proc/meminfo").read_text(), re.M)
    )
    available = int(values["MemAvailable"]) * 1024
    limit = min(768 * 1024 * 1024, available - RESERVE - storage)
    if limit < 256 * 1024 * 1024:
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


def application_command(value):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > 4096
    ):
        raise AppError("Enter an application command of at most 4096 UTF-8 bytes.")
    try:
        arguments = shlex.split(value)
    except ValueError as error:
        raise AppError("Check the command quotation marks.") from error
    if (
        not arguments
        or len(arguments) > 128
        or any("\x00" in argument for argument in arguments)
    ):
        raise AppError("Enter a command with at most 128 arguments.")
    return arguments


def desktop_entry(identifier):
    path = APPLICATIONS / file_name(identifier)
    if path.suffix != ".desktop":
        raise AppError("Choose an installed application.")
    with path.open("rb") as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise AppError("The application entry is too large.")
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.read_string(data.decode("utf-8"))
    entry = parser["Desktop Entry"]
    if (
        entry.get("Type") != "Application"
        or entry.get("Hidden", "false").lower() == "true"
        or not entry.get("Exec")
    ):
        raise AppError("The application entry is unavailable.")
    return entry


def applications():
    result = []
    for path in APPLICATIONS.glob("*.desktop"):
        try:
            entry = desktop_entry(path.name)
            result.append({"id": path.name, "name": entry.get("Name", path.stem)})
        except (OSError, UnicodeError, configparser.Error, KeyError, AppError):
            continue
    return sorted(result, key=lambda item: (item["name"].casefold(), item["id"]))


def desktop_command(identifier, selected=None):
    entry = desktop_entry(identifier)
    arguments = application_command(entry["Exec"])
    result = []
    path = "/workspace/" + file_name(selected) if selected else None
    replacements = {
        "c": entry.get("Name", identifier),
        "k": str(APPLICATIONS / identifier),
    }
    for argument in arguments:
        if argument in {"%f", "%F", "%u", "%U"}:
            if path:
                result.append(Path(path).as_uri() if argument in {"%u", "%U"} else path)
        elif argument == "%i":
            if entry.get("Icon"):
                result += ["--icon", entry["Icon"]]
        elif argument not in {"%d", "%D", "%n", "%N", "%v", "%m"}:
            value = []
            index = 0
            while index < len(argument):
                if argument[index] != "%":
                    value.append(argument[index])
                    index += 1
                    continue
                index += 1
                if index == len(argument):
                    raise AppError(
                        "The application entry contains an invalid field code."
                    )
                code = argument[index]
                if code == "%":
                    value.append("%")
                elif code in replacements:
                    value.append(replacements[code])
                elif code in {"f", "u"} and path:
                    value.append(Path(path).as_uri() if code == "u" else path)
                else:
                    raise AppError(
                        "The application entry contains an unsupported field code."
                    )
                index += 1
            result.append("".join(value))
    if not result:
        raise AppError("The application entry contains no command.")
    return result


def process_start(pid):
    return Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()[19]


def filter_fd():
    data = command([str(EXEC / "guard"), "filter"], capture_output=True).stdout
    if not data or len(data) % 8 or len(data) > 32768:
        raise AppError("The App Airlock syscall filter is invalid.")
    descriptor = os.memfd_create(
        "ph4ntxm-app-airlock-filter", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
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


def sandbox(descriptor):
    args = [
        str(EXEC / "bwrap"),
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--hostname",
        "app-airlock",
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
        "--dir",
        "/sys",
        "--dev",
        "/dev",
        "--size",
        str(128 * 1024 * 1024),
        "--tmpfs",
        "/tmp",
        "--size",
        str(16 * 1024 * 1024),
        "--tmpfs",
        "/run",
        "--size",
        str(64 * 1024 * 1024),
        "--tmpfs",
        "/home/airlock",
        "--dir",
        "/etc",
        "--dir",
        "/workspace",
        "--dir",
        "/var/cache",
        "--tmpfs",
        "/usr/share/dbus-1/services",
        "--chdir",
        "/workspace",
        "--seccomp",
        str(descriptor),
    ]
    for path in (
        "/etc/fonts",
        "/etc/ld.so.cache",
        "/etc/alternatives",
        "/var/cache/fontconfig",
    ):
        if Path(path).exists():
            args += ["--ro-bind", path, path]
    for key, value in {
        **SAFE_ENV,
        "HOME": "/home/airlock",
        "USER": "airlock",
        "LOGNAME": "airlock",
        "XDG_RUNTIME_DIR": "/run",
        "XDG_CONFIG_HOME": "/home/airlock/.config",
        "XDG_CACHE_HOME": "/home/airlock/.cache",
        "XDG_DATA_HOME": "/home/airlock/.local/share",
        "XDG_CONFIG_DIRS": "/config/xdg",
        "NO_AT_BRIDGE": "1",
        "GDK_BACKEND": "x11",
        "GDK_GL": "disable",
        "LIBGL_ALWAYS_SOFTWARE": "true",
        "GSETTINGS_BACKEND": "memory",
        "GIO_USE_VFS": "local",
        "GIO_USE_VOLUME_MONITOR": "unix",
        "PS1": "airlock:\\w\\$ ",
    }.items():
        args += ["--setenv", key, value]
    return args


def check_ready():
    if os.getuid() == 0:
        raise AppError("Open App Airlock from the normal desktop account.")
    for path in (
        EXEC / "guard",
        EXEC / "bwrap",
        "/usr/bin/Xephyr",
        "/usr/bin/xterm",
        "/usr/bin/xfwm4",
        "/usr/bin/mousepad",
        "/usr/bin/python3",
        "/usr/bin/bash",
        "/usr/bin/dbus-daemon",
        "/usr/bin/systemd-run",
        "/usr/bin/systemctl",
    ):
        trusted(path)
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
                str(LIB / "app_airlock.py"),
                "--probe",
            ],
            pass_fds=(descriptor,),
            capture_output=True,
            timeout=15,
        )
    except subprocess.CalledProcessError as error:
        raise AppError(
            "App Airlock isolation is unavailable. No application was opened."
        ) from error
    finally:
        os.close(descriptor)


def read_json(path):
    with Path(path).open("rb") as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise AppError("The App Airlock control record is invalid.")
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
    if result.returncode and not values:
        raise AppError("The App Airlock service state could not be verified.")
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
            tempfile.mkdtemp(prefix="ph4ntxm-app-airlock-", dir=ram_directory())
        )
        self.workspace = self.directory / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.items = []
        self.unit = None
        self.cgroup = ""
        self.running = False
        self.closed = False

    def require_stopped(self):
        if self.closed:
            raise AppError("The App Airlock session is closed.")
        if self.unit and not stopped(self.unit, self.cgroup):
            raise AppError(
                "Stop the isolated application before changing or exporting files."
            )
        self.running = False

    def add(self, paths):
        self.require_stopped()
        if len(self.items) + len(paths) > MAX_FILES:
            raise AppError("Import up to 32 files per workspace.")
        existing = sum(item["size"] for item in self.items)
        added = []
        try:
            for value in paths:
                path = Path(value).expanduser().absolute()
                name = file_name(path.name)
                if str(path).startswith(("/proc/", "/sys/", "/dev/")):
                    raise AppError("Import a regular file.")
                source = os.open(
                    path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                )
                destination = None
                created = False
                try:
                    before = os.fstat(source)
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or not 0 < before.st_size <= MAX_INPUT
                    ):
                        raise AppError(
                            "Import nonempty regular files of at most 64 MiB."
                        )
                    if existing + before.st_size > MAX_INPUT:
                        raise AppError(
                            "Imported files must not exceed 64 MiB combined."
                        )
                    memory_budget(before.st_size)
                    destination = os.open(
                        self.workspace / name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                        0o600,
                    )
                    created = True
                    copied = 0
                    while True:
                        data = os.read(
                            source, min(1024 * 1024, before.st_size - copied + 1)
                        )
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
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    ) != (before.st_size, before.st_mtime_ns, before.st_ctime_ns):
                        raise AppError("An imported file changed during copying.")
                except BaseException:
                    if created:
                        (self.workspace / name).unlink(missing_ok=True)
                    raise
                finally:
                    os.close(source)
                    if destination is not None:
                        os.close(destination)
                added.append({"id": name, "name": name, "size": copied})
                existing += copied
            self.items.extend(added)
        except BaseException:
            for item in added:
                (self.workspace / item["id"]).unlink(missing_ok=True)
            raise

    def remove(self, identifiers):
        self.require_stopped()
        for identifier in identifiers:
            if identifier not in {item["id"] for item in self.items}:
                raise AppError("The selected imported file is unavailable.")
            path = self.workspace / file_name(identifier)
            if path.is_dir() and not path.is_symlink():
                raise AppError("Clear the workspace to remove generated directories.")
            path.unlink(missing_ok=True)
        self.items = [item for item in self.items if item["id"] not in identifiers]

    def start(
        self, application_id=None, selected_id=None, settings=None, custom_command=None
    ):
        self.require_stopped()
        if bool(application_id) == bool(custom_command):
            raise AppError("Choose an application or enter a command.")
        if application_id and selected_id is not None:
            if selected_id not in {item["id"] for item in self.items}:
                raise AppError("Select an imported file.")
            source = self.workspace / file_name(selected_id)
            if not stat.S_ISREG(source.lstat().st_mode):
                raise AppError(
                    "The selected imported file is no longer a regular file."
                )
        arguments = (
            desktop_command(application_id, selected_id)
            if application_id
            else application_command(custom_command)
        )
        terminal = True
        if application_id:
            entry = desktop_entry(application_id)
            terminal = entry.get("Terminal", "false").strip().lower() == "true"
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
        self.unit = "ph4ntxm-app-airlock-" + uuid.uuid4().hex + ".service"
        for name in (
            "state.json",
            "request.json",
            "state.json.new",
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
                "terminal": terminal,
                "launcher_pid": os.getpid(),
                "launcher_start": process_start(os.getpid()),
                "display": int(display.group(1)),
                "settings": settings or {},
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
                    "TasksMax=128",
                    "-p",
                    "CPUQuota=200%",
                    "-p",
                    "KillMode=control-group",
                    "-p",
                    "TimeoutStopSec=3s",
                    "-p",
                    "RuntimeMaxSec=7200",
                    "-p",
                    "LimitCORE=0",
                    "-p",
                    "LimitFSIZE=" + str(MAX_INPUT),
                    "-p",
                    "StandardInput=null",
                    "-p",
                    "StandardOutput=null",
                    "-p",
                    "StandardError=null",
                    "--",
                    "/usr/bin/python3",
                    "-I",
                    str(LIB / "app_airlock.py"),
                    "--session",
                    str(self.directory),
                ],
                env=environment(),
                capture_output=True,
            )
            for _ in range(150):
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
                        "The isolated application could not start. Check the App Airlock prerequisites."
                    )
                time.sleep(0.1)
            raise AppError("The isolated application did not become ready.")
        except BaseException:
            self.stop()
            raise

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
                "message": "Offline workspace ready.",
                "exit_code": None,
            }
        alive = not stopped(self.unit, self.cgroup)
        path = self.directory / "state.json"
        state = (
            read_json(path)
            if path.exists()
            else {
                "state": "starting",
                "message": "Starting the isolated application.",
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
                    if info.st_size > MAX_INPUT:
                        raise AppError(
                            "A workspace file exceeds the 64 MiB export limit."
                        )
                    total += info.st_size
                    if total > MAX_OUTPUT:
                        raise AppError(
                            "Workspace results exceed the 128 MiB combined export limit."
                        )
                    result.append(
                        {"id": relative, "name": relative, "size": info.st_size}
                    )

        descriptor = os.open(
            self.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
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
                self.workspace,
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
                or info.st_size > MAX_INPUT
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
        self.items = []

    def close(self):
        if self.closed:
            return
        self.stop()
        remove_tree(self.directory)
        self.closed = True


def configure(directory, settings, nested=100):
    directory.mkdir(mode=0o700)
    home = directory / "home"
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
        "airlock:x:%d:%d:Airlock:/home/airlock:/bin/bash\n" % (os.getuid(), os.getgid())
    )
    (directory / "group").write_text("airlock:x:%d:\n" % os.getgid())
    (directory / "machine-id").write_text(uuid.uuid4().hex + "\n")
    (directory / "dbus.conf").write_text(
        "<busconfig><type>session</type><listen>unix:path=/run/bus</listen>"
        '<auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/>'
        '<allow receive_sender="*"/><allow own="*"/></policy></busconfig>\n'
    )


def configured(args, config):
    args += ["--ro-bind", str(config), "/config"]
    for name in ("passwd", "group", "machine-id"):
        args += ["--ro-bind", str(config / name), "/etc/" + name]
    return args


def wait_socket(path, process):
    for _ in range(150):
        if process.poll() is not None:
            raise AppError("An isolated display component could not start.")
        if path.is_socket():
            return
        time.sleep(0.04)
    raise AppError("The isolated display did not become ready.")


def launch_command(launch):
    if not isinstance(launch, dict) or set(launch) != {"arguments", "terminal"}:
        raise AppError("The application launch record is invalid.")
    arguments = launch["arguments"]
    if (
        not isinstance(arguments, list)
        or not arguments
        or len(arguments) > 128
        or not all(
            isinstance(value, str) and "\x00" not in value for value in arguments
        )
        or not isinstance(launch["terminal"], bool)
    ):
        raise AppError("The application command is invalid.")
    if not launch["terminal"]:
        return arguments
    return [
        "/usr/bin/xterm",
        "-title",
        "PH4NTXM App Airlock - Offline",
        "-fa",
        "Monospace",
        "-fs",
        "11",
        "-hold",
        "-e",
        *arguments,
    ]


def inside():
    shutil.copytree("/config/home", "/home/airlock/.config", dirs_exist_ok=True)
    os.environ.update(
        DISPLAY=Path("/config/display").read_text(),
        XAUTHORITY="/config/nested.auth",
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/bus",
    )
    children = []
    try:
        bus = subprocess.Popen(
            ["/usr/bin/dbus-daemon", "--nofork", "--config-file=/config/dbus.conf"],
            stdin=subprocess.DEVNULL,
        )
        children.append(bus)
        wait_socket(Path("/run/bus"), bus)
        xfconf = next(Path("/usr/lib").glob("*/xfce4/xfconf/xfconfd"))
        children.append(subprocess.Popen([str(xfconf)], stdin=subprocess.DEVNULL))
        children.append(
            subprocess.Popen(
                ["/usr/bin/xfwm4", "--compositor=off", "--sm-client-disable"],
                stdin=subprocess.DEVNULL,
            )
        )
        payload = launch_command(read_json("/config/launch.json"))
        application = subprocess.Popen(payload, stdin=subprocess.DEVNULL)
        children.append(application)
        while application.poll() is None:
            if bus.poll() is not None or children[2].poll() is not None:
                raise AppError("An isolated desktop component stopped.")
            time.sleep(0.2)
        return application.returncode
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()


def session(directory):
    directory = Path(directory)
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise AppError("The private App Airlock directory could not be verified.")
    group = next(
        line.split(":", 2)[2]
        for line in Path("/proc/self/cgroup").read_text().splitlines()
        if line.startswith("0::")
    )
    cgroup = Path("/sys/fs/cgroup") / group.lstrip("/")
    if (cgroup / "memory.max").read_text().strip() == "max" or (
        cgroup / "memory.swap.max"
    ).read_text().strip() != "0":
        raise AppError("The App Airlock resource limits are not active.")
    request = read_json(directory / "request.json")
    nested = 101 if request["display"] == 100 else 100
    configure(directory / "config", request["settings"], nested)
    sockets = directory / "x11"
    sockets.mkdir(mode=0o700, exist_ok=True)
    descriptor = filter_fd()
    children = []
    controller = None

    def spawn(args):
        number = os.open("/proc/self/fd/%d" % descriptor, os.O_RDONLY | os.O_CLOEXEC)
        args[args.index("--seccomp") + 1] = str(number)
        try:
            process = subprocess.Popen(
                args,
                pass_fds=(number,),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        finally:
            os.close(number)
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
        write_json(
            directory / "config/launch.json",
            {"arguments": request["command"], "terminal": request["terminal"]},
        )
        host = request["display"]
        display_args = configured(sandbox(descriptor), directory / "config") + [
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
            "/usr/bin/Xephyr",
            ":%d" % nested,
            "-screen",
            "1100x700",
            "-resizeable",
            "-nolisten",
            "tcp",
            "-no-host-grab",
            "-auth",
            "/config/nested.auth",
            "-extension",
            "GLX",
            "-extension",
            "XTEST",
            "-noreset",
            "-title",
            "PH4NTXM App Airlock - Offline",
        ]
        display = spawn(display_args)
        wait_socket(sockets / ("X%d" % nested), display)
        payload_args = configured(sandbox(descriptor), directory / "config") + [
            "--ro-bind",
            str(sockets / ("X%d" % nested)),
            "/tmp/.X11-unix/X%d" % nested,
            "--bind",
            str(directory / "workspace"),
            "/workspace",
            str(EXEC / "guard"),
            "run",
            "--",
            "/usr/bin/python3",
            "-I",
            str(LIB / "app_airlock.py"),
            "--inside",
        ]
        application = spawn(payload_args)
        time.sleep(0.5)
        if application.poll() is not None or display.poll() is not None:
            raise AppError(
                "The isolated desktop could not start. No application was opened outside Airlock."
            )
        write_json(
            directory / "state.json",
            {
                "state": "running",
                "message": "Offline application running. Save results under /workspace.",
                "exit_code": None,
            },
        )
        while application.poll() is None and display.poll() is None:
            if select.select([controller], [], [], 0.2)[0]:
                raise SessionStopped("The controlling application is unavailable.")
        code = application.poll()
        state = {
            "state": "finished",
            "message": "The isolated application has stopped. Review results before exporting.",
            "exit_code": code,
        }
        return 0
    except SessionStopped:
        state = {
            "state": "finished",
            "message": "The isolated session was stopped. Results remain in private RAM.",
            "exit_code": None,
        }
        return 0
    except AppError as error:
        state["message"] = str(error)
        return 1
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
        if controller is not None:
            os.close(controller)
        write_json(directory / "state.json", state)


def probe():
    import socket

    assert not os.listdir("/proc")
    assert not os.listdir("/sys")
    for path in (
        "/run/user",
        "/run/dbus/system_bus_socket",
        "/dev/dri",
        "/dev/sda",
        "/etc/shadow",
        "/tmp/.X11-unix",
    ):
        assert not os.path.exists(path)
    assert ctypes.CDLL(None).prctl(39, 0, 0, 0, 0) == 1
    for family in (
        socket.AF_INET,
        socket.AF_INET6,
        socket.AF_NETLINK,
        socket.AF_PACKET,
    ):
        try:
            socket.socket(family)
        except PermissionError:
            pass
        else:
            raise AppError("The offline socket filter is not active.")
    descriptors = os.openpty()
    for descriptor in descriptors:
        os.close(descriptor)
    return 0


def main():
    parser = argparse.ArgumentParser(description="PH4NTXM App Airlock runtime")
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
