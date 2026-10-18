# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import contextlib
import fcntl
import json
import logging
import os
import re
import secrets
import select
import socket
import stat
import subprocess
import sys
import time


RUNTIME_DIRECTORY = "/run/ph4ntxm-dead-man-switch"
STATE_FILE = "state.json"
LOCK_FILE = "state.lock"
DAEMON_LOCK_FILE = "daemon.lock"
DEFAULT_MINUTES = 15
MIN_MINUTES = 1
MAX_MINUTES = 1440
WARNING_SECONDS = 60
HEARTBEAT_SECONDS = 1
STALE_SECONDS = 8
NS = 1_000_000_000
MAX_STATE_BYTES = 4096
MAX_INPUT_BYTES = 1024
INPUT_TIMEOUT_SECONDS = 5
WATCHDOG_NOTIFY_TIMEOUT_SECONDS = 0.2
PANIC_COMMAND = [
    "/usr/bin/systemctl", "start", "--no-block", "ph4ntxm-panic.service"
]
STATE_KEYS = {
    "version", "boot_id", "generation", "status", "duration_seconds",
    "deadline_boottime_ns", "heartbeat_boottime_ns", "dispatched"
}
GENERATION_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
BOOT_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
LOGGER = logging.getLogger("ph4ntxm-dead-man-switch")


class StateError(Exception):
    pass


class ActionError(Exception):
    pass


def boottime_ns():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def boot_id():
    with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as stream:
        value = stream.read(64).strip()
    if not BOOT_PATTERN.fullmatch(value):
        raise StateError("Current boot identity is unavailable")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def decode_json(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)


def valid_generation(value):
    return isinstance(value, str) and (
        value == "" or GENERATION_PATTERN.fullmatch(value) is not None
    )


def initial_state(current_boot, now):
    return {
        "version": 1,
        "boot_id": current_boot,
        "generation": "",
        "status": "disarmed",
        "duration_seconds": DEFAULT_MINUTES * 60,
        "deadline_boottime_ns": 0,
        "heartbeat_boottime_ns": now,
        "dispatched": False,
    }


def validate_state(value, current_boot):
    if not isinstance(value, dict) or set(value) != STATE_KEYS:
        raise StateError("Timer state is invalid")
    if type(value["version"]) is not int or value["version"] != 1:
        raise StateError("Timer state version is invalid")
    if value["boot_id"] != current_boot:
        raise StateError("Timer state belongs to a different boot")
    if not valid_generation(value["generation"]):
        raise StateError("Timer state generation is invalid")
    if value["status"] not in ("disarmed", "armed", "triggered"):
        raise StateError("Timer state status is invalid")
    duration = value["duration_seconds"]
    if (
        type(duration) is not int or duration < MIN_MINUTES * 60
        or duration > MAX_MINUTES * 60 or duration % 60 != 0
    ):
        raise StateError("Timer state duration is invalid")
    for name in ("deadline_boottime_ns", "heartbeat_boottime_ns"):
        if type(value[name]) is not int or not 0 <= value[name] < 2 ** 63:
            raise StateError("Timer state time is invalid")
    if value["heartbeat_boottime_ns"] <= 0:
        raise StateError("Timer state heartbeat is invalid")
    if type(value["dispatched"]) is not bool:
        raise StateError("Timer state dispatch status is invalid")
    if value["status"] == "disarmed":
        if value["deadline_boottime_ns"] != 0 or value["dispatched"]:
            raise StateError("Disarmed timer state is invalid")
    elif not value["generation"] or value["deadline_boottime_ns"] <= 0:
        raise StateError("Active timer state is invalid")
    if value["status"] == "armed" and value["dispatched"]:
        raise StateError("Armed timer dispatch status is invalid")
    if value["deadline_boottime_ns"] > (
        value["heartbeat_boottime_ns"] + (duration + STALE_SECONDS) * NS
    ):
        raise StateError("Timer state deadline is invalid")
    return value


def snapshot_for(state, now):
    if state is None:
        return {
            "ok": True,
            "state": "disarmed",
            "generation": "",
            "duration_seconds": DEFAULT_MINUTES * 60,
            "remaining_seconds": 0,
            "deadline_boottime_ns": 0,
            "message": "Timer is disarmed.",
        }
    status = state["status"]
    remaining = 0
    if status == "armed":
        remaining = max(0, (state["deadline_boottime_ns"] - now + NS - 1) // NS)
        status = "warning" if remaining <= WARNING_SECONDS else "armed"
    messages = {
        "disarmed": "Timer is disarmed.",
        "armed": "Timer is armed.",
        "warning": "Timer expires soon. Renew it or disarm it with your password.",
        "triggered": "Timer expired. Panic was requested." if state["dispatched"]
        else "Timer expired. Panic request is pending; cancellation is unavailable.",
    }
    result = {
        "ok": True,
        "state": status,
        "generation": state["generation"],
        "duration_seconds": state["duration_seconds"],
        "remaining_seconds": remaining,
        "deadline_boottime_ns": state["deadline_boottime_ns"],
        "message": messages[status],
    }
    age = now - state["heartbeat_boottime_ns"]
    if age > STALE_SECONDS * NS or age < 0:
        result.update(
            ok=False,
            state="degraded",
            message="Timer daemon heartbeat is unavailable. Timer information is retained.",
        )
    return result


def degraded_snapshot(message):
    result = snapshot_for(None, 0)
    result.update(ok=False, state="degraded", message=message)
    return result


class StateStore:
    def __init__(self, path=RUNTIME_DIRECTORY, owner_uid=0, owner_gid=0):
        self.path = path
        self.owner_uid = owner_uid
        self.owner_gid = owner_gid

    def _check(self, info, mode, directory=False):
        correct_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if (
            not correct_type or info.st_uid != self.owner_uid
            or info.st_gid != self.owner_gid or stat.S_IMODE(info.st_mode) != mode
            or (not directory and info.st_nlink != 1)
        ):
            raise StateError("Timer state path permissions are unsafe")

    @contextlib.contextmanager
    def directory(self, create=False):
        parent, name = os.path.split(self.path)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if create:
                try:
                    os.mkdir(name, mode=0o755, dir_fd=parent_fd)
                except FileExistsError:
                    pass
            directory_fd = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_fd,
            )
            try:
                self._check(os.fstat(directory_fd), 0o755, directory=True)
                yield directory_fd
            finally:
                os.close(directory_fd)
        finally:
            os.close(parent_fd)

    def _open_lock(self, directory_fd, name):
        descriptor = os.open(
            name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            0o600, dir_fd=directory_fd,
        )
        try:
            self._check(os.fstat(descriptor), 0o600)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    @contextlib.contextmanager
    def locked(self):
        with self.directory(create=True) as directory_fd:
            descriptor = self._open_lock(directory_fd, LOCK_FILE)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield directory_fd, descriptor
            finally:
                os.close(descriptor)

    @contextlib.contextmanager
    def daemon_lock(self):
        with self.directory(create=True) as directory_fd:
            descriptor = self._open_lock(directory_fd, DAEMON_LOCK_FILE)
            try:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise StateError("Timer daemon is already running") from error
                yield
            finally:
                os.close(descriptor)

    def read(self, directory_fd, current_boot):
        try:
            descriptor = os.open(
                STATE_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(descriptor)
            self._check(info, 0o644)
            if info.st_size > MAX_STATE_BYTES:
                raise StateError("Timer state exceeds its size limit")
            raw = os.read(descriptor, MAX_STATE_BYTES + 1)
            if len(raw) > MAX_STATE_BYTES:
                raise StateError("Timer state exceeds its size limit")
            try:
                value = decode_json(raw)
            except (ValueError, UnicodeError, RecursionError) as error:
                raise StateError("Timer state JSON is invalid") from error
            return validate_state(value, current_boot)
        finally:
            os.close(descriptor)

    def write(self, directory_fd, value):
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(raw) > MAX_STATE_BYTES:
            raise StateError("Timer state exceeds its size limit")
        temporary = ".state-" + secrets.token_hex(16)
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o644, dir_fd=directory_fd,
        )
        try:
            os.fchmod(descriptor, 0o644)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(descriptor)
            os.replace(temporary, STATE_FILE, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass

    def load_locked(self, directory_fd, lock_fd, current_boot, now, initialize=False):
        state = self.read(directory_fd, current_boot)
        marker = os.pread(lock_fd, 32, 0)
        if marker not in (b"", b"initialized\n"):
            raise StateError("Timer initialization marker is invalid")
        if state is None:
            if marker or not initialize:
                raise StateError("Timer state is unavailable")
            state = initial_state(current_boot, now)
            self.write(directory_fd, state)
        if not marker:
            os.pwrite(lock_fd, b"initialized\n", 0)
            os.fsync(lock_fd)
        return state


def read_snapshot():
    try:
        store = StateStore()
        current_boot = boot_id()
        try:
            with store.directory() as directory_fd:
                state = store.read(directory_fd, current_boot)
                if state is None:
                    try:
                        marker = os.stat(LOCK_FILE, dir_fd=directory_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        marker = None
                    if marker is not None:
                        store._check(marker, 0o600)
                        if marker.st_size:
                            raise StateError("Previously initialized timer state is unavailable")
        except FileNotFoundError:
            state = None
        return snapshot_for(state, boottime_ns())
    except (OSError, ValueError, StateError, OverflowError, RecursionError):
        return degraded_snapshot("Timer state is unavailable or invalid. Check the daemon service.")


def dispatch_panic():
    try:
        completed = subprocess.run(
            PANIC_COMMAND,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout=3,
            check=False,
            close_fds=True,
        )
        return completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def watchdog_ping(ready=False):
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address[0] not in ("/", "@") or len(os.fsencode(address)) > 107:
        raise StateError("Timer watchdog socket address is invalid")
    if address[0] == "@":
        address = "\0" + address[1:]
    payload = b"READY=1\nWATCHDOG=1" if ready else b"WATCHDOG=1"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as notifier:
            notifier.settimeout(WATCHDOG_NOTIFY_TIMEOUT_SECONDS)
            notifier.connect(address)
            if notifier.send(payload) != len(payload):
                raise StateError("Timer watchdog notification was incomplete")
    except (OSError, ValueError) as error:
        raise StateError("Timer watchdog notification failed") from error


class TimerEngine:
    def __init__(self, store=None, clock=None, dispatch=None, current_boot=None):
        self.store = store if store is not None else StateStore()
        self.clock = clock if clock is not None else boottime_ns
        self.dispatch = dispatch if dispatch is not None else dispatch_panic
        self.current_boot = current_boot if current_boot is not None else boot_id()
        self.last_log = {}

    def report(self, message):
        now = self.clock()
        if message not in self.last_log or now - self.last_log[message] >= 60 * NS:
            LOGGER.error("%s", message)
            self.last_log[message] = now

    def expire(self, directory_fd, state, now):
        if state["status"] == "armed" and now >= state["deadline_boottime_ns"]:
            state.update(
                status="triggered", generation=secrets.token_hex(16),
                heartbeat_boottime_ns=now,
            )
            self.store.write(directory_fd, state)
        if state["status"] == "triggered" and not state["dispatched"]:
            if self.dispatch():
                state["dispatched"] = True
                state["heartbeat_boottime_ns"] = self.clock()
                self.store.write(directory_fd, state)
            else:
                self.report("Panic service request failed; the expired timer will retry")
        return state

    def tick(self):
        with self.store.locked() as (directory_fd, lock_fd):
            now = self.clock()
            state = self.store.load_locked(
                directory_fd, lock_fd, self.current_boot, now, initialize=True,
            )
            state = self.expire(directory_fd, state, now)
            state["heartbeat_boottime_ns"] = self.clock()
            self.store.write(directory_fd, state)
            return snapshot_for(state, self.clock())

    def mutate(self, action, payload):
        validate_payload(action, payload)
        with self.store.locked() as (directory_fd, lock_fd):
            now = self.clock()
            state = self.store.load_locked(directory_fd, lock_fd, self.current_boot, now)
            now = self.clock()
            state = self.expire(directory_fd, state, now)
            if state["status"] == "triggered":
                raise ActionError("Timer has expired; renewal and cancellation are unavailable")
            if snapshot_for(state, now)["state"] == "degraded":
                raise ActionError("Timer daemon heartbeat is unavailable")
            if payload["generation"] != state["generation"]:
                raise ActionError("Timer changed during authentication; refresh and authenticate again")
            if action == "arm" and state["status"] != "disarmed":
                raise ActionError("Timer is already armed")
            if action in ("renew", "disarm") and state["status"] != "armed":
                raise ActionError("Timer is not armed")
            now = self.clock()
            state = self.expire(directory_fd, state, now)
            if state["status"] == "triggered":
                raise ActionError("Timer has expired; renewal and cancellation are unavailable")
            if snapshot_for(state, now)["state"] == "degraded":
                raise ActionError("Timer daemon heartbeat is unavailable")
            if action == "disarm":
                state.update(status="disarmed", deadline_boottime_ns=0, dispatched=False)
            else:
                duration = payload["minutes"] * 60
                state.update(
                    status="armed", duration_seconds=duration,
                    deadline_boottime_ns=now + duration * NS, dispatched=False,
                )
            state["generation"] = secrets.token_hex(16)
            self.store.write(directory_fd, state)
            return snapshot_for(state, self.clock())

    def run(self):
        with self.store.daemon_lock():
            ready = False
            while True:
                try:
                    self.tick()
                except (OSError, ValueError, StateError, OverflowError, RecursionError):
                    self.report("Timer state is unavailable or invalid; timer service is degraded")
                watchdog_ping(ready=not ready)
                ready = True
                time.sleep(HEARTBEAT_SECONDS)


def validate_payload(action, payload):
    if action not in ("arm", "renew", "disarm"):
        raise ActionError("Unknown timer action")
    expected = {"generation"} if action == "disarm" else {"generation", "minutes"}
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ActionError("Invalid timer action fields")
    if not valid_generation(payload["generation"]):
        raise ActionError("Invalid timer generation")
    if action != "disarm" and (
        type(payload["minutes"]) is not int
        or not MIN_MINUTES <= payload["minutes"] <= MAX_MINUTES
    ):
        raise ActionError("Timer duration must be an integer from 1 to 1440 minutes")


def read_payload(descriptor):
    deadline = time.monotonic() + INPUT_TIMEOUT_SECONDS
    raw = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ActionError("Timer request input timed out")
        ready, _, _ = select.select([descriptor], [], [], remaining)
        if not ready:
            raise ActionError("Timer request input timed out")
        chunk = os.read(descriptor, MAX_INPUT_BYTES + 1 - len(raw))
        if not chunk:
            break
        raw.extend(chunk)
        if len(raw) > MAX_INPUT_BYTES:
            raise ActionError("Timer request exceeds its size limit")
    try:
        return decode_json(bytes(raw))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ActionError("Invalid timer request JSON") from error


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    try:
        if os.geteuid() != 0:
            raise ActionError("Administrator access is required")
        if len(arguments) != 1 or arguments[0] not in ("daemon", "arm", "renew", "disarm"):
            raise ActionError("Exactly one valid timer action is required")
        action = arguments[0]
        if action == "daemon":
            logging.basicConfig(level=logging.ERROR, format="%(name)s: %(message)s")
            TimerEngine().run()
            return 0
        payload = read_payload(sys.stdin.fileno())
        validate_payload(action, payload)
        result = TimerEngine().mutate(action, payload)
        print(json.dumps(result, separators=(",", ":")), flush=True)
        return 0
    except (ActionError, StateError) as error:
        result = {"ok": False, "error": str(error)}
    except (OSError, ValueError, OverflowError, RecursionError):
        result = {"ok": False, "error": "Timer operation failed; check the daemon service"}
    print(json.dumps(result, separators=(",", ":")), flush=True)
    return 1
