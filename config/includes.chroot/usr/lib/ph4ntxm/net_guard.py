# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time

STATE = Path("/run/ph4ntxm-net-guard")
PINS = Path("/sys/fs/bpf/ph4ntxm-net-guard")
UNIT = "ph4ntxm-net-guard.service"
NATIVE = "/usr/local/sbin/ph4ntxm-net-guard-native"
MANIFEST = Path("/usr/lib/ph4ntxm/net-guard.sha256")
ARTIFACTS = {
    NATIVE,
    "/usr/lib/ph4ntxm/net-guard.bpf.o",
    "/usr/lib/ph4ntxm/net_guard.py",
    "/usr/local/sbin/ph4ntxm-net-guard-control",
}
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
LIMIT = 524288


class GuardError(Exception):
    pass


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardError("Duplicate control field.")
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object)


def protected_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise GuardError("Net Guard storage is not protected.")


def protected_read(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_size > maximum
        ):
            raise GuardError("Net Guard installation is not protected.")
        data = handle.read(maximum + 1)
        if len(data) > maximum:
            raise GuardError("Net Guard installation exceeds its limit.")
        return data


def validate_installation():
    entries = {}
    for line in protected_read(MANIFEST, 4096).decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (/[A-Za-z0-9_./-]+)", line)
        if not match or match[2] in entries:
            raise GuardError("Net Guard installation manifest is invalid.")
        entries[match[2]] = match[1]
    if set(entries) != ARTIFACTS:
        raise GuardError("Net Guard installation manifest is incomplete.")
    for name, expected in entries.items():
        if hashlib.sha256(protected_read(Path(name), 16777216)).hexdigest() != expected:
            raise GuardError("Net Guard installation verification failed.")


def run(argv, payload=None, timeout=8):
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=SAFE_ENV,
            close_fds=True,
        )
    except OSError as error:
        raise GuardError("Net Guard helper could not start.") from error
    try:
        if payload is not None:
            process.stdin.write(payload)
            process.stdin.close()
        output = bytearray()
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise GuardError("Net Guard did not respond in time.")
                if not selector.select(remaining):
                    raise GuardError("Net Guard did not respond in time.")
                block = os.read(
                    process.stdout.fileno(), min(65536, LIMIT + 1 - len(output))
                )
                if not block:
                    break
                output.extend(block)
                if len(output) > LIMIT:
                    raise GuardError("Net Guard response exceeds its limit.")
        returncode = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return returncode, bytes(output)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GuardError("Net Guard control failed.") from error
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()


def service_info():
    code, raw = run(
        [
            "/usr/bin/systemctl",
            "show",
            "--no-pager",
            "--property=ActiveState,SubState,MainPID",
            UNIT,
        ],
        timeout=5,
    )
    if code:
        raise GuardError("Net Guard service state is unavailable.")
    fields = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise GuardError("Net Guard service state is invalid.")
        fields[key] = value
    if (
        set(fields) != {"ActiveState", "SubState", "MainPID"}
        or not fields["MainPID"].isdigit()
    ):
        raise GuardError("Net Guard service state is invalid.")
    return fields


def inactive_snapshot():
    if os.path.lexists(PINS):
        return {
            "ok": False,
            "state": "attention",
            "enabled": True,
            "generation": "",
            "message": "Kernel protection state needs recovery. Enable to recover or Disable with the session password.",
            "requests": [],
            "overflow": 0,
        }
    return {
        "ok": True,
        "state": "off",
        "enabled": False,
        "generation": "",
        "message": "Net Guard is off.",
        "requests": [],
        "overflow": 0,
    }


def native_command(command):
    code, raw = run(
        [NATIVE, "client"], (json.dumps(command, separators=(",", ":")) + "\n").encode()
    )
    try:
        result = decode(raw)
    except (ValueError, UnicodeError) as error:
        raise GuardError("Net Guard returned an invalid response.") from error
    if (
        not isinstance(result, dict)
        or type(result.get("ok")) is not bool
        or result.get("state") not in {"off", "on", "attention"}
    ):
        raise GuardError("Net Guard returned an invalid state.")
    if (
        type(result.get("enabled")) is not bool
        or not isinstance(result.get("message"), str)
        or len(result["message"]) > 4096
    ):
        raise GuardError("Net Guard returned invalid status details.")
    if not isinstance(result.get("generation"), str) or not re.fullmatch(
        "[0-9a-f]{32}", result["generation"]
    ):
        raise GuardError("Net Guard returned an invalid generation.")
    if (
        not isinstance(result.get("requests"), list)
        or len(result["requests"]) > 256
        or type(result.get("overflow")) is not int
    ):
        raise GuardError("Net Guard returned invalid requests.")
    if code and result["ok"]:
        raise GuardError("Net Guard helper failed.")
    return result


def prepare():
    protected_directory(Path("/run"))
    STATE.mkdir(mode=0o700, exist_ok=True)
    protected_directory(STATE)
    if STATE.stat().st_mode & 0o077:
        raise GuardError("Net Guard runtime permissions are invalid.")


@contextlib.contextmanager
def control_lock():
    prepare()
    descriptor = os.open(
        STATE / "control.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
    )
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise GuardError("Net Guard control lock is not protected.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise GuardError(
                "Another Net Guard action is in progress. Refresh and retry."
            ) from error
        yield
    finally:
        os.close(descriptor)


def prepare_pins():
    parent = PINS.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or (parent.st_mode & 0o022 and not parent.st_mode & stat.S_ISVTX)
    ):
        raise GuardError("Net Guard BPF storage is not protected.")
    if not PINS.parent.is_mount():
        raise GuardError("Net Guard requires the BPF filesystem to be mounted.")
    PINS.mkdir(mode=0o700, exist_ok=True)
    protected_directory(PINS)
    if PINS.stat().st_mode & 0o077:
        raise GuardError("Net Guard kernel storage permissions are invalid.")


def ensure_service():
    prepare_pins()
    info = service_info()
    if info["ActiveState"] == "failed":
        run(["/usr/bin/systemctl", "reset-failed", UNIT], timeout=5)
    code, _ = run(["/usr/bin/systemctl", "start", UNIT], timeout=20)
    if code:
        raise GuardError(
            "Net Guard service could not start. Existing kernel protection remains in place."
        )
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        info = service_info()
        if (
            info["ActiveState"] == "active"
            and info["SubState"] == "running"
            and int(info["MainPID"]) > 0
        ):
            try:
                return native_command({"action": "snapshot"})
            except GuardError:
                pass
        if info["ActiveState"] == "failed":
            break
        time.sleep(0.1)
    raise GuardError(
        "Net Guard could not verify its kernel protection. Existing protection remains in place."
    )


def action(name, payload):
    validate_installation()
    if name == "prepare":
        prepare()
        return {"ok": True}
    if name == "snapshot":
        info = service_info()
        if (
            info["ActiveState"] != "active"
            or info["SubState"] != "running"
            or int(info["MainPID"]) <= 0
        ):
            return inactive_snapshot()
        return native_command({"action": name})
    with control_lock():
        ensure_service()
        return native_command({"action": name, **payload})


def entry():
    if os.geteuid() != 0:
        print(
            json.dumps(
                {"ok": False, "message": "Administrator authentication is required."}
            )
        )
        return 1
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in {
            "prepare",
            "snapshot",
            "enable",
            "disable",
            "allow",
        }:
            raise GuardError("Invalid Net Guard action.")
        payload = {}
        if sys.argv[1] == "allow":
            raw = sys.stdin.buffer.read(513)
            if len(raw) > 512:
                raise GuardError("Approval request exceeds its limit.")
            payload = decode(raw)
            if not isinstance(payload, dict) or set(payload) != {
                "generation",
                "request_id",
            }:
                raise GuardError("Invalid approval request.")
            if any(
                not isinstance(value, str) or not re.fullmatch("[0-9a-f]{32}", value)
                for value in payload.values()
            ):
                raise GuardError("Invalid approval identity.")
        result = action(sys.argv[1], payload)
    except (GuardError, OSError, ValueError, UnicodeError) as error:
        result = {
            "ok": False,
            "state": "attention",
            "enabled": True,
            "generation": "",
            "message": (
                str(error)
                if isinstance(error, GuardError)
                else "Net Guard control is unavailable."
            ),
            "requests": [],
            "overflow": 0,
        }
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0 if result.get("ok") else 1
