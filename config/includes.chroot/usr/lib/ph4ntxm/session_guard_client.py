# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import threading
import time
import unicodedata

CONTROL = "/usr/local/sbin/ph4ntxm-session-guard-control"
LOCKDOWN_STATUS = "/run/ph4ntxm-lockdown-status.json"
MAX_OUTPUT = 256 * 1024
TOKEN = re.compile(r"[0-9a-f]{32}")
POLL_INTERVAL_MS = 10000


def display_text(value, limit=1024):
    return "".join(
        character if unicodedata.category(character) not in {"Cc", "Cf", "Cs"} else "�"
        for character in str(value)[:limit]
    )


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate response field")
        result[key] = value
    return result


def bounded_text(value, limit):
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError("Invalid Session Guard text")
    return display_text(value, limit)


def timestamp(value):
    return type(value) in {int, float} and math.isfinite(value) and value >= 0


def validate_snapshot(data):
    if (
        not isinstance(data, dict)
        or data.get("ok") is not True
        or type(data.get("schema")) is not int
        or data["schema"] != 1
        or type(data.get("available")) is not bool
        or type(data.get("enabled")) is not bool
        or not isinstance(data.get("generation"), str)
        or TOKEN.fullmatch(data["generation"]) is None
        or not isinstance(data.get("mode"), str)
        or data["mode"] not in {"linux", "windows", "lonewolf", "unknown"}
        or (data["mode"] == "unknown" and data["enabled"])
        or type(data.get("sequence")) is not int
        or data["sequence"] < 0
        or not timestamp(data.get("last_poll_boottime"))
        or type(data.get("poll_interval")) is not int
        or data["poll_interval"] != 10
        or not isinstance(data.get("checks"), list)
        or len(data["checks"]) > 32
        or not isinstance(data.get("incidents"), list)
        or len(data["incidents"]) > 64
    ):
        raise ValueError("Invalid Session Guard snapshot")
    age = time.clock_gettime(time.CLOCK_BOOTTIME) - data["last_poll_boottime"]
    if not 0 <= age <= 30:
        raise ValueError("Session Guard status is stale or has a future timestamp")
    checks = []
    for item in data["checks"]:
        if (
            not isinstance(item, dict)
            or type(item.get("healthy")) is not bool
            or not isinstance(item.get("status"), str)
            or item["status"] not in {"healthy", "pending", "failed"}
        ):
            raise ValueError("Invalid Session Guard check")
        checks.append(
            {
                "code": bounded_text(item.get("code"), 64),
                "title": bounded_text(item.get("title"), 160),
                "detail": bounded_text(item.get("detail"), 2048),
                "healthy": item["healthy"],
                "status": item["status"],
            }
        )
    incidents = []
    identifiers = set()
    for item in data["incidents"]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("id"), str)
            or TOKEN.fullmatch(item["id"]) is None
            or item["id"] in identifiers
            or type(item.get("active")) is not bool
            or item.get("severity") != "warning"
            or not isinstance(item.get("mode"), str)
            or item["mode"] not in {"linux", "windows", "lonewolf"}
            or not timestamp(item.get("first_seen_boottime"))
            or (
                item.get("resolved_boottime") is not None
                and not timestamp(item["resolved_boottime"])
            )
        ):
            raise ValueError("Invalid Session Guard incident")
        identifiers.add(item["id"])
        incidents.append(
            {
                "id": item["id"],
                "active": item["active"],
                "code": bounded_text(item.get("code"), 64),
                "title": bounded_text(item.get("title"), 160),
                "detail": bounded_text(item.get("detail"), 2048),
                "first_seen_boottime": item["first_seen_boottime"],
                "resolved_boottime": item.get("resolved_boottime"),
            }
        )
    return {**data, "checks": checks, "incidents": incidents}


def notification_icon():
    if os.path.isfile(
        "/usr/share/icons/Lyra-blue-dark/apps/scalable/ph4ntxm-session-guard.svg"
    ):
        return "ph4ntxm-session-guard"
    return "ph4ntxm-health"


def lockdown_state(path=LOCKDOWN_STATUS):
    descriptor = None
    try:
        parent = os.stat(os.path.dirname(path), follow_symlinks=False)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            return None
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or info.st_size > 4096
        ):
            return None
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            content = handle.read(4097)
        if len(content) > 4096:
            return None
        data = json.loads(content.decode("utf-8"), object_pairs_hook=unique_object)
        if not isinstance(data, dict) or type(data.get("enabled")) is not bool:
            return None
        return data["enabled"]
    except (OSError, ValueError, UnicodeError, RecursionError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def lockdown_enabled(path=LOCKDOWN_STATUS):
    return lockdown_state(path) is True


class BoundedProcess:
    def __init__(self):
        self.cancelled = threading.Event()
        self.process = None
        self.lock = threading.Lock()

    def cancel(self):
        self.cancelled.set()
        self.stop_process()

    def stop_process(self, force=False):
        with self.lock:
            process = self.process
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
                except OSError:
                    pass

    def run_process(
        self, command, timeout, input_data=None, environment=None, maximum=MAX_OUTPUT
    ):
        process = None
        try:
            if self.cancelled.is_set():
                raise InterruptedError("Request cancelled")
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=environment,
                close_fds=True,
                start_new_session=True,
            )
            with self.lock:
                self.process = process
            if self.cancelled.is_set():
                raise InterruptedError("Request cancelled")
            if input_data is not None:
                process.stdin.write(input_data)
                process.stdin.close()
            os.set_blocking(process.stdout.fileno(), False)
            output = bytearray()
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map() or process.poll() is None:
                    if self.cancelled.is_set():
                        raise InterruptedError("Request cancelled")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("Request timed out")
                    for key, _ in selector.select(min(0.2, remaining)):
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        elif len(output) + len(chunk) > maximum:
                            raise ValueError("Response exceeds its limit")
                        else:
                            output.extend(chunk)
                    if not selector.get_map() and process.poll() is None:
                        self.cancelled.wait(min(0.05, remaining))
            return process.wait(), bytes(output)
        finally:
            if process is not None:
                if process.poll() is None:
                    self.stop_process()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        self.stop_process(True)
                        try:
                            process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            pass
                for handle in (process.stdin, process.stdout):
                    if handle is not None and not handle.closed:
                        try:
                            handle.close()
                        except OSError:
                            pass
            with self.lock:
                self.process = None



class HelperCall(BoundedProcess):
    def __init__(self, action="status", generation=None, password=None):
        super().__init__()
        if action not in {"status", "enable", "disable"}:
            raise ValueError("Invalid Session Guard action")
        self.action = action
        self.input = None
        if action == "status":
            if generation is not None or password is not None:
                raise ValueError("Unexpected status input")
        else:
            if (
                not isinstance(generation, str)
                or TOKEN.fullmatch(generation) is None
                or not isinstance(password, str)
                or not password
                or len(password) > 4096
                or any(character in password for character in "\n\r\x00")
            ):
                raise ValueError("Invalid authorization input")
            encoded = password.encode("utf-8")
            if len(encoded) > 2048:
                raise ValueError("Authorization input exceeds its limit")
            self.input = bytearray(
                encoded + b"\n"
                + json.dumps({"generation": generation}, separators=(",", ":")).encode("ascii")
                + b"\n"
            )

    def run(self):
        result = self.read_result()
        if self.action == "status":
            result["lockdown_enabled"] = lockdown_state()
        return result

    def read_result(self):
        command = (
            [CONTROL, "status"]
            if self.action == "status"
            else ["/usr/bin/sudo", "-k", "-S", "-p", "", "--", CONTROL, self.action]
        )
        try:
            code, output = self.run_process(
                command, 5 if self.action == "status" else 30, self.input
            )
            data = json.loads(output.decode("utf-8"), object_pairs_hook=unique_object)
            if code != 0 or not isinstance(data, dict) or data.get("ok") is not True:
                message = data.get("message") if isinstance(data, dict) else None
                return {
                    "ok": False,
                    "error": display_text(
                        message
                        or "Session Guard could not complete the request. "
                        "Refresh to check its state."
                    ),
                }
            if self.action == "status":
                return validate_snapshot(data)
            return {"ok": True}
        except InterruptedError:
            return {"ok": False, "error": "Session Guard request cancelled."}
        except TimeoutError:
            return {
                "ok": False,
                "error": (
                    "Session Guard did not respond in time. "
                    "An authorized action may still complete. "
                    "Refresh to check its state."
                ),
            }
        except (OSError, UnicodeError, ValueError, RecursionError, subprocess.SubprocessError):
            return {
                "ok": False,
                "error": (
                    "Session Guard could not read a valid response. "
                    "Refresh to check its state."
                ),
            }
        finally:
            if self.input is not None:
                self.input[:] = b"\x00" * len(self.input)
                self.input = None


class LockdownCall(BoundedProcess):
    def __init__(self, action="enable", password=None):
        super().__init__()
        if action not in {"enable", "disable"}:
            raise ValueError("Invalid Lockdown action")
        self.action = action
        self.input = None
        if action == "disable":
            if (
                not isinstance(password, str)
                or not password
                or len(password) > 512
                or any(character in password for character in "\n\r\x00")
            ):
                raise ValueError("Invalid authorization input")
            self.input = bytearray(password.encode("utf-8") + b"\n")
        elif password is not None:
            raise ValueError("Unexpected Lockdown input")

    def run(self):
        command = (
            ["/usr/bin/sudo", "-n", "/usr/local/sbin/ph4ntxm-firewall-control", "enable"]
            if self.action == "enable"
            else [
                "/usr/bin/sudo",
                "-k",
                "-S",
                "-p",
                "",
                "--",
                "/usr/local/sbin/ph4ntxm-firewall-control",
                "disable",
            ]
        )
        try:
            code, _ = self.run_process(command, 30, self.input, maximum=4096)
            state = lockdown_state()
            if code == 0 and state is (self.action == "enable"):
                return {
                    "ok": True,
                    "lockdown_enabled": state,
                    "message": f"Lockdown {self.action}d and verified.",
                }
        except (OSError, ValueError, TimeoutError, InterruptedError, subprocess.SubprocessError):
            pass
        finally:
            if self.input is not None:
                self.input[:] = b"\x00" * len(self.input)
                self.input = None
        return {"ok": False, "error": "Lockdown could not be verified. Check the firewall status."}


class EpisodeTracker:
    def __init__(self):
        self.seen = set()
        self.inflight = set()
        self.current = {}

    def update(self, snapshot):
        self.current = {
            (snapshot["generation"], item["id"]): item
            for item in snapshot["incidents"]
            if snapshot["enabled"] and item["active"]
        }
        self.seen.intersection_update(self.current)
        return set(self.current) - self.seen - self.inflight

    def take(self):
        pending = set(self.current) - self.seen - self.inflight
        self.inflight.update(pending)
        return {key: self.current[key] for key in sorted(pending)}

    def finish(self, episodes, delivered):
        self.inflight.difference_update(episodes)
        if delivered:
            self.seen.update(set(episodes).intersection(self.current))
