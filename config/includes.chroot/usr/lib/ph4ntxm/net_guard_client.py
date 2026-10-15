# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import json
import os
import re
import selectors
import signal
import subprocess
import threading
import time
import unicodedata

CONTROL = "/usr/local/sbin/ph4ntxm-net-guard-control"
MAX_OUTPUT = 512 * 1024
MAX_REQUESTS = 256
TOKEN = re.compile(r"[0-9a-f]{32}")
PROTOCOLS = {"tcp", "udp", "icmp", "icmpv6", "raw", "unknown"}


def display_text(value, limit=4096):
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
        raise ValueError("Invalid Net Guard text")
    return display_text(value, limit)


def validate_snapshot(data):
    if not isinstance(data, dict) or type(data.get("ok")) is not bool:
        raise ValueError("Invalid Net Guard response")
    state = data.get("state")
    enabled = data.get("enabled")
    generation = data.get("generation")
    requests = data.get("requests")
    overflow = data.get("overflow")
    if (
        not isinstance(state, str)
        or state not in {"off", "on", "attention"}
        or type(enabled) is not bool
        or not isinstance(generation, str)
        or (generation != "" and TOKEN.fullmatch(generation) is None)
        or (state == "on" and (not enabled or not generation))
        or (state == "off" and enabled)
        or not isinstance(requests, list)
        or len(requests) > MAX_REQUESTS
        or type(overflow) is not int
        or not 0 <= overflow <= 0xFFFFFFFFFFFFFFFF
    ):
        raise ValueError("Invalid Net Guard snapshot")
    message = bounded_text(data.get("message"), 4096)
    checked = []
    identifiers = set()
    for item in requests:
        if not isinstance(item, dict):
            raise ValueError("Invalid network request")
        request_id = item.get("request_id")
        pid = item.get("pid")
        port = item.get("port")
        protocol = item.get("protocol")
        if (
            not isinstance(request_id, str)
            or TOKEN.fullmatch(request_id) is None
            or request_id in identifiers
            or type(pid) is not int
            or not 1 <= pid <= 0x7FFFFFFF
            or type(port) is not int
            or not 0 <= port <= 65535
            or not isinstance(protocol, str)
            or protocol not in PROTOCOLS
            or type(item.get("approved")) is not bool
            or type(item.get("approval_available")) is not bool
        ):
            raise ValueError("Invalid network request details")
        identifiers.add(request_id)
        checked.append(
            {
                "request_id": request_id,
                "pid": pid,
                "port": port,
                "protocol": protocol,
                "approved": item["approved"],
                "approval_available": item["approval_available"],
                "app_name": bounded_text(item.get("app_name"), 256)
                or "Unnamed process",
                "executable": bounded_text(item.get("executable"), 4096),
                "destination": bounded_text(item.get("destination"), 256),
                "reason": bounded_text(item.get("reason"), 1024),
            }
        )
    if checked and not generation:
        raise ValueError("Network requests have no service identity")
    return {
        "ok": data["ok"],
        "state": state,
        "enabled": enabled,
        "generation": generation,
        "message": message,
        "requests": checked,
        "overflow": overflow,
    }


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
    def __init__(self, action, payload=None):
        super().__init__()
        if action not in {"snapshot", "enable", "disable", "allow"}:
            raise ValueError("Invalid Net Guard action")
        if action == "allow":
            if (
                not isinstance(payload, dict)
                or set(payload) != {"generation", "request_id"}
                or any(
                    not isinstance(value, str) or TOKEN.fullmatch(value) is None
                    for value in payload.values()
                )
            ):
                raise ValueError("Invalid process approval request")
        elif payload is not None:
            raise ValueError("Unexpected Net Guard input")
        self.action = action
        self.payload = dict(payload) if payload is not None else None
        self.input = (
            json.dumps(self.payload, separators=(",", ":")).encode("ascii") + b"\n"
            if self.payload is not None
            else None
        )
        if self.input is not None and len(self.input) > 4096:
            raise ValueError("Net Guard request exceeds its limit")

    def run(self):
        options = ["-n"] if self.action == "snapshot" else ["-A", "-k"]
        environment = dict(os.environ)
        environment["SUDO_ASKPASS"] = "/usr/local/bin/ph4ntxm-askpass"
        try:
            code, output = self.run_process(
                ["/usr/bin/sudo", *options, "--", CONTROL, self.action],
                10 if self.action == "snapshot" else 120,
                self.input,
                environment,
            )
            try:
                result = json.loads(
                    output.decode("utf-8"), object_pairs_hook=unique_object
                )
            except (UnicodeError, ValueError, RecursionError):
                if code != 0:
                    return {
                        "ok": False,
                        "error": (
                            "Net Guard status is unavailable."
                            if self.action == "snapshot"
                            else "Authorization was cancelled or the action failed. Refresh to check the current state."
                        ),
                    }
                raise
            if isinstance(result, dict) and result.get("ok") is False:
                if "state" in result:
                    return validate_snapshot(result)
                return {
                    "ok": False,
                    "error": display_text(
                        result.get("error")
                        or result.get("message")
                        or "Net Guard could not complete the request.",
                        1024,
                    ),
                }
            if code != 0:
                return {
                    "ok": False,
                    "error": "Net Guard could not complete the request. Refresh to check the current state.",
                }
            return validate_snapshot(result)
        except InterruptedError:
            return {"ok": False, "error": "Net Guard request cancelled."}
        except TimeoutError:
            return {
                "ok": False,
                "error": "Net Guard did not respond in time. An authorized action may still complete; refresh to check its state.",
            }
        except (
            OSError,
            UnicodeError,
            ValueError,
            RecursionError,
            subprocess.SubprocessError,
        ):
            return {
                "ok": False,
                "error": "Net Guard could not read a valid response. Refresh to check the current state.",
            }
