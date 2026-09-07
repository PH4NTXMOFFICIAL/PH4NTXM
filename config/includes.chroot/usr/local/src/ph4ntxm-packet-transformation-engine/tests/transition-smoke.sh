#!/bin/sh
set -eu

SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GUARD=$SOURCE/../../sbin/ph4ntxm-packet-transformation-engine-guard.sh

[ "$(id -u)" -eq 0 ] || {
    echo "transition-smoke.sh must run as root" >&2
    exit 1
}

if [ "${PH4NTXM_TRANSITION_TEST_NAMESPACE:-0}" != 1 ]; then
    exec unshare --mount --net --pid --fork --mount-proc \
        env PH4NTXM_TRANSITION_TEST_NAMESPACE=1 "$0"
fi

mount --make-rprivate /
mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /run
mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
install -d -o root -g root -m 0755 /run/ph4ntxm
printf '%s\n' linux > /run/ph4ntxm/mode
chmod 0644 /run/ph4ntxm/mode

python3 - "$GUARD" <<'PY'
import os
import array
import signal
import socket
import subprocess
import sys
import threading
import time


guard = sys.argv[1]
state = "/run/ph4ntxm"
notify_name = "ph4ntxm-packet-transformation-engine-transition-notify"
notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
notify.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
notify.bind("\0" + notify_name)
stop_notify = threading.Event()


def drain_notify():
    notify.settimeout(0.2)
    while not stop_notify.is_set():
        try:
            _, ancillary, _, _ = notify.recvmsg(4096, socket.CMSG_SPACE(64))
        except TimeoutError:
            continue
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                descriptors = array.array("i")
                descriptors.frombytes(data[: len(data) - len(data) % descriptors.itemsize])
                for descriptor in descriptors:
                    os.close(descriptor)


notify_thread = threading.Thread(target=drain_notify, daemon=True)
notify_thread.start()
environment = os.environ.copy()
environment["NOTIFY_SOCKET"] = "@" + notify_name
process = subprocess.Popen([guard, "watch"], env=environment)


def values(path):
    result = {}
    with open(path, "r", encoding="ascii") as source:
        for line in source.read().splitlines():
            key, value = line.split("=", 1)
            if key in result:
                raise RuntimeError(f"duplicate state key {key}")
            result[key] = value
    return result


def wait_for(predicate, message, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Packet Transformation Engine guardian exited during transition test")
        try:
            if predicate():
                return
        except (FileNotFoundError, OSError, ValueError):
            pass
        time.sleep(0.05)
    raise RuntimeError(message)


def request(profile, token):
    temporary = f"{state}/.transition-test-{token}"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as destination:
        destination.write(f"PROFILE={profile}\nTOKEN={token}\n")
    os.replace(temporary, f"{state}/packet-transformation-engine-guard-request")
    wait_for(
        lambda: values(f"{state}/packet-transformation-engine-guard-transition") == {
            "STATUS": "complete",
            "PROFILE": profile,
            "TOKEN": token,
        },
        f"{profile} transition was not acknowledged",
    )


try:
    wait_for(
        lambda: values(f"{state}/packet-transformation-engine-guard-ready")["PROFILE"] == "normal",
        "initial normal readiness was not published",
    )
    request("lockdown", "11111111111111111111111111111111")
    if not os.path.isfile(f"{state}/packet-transformation-engine-guard-sealed"):
        raise RuntimeError("lockdown transition did not seal egress")
    wait_for(
        lambda: values(f"{state}/packet-transformation-engine-guard-ready")["PROFILE"] == "lockdown",
        "lockdown readiness was not published",
    )
    request("normal", "22222222222222222222222222222222")
    if os.path.exists(f"{state}/packet-transformation-engine-guard-sealed"):
        raise RuntimeError("normal transition left egress sealed")
    wait_for(
        lambda: values(f"{state}/packet-transformation-engine-guard-ready")["PROFILE"] == "normal",
        "restored normal readiness was not published",
    )
    malformed = f"{state}/.transition-test-malformed"
    descriptor = os.open(malformed, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as destination:
        destination.write("PROFILE=normal\n")
    os.replace(malformed, f"{state}/packet-transformation-engine-guard-request")
    wait_for(
        lambda: os.path.isfile(f"{state}/packet-transformation-engine-guard-sealed"),
        "malformed transition request did not seal egress",
    )
    if os.path.exists(f"{state}/packet-transformation-engine-guard-ready"):
        raise RuntimeError("malformed transition request left stale readiness")
    os.unlink(f"{state}/packet-transformation-engine-guard-request")
    request("normal", "33333333333333333333333333333333")
    if os.path.exists(f"{state}/packet-transformation-engine-guard-sealed"):
        raise RuntimeError("normal recovery left egress sealed")
    wait_for(
        lambda: values(f"{state}/packet-transformation-engine-guard-ready")["PROFILE"] == "normal",
        "normal readiness was not restored after malformed request",
    )
    with open(f"{state}/mode", "w", encoding="ascii") as destination:
        destination.write("corrupt\n")
    deadline = time.monotonic() + 3
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    if process.poll() is None or process.returncode == 0:
        raise RuntimeError("guardian did not fail closed after mode-state corruption")
    if os.path.exists(f"{state}/packet-transformation-engine-guard-ready"):
        raise RuntimeError("guardian left stale readiness after mode-state corruption")
    print("packet_engine-transition-handshake: PASS")
finally:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    stop_notify.set()
    notify_thread.join(timeout=1)
    notify.close()
PY
