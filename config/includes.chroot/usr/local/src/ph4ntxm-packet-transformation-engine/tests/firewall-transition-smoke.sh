#!/bin/sh
set -eu

SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE_ROOT=$(CDPATH= cd -- "$SOURCE/../../../.." && pwd)
PACKET_TRANSFORMATION_ENGINE_GUARD=$IMAGE_ROOT/usr/local/sbin/ph4ntxm-packet-transformation-engine-guard.sh
FIREWALL_GUARD=$IMAGE_ROOT/usr/local/sbin/ph4ntxm-firewall-guard.sh
FIREWALL_CONTROL=$IMAGE_ROOT/usr/local/sbin/ph4ntxm-firewall-control

if [ "$#" -ne 4 ] || [ "$(id -u)" -ne 0 ]; then
    echo "usage: firewall-transition-smoke.sh NATIVE LOADER BPF_OBJECT ROOTFS" >&2
    exit 2
fi

NATIVE=$1
LOADER=$2
OBJECT=$3
ROOTFS=$4

[ -x "$NATIVE" ] && [ -x "$LOADER" ] && [ -r "$OBJECT" ] && \
    [ -x "$PACKET_TRANSFORMATION_ENGINE_GUARD" ] && [ -x "$FIREWALL_GUARD" ] && \
    [ -x "$FIREWALL_CONTROL" ] && [ -d "$ROOTFS" ] || exit 1

if [ "${PH4NTXM_FIREWALL_TRANSITION_TEST_NAMESPACE:-0}" != 1 ]; then
    exec unshare --mount --propagation private --net --pid --fork --mount-proc \
        env PH4NTXM_FIREWALL_TRANSITION_TEST_NAMESPACE=1 \
        "$0" "$NATIVE" "$LOADER" "$OBJECT" "$ROOTFS"
fi

mount --make-rprivate /
mount -t proc -o nosuid,nodev,noexec proc "$ROOTFS/proc"
mount -t sysfs -o ro,nosuid,nodev,noexec sysfs "$ROOTFS/sys"
mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs "$ROOTFS/run"
mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs "$ROOTFS/usr/local/sbin"
mount -t tmpfs -o mode=0755,nodev,nosuid,noexec tmpfs "$ROOTFS/usr/lib/ph4ntxm"
mount -t tmpfs -o mode=0755,nodev,nosuid,noexec tmpfs "$ROOTFS/etc/firewall"
mount --bind "$ROOTFS/usr/bin/true" "$ROOTFS/usr/bin/systemd-notify"

install -o root -g root -m 0755 "$PACKET_TRANSFORMATION_ENGINE_GUARD" \
    "$ROOTFS/usr/local/sbin/ph4ntxm-packet-transformation-engine-guard.sh"
install -o root -g root -m 0755 "$FIREWALL_GUARD" \
    "$ROOTFS/usr/local/sbin/ph4ntxm-firewall-guard.sh"
install -o root -g root -m 0755 "$FIREWALL_CONTROL" \
    "$ROOTFS/usr/local/sbin/ph4ntxm-firewall-control"
install -o root -g root -m 0755 "$NATIVE" \
    "$ROOTFS/usr/local/sbin/ph4ntxm-packet-transformation-engine-native"
install -o root -g root -m 0755 "$LOADER" \
    "$ROOTFS/usr/local/sbin/ph4ntxm-packet-transformation-engine-loader"
install -o root -g root -m 0644 "$OBJECT" \
    "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.bpf.o"
install -o root -g root -m 0644 "$IMAGE_ROOT/etc/firewall/normal.nft" \
    "$ROOTFS/etc/firewall/normal.nft"
install -o root -g root -m 0644 "$IMAGE_ROOT/etc/firewall/lockdown.nft" \
    "$ROOTFS/etc/firewall/lockdown.nft"
install -o root -g root -m 0644 "$IMAGE_ROOT/etc/firewall/rules.sha256" \
    "$ROOTFS/etc/firewall/rules.sha256"

(cd "$ROOTFS" && sha256sum \
    usr/lib/ph4ntxm/packet-transformation-engine.bpf.o \
    usr/local/sbin/ph4ntxm-packet-transformation-engine-loader \
    usr/local/sbin/ph4ntxm-packet-transformation-engine-native) \
    > "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.sha256"
chmod 0644 "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.sha256"
install -d -o root -g root -m 0755 "$ROOTFS/run/ph4ntxm"
printf '%s\n' linux > "$ROOTFS/run/ph4ntxm/mode"
chmod 0644 "$ROOTFS/run/ph4ntxm/mode"

python3 - "$ROOTFS" <<'PY'
import hashlib
import os
import signal
import subprocess
import sys
import time


root = sys.argv[1]
state = os.path.join(root, "run/ph4ntxm")
transformation_ready = os.path.join(state, "packet-transformation-engine-guard-ready")
firewall_ready = os.path.join(state, "firewall-ready")
status = os.path.join(root, "run/ph4ntxm-lockdown-status.json")


def chroot(*arguments, check=True, timeout=20):
    return subprocess.run(
        ["chroot", root, *arguments],
        check=check,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def values(path):
    result = {}
    with open(path, "r", encoding="ascii") as source:
        lines = source.read().splitlines()
    for line in lines:
        key, value = line.split("=", 1)
        if key in result:
            raise RuntimeError(f"duplicate state key {key}")
        result[key] = value
    return result


def ready_profile(path, profile):
    data = values(path)
    return data.get("PROFILE") == profile and data.get("UPTIME_SECONDS", "").isdigit()


def wait_for(predicate, message, processes, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for process in processes:
            if process.poll() is not None:
                raise RuntimeError(f"service exited during integration test: {process.args}")
        try:
            if predicate():
                return
        except (FileNotFoundError, OSError, UnicodeError, ValueError):
            pass
        time.sleep(0.05)
    raise RuntimeError(message)


def assert_profiles(profile, processes):
    wait_for(
        lambda: ready_profile(transformation_ready, profile)
        and ready_profile(firewall_ready, profile),
        f"Packet Transformation Engine and firewall did not converge on {profile}",
        processes,
    )


packet_engine = subprocess.Popen(
    ["chroot", root, "/usr/local/sbin/ph4ntxm-packet-transformation-engine-guard.sh", "watch"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.PIPE,
    text=True,
)
firewall = None
try:
    wait_for(
        lambda: ready_profile(transformation_ready, "normal"),
        "Packet Transformation Engine guardian did not publish initial readiness",
        [packet_engine],
    )
    firewall = subprocess.Popen(
        ["chroot", root, "/usr/local/sbin/ph4ntxm-firewall-guard.sh"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    processes = [packet_engine, firewall]
    assert_profiles("normal", processes)

    chroot("nft", "flush", "ruleset")
    try:
        os.unlink(firewall_ready)
    except FileNotFoundError:
        pass
    assert_profiles("normal", processes)
    ruleset = chroot("nft", "-s", "list", "ruleset").stdout.encode("utf-8")
    ready_hash = values(firewall_ready)["RULESET_SHA256"]
    actual_hash = hashlib.sha256(ruleset).hexdigest()
    if ready_hash != actual_hash:
        raise RuntimeError(
            f"firewall readiness hash does not match the restored ruleset: "
            f"ready={ready_hash} actual={actual_hash}"
        )

    temporary = status + ".tmp"
    with open(temporary, "w", encoding="ascii") as destination:
        destination.write("{malformed\n")
    os.chmod(temporary, 0o644)
    os.replace(temporary, status)
    assert_profiles("lockdown", processes)

    chroot("/usr/local/sbin/ph4ntxm-firewall-control", "disable")
    assert_profiles("normal", processes)
    chroot("/usr/local/sbin/ph4ntxm-firewall-control", "enable")
    assert_profiles("lockdown", processes)
    chroot("/usr/local/sbin/ph4ntxm-firewall-control", "disable")
    assert_profiles("normal", processes)
    print("packet_engine-firewall-transition-integration: PASS")
finally:
    for process in (firewall, packet_engine):
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
    for process in (firewall, packet_engine):
        if process is None:
            continue
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)
PY
