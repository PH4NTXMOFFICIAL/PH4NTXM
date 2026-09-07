#!/bin/sh
set -eu

if [ "$#" -ne 2 ] || [ "$(id -u)" -ne 0 ]; then
    exit 2
fi

BINARY=$1
RULES=$2

mount --make-rprivate /
mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /run
install -d -o root -g root -m 0755 /run/ph4ntxm
printf '%s\n' linux > /run/ph4ntxm/mode
printf '%064d\n' 0 > /run/ph4ntxm/persona_seed
chmod 0644 /run/ph4ntxm/mode /run/ph4ntxm/persona_seed

ip link set lo up
ip link add audit0 type dummy
ip address add 192.0.2.10/24 dev audit0
ip -6 address add 2001:db8::10/64 dev audit0
ip link set audit0 up
ip route add 198.51.100.0/24 dev audit0
ip -6 route add 2001:db8:1::/64 dev audit0

nft -f "$RULES"

python3 - "$BINARY" <<'PY'
import os
import signal
import socket
import subprocess
import sys
import time

binary = sys.argv[1]
notify_name = "ph4ntxm-packet-transformation-engine-production-notify"
notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
notify.bind("\0" + notify_name)
notify.settimeout(5)
environment = os.environ.copy()
environment["NOTIFY_SOCKET"] = "@" + notify_name
process = subprocess.Popen([binary], env=environment)

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 53))
listener.listen(2)
listener.settimeout(3)

try:
    if b"READY=1" not in notify.recv(512):
        raise RuntimeError("native Packet Transformation Engine did not report readiness")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(3)
    client.connect(("198.51.100.20", 53))
    accepted, _ = listener.accept()
    client.sendall(b"production-firewall-dns")
    if accepted.recv(64) != b"production-firewall-dns":
        raise RuntimeError("production firewall altered redirected TCP payload")
    accepted.sendall(b"ok")
    if client.recv(2) != b"ok":
        raise RuntimeError("production firewall lost redirected TCP reply")
    accepted.close()
    client.close()

    sender4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender4.bind(("192.0.2.10", 0))
    sender4.sendto(b"production-ipv4", ("198.51.100.20", 9))
    sender4.close()

    sender6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sender6.bind(("2001:db8::10", 0))
    sender6.sendto(b"production-ipv6", ("2001:db8:1::20", 9))
    sender6.close()
    deadline = time.monotonic() + 7
    watchdog = False
    while time.monotonic() < deadline:
        notify.settimeout(deadline - time.monotonic())
        if b"WATCHDOG=1" in notify.recv(512):
            watchdog = True
            break
    if not watchdog:
        raise RuntimeError("native Packet Transformation Engine did not emit its watchdog heartbeat")
    if process.poll() is not None:
        raise RuntimeError("native Packet Transformation Engine exited under the production firewall")
finally:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    notify.close()

blocked = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
blocked.settimeout(0.5)
try:
    blocked.connect(("198.51.100.20", 53))
except OSError:
    pass
else:
    raise RuntimeError("production firewall bypassed an unbound NFQUEUE")
finally:
    blocked.close()
    listener.close()
PY
