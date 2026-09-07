#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ "$(id -u)" -ne 0 ]; then
    echo "usage: queue-saturation-smoke.sh NATIVE_BINARY" >&2
    exit 2
fi

BINARY=$1
[ -x "$BINARY" ] || exit 1

if [ "${PH4NTXM_QUEUE_TEST_NAMESPACE:-0}" != 1 ]; then
    exec unshare --mount --propagation private --net --pid --fork --mount-proc \
        env PH4NTXM_QUEUE_TEST_NAMESPACE=1 "$0" "$BINARY"
fi

mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /run
install -d -o root -g root -m 0755 /run/ph4ntxm
printf '%s\n' linux > /run/ph4ntxm/mode
printf '%064d\n' 0 > /run/ph4ntxm/persona_seed
chmod 0644 /run/ph4ntxm/mode /run/ph4ntxm/persona_seed

ip link set lo up
ip link add audit0 type dummy
ip address add 192.0.2.10/24 dev audit0
ip link set audit0 up
ip route add 198.51.100.0/24 dev audit0

nft -f - <<'EOF'
flush ruleset
table ip raw {
  counter accepted_after_transformation {
  }
  chain prerouting {
    type filter hook prerouting priority raw; policy accept;
    iifname != "lo" meta mark set 0
    iifname != "lo" queue num 1
  }
  chain prerouting_verify {
    type filter hook prerouting priority -290; policy accept;
    iifname != "lo" meta mark != 0x50544531 drop
    iifname != "lo" meta mark set 0
  }
  chain output {
    type filter hook output priority -90; policy accept;
    oifname != "lo" meta mark set 0
    oifname != "lo" queue num 2
  }
  chain output_verify {
    type filter hook output priority -80; policy accept;
    oifname != "lo" meta mark != 0x50544531 drop
    oifname != "lo" meta mark set 0
    oifname != "lo" counter name accepted_after_transformation
  }
}
EOF

python3 - "$BINARY" <<'PY'
import os
import re
import signal
import socket
import subprocess
import sys
import time


binary = sys.argv[1]
notify_name = "ph4ntxm-packet-transformation-engine-queue-saturation-notify"
notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
notify.bind("\0" + notify_name)
notify.settimeout(5)
environment = os.environ.copy()
environment["NOTIFY_SOCKET"] = "@" + notify_name
process = subprocess.Popen([binary], env=environment)
stopped = False


def accepted_packets():
    state = subprocess.check_output(
        ["nft", "list", "counter", "ip", "raw", "accepted_after_transformation"],
        text=True,
    )
    match = re.search(r"packets (\d+)", state)
    if match is None:
        raise RuntimeError("could not read the post-Packet Transformation Engine counter")
    return int(match.group(1))


def queue_drops():
    with open("/proc/net/netfilter/nfnetlink_queue", "r", encoding="ascii") as source:
        for line in source:
            fields = line.split()
            if len(fields) == 9 and fields[0] == "2":
                return int(fields[5]), int(fields[6])
    raise RuntimeError("outbound NFQUEUE status was not available")


try:
    if b"READY=1" not in notify.recv(512):
        raise RuntimeError("native Packet Transformation Engine did not report readiness")
    os.kill(process.pid, signal.SIGSTOP)
    stopped = True
    senders = []
    for _ in range(128):
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.setblocking(False)
        sender.bind(("192.0.2.10", 0))
        senders.append(sender)
    successful = 0
    payload = b"q" * 1_200
    for sequence in range(50_000):
        try:
            senders[sequence % len(senders)].sendto(
                sequence.to_bytes(4, "big") + payload,
                ("198.51.100.20", 9),
            )
            successful += 1
        except OSError:
            pass
    for sender in senders:
        sender.close()
    deadline = time.monotonic() + 5
    dropped = (0, 0)
    while time.monotonic() < deadline:
        dropped = queue_drops()
        if dropped[0] > 0 or dropped[1] > 0:
            break
        time.sleep(0.05)
    if dropped == (0, 0):
        with open("/proc/net/netfilter/nfnetlink_queue", "r", encoding="ascii") as source:
            status = source.read().strip()
        raise RuntimeError(
            f"NFQUEUE saturation did not register a drop; successful={successful}; status={status}"
        )
    os.kill(process.pid, signal.SIGCONT)
    stopped = False
    try:
        status = process.wait(timeout=12)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("native Packet Transformation Engine stayed active after a queue drop") from error
    if status == 0:
        raise RuntimeError("native Packet Transformation Engine reported success after a queue drop")

    before = accepted_packets()
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.bind(("192.0.2.10", 0))
    try:
        sender.sendto(b"must-remain-dropped", ("198.51.100.20", 9))
    except OSError:
        pass
    sender.close()
    time.sleep(0.2)
    if accepted_packets() != before:
        raise RuntimeError("traffic bypassed the unbound saturated queue")
finally:
    if stopped and process.poll() is None:
        os.kill(process.pid, signal.SIGCONT)
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    notify.close()

print("nfqueue-saturation-detected-and-failed-closed: PASS")
PY
