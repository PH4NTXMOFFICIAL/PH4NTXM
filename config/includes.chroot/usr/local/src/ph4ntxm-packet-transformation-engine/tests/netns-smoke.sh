#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ "$(id -u)" -ne 0 ]; then
    exit 2
fi

BINARY=$1

mount --make-rprivate /
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
table ip nat {
  chain output {
    type nat hook output priority dstnat;
    tcp dport 5353 redirect to :5353
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
notify_name = "ph4ntxm-packet-transformation-engine-netns-notify"
listener = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
listener.bind("\0" + notify_name)
listener.settimeout(5)
environment = os.environ.copy()
environment["NOTIFY_SOCKET"] = "@" + notify_name
process = subprocess.Popen([binary], env=environment)


def accepted_packets():
    state = subprocess.check_output(
        ["nft", "list", "counter", "ip", "raw", "accepted_after_transformation"], text=True
    )
    match = re.search(r"packets (\d+)", state)
    if match is None:
        raise RuntimeError("could not read native Packet Transformation Engine provenance counter")
    return int(match.group(1))


try:
    message = listener.recv(512)
    if b"READY=1" not in message:
        raise RuntimeError("native Packet Transformation Engine did not report readiness")
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.bind(("192.0.2.10", 0))
    sender.sendto(b"ph4ntxm-native-packet_engine-smoke", ("198.51.100.20", 9))
    sender.close()
    time.sleep(0.25)
    if process.poll() is not None:
        raise RuntimeError("native Packet Transformation Engine exited while processing an NFQUEUE packet")
    if accepted_packets() < 1:
        raise RuntimeError("packet did not pass the native Packet Transformation Engine provenance gate")

    external_before_redirect = accepted_packets()
    listener_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener_tcp.bind(("127.0.0.1", 5353))
    listener_tcp.listen(1)
    listener_tcp.settimeout(3)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(3)
    client.connect(("198.51.100.20", 5353))
    accepted, _ = listener_tcp.accept()
    client.sendall(b"dns-over-tcp-regression")
    if accepted.recv(64) != b"dns-over-tcp-regression":
        raise RuntimeError("post-DNAT loopback TCP payload mismatch")
    accepted.sendall(b"ok")
    if client.recv(2) != b"ok":
        raise RuntimeError("post-DNAT loopback TCP reply mismatch")
    accepted.close()
    client.close()
    listener_tcp.close()
    if accepted_packets() <= external_before_redirect:
        raise RuntimeError("local DNAT traffic did not pass Packet Transformation Engine validation")
    time.sleep(0.25)
    if process.poll() is not None:
        raise RuntimeError("native Packet Transformation Engine exited while processing local DNAT traffic")
finally:
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
    listener.close()

before = accepted_packets()
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender.bind(("192.0.2.10", 0))
try:
    sender.sendto(b"ph4ntxm-native-packet_engine-must-drop", ("198.51.100.20", 9))
except OSError:
    pass
sender.close()
time.sleep(0.25)
if accepted_packets() != before:
    raise RuntimeError("packet bypassed an unbound fail-closed NFQUEUE")
PY

expect_startup_rejection() {
    if timeout 2 "$BINARY" >/dev/null 2>&1; then
        status=0
    else
        status=$?
    fi
    if [ "$status" -ne 1 ]; then
        echo "native Packet Transformation Engine did not reject unsafe configuration (status=$status)" >&2
        exit 1
    fi
}

chmod 0666 /run/ph4ntxm/mode
expect_startup_rejection
chmod 0644 /run/ph4ntxm/mode

printf 'linux\000windows\n' > /run/ph4ntxm/mode
expect_startup_rejection
printf '%s\n' linux > /run/ph4ntxm/mode

printf 'linux \n' > /run/ph4ntxm/mode
expect_startup_rejection
printf 'linux\n\n' > /run/ph4ntxm/mode
expect_startup_rejection
printf linux > /run/ph4ntxm/mode
expect_startup_rejection
printf '%s\n' linux > /run/ph4ntxm/mode

chmod 0666 /run/ph4ntxm/persona_seed
expect_startup_rejection
chmod 0644 /run/ph4ntxm/persona_seed

printf '%064d\n\n' 0 > /run/ph4ntxm/persona_seed
expect_startup_rejection
printf '%064d\n' 0 > /run/ph4ntxm/persona_seed

mv /run/ph4ntxm/mode /run/ph4ntxm/mode.valid
ln -s mode.valid /run/ph4ntxm/mode
expect_startup_rejection
rm /run/ph4ntxm/mode
mv /run/ph4ntxm/mode.valid /run/ph4ntxm/mode
