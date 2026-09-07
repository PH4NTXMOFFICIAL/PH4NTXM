#!/bin/bash
set -euo pipefail
[[ $# == 3 && $(id -u) == 0 ]] || { echo "usage: $0 ROOTFS BUILD_DIR linux|windows" >&2; exit 2; }
[[ $3 == linux || $3 == windows ]] || exit 2
[[ -d $1 && $1 != / && -x $2/ph4ntxm-packet-transformation-engine-loader ]] || exit 2
if [[ ${PACKET_TRANSFORMATION_ENGINE_DHCP_ISOLATED:-0} != 1 ]]; then
 exec unshare --mount --propagation private --net --uts --pid --fork --mount-proc env PACKET_TRANSFORMATION_ENGINE_DHCP_ISOLATED=1 "$0" "$@"
fi
root=$(realpath "$1")
build=$(realpath "$2")
mode=$3
src=$(CDPATH= cd -- "$(dirname -- "$0")/../../../../.." && pwd)
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t sysfs sysfs "$root/sys"
for dir in run tmp etc/NetworkManager etc/dhcp var/lib/NetworkManager var/lib/dhcp usr/local/sbin usr/lib/ph4ntxm; do
 mount -t tmpfs tmpfs "$root/$dir"
done
mkdir -p "$root/run/dbus" "$root/run/ph4ntxm"
printf '%s\n' "$mode" > "$root/run/ph4ntxm/mode"
printf '%064d\n' 0 > "$root/run/ph4ntxm/persona_seed"
printf 'packet_engine-test\n' > "$root/run/hostname"
mount --bind "$root/run/hostname" "$root/etc/hostname"
cp "$src/etc/NetworkManager/NetworkManager.conf" "$root/etc/NetworkManager/NetworkManager.conf"
printf '\n[keyfile]\nunmanaged-devices=interface-name:audit1\n' >> "$root/etc/NetworkManager/NetworkManager.conf"
printf '\n[device-packet_engine-test]\nmatch-device=interface-name:audit0\nmanaged=true\n' >> "$root/etc/NetworkManager/NetworkManager.conf"
chroot "$root" bash < "$src/usr/local/sbin/ph4ntxm-dhcp-session-generator.sh"
ip link set lo up
ip link add audit0 type veth peer name audit1
ip link set audit0 address 02:00:00:12:34:56
ip link set audit0 up
ip link set audit1 up
mkdir -p "$root/run/udev/data"
for dev in audit0 audit1; do
 index=$(cat "$root/sys/class/net/$dev/ifindex")
 printf 'I:1\nE:ID_NET_DRIVER=veth\n' > "$root/run/udev/data/n$index"
done
unshare --net sleep 180 &
server=$!
sleep 0.3
ip link set audit1 netns "$server"
nsenter -t "$server" -n ip link set lo up
nsenter -t "$server" -n ip link set audit1 up
nsenter -t "$server" -n ip addr add 192.0.2.1/24 dev audit1
nsenter -t "$server" -n /usr/sbin/dnsmasq --no-daemon --conf-file=/dev/null --port=0 --interface=audit1 --bind-interfaces --dhcp-range=192.0.2.10,192.0.2.20,255.255.255.0,1h --dhcp-option=3,192.0.2.1 --dhcp-leasefile="$root/run/leases" --pid-file= --user=root --group=root --log-dhcp > "$root/run/dnsmasq.log" 2>&1 &
nsenter -t "$server" -n python3 -c '
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"PACKET_TRANSFORMATION_ENGINE_TCP_OK")
HTTPServer(("192.0.2.1", 8080), Handler).serve_forever()
' > "$root/run/http.log" 2>&1 &
install -m 0755 "$build/ph4ntxm-packet-transformation-engine-loader" "$root/usr/local/sbin/ph4ntxm-packet-transformation-engine-loader"
install -m 0755 "$build/ph4ntxm-packet-transformation-engine-native" "$root/usr/local/sbin/ph4ntxm-packet-transformation-engine-native"
install -m 0644 "$build/packet-transformation-engine.bpf.o" "$root/usr/lib/ph4ntxm/packet-transformation-engine.bpf.o"
tc qdisc add dev audit0 clsact
tc filter add dev audit0 egress pref 2 protocol all matchall action drop
chroot "$root" setpriv --bounding-set=-all,+net_admin,+bpf \
 --inh-caps=-all,+net_admin,+bpf --ambient-caps=-all,+net_admin,+bpf --no-new-privs \
 /usr/local/sbin/ph4ntxm-packet-transformation-engine-loader attach audit0
nft -f "$src/etc/firewall/normal.nft"
chroot "$root" python3 -c 'import socket; s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.bind("/run/notify"); exec("while True: s.recv(8192)")' &
sleep 0.2
chroot "$root" env NOTIFY_SOCKET=/run/notify /usr/local/sbin/ph4ntxm-packet-transformation-engine-native > "$root/run/engine.log" 2>&1 &
engine=$!
chroot "$root" dbus-daemon --system --nofork --nopidfile > "$root/run/dbus.log" 2>&1 &
sleep 1
chroot "$root" /usr/sbin/NetworkManager --no-daemon --log-level=DEBUG --log-domains=ALL > "$root/run/nm.log" 2>&1 &
sleep 2
chroot "$root" nmcli device set audit0 managed yes
chroot "$root" nmcli --wait 20 device connect audit0
chroot "$root" nmcli -f GENERAL.STATE,IP4.ADDRESS,IP4.GATEWAY device show audit0
chroot "$root" /usr/local/sbin/ph4ntxm-packet-transformation-engine-loader stats audit0
grep -E "DHCP(DISCOVER|OFFER|REQUEST|ACK)" "$root/run/dnsmasq.log"
cat "$root/run/engine.log"
ip -4 address show dev audit0
ip -4 route
test -s "$root/run/leases"
ping -I audit0 -c 2 -W 2 192.0.2.1
kill -0 "$engine"
chroot "$root" nmcli device disconnect audit0
chroot "$root" nmcli --wait 20 device connect audit0
[[ $(chroot "$root" cat /sys/class/net/audit0/address) == 02:00:00:12:34:56 ]]
chroot "$root" /usr/local/sbin/ph4ntxm-packet-transformation-engine-loader verify audit0
ping -I audit0 -c 1 -W 2 192.0.2.1
chroot "$root" python3 -c '
import urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
assert opener.open("http://192.0.2.1:8080/", timeout=5).read() == b"PACKET_TRANSFORMATION_ENGINE_TCP_OK"
print("native-nfqueue-tc-protected-http: PASS")
'
kill -0 "$engine"
printf 'networkmanager-dhcp-reconnect-%s: PASS\n' "$mode"
