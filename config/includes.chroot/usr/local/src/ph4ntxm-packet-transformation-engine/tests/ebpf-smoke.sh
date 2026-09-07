#!/bin/sh
set -eu

SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
LOADER=${1:-$SOURCE/target/ebpf/ph4ntxm-packet-transformation-engine-loader}

[ "$(id -u)" -eq 0 ] || {
    echo "ebpf-smoke.sh must run as root" >&2
    exit 1
}
[ -x "$LOADER" ] || {
    echo "missing eBPF loader: $LOADER" >&2
    exit 1
}

if [ "${PH4NTXM_EBPF_TEST_NAMESPACE:-0}" != 1 ]; then
    exec unshare --mount --net --pid --fork --mount-proc \
        env PH4NTXM_EBPF_TEST_NAMESPACE=1 "$0" "$LOADER"
fi

mount --make-rprivate /
mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs /run
install -d -o root -g root -m 0755 /run/ph4ntxm
printf '%s\n' linux > /run/ph4ntxm/mode
printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > /run/ph4ntxm/test-hostname
chmod 0644 /run/ph4ntxm/mode /run/ph4ntxm/test-hostname
mount --bind /run/ph4ntxm/test-hostname /etc/hostname
mount -o remount,bind,ro /etc/hostname

ip link add audit0 type veth peer name audit1
ip link set audit0 up
ip link set audit1 up
ip address add 10.0.0.1/24 dev audit0
ip -6 address add 2001:db8::1/64 dev audit0 nodad
audit1_mac=$(ip -brief link show dev audit1 | awk '{print $3}')
ip neigh replace 10.0.0.2 lladdr "$audit1_mac" nud permanent dev audit0
ip -6 neigh replace 2001:db8::2 lladdr "$audit1_mac" nud permanent dev audit0

tc qdisc add dev audit0 clsact
tc filter add dev audit0 egress pref 2 protocol all matchall action drop
"$LOADER" attach audit0
"$LOADER" verify audit0
"$LOADER" identity audit0 | awk -F= '
    $1 == "PROGRAM_ID" && $2 ~ /^[1-9][0-9]*$/ {id++}
    $1 == "PROGRAM_TAG" && $2 ~ /^[0-9a-f]{16}$/ {tag++}
    END {exit id != 1 || tag != 1}
'
dump_on_failure() {
    status=$?
    trap - EXIT
    if [ "$status" -ne 0 ]; then
        "$LOADER" stats audit0 || true
        tc -s filter show dev audit0 egress || true
    fi
    exit "$status"
}
trap dump_on_failure EXIT
/usr/bin/python3 "$SOURCE/tests/ebpf-smoke.py" audit0 audit1 "$LOADER"
"$LOADER" stats audit0 | awk -F= '
    NF == 2 && $1 ~ /^[a-z0-9_]+$/ && $2 ~ /^[0-9]+$/ {count++}
    END {exit count != 23}
'

chmod 0666 /run/ph4ntxm/mode
if "$LOADER" verify audit0 >/dev/null 2>&1; then
    echo "eBPF loader accepted group/world-writable mode state" >&2
    exit 1
fi
chmod 0644 /run/ph4ntxm/mode

printf 'linux\000windows\n' > /run/ph4ntxm/mode
if "$LOADER" verify audit0 >/dev/null 2>&1; then
    echo "eBPF loader accepted embedded-NUL mode state" >&2
    exit 1
fi
printf '%s\n' windows > /run/ph4ntxm/mode

printf 'windows \n' > /run/ph4ntxm/mode
if "$LOADER" verify audit0 >/dev/null 2>&1; then
    echo "eBPF loader accepted a space-padded mode state" >&2
    exit 1
fi
printf 'windows\n\n' > /run/ph4ntxm/mode
if "$LOADER" verify audit0 >/dev/null 2>&1; then
    echo "eBPF loader accepted a multi-line mode state" >&2
    exit 1
fi
printf windows > /run/ph4ntxm/mode
if "$LOADER" verify audit0 >/dev/null 2>&1; then
    echo "eBPF loader accepted a non-terminated mode state" >&2
    exit 1
fi
printf '%s\n' windows > /run/ph4ntxm/mode

mv /run/ph4ntxm/mode /run/ph4ntxm/mode.valid
ln -s mode.valid /run/ph4ntxm/mode
if "$LOADER" verify audit0 >/dev/null 2>&1; then
    echo "eBPF loader followed a mode-state symlink" >&2
    exit 1
fi
rm /run/ph4ntxm/mode
mv /run/ph4ntxm/mode.valid /run/ph4ntxm/mode

"$LOADER" verify audit0
tc filter del dev audit0 egress pref 1
/usr/bin/python3 "$SOURCE/tests/ebpf-smoke.py" --fallback
