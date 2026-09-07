#!/bin/sh
set -eu

SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GUARD=$SOURCE/../../sbin/ph4ntxm-packet-transformation-engine-guard.sh

if [ "$#" -ne 3 ] || [ "$(id -u)" -ne 0 ]; then
    echo "usage: guardian-smoke.sh LOADER BPF_OBJECT ROOTFS" >&2
    exit 2
fi

LOADER=$1
OBJECT=$2
ROOTFS=$3

[ -x "$LOADER" ] && [ -r "$OBJECT" ] && [ -x "$GUARD" ] && [ -d "$ROOTFS" ] || exit 1

if [ "${PH4NTXM_GUARDIAN_TEST_NAMESPACE:-0}" != 1 ]; then
    exec unshare --mount --net --pid --fork --mount-proc \
        env PH4NTXM_GUARDIAN_TEST_NAMESPACE=1 "$0" "$LOADER" "$OBJECT" "$ROOTFS"
fi

mount --make-rprivate /
mount --bind /proc "$ROOTFS/proc"
mount --bind /sys "$ROOTFS/sys"
mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs "$ROOTFS/run"
mount -t tmpfs -o mode=0755,nodev,nosuid tmpfs "$ROOTFS/usr/local/sbin"
mount -t tmpfs -o mode=0755,nodev,nosuid,noexec tmpfs "$ROOTFS/usr/lib/ph4ntxm"

install -o root -g root -m 0755 "$GUARD" \
    "$ROOTFS/usr/local/sbin/ph4ntxm-packet-transformation-engine-guard.sh"
install -o root -g root -m 0755 "$LOADER" \
    "$ROOTFS/usr/local/sbin/ph4ntxm-packet-transformation-engine-loader"
install -o root -g root -m 0755 "$LOADER" \
    "$ROOTFS/usr/local/sbin/ph4ntxm-packet-transformation-engine-native"
install -o root -g root -m 0644 "$OBJECT" "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.bpf.o"
cp "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.bpf.o" \
    "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.bpf.o.clean"
(cd "$ROOTFS" && sha256sum \
    usr/lib/ph4ntxm/packet-transformation-engine.bpf.o \
    usr/local/sbin/ph4ntxm-packet-transformation-engine-loader \
    usr/local/sbin/ph4ntxm-packet-transformation-engine-native) \
    > "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.sha256"
chown root:root "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.sha256"
chmod 0644 "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.sha256"

install -d -o root -g root -m 0755 "$ROOTFS/run/ph4ntxm"
printf '%s\n' linux > "$ROOTFS/run/ph4ntxm/mode"
printf '%s\n' ph4ntxm > "$ROOTFS/run/test-hostname"
chmod 0644 "$ROOTFS/run/ph4ntxm/mode" "$ROOTFS/run/test-hostname"
mount --bind "$ROOTFS/run/test-hostname" "$ROOTFS/etc/hostname"
mount -o remount,bind,ro "$ROOTFS/etc/hostname"

ip link add audit0 type veth peer name audit1
ip link set audit0 up
ip link set audit1 up

fake_net=$(mktemp -d /tmp/ph4ntxm-packet-transformation-engine-fake-net.XXXXXX)
install -d -m 0755 "$fake_net/audit0/device" "$fake_net/audit1/device"
mount --bind "$fake_net" "$ROOTFS/sys/class/net"

run_guard() {
    chroot "$ROOTFS" /usr/local/sbin/ph4ntxm-packet-transformation-engine-guard.sh "$@"
}

run_guard_without_sys_admin() {
    chroot "$ROOTFS" setpriv \
        --bounding-set=-all,+net_admin,+bpf \
        --inh-caps=-all,+net_admin,+bpf \
        --ambient-caps=-all,+net_admin,+bpf \
        --no-new-privs -- \
        /usr/local/sbin/ph4ntxm-packet-transformation-engine-guard.sh "$@"
}

fallback_only() {
    chroot "$ROOTFS" tc -j -details filter show dev audit0 egress | \
        chroot "$ROOTFS" jq -e '
            [.[] | select(.options != null)] as $filters |
            ($filters | length) == 1 and
            $filters[0].protocol == "all" and $filters[0].pref == 2 and
            $filters[0].kind == "matchall" and
            ($filters[0].options.actions | length) == 1 and
            $filters[0].options.actions[0].kind == "gact" and
            $filters[0].options.actions[0].control_action.type == "drop"
        ' >/dev/null
}

run_guard enforce audit0
run_guard verify audit0
run_guard runtime
identity_file=$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-audit0.identity
[ -f "$identity_file" ] && [ "$(wc -l < "$identity_file")" -eq 7 ]
first_id=$(awk -F= '$1 == "PROGRAM_ID" {print $2}' "$identity_file")

chroot "$ROOTFS" tc filter del dev audit0 egress pref 1
run_guard_without_sys_admin enforce audit0
run_guard_without_sys_admin verify audit0

printf 'lin\nux' > "$ROOTFS/run/ph4ntxm/mode"
if run_guard verify audit0 >/dev/null 2>&1; then
    echo "guardian accepted a malformed normal-mode state" >&2
    exit 1
fi
printf '%s\n' linux > "$ROOTFS/run/ph4ntxm/mode"

printf '%s\n' windows > "$ROOTFS/run/ph4ntxm/mode"
if run_guard verify audit0 >/dev/null 2>&1; then
    echo "guardian accepted a classifier configured for another mode" >&2
    exit 1
fi
printf '%s\n' linux > "$ROOTFS/run/ph4ntxm/mode"

printf '%s\n' changed-hostname > "$ROOTFS/run/test-hostname"
if run_guard verify audit0 >/dev/null 2>&1; then
    echo "guardian accepted a classifier configured for another hostname" >&2
    exit 1
fi
printf '%s\n' ph4ntxm > "$ROOTFS/run/test-hostname"

ip link set dev audit0 down
ip link set dev audit0 address 02:00:00:00:00:01
if run_guard verify audit0 >/dev/null 2>&1; then
    echo "guardian accepted a classifier configured for another MAC address" >&2
    exit 1
fi
run_guard enforce audit0
run_guard verify audit0

chmod 0666 "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.sha256"
if run_guard runtime >/dev/null 2>&1; then
    echo "runtime gate accepted a writable artifact manifest" >&2
    exit 1
fi
if run_guard verify audit0 >/dev/null 2>&1; then
    echo "guardian accepted a writable artifact manifest" >&2
    exit 1
fi
if run_guard enforce audit0 >/dev/null 2>&1; then
    echo "guardian attached while the artifact manifest was writable" >&2
    exit 1
fi
fallback_only
printf 'sealed\n' > "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed"
chmod 0600 "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed"
run_guard verify audit0
rm "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed"
chmod 0644 "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.sha256"
ip link set dev audit0 up
run_guard enforce audit0
run_guard verify audit0

chmod 0777 "$ROOTFS/usr/local/sbin/ph4ntxm-packet-transformation-engine-loader"
if run_guard verify audit0 >/dev/null 2>&1; then
    echo "guardian accepted a writable eBPF loader" >&2
    exit 1
fi
chmod 0755 "$ROOTFS/usr/local/sbin/ph4ntxm-packet-transformation-engine-loader"
run_guard enforce audit0
run_guard verify audit0

printf 'corrupt\n' > "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed"
chmod 0600 "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed"
if run_guard unseal >/dev/null 2>&1; then
    echo "guardian unsealed a malformed seal state" >&2
    exit 1
fi
run_guard enforce audit0
run_guard verify audit0
fallback_only
rm "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed"
ip link set dev audit0 up
run_guard enforce audit0
run_guard verify audit0

printf '{invalid json\n' > "$ROOTFS/run/ph4ntxm-lockdown-status.json"
chmod 0644 "$ROOTFS/run/ph4ntxm-lockdown-status.json"
printf 'sealed\n' > "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed"
chmod 0600 "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed"
if run_guard unseal >/dev/null 2>&1; then
    echo "guardian unsealed with malformed Lockdown status" >&2
    exit 1
fi
run_guard enforce audit0
run_guard verify audit0
fallback_only
rm "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed"
rm "$ROOTFS/run/ph4ntxm-lockdown-status.json"
ip link set dev audit0 up
run_guard enforce audit0
run_guard verify audit0

run_guard seal
[ -f "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed" ]
if ip -o link show dev audit0 | grep -q '<[^>]*UP[^>]*>'; then
    echo "guardian left the interface up while sealed" >&2
    exit 1
fi
fallback_only
links_file=$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed-links
cp "$links_file" "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed-links.clean"
rm "$links_file"
if run_guard unseal >/dev/null 2>&1; then
    echo "guardian unsealed without protected link state" >&2
    exit 1
fi
run_guard enforce audit0
run_guard verify audit0
fallback_only
mv "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed-links.clean" "$links_file"
chmod 0600 "$links_file"
cp "$links_file" "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed-links.clean"
printf 'audit0' > "$links_file"
chmod 0600 "$links_file"
if run_guard unseal >/dev/null 2>&1; then
    echo "guardian unsealed with malformed link state" >&2
    exit 1
fi
run_guard enforce audit0
run_guard verify audit0
fallback_only
mv "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed-links.clean" "$links_file"
chmod 0600 "$links_file"
run_guard unseal
[ ! -e "$ROOTFS/run/ph4ntxm/packet-transformation-engine-guard-sealed" ]
ip -o link show dev audit0 | grep -q '<[^>]*UP[^>]*>'
run_guard verify audit0
first_id=$(awk -F= '$1 == "PROGRAM_ID" {print $2}' "$identity_file")

printf 'audit0\naudit0\n' > "$links_file"
chmod 0600 "$links_file"
if run_guard verify audit0 >/dev/null 2>&1; then
    echo "guardian accepted stale duplicate link state without a seal" >&2
    exit 1
fi
run_guard enforce audit0
run_guard verify audit0
fallback_only
run_guard seal
run_guard unseal
run_guard verify audit0

chroot "$ROOTFS" tc filter del dev audit0 egress pref 1
if run_guard verify audit0 >/dev/null 2>&1; then
    echo "guardian accepted a detached Packet Transformation Engine classifier" >&2
    exit 1
fi
fallback_only
run_guard enforce audit0
run_guard verify audit0
second_id=$(awk -F= '$1 == "PROGRAM_ID" {print $2}' "$identity_file")
[ "$first_id" != "$second_id" ] || {
    echo "guardian did not bind identity to the replacement program" >&2
    exit 1
}

sed 's/^PROGRAM_TAG=.*/PROGRAM_TAG=0000000000000000/' "$identity_file" \
    > "$identity_file.forged"
mv "$identity_file.forged" "$identity_file"
chmod 0600 "$identity_file"
if run_guard verify audit0 >/dev/null 2>&1; then
    echo "guardian accepted a forged program identity" >&2
    exit 1
fi
run_guard enforce audit0
run_guard verify audit0

printf 'corrupt\n' >> "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.bpf.o"
if run_guard enforce audit0 >/dev/null 2>&1; then
    echo "guardian attached an artifact with a bad manifest hash" >&2
    exit 1
fi
if ip -o link show dev audit0 | grep -q '<[^>]*UP[^>]*>'; then
    echo "guardian left the interface up after artifact-integrity failure" >&2
    exit 1
fi
fallback_only

cp "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.bpf.o.clean" \
    "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.bpf.o"
chmod 0644 "$ROOTFS/usr/lib/ph4ntxm/packet-transformation-engine.bpf.o"
ip link set audit0 up
run_guard enforce audit0
run_guard verify audit0

echo "packet-transformation-engine-guardian-identity-and-fail-closed: PASS"
