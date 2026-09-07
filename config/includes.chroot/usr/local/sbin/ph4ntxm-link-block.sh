#!/usr/bin/env bash
set -euo pipefail

ip link set lo up

udevadm settle --timeout=10 >/dev/null 2>&1 || true

failed=0
while IFS= read -r dev; do
    dev=${dev%%@*}
    [[ -n "$dev" && "$dev" != "lo" ]] || continue
    [[ -d "/sys/class/net/$dev/device" ]] || continue
    if ! ip link set "$dev" down; then
        printf 'ph4ntxm-link-block: failed to block %s\n' "$dev" >&2
        failed=1
    fi
done < <(ip -o link show | awk -F': ' '{print $2}')

if ! /sbin/swapoff -a; then
    printf 'ph4ntxm-link-block: failed to disable swap\n' >&2
    failed=1
fi

(( failed == 0 ))
