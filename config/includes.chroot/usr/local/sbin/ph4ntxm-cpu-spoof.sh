#!/usr/bin/env bash
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -euo pipefail

STATE_DIR="/run/ph4ntxm"

MODE_FILE="$STATE_DIR/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' <"$MODE_FILE")"
case "$MODE" in
    linux | windows) ;;
    lonewolf) exit 0 ;;
    *) exit 1 ;;
esac

[[ -r "$STATE_DIR/cores_env" ]] || exit 1
[[ -s "$STATE_DIR/persona_seed" ]] || exit 1
source "$STATE_DIR/cores_env"
[[ "${PH4_REPORTED_CORES:-}" =~ ^[1-9][0-9]*$ ]] || exit 1
RANDOM=$((16#$(printf '%s%s' "$(cat "$STATE_DIR/persona_seed")" cpuinfo | sha256sum | cut -c1-4) & 32767))

FAKE_CPUINFO="$STATE_DIR/fake_cpuinfo"
/usr/bin/python3 /usr/lib/ph4ntxm/hardware/inventory.py --cpuinfo >"$FAKE_CPUINFO"

FAKE_SYSFS="$STATE_DIR/fake_online"
MAX_CORE_IDX=$((PH4_REPORTED_CORES - 1))

if ((MAX_CORE_IDX == 0)); then
    printf '0\n' >"$FAKE_SYSFS"
else
    printf '0-%d\n' "$MAX_CORE_IDX" >"$FAKE_SYSFS"
fi
chmod 0444 "$FAKE_CPUINFO" "$FAKE_SYSFS"

mounted_targets=()
cleanup_partial_mounts() {
    local target
    for ((idx = ${#mounted_targets[@]} - 1; idx >= 0; idx--)); do
        target=${mounted_targets[$idx]}
        umount "$target" >/dev/null 2>&1 || true
    done
}
trap cleanup_partial_mounts ERR

bind_readonly() {
    local source_file=$1 target=$2
    umount "$target" >/dev/null 2>&1 || true
    mount --bind "$source_file" "$target"
    mounted_targets+=("$target")
    mount -o remount,ro,bind "$target"
}

bind_readonly "$FAKE_CPUINFO" /proc/cpuinfo
bind_readonly "$FAKE_SYSFS" /sys/devices/system/cpu/online
bind_readonly "$FAKE_SYSFS" /sys/devices/system/cpu/present
bind_readonly "$FAKE_SYSFS" /sys/devices/system/cpu/possible

trap - ERR
