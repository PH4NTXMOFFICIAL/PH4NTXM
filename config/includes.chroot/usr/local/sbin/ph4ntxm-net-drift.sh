#!/usr/bin/env bash
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -euo pipefail

MODE_FILE="/run/ph4ntxm/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' <"$MODE_FILE")"

if [[ "$MODE" == "lonewolf" ]]; then
    exit 0
fi

TC="/usr/sbin/tc"
IP="/usr/sbin/ip"
SLEEP="/bin/sleep"
BASENAME="/usr/bin/basename"
GREP="/bin/grep"
OD="/usr/bin/od"
TR="/usr/bin/tr"
DATE="/bin/date"
SEED_FILE=/run/ph4ntxm/persona_seed
JITTER_FILE=/run/ph4ntxm/boot_jitter

[[ -s "$SEED_FILE" && -s "$JITTER_FILE" ]] || exit 1

NETEM_HANDLE=4e44:

declare -A MANAGED_IFACES=()
declare -A ELIGIBLE_IFACES=()

remove_netem() {
    local IFACE=$1
    if [[ ! -e "/sys/class/net/$IFACE" ]] ||
        $TC qdisc del dev "$IFACE" root handle "$NETEM_HANDLE" netem >/dev/null 2>&1; then
        unset 'MANAGED_IFACES[$IFACE]'
    fi
}

cleanup() {
    local IFACE
    for IFACE in "${!MANAGED_IFACES[@]}"; do
        remove_netem "$IFACE"
    done
}

shutdown() {
    trap - EXIT
    cleanup
    exit 0
}

trap cleanup EXIT
trap shutdown INT TERM

DELAY=${1:-20}
JIT=${2:-5}
LOSS=${3:-1}

clamp() {
    local v=$1 min=$2 max=$3
    ((v < min)) && v=$min
    ((v > max)) && v=$max
    echo "$v"
}

DELAY=$(clamp "$DELAY" 5 150)
JIT=$(clamp "$JIT" 1 50)
LOSS=$(clamp "$LOSS" 0 5)

SEED_HEX=$(printf '%s%s%s%s' "$(cat "$SEED_FILE")" "$(cat "$JITTER_FILE")" "$($DATE +%s%N)" "$($OD -An -N2 -tu2 /dev/urandom 2>/dev/null | $TR -d ' ')" | sha256sum | cut -c1-8)
SEED=$((16#$SEED_HEX))

rand() {
    SEED=$(((SEED ^ $($DATE +%s%N)) & 0xffffffff))
    SEED=$(((SEED * 1664525 + 1013904223) & 0xffffffff))
    echo "$SEED"
}

while true; do
    SLEEP_TIME=$((($(rand) % 40) + 20))
    $SLEEP "$SLEEP_TIME"

    DRIFT=$((($(rand) % 5) - 2))
    JDRIFT=$((($(rand) % 3) - 1))
    LDRIFT=$((($(rand) % 3) - 1))

    DELAY=$((DELAY + DRIFT))
    JIT=$((JIT + JDRIFT))
    LOSS=$((LOSS + LDRIFT))
    DELAY=$(clamp "$DELAY" 5 150)
    JIT=$(clamp "$JIT" 1 50)
    LOSS=$(clamp "$LOSS" 0 5)

    ELIGIBLE_IFACES=()
    for IFACE_PATH in /sys/class/net/*; do
        IFACE="$($BASENAME "$IFACE_PATH")"

        [[ "$IFACE" == "lo" ]] && continue
        [[ "$IFACE" == veth* || "$IFACE" == docker* || "$IFACE" == br-* ||
            "$IFACE" == virbr* || "$IFACE" == tun* || "$IFACE" == tap* ||
            "$IFACE" == wg* || "$IFACE" == dummy* || "$IFACE" == vbr* ]] && continue

        ELIGIBLE_IFACES["$IFACE"]=1
        ADDRESSES=$($IP -4 addr show dev "$IFACE" 2>/dev/null) || continue
        ROUTES=$($IP -4 route show default dev "$IFACE" 2>/dev/null) || continue
        if ! $GREP -q "inet " <<<"$ADDRESSES" || ! $GREP -q '^default ' <<<"$ROUTES"; then
            unset 'ELIGIBLE_IFACES[$IFACE]'
            continue
        fi

        if [[ -d "/sys/class/net/$IFACE/wireless" ]]; then
            LOSS_IF=$(clamp "$LOSS" 0 1)
            JIT_IF=$(clamp "$JIT" 1 10)
        else
            LOSS_IF=$(clamp "$LOSS" 0 5)
            JIT_IF=$(clamp "$JIT" 1 50)
        fi

        if $TC qdisc replace dev "$IFACE" root handle "$NETEM_HANDLE" netem \
            delay ${DELAY}ms ${JIT_IF}ms distribution normal \
            loss ${LOSS_IF}% \
            duplicate 0.02% \
            reorder 0.05% \
            >/dev/null 2>&1; then
            MANAGED_IFACES["$IFACE"]=1
        fi

    done

    for IFACE in "${!MANAGED_IFACES[@]}"; do
        if [[ "${ELIGIBLE_IFACES[$IFACE]:-0}" != 1 ]]; then
            remove_netem "$IFACE"
        fi
    done
done
