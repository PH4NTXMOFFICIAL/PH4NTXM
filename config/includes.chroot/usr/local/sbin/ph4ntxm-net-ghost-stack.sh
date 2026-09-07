#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/run/ph4ntxm"
STATE_FILE="$STATE_DIR/ghost_stack"

MODE_FILE="$STATE_DIR/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' < "$MODE_FILE")"

case "$MODE" in
    linux|windows) ;;
    lonewolf) exit 0 ;;
    *) exit 1 ;;
esac

safe() { "$@" >/dev/null 2>&1 || true; }

SEED_FILE="$STATE_DIR/persona_seed"
JITTER_FILE="$STATE_DIR/boot_jitter"
PRIMARY_MAC_FILE="$STATE_DIR/boot_mac"

[[ -r "$SEED_FILE" && -r "$JITTER_FILE" && -r "$PRIMARY_MAC_FILE" ]] || exit 1

: > "$STATE_FILE"
chmod 0600 "$STATE_FILE"

SEED=$(cat "$SEED_FILE" 2>/dev/null || echo "0")
JITTER=$(cat "$JITTER_FILE" 2>/dev/null || echo "0")
OUI=$(cut -d: -f1-3 "$PRIMARY_MAC_FILE" 2>/dev/null || echo "02:00:00")

safe /usr/sbin/sysctl -w net.ipv4.conf.all.rp_filter=2
safe /usr/sbin/sysctl -w net.ipv4.ip_forward=0

seeded_random() {
    local max=$1 salt=$2
    local hash
    hash=$(printf "%s%s" "$SEED" "$salt" | sha256sum 2>/dev/null | cut -c1-8 || echo "1")
    echo $((16#$hash % max)) 2>/dev/null || echo 0
}

session_random() {
    local max=$1 salt=$2
    local hash
    hash=$(printf "%s%s%s" "$SEED" "$JITTER" "$salt" | sha256sum 2>/dev/null | cut -c1-8 || echo "1")
    echo $((16#$hash % max)) 2>/dev/null || echo 0
}

if [[ "$MODE" != "windows" ]]; then
    if [[ "$(session_random 2 "global_skip")" == "0" ]]; then
        exit 0
    fi
fi

gen_mac_aligned() {
    local salt=$1
    printf "%s:%02x:%02x:%02x\n" \
        "$OUI" \
        "$(session_random 256 "a-$salt")" \
        "$(session_random 256 "b-$salt")" \
        "$(session_random 256 "c-$salt")"
}

PRIMARY_IF=$(ls /sys/class/net 2>/dev/null | grep -vE '^(lo|docker.*|veth.*|br-.*|virbr.*|tun.*|tap.*|dummy.*|vbr.*)$' | head -n1 || true)
PRIMARY_IF=${PRIMARY_IF:-eth0}

case "$PRIMARY_IF" in
    enp*) IF_PREFIX="enp" ;;
    wlp*) IF_PREFIX="wlp" ;;
    *) IF_PREFIX="eth" ;;
esac

BASE_IDX=$(echo "$PRIMARY_IF" | grep -o '[0-9]\+' | head -n1 || true)
BASE_IDX=${BASE_IDX:-0}

PERSONA=$(seeded_random 4 "persona")

gen_ifname() {
    local i=$1
    case "$PERSONA" in
        0) echo "${IF_PREFIX}$((BASE_IDX+i+1))s0" ;;
        1) echo "veth$(session_random 65535 "veth-$i")" ;;
        2) echo "virbr$(( (BASE_IDX+i+1) % 10 ))" ;;
        3) echo "vbr$i" ;;
    esac
}

spawn_interface() {
    local i=$1
    local IFACE
    IFACE=$(gen_ifname "$i")

    [[ "$IFACE" == "$PRIMARY_IF" ]] && return 0
    ip link show "$IFACE" >/dev/null 2>&1 && return 0

    local TYPE
    TYPE=$(seeded_random 4 "type-$i")

    local RND_HOST=$((2 + $(session_random 250 "host-$i")))

    case "$TYPE" in
        0|2)
            safe ip link add "$IFACE" type dummy
            safe ip link set "$IFACE" address "$(gen_mac_aligned "$IFACE")"
            [[ "$TYPE" == "0" ]] && safe ip addr add "192.0.2.$RND_HOST/32" dev "$IFACE" noprefixroute
            safe ip link set "$IFACE" up
            ;;
        1)
            safe ip link add "$IFACE" type bridge
            safe ip link set "$IFACE" address "$(gen_mac_aligned "$IFACE")"
            safe ip link set "$IFACE" up
            ;;
        3)
            safe ip link add "$IFACE" type dummy
            safe ip link set "$IFACE" address "$(gen_mac_aligned "$IFACE")"
            safe ip addr add "198.51.100.$RND_HOST/32" dev "$IFACE" noprefixroute
            safe ip link set "$IFACE" up
            ;;
    esac

    if ip link show "$IFACE" >/dev/null 2>&1; then
        echo "$IFACE" >> "$STATE_FILE"
    fi
}

apply_windows() {
    local EXTRA=$(seeded_random 4 "win_extra")
    local COUNT=1

    (( EXTRA == 2 )) && COUNT=2
    (( EXTRA == 3 )) && COUNT=3

    win_name() {
        local i=$1
        case $((i % 4)) in
            0) [[ $i -eq 0 ]] && echo "Ethernet" || echo "Ethernet $((i+1))" ;;
            1) [[ $i -eq 0 ]] && echo "Wi-Fi" || echo "Wi-Fi $((i+1))" ;;
            2) echo "vEthernet (Default Switch)" ;;
            3) echo "vEthernet (WSL)" ;;
        esac
    }

    for ((i=0;i<COUNT;i++)); do
        IFACE=$(win_name "$i")
        ip link show "$IFACE" >/dev/null 2>&1 && continue

        local DEV="win-$i"
        local TYPE
        TYPE=$(seeded_random 4 "win_type-$i")

        case "$TYPE" in
            0|2)
                safe ip link add "$DEV" type dummy
                safe ip link set "$DEV" address "$(gen_mac_aligned "win-$i")"
                [[ $i -eq 0 ]] && safe ip addr add "203.0.113.$((100 + BASE_IDX % 100))/32" dev "$DEV" noprefixroute
                safe ip link set "$DEV" up
                ;;
            1)
                safe ip link add "vSwitch-$i" type bridge
                safe ip link set "vSwitch-$i" address "$(gen_mac_aligned "vSwitch-$i")"
                safe ip link set "vSwitch-$i" up
                DEV="vSwitch-$i"
                ;;
            3)
                safe ip link add "$DEV" type dummy
                safe ip link set "$DEV" address "$(gen_mac_aligned "win-$i")"
                safe ip addr add "198.51.100.$((2 + i))/32" dev "$DEV" noprefixroute
                safe ip link set "$DEV" up
                ;;
        esac

        if ip link show "$DEV" >/dev/null 2>&1; then
            echo "$IFACE:$DEV" >> "$STATE_FILE"
        fi
    done
}

apply_linux() {
    local EXTRA=$(seeded_random 4 "extra")
    local COUNT=1

    (( EXTRA == 2 )) && COUNT=2
    (( EXTRA == 3 )) && COUNT=3

    for ((i=0;i<COUNT;i++)); do
        spawn_interface "$i"
    done
}

case "$MODE" in
    windows) apply_windows ;;
    linux) apply_linux ;;
esac

exit 0
