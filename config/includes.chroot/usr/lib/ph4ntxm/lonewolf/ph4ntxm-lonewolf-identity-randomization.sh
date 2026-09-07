#!/usr/bin/env bash
set -euo pipefail

safe() { "$@" >/dev/null 2>&1 || true; }

STATE_DIR="/run/ph4ntxm"

MODE_FILE="$STATE_DIR/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' < "$MODE_FILE")"

if [[ "$MODE" != "lonewolf" ]]; then
    exit 0
fi

IDENTITY_READY_FILE="$STATE_DIR/identity-ready"
exec 9>"$STATE_DIR/identity.lock"
flock -x 9
if [[ -r "$IDENTITY_READY_FILE" ]] && \
   [[ "$(tr -d '\n' < "$IDENTITY_READY_FILE")" == "$MODE" ]]; then
    exit 0
fi

BOOT_HOST_FILE="$STATE_DIR/boot_hostname"
BOOT_MAC_DIR="$STATE_DIR/boot_mac"
BOOT_MID_FILE="$STATE_DIR/boot_machine_id"
SEED_FILE="$STATE_DIR/lonewolf_seed"

mkdir -p "$STATE_DIR"
install -d -o root -g root -m 0700 "$BOOT_MAC_DIR"

if [[ ! -s "$BOOT_MID_FILE" ]]; then
    BOOT_MID=$(tr -d '\n' < /etc/machine-id 2>/dev/null || true)
    [[ "$BOOT_MID" =~ ^[0-9a-f]{32}$ ]] || exit 1
    [[ "$BOOT_MID" != "00000000000000000000000000000000" ]] || exit 1
    mid_tmp=$(mktemp "$STATE_DIR/.boot-machine-id.XXXXXX")
    printf '%s\n' "$BOOT_MID" > "$mid_tmp"
    chmod 0644 "$mid_tmp"
    mv -f "$mid_tmp" "$BOOT_MID_FILE"
fi
BOOT_MID=$(tr -d '\n' < "$BOOT_MID_FILE")
[[ "$BOOT_MID" =~ ^[0-9a-f]{32}$ ]] || exit 1
[[ "$(tr -d '\n' < /etc/machine-id 2>/dev/null || true)" == "$BOOT_MID" ]] || exit 1

if [[ ! -s "$SEED_FILE" ]]; then
    seed_tmp=$(mktemp "$STATE_DIR/.lonewolf-seed.XXXXXX")
    {
        head -c 32 /dev/urandom
        printf '%s' "$BOOT_MID"
    } | sha256sum | awk '{print $1}' > "$seed_tmp"
    chmod 0600 "$seed_tmp"
    mv -f "$seed_tmp" "$SEED_FILE"
fi
SEED=$(tr -d '\n' < "$SEED_FILE")
[[ "$SEED" =~ ^[0-9a-f]{64}$ ]] || exit 1

seeded_random() {
    local max=$1 salt=${2:-default}
    local hash
    (( max > 0 )) || { echo 0; return; }
    hash=$(printf '%s%s' "$SEED" "$salt" | sha256sum | cut -c1-8)
    echo $((16#$hash % max))
}

seeded_hex() {
    local length=$1 salt=$2
    printf '%s%s' "$SEED" "$salt" | sha256sum | cut -c1-"$length"
}

generate_hostname() {
    local roll
    roll=$(seeded_random 100 hostname-roll)

    if [ "$roll" -lt 70 ]; then
        names=(debian ubuntu linux archlinux fedora manjaro pop-os localhost)
        printf '%s' "${names[$(seeded_random "${#names[@]}" hostname-name)]}"
    elif [ "$roll" -lt 90 ]; then
        prefixes=(pc node host srv box dev)
        printf '%s-%s' \
            "${prefixes[$(seeded_random "${#prefixes[@]}" hostname-prefix)]}" \
            "$(seeded_hex 4 hostname-suffix)"
    else
        seeded_hex 8 hostname-random
    fi
}

generate_mac() {
    local iface=$1 hex
    hex=$(seeded_hex 10 "mac-$iface")
    printf '02:%s:%s:%s:%s:%s\n' \
        "${hex:0:2}" "${hex:2:2}" "${hex:4:2}" "${hex:6:2}" "${hex:8:2}"
}

if [[ ! -s "$BOOT_HOST_FILE" ]]; then
    HOST="$(generate_hostname)"
    HOST="$(printf "%s" "$HOST" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')"
    host_tmp=$(mktemp "$STATE_DIR/.boot-hostname.XXXXXX")
    echo "${HOST:0:16}" > "$host_tmp"
    chmod 0600 "$host_tmp"
    mv -f "$host_tmp" "$BOOT_HOST_FILE"
fi
HOST=$(cat "$BOOT_HOST_FILE")
[[ "$HOST" =~ ^[a-z0-9]([a-z0-9-]{0,14}[a-z0-9])?$ ]] || exit 1

printf '%s\n' "$HOST" > /etc/hostname
hostname "$HOST"

if grep -q '^127\.0\.1\.1' /etc/hosts 2>/dev/null; then
    sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$HOST/" /etc/hosts
else
    printf '\n127.0.1.1\t%s\n' "$HOST" >> /etc/hosts
fi

install -d -m 0755 /var/lib/dbus
ln -sf /etc/machine-id /var/lib/dbus/machine-id

declare -A LONEWOLF_MACS
for devpath in /sys/class/net/*; do
    iface=$(basename "$devpath")
    [[ "$iface" == "lo" ]] && continue
    [[ -d "/sys/class/net/$iface/device" ]] || continue
    
    IFACE_MAC_FILE="$BOOT_MAC_DIR/$iface"
    if [[ ! -s "$IFACE_MAC_FILE" ]]; then
        mac_tmp=$(mktemp "$BOOT_MAC_DIR/.mac.XXXXXX")
        generate_mac "$iface" > "$mac_tmp"
        chmod 0600 "$mac_tmp"
        mv -f "$mac_tmp" "$IFACE_MAC_FILE"
    fi
    LONEWOLF_MACS["$iface"]=$(tr -d '\n' < "$IFACE_MAC_FILE")
    [[ "${LONEWOLF_MACS[$iface]}" =~ ^02:([0-9a-f]{2}:){4}[0-9a-f]{2}$ ]] || exit 1
done

apply_mac() {
    local iface=$1 target=$2 attempt current
    for attempt in {1..10}; do
        if ip link set "$iface" down 2>/dev/null && \
           ip link set "$iface" address "$target" 2>/dev/null; then
            current=$(tr -d '\n' < "/sys/class/net/$iface/address" 2>/dev/null || true)
            [[ "$current" == "$target" ]] && return 0
        fi
        udevadm settle --timeout=2 >/dev/null 2>&1 || true
        sleep 0.5
    done
    return 1
}

mac_failed=0
for if_name in "${!LONEWOLF_MACS[@]}"; do
    if ! apply_mac "$if_name" "${LONEWOLF_MACS[$if_name]}"; then
        printf 'ph4ntxm-lonewolf-identity: failed to set protected MAC on %s\n' "$if_name" >&2
        mac_failed=1
    fi
done

(( mac_failed == 0 )) || exit 1

safe sync
safe udevadm trigger --action=change --subsystem-match=net
safe udevadm settle --timeout=10

ready_tmp=$(mktemp "$STATE_DIR/.identity-ready.XXXXXX")
printf '%s\n' "$MODE" > "$ready_tmp"
chmod 0644 "$ready_tmp"
mv "$ready_tmp" "$IDENTITY_READY_FILE"

sleep 1

exit 0
