#!/usr/bin/env bash
set -euo pipefail

MODE_FILE=/run/ph4ntxm/mode
IDENTITY_READY_FILE=/run/ph4ntxm/identity-ready
[[ -r "$MODE_FILE" && -r "$IDENTITY_READY_FILE" ]] || exit 1
MODE="$(tr -d '\n' < "$MODE_FILE")"
[[ "$MODE" == "$(tr -d '\n' < "$IDENTITY_READY_FILE")" ]] || exit 1
[[ "$(cat /sys/kernel/kexec_crash_loaded 2>/dev/null || echo 0)" == "1" ]] || exit 1
[[ "$(cat /proc/sys/kernel/kexec_load_disabled 2>/dev/null || echo 0)" == "1" ]] || exit 1

if [[ "$MODE" == "linux" || "$MODE" == "windows" ]]; then
    /usr/bin/systemctl is-active --quiet ph4ntxm-nft-rules.service || exit 1
    /usr/bin/systemctl is-active --quiet ph4ntxm-packet-transformation-engine.service || exit 1
elif [[ "$MODE" == "lonewolf" ]]; then
    READY_FILE=/run/ph4ntxm/firewall-ready
    MANIFEST=/usr/lib/ph4ntxm/lonewolf/lonewolf.nft.sha256
    protected_file() {
        local path=$1 owner mode
        [[ -f "$path" && ! -L "$path" && -r "$path" ]] || return 1
        owner=$(stat -c '%u' "$path")
        mode=$(stat -c '%a' "$path")
        [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
        (( (8#$mode & 0022) == 0 ))
    }
    value() {
        local key=$1 file=$2
        awk -F= -v key="$key" '$1 == key {count++; result=substr($0, length(key) + 2)} END {if (count != 1) exit 1; print result}' "$file"
    }
    protected_file "$READY_FILE" || exit 1
    protected_file "$MANIFEST" || exit 1
    /usr/bin/systemctl is-active --quiet ph4ntxm-lonewolf-firewall-guard.service || exit 1
    [[ "$(value PROFILE "$READY_FILE")" == lonewolf ]] || exit 1
    SOURCE_HASH=$(tr -d '\n' < "$MANIFEST")
    [[ "$SOURCE_HASH" =~ ^[0-9a-f]{64}$ ]] || exit 1
    [[ "$(value SOURCE_SHA256 "$READY_FILE")" == "$SOURCE_HASH" ]] || exit 1
    [[ "$(value RULESET_SHA256 "$READY_FILE")" =~ ^[0-9a-f]{64}$ ]] || exit 1
    READY_UPTIME=$(value UPTIME_SECONDS "$READY_FILE")
    CURRENT_UPTIME=$(cut -d. -f1 /proc/uptime)
    [[ "$READY_UPTIME" =~ ^[0-9]+$ ]] || exit 1
    (( READY_UPTIME <= CURRENT_UPTIME && CURRENT_UPTIME - READY_UPTIME <= 6 )) || exit 1
else
    exit 1
fi

devices=()
while IFS= read -r dev; do
    dev=${dev%%@*}
    [[ -n "$dev" && "$dev" != "lo" ]] || continue
    [[ -d "/sys/class/net/$dev/device" ]] || continue
    [[ "$(/usr/local/sbin/ph4ntxm-net-hotplug.sh "$dev")" == "protected" ]] || exit 1
    devices+=("$dev")
done < <(ip -o link show | awk -F': ' '{print $2}')

udevadm trigger --action=change --subsystem-match=net
udevadm settle --timeout=10

for dev in "${devices[@]}"; do
    [[ "$(/usr/local/sbin/ph4ntxm-net-hotplug.sh "$dev")" == "protected" ]] || exit 1
    ip link set "$dev" up
done
