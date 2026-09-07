#!/usr/bin/env bash
set -euo pipefail

MODE_FILE="/run/ph4ntxm/mode"
STATUS_FILE="/run/ph4ntxm-lockdown-status.json"

NFT="/usr/sbin/nft"
CONNTRACK="/usr/sbin/conntrack"
SHA256="/usr/bin/sha256sum"
MANIFEST="/etc/firewall/rules.sha256"
PACKET_TRANSFORMATION_ENGINE_REQUEST=/run/ph4ntxm/packet-transformation-engine-guard-request
PACKET_TRANSFORMATION_ENGINE_ACK=/run/ph4ntxm/packet-transformation-engine-guard-transition

NORMAL_FILE="/etc/firewall/normal.nft"
LOCKDOWN_FILE="/etc/firewall/lockdown.nft"

SLEEP_INTERVAL=2
LOCK_FILE=/run/ph4ntxm/firewall.lock
READY_FILE=/run/ph4ntxm/firewall-ready

safe() { "$@" >/dev/null 2>&1 || true; }

protected_file() {
    local path=$1
    local mode

    [[ -f "$path" && ! -L "$path" && -r "$path" && "$(stat -c '%u' "$path")" == 0 ]] ||
        return 1
    mode=$(stat -c '%a' "$path")
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 0022) == 0 ))
}

protected_directory() {
    local path=$1
    local mode

    [[ -d "$path" && ! -L "$path" && "$(stat -c '%u' "$path")" == 0 ]] || return 1
    mode=$(stat -c '%a' "$path")
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 0022) == 0 ))
}

state_value() {
    local key=$1
    local file=$2

    awk -F= -v key="$key" '
        $1 == key { count++; value=substr($0, length(key) + 2) }
        END { if (count != 1) exit 1; print value }
    ' "$file"
}

force_physical_links_down() {
    local path iface

    for path in /sys/class/net/*; do
        [[ -d "$path/device" ]] || continue
        iface=${path##*/}
        ip link set dev "$iface" down >/dev/null 2>&1 || true
    done
}

request_packet_transformation_engine_transition() {
    local profile=$1
    local token
    local temporary
    local attempt

    [[ "$profile" == normal || "$profile" == lockdown ]] || return 1
    token=$(tr -d '-' < /proc/sys/kernel/random/uuid) || return 1
    [[ "$token" =~ ^[0-9a-f]{32}$ ]] || return 1
    temporary=$(mktemp /run/ph4ntxm/.packet-transformation-engine-guard-request.XXXXXX) || return 1
    printf 'PROFILE=%s\nTOKEN=%s\n' "$profile" "$token" > "$temporary" || return 1
    chmod 0600 "$temporary" || return 1
    mv -f "$temporary" "$PACKET_TRANSFORMATION_ENGINE_REQUEST" || return 1
    for ((attempt = 0; attempt < 100; attempt++)); do
        if protected_file "$PACKET_TRANSFORMATION_ENGINE_ACK" && [[ "$(wc -l < "$PACKET_TRANSFORMATION_ENGINE_ACK")" == 3 ]] && \
           [[ "$(state_value STATUS "$PACKET_TRANSFORMATION_ENGINE_ACK" 2>/dev/null || true)" == complete ]] && \
           [[ "$(state_value PROFILE "$PACKET_TRANSFORMATION_ENGINE_ACK" 2>/dev/null || true)" == "$profile" ]] && \
           [[ "$(state_value TOKEN "$PACKET_TRANSFORMATION_ENGINE_ACK" 2>/dev/null || true)" == "$token" ]]; then
            return 0
        fi
        sleep 0.1 || return 1
    done
    return 1
}

protected_file "$MODE_FILE" || exit 1
MODE_SIZE=$(stat -c '%s' "$MODE_FILE") || exit 1
MODE=$(cat "$MODE_FILE") || exit 1
case "$MODE" in
    lonewolf) [[ "$MODE_SIZE" == 9 ]] || exit 1; exit 0 ;;
    linux) [[ "$MODE_SIZE" == 6 ]] || exit 1 ;;
    windows) [[ "$MODE_SIZE" == 8 ]] || exit 1 ;;
    *) exit 1 ;;
esac

clear_ready() {
    rm -f "$READY_FILE" || return 1
}

publish_ready() {
    local ready_tmp
    local uptime_seconds

    ready_tmp=$(mktemp /run/ph4ntxm/.firewall-ready.XXXXXX) || return 1
    uptime_seconds=$(cut -d. -f1 /proc/uptime) || return 1
    [[ "$uptime_seconds" =~ ^[0-9]+$ ]] || return 1
    printf 'PROFILE=%s\nRULESET_SHA256=%s\nUPTIME_SECONDS=%s\n' \
        "$ACTIVE_PROFILE" "$EXPECTED_HASH" "$uptime_seconds" > "$ready_tmp" || return 1
    chmod 0644 "$ready_tmp" || return 1
    mv -f "$ready_tmp" "$READY_FILE" || return 1
}

trap clear_ready EXIT INT TERM HUP

is_lockdown() {
    if [[ ! -e "$STATUS_FILE" && ! -L "$STATUS_FILE" ]]; then
        return 1
    fi
    if ! protected_file "$STATUS_FILE" ||
       ! jq -e 'type == "object" and keys == ["enabled"] and (.enabled | type) == "boolean"' \
            "$STATUS_FILE" >/dev/null 2>&1; then
        return 0
    fi
    jq -e '.enabled == true' "$STATUS_FILE" >/dev/null
}

select_profile() {
    if is_lockdown; then
        DESIRED_PROFILE="lockdown"
        DESIRED_RULES="$LOCKDOWN_FILE"
    else
        DESIRED_PROFILE="normal"
        DESIRED_RULES="$NORMAL_FILE"
    fi
}

validate_profile() {
    protected_file "$MANIFEST" || return 1
    protected_file "$DESIRED_RULES" || return 1
    case "$DESIRED_PROFILE" in
        normal)
            (cd / && $SHA256 --check --status --strict "$MANIFEST") || return 1
            [[ "$($SHA256 "$DESIRED_RULES" | awk '{print $1}')" == "234323ac0f160373d8d7d23c86d64e00dcbb264fe87afb34c727295fad53092d" ]]
            ;;
        lockdown)
            [[ "$($SHA256 "$DESIRED_RULES" | awk '{print $1}')" == "7fe94742884f1b20f84980701594811371a2c8c4a0b255cb0071a6eadab36d26" ]]
            ;;
        *)
            return 1
            ;;
    esac
}

apply_lockdown() {
    local packet_transformation_engine_sealed=1

    if ! request_packet_transformation_engine_transition lockdown; then
        packet_transformation_engine_sealed=0
        force_physical_links_down
    fi
    if protected_file "$LOCKDOWN_FILE" && \
       [[ "$($SHA256 "$LOCKDOWN_FILE" | awk '{print $1}')" == "7fe94742884f1b20f84980701594811371a2c8c4a0b255cb0071a6eadab36d26" ]] && \
       $NFT -c -f "$LOCKDOWN_FILE" && $NFT -f "$LOCKDOWN_FILE"; then
        :
    else
        $NFT -f - <<'EOF' || return 1
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
  }
  chain output {
    type filter hook output priority 0; policy drop;
  }
}
EOF
    fi
    safe $CONNTRACK -F
    if (( ! packet_transformation_engine_sealed )); then
        clear_ready || return 1
        return 1
    fi
    EXPECTED_HASH="$($NFT -s list ruleset | $SHA256 | awk '{print $1}')" || return 1
    [[ "$EXPECTED_HASH" =~ ^[0-9a-f]{64}$ ]] || return 1
    ACTIVE_PROFILE="lockdown"
    publish_ready || return 1
}

apply_profile() {
    validate_profile || return 1
    $NFT -c -f "$DESIRED_RULES" || return 1
    $NFT -f "$DESIRED_RULES" || return 1
    safe $CONNTRACK -F
    if ! request_packet_transformation_engine_transition normal; then
        force_physical_links_down
        return 1
    fi
    EXPECTED_HASH="$($NFT -s list ruleset | $SHA256 | awk '{print $1}')" || return 1
    [[ "$EXPECTED_HASH" =~ ^[0-9a-f]{64}$ ]] || return 1
    ACTIVE_PROFILE="$DESIRED_PROFILE"
    publish_ready || return 1
}

protected_directory /run/ph4ntxm || exit 1
exec 9>"$LOCK_FILE" || exit 1
flock -x 9 || exit 1
select_profile
if [[ "$DESIRED_PROFILE" == "lockdown" ]]; then
    apply_lockdown || exit 1
elif validate_profile && $NFT -c -f "$DESIRED_RULES"; then
    apply_profile || exit 1
else
    apply_lockdown || exit 1
fi
flock -u 9 || exit 1

while true; do
    flock -x 9 || exit 1
    select_profile
    CURRENT="$($NFT -s list ruleset 2>/dev/null | $SHA256 | awk '{print $1}' || echo "")"

    if [[ "$DESIRED_PROFILE" != "$ACTIVE_PROFILE" ]]; then
        clear_ready || exit 1
        if [[ "$DESIRED_PROFILE" == "lockdown" ]]; then
            apply_lockdown || exit 1
        elif validate_profile && $NFT -c -f "$DESIRED_RULES"; then
            apply_profile || exit 1
        else
            apply_lockdown || exit 1
        fi
        flock -u 9 || exit 1
        sleep "$SLEEP_INTERVAL" || exit 1
        continue
    fi

    if [[ -z "$CURRENT" || "$CURRENT" != "$EXPECTED_HASH" ]]; then
        clear_ready || exit 1
        apply_lockdown || exit 1
        if [[ "$DESIRED_PROFILE" != "lockdown" ]] && validate_profile && $NFT -c -f "$DESIRED_RULES"; then
            apply_profile || exit 1
        fi
    else
        publish_ready || exit 1
    fi

    flock -u 9 || exit 1
    sleep "$SLEEP_INTERVAL" || exit 1
done
