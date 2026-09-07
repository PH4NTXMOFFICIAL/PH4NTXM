#!/usr/bin/env bash
set -euo pipefail

MODE_FILE="/run/ph4ntxm/mode"
STATUS_FILE="/run/ph4ntxm-lockdown-status.json"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' < "$MODE_FILE")"

if [[ "$MODE" != "lonewolf" ]]; then
    exit 0
fi

NFT="/usr/sbin/nft"
CONNTRACK="/usr/sbin/conntrack"
SHA256="/usr/bin/sha256sum"

LONEWOLF_FILE="/usr/lib/ph4ntxm/lonewolf/lonewolf.nft"
LONEWOLF_MANIFEST="/usr/lib/ph4ntxm/lonewolf/lonewolf.nft.sha256"
LOCKDOWN_FILE="/etc/firewall/lockdown.nft"
FIREWALL_MANIFEST="/etc/firewall/rules.sha256"

SLEEP_INTERVAL=2
LOCK_FILE=/run/ph4ntxm/firewall.lock
READY_FILE=/run/ph4ntxm/firewall-ready
exec 9>"$LOCK_FILE"

safe() { "$@" >/dev/null 2>&1 || true; }

clear_ready() {
    rm -f "$READY_FILE"
}

publish_ready() {
    local ready_tmp uptime_seconds
    uptime_seconds=$(cut -d. -f1 /proc/uptime)
    ready_tmp=$(mktemp /run/ph4ntxm/.firewall-ready.XXXXXX)
    printf 'PROFILE=%s\nSOURCE_SHA256=%s\nRULESET_SHA256=%s\nUPTIME_SECONDS=%s\n' \
        "$ACTIVE_PROFILE" "$ACTIVE_SOURCE_HASH" "$EXPECTED_HASH" "$uptime_seconds" > "$ready_tmp"
    chmod 0644 "$ready_tmp"
    mv -f "$ready_tmp" "$READY_FILE"
}

file_is_protected() {
    local path=$1 owner mode
    [[ -f "$path" && ! -L "$path" ]] || return 1
    owner=$(stat -c '%u' "$path")
    mode=$(stat -c '%a' "$path")
    [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$mode & 0022) == 0 ))
}

manifest_hash() {
    local profile=$1 value
    case "$profile" in
        lonewolf)
            file_is_protected "$LONEWOLF_MANIFEST" || return 1
            value=$(tr -d '\n' < "$LONEWOLF_MANIFEST")
            ;;
        lockdown)
            file_is_protected "$FIREWALL_MANIFEST" || return 1
            value=$(awk '$2 == "/etc/firewall/lockdown.nft" {print $1}' "$FIREWALL_MANIFEST")
            ;;
        *)
            return 1
            ;;
    esac
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$value"
}

trap clear_ready EXIT INT TERM HUP

select_profile() {
    if [[ ! -e "$STATUS_FILE" ]]; then
        DESIRED_PROFILE="lonewolf"
        DESIRED_RULES="$LONEWOLF_FILE"
    elif ! file_is_protected "$STATUS_FILE"; then
        DESIRED_PROFILE="lockdown"
        DESIRED_RULES="$LOCKDOWN_FILE"
    elif grep -Eq '^\{"enabled":[[:space:]]*true\}[[:space:]]*$' "$STATUS_FILE"; then
        DESIRED_PROFILE="lockdown"
        DESIRED_RULES="$LOCKDOWN_FILE"
    elif grep -Eq '^\{"enabled":[[:space:]]*false\}[[:space:]]*$' "$STATUS_FILE"; then
        DESIRED_PROFILE="lonewolf"
        DESIRED_RULES="$LONEWOLF_FILE"
    else
        DESIRED_PROFILE="lockdown"
        DESIRED_RULES="$LOCKDOWN_FILE"
    fi
}

validate_profile() {
    local expected actual
    file_is_protected "$DESIRED_RULES" || return 1
    expected=$(manifest_hash "$DESIRED_PROFILE") || return 1
    actual=$($SHA256 "$DESIRED_RULES" | awk '{print $1}')
    [[ "$actual" == "$expected" ]] || return 1
    $NFT -c -f "$DESIRED_RULES"
}

apply_lockdown() {
    DESIRED_PROFILE=lockdown
    DESIRED_RULES=$LOCKDOWN_FILE
    clear_ready
    if validate_profile; then
        $NFT -f "$LOCKDOWN_FILE"
        ACTIVE_SOURCE_HASH=$(manifest_hash lockdown)
        ACTIVE_PROFILE=lockdown
        safe $CONNTRACK -F
        EXPECTED_HASH="$($NFT -s list ruleset | $SHA256 | awk '{print $1}')"
        publish_ready
        return 0
    else
        $NFT -f - <<'EOF'
flush ruleset
table inet ph4ntxm_emergency {
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
        ACTIVE_SOURCE_HASH=emergency
    fi
    safe $CONNTRACK -F
    EXPECTED_HASH="$($NFT -s list ruleset | $SHA256 | awk '{print $1}')"
    ACTIVE_PROFILE=emergency
    clear_ready
    return 1
}

apply_profile() {
    validate_profile || return 1
    $NFT -f "$DESIRED_RULES" || return 1
    safe $CONNTRACK -F
    EXPECTED_HASH="$($NFT -s list ruleset | $SHA256 | awk '{print $1}')"
    [[ "$EXPECTED_HASH" =~ ^[0-9a-f]{64}$ ]] || return 1
    ACTIVE_PROFILE="$DESIRED_PROFILE"
    ACTIVE_SOURCE_HASH=$(manifest_hash "$ACTIVE_PROFILE")
    publish_ready
}

enforce_desired() {
    select_profile
    if apply_profile; then
        return 0
    fi
    apply_lockdown || true
    return 1
}

flock -x 9
enforce_desired || true
flock -u 9
/usr/bin/systemd-notify --ready --status="Lonewolf firewall guardian active: $ACTIVE_PROFILE"

while true; do
    sleep "$SLEEP_INTERVAL"
    flock -x 9
    select_profile
    CURRENT="$($NFT -s list ruleset 2>/dev/null | $SHA256 | awk '{print $1}' || echo "")"
    CURRENT_SOURCE=""
    ACTUAL_SOURCE=""
    case "$ACTIVE_PROFILE" in
        lonewolf)
            CURRENT_SOURCE=$(manifest_hash lonewolf 2>/dev/null || true)
            ACTUAL_SOURCE=$($SHA256 "$LONEWOLF_FILE" 2>/dev/null | awk '{print $1}' || true)
            ;;
        lockdown)
            CURRENT_SOURCE=$(manifest_hash lockdown 2>/dev/null || true)
            ACTUAL_SOURCE=$($SHA256 "$LOCKDOWN_FILE" 2>/dev/null | awk '{print $1}' || true)
            ;;
    esac

    if [[ "$ACTIVE_PROFILE" == emergency ]] || \
       [[ "$DESIRED_PROFILE" != "$ACTIVE_PROFILE" ]] || \
       [[ -z "$CURRENT" || "$CURRENT" != "$EXPECTED_HASH" ]] || \
       [[ -z "$CURRENT_SOURCE" || "$CURRENT_SOURCE" != "$ACTUAL_SOURCE" ]]; then
        clear_ready
        apply_lockdown || true
        enforce_desired || true
    else
        ACTIVE_SOURCE_HASH=$CURRENT_SOURCE
        publish_ready
    fi

    flock -u 9
done
