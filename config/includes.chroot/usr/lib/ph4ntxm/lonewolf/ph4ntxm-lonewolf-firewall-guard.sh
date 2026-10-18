#!/usr/bin/env bash
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -euo pipefail

MODE_FILE="/run/ph4ntxm/mode"
STATUS_FILE="/run/ph4ntxm-lockdown-status.json"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' <"$MODE_FILE")"

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
ACTIVE_PROFILE=unavailable
ACTIVE_SOURCE_HASH=""
EXPECTED_HASH=""
ACTIVE_POLICY_HASH=""
POLICY_FILE=""
CONNECTION_CONTROL=/usr/local/sbin/ph4ntxm-tor-connection-control
exec 9>"$LOCK_FILE"

safe() { "$@" >/dev/null 2>&1 || true; }

clear_ready() {
    rm -f "$READY_FILE"
}

publish_ready() {
    local ready_tmp uptime_seconds
    uptime_seconds=$(cut -d. -f1 /proc/uptime) || return 1
    [[ "$uptime_seconds" =~ ^[0-9]+$ ]] || return 1
    ready_tmp=$(mktemp /run/ph4ntxm/.firewall-ready.XXXXXX) || return 1
    if ! printf 'PROFILE=%s\nSOURCE_SHA256=%s\nRULESET_SHA256=%s\nUPTIME_SECONDS=%s\n' \
        "$ACTIVE_PROFILE" "$ACTIVE_SOURCE_HASH" "$EXPECTED_HASH" "$uptime_seconds" >"$ready_tmp" \
        || ! chmod 0644 "$ready_tmp" \
        || ! mv -f "$ready_tmp" "$READY_FILE"; then
        rm -f "$ready_tmp"
        return 1
    fi
}

file_is_protected() {
    local path=$1 owner mode
    [[ -f "$path" && ! -L "$path" ]] || return 1
    owner=$(stat -c '%u' "$path") || return 1
    mode=$(stat -c '%a' "$path") || return 1
    [[ "$owner" == 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (((8#$mode & 0022) == 0))
}

manifest_hash() {
    local profile=$1 value
    case "$profile" in
        lonewolf)
            file_is_protected "$LONEWOLF_MANIFEST" || return 1
            value=$(tr -d '\n' <"$LONEWOLF_MANIFEST") || return 1
            ;;
        lockdown)
            file_is_protected "$FIREWALL_MANIFEST" || return 1
            value=$(awk '$2 == "/etc/firewall/lockdown.nft" {print $1}' "$FIREWALL_MANIFEST") || return 1
            ;;
        *)
            return 1
            ;;
    esac
    [[ "$value" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$value"
}

cleanup() {
    clear_ready
    [[ -z "$POLICY_FILE" ]] || rm -f "$POLICY_FILE"
}

trap cleanup EXIT INT TERM HUP

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
    actual=$($SHA256 "$DESIRED_RULES" | awk '{print $1}') || return 1
    [[ "$actual" == "$expected" ]] || return 1
    if [[ "$DESIRED_PROFILE" == lonewolf ]]; then
        [[ -z "$POLICY_FILE" ]] || rm -f "$POLICY_FILE"
        POLICY_FILE=$(mktemp /run/ph4ntxm/.tor-policy.XXXXXX) || return 1
        "$CONNECTION_CONTROL" render >"$POLICY_FILE" || return 1
        DESIRED_RULES=$POLICY_FILE
    fi
    DESIRED_POLICY_HASH=$($SHA256 "$DESIRED_RULES" | awk '{print $1}') || return 1
    $NFT -c -f "$DESIRED_RULES"
}

apply_lockdown() {
    DESIRED_PROFILE=lockdown
    DESIRED_RULES=$LOCKDOWN_FILE
    ACTIVE_PROFILE=unavailable
    ACTIVE_SOURCE_HASH=""
    EXPECTED_HASH=""
    clear_ready || return 1
    if validate_profile && $NFT -f "$LOCKDOWN_FILE"; then
        safe $CONNTRACK -F
        if ACTIVE_SOURCE_HASH=$(manifest_hash lockdown) \
            && EXPECTED_HASH="$($NFT -s list ruleset | $SHA256 | awk '{print $1}')" \
            && [[ "$EXPECTED_HASH" =~ ^[0-9a-f]{64}$ ]]; then
            ACTIVE_PROFILE=lockdown
            if publish_ready; then
                return 0
            fi
        fi
    fi
    clear_ready || return 1
    ACTIVE_PROFILE=unavailable
    ACTIVE_SOURCE_HASH=""
    EXPECTED_HASH=""
    $NFT -f - <<'EOF' || return 1
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
    ACTIVE_PROFILE=emergency
    ACTIVE_SOURCE_HASH=emergency
    safe $CONNTRACK -F
    EXPECTED_HASH="$($NFT -s list ruleset | $SHA256 | awk '{print $1}')" || return 1
    [[ "$EXPECTED_HASH" =~ ^[0-9a-f]{64}$ ]] || return 1
    return 1
}

apply_profile() {
    clear_ready || return 1
    validate_profile || return 1
    $NFT -f "$DESIRED_RULES" || return 1
    safe $CONNTRACK -F
    EXPECTED_HASH="$($NFT -s list ruleset | $SHA256 | awk '{print $1}')" || return 1
    [[ "$EXPECTED_HASH" =~ ^[0-9a-f]{64}$ ]] || return 1
    ACTIVE_PROFILE="$DESIRED_PROFILE"
    ACTIVE_POLICY_HASH=$DESIRED_POLICY_HASH
    ACTIVE_SOURCE_HASH=$(manifest_hash "$ACTIVE_PROFILE") || return 1
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
/usr/bin/systemd-notify --ready --status="Lone Wolf firewall guardian active: ${ACTIVE_PROFILE/lonewolf/Lone Wolf}"

while true; do
    sleep "$SLEEP_INTERVAL"
    flock -x 9
    select_profile
    CURRENT="$($NFT -s list ruleset 2>/dev/null | $SHA256 | awk '{print $1}')" || CURRENT=""
    CURRENT_SOURCE=""
    ACTUAL_SOURCE=""
    CURRENT_POLICY=""
    case "$ACTIVE_PROFILE" in
        lonewolf)
            CURRENT_SOURCE=$(manifest_hash lonewolf 2>/dev/null) || CURRENT_SOURCE=""
            ACTUAL_SOURCE=$($SHA256 "$LONEWOLF_FILE" 2>/dev/null | awk '{print $1}') || ACTUAL_SOURCE=""
            CURRENT_POLICY=$("$CONNECTION_CONTROL" policy-hash 2>/dev/null) || CURRENT_POLICY=""
            ;;
        lockdown)
            CURRENT_SOURCE=$(manifest_hash lockdown 2>/dev/null) || CURRENT_SOURCE=""
            ACTUAL_SOURCE=$($SHA256 "$LOCKDOWN_FILE" 2>/dev/null | awk '{print $1}') || ACTUAL_SOURCE=""
            ;;
    esac

    if [[ "$ACTIVE_PROFILE" == emergency ]] \
        || [[ "$DESIRED_PROFILE" != "$ACTIVE_PROFILE" ]] \
        || [[ -z "$CURRENT" || "$CURRENT" != "$EXPECTED_HASH" ]] \
        || [[ -z "$CURRENT_SOURCE" || "$CURRENT_SOURCE" != "$ACTUAL_SOURCE" ]] \
        || { [[ "$ACTIVE_PROFILE" == lonewolf ]] && [[ -z "$CURRENT_POLICY" || "$CURRENT_POLICY" != "$ACTIVE_POLICY_HASH" ]]; }; then
        clear_ready
        apply_lockdown || true
        enforce_desired || true
    else
        ACTIVE_SOURCE_HASH=$CURRENT_SOURCE
        publish_ready
    fi

    flock -u 9
done
