#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
STATE_DIR=/run/ph4ntxm
MODE_FILE=$STATE_DIR/mode
LOADER=/usr/local/sbin/ph4ntxm-packet-transformation-engine-loader
NATIVE=/usr/local/sbin/ph4ntxm-packet-transformation-engine-native
MANIFEST=/usr/lib/ph4ntxm/packet-transformation-engine.sha256
OBJECT=/usr/lib/ph4ntxm/packet-transformation-engine.bpf.o
READY_FILE=$STATE_DIR/packet-transformation-engine-guard-ready
LOCKDOWN_STATUS=/run/ph4ntxm-lockdown-status.json
SEAL_FILE=$STATE_DIR/packet-transformation-engine-guard-sealed
LINKS_FILE=$STATE_DIR/packet-transformation-engine-guard-sealed-links
REQUEST_FILE=$STATE_DIR/packet-transformation-engine-guard-request
ACK_FILE=$STATE_DIR/packet-transformation-engine-guard-transition
SLEEP_SECONDS=2

[[ "$(id -u)" == 0 ]] || exit 1

normal_mode() {
    local mode
    local size

    protected_file "$MODE_FILE" || return 1
    size=$(stat -c '%s' "$MODE_FILE") || return 1
    mode=$(cat "$MODE_FILE") || return 1
    [[ "$mode" == linux && "$size" == 6 ]] ||
        [[ "$mode" == windows && "$size" == 8 ]]
}

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

valid_lockdown_status() {
    protected_file "$LOCKDOWN_STATUS" &&
        jq -e 'type == "object" and keys == ["enabled"] and (.enabled | type) == "boolean"' \
            "$LOCKDOWN_STATUS" >/dev/null 2>&1
}

status_lockdown() {
    valid_lockdown_status && jq -e '.enabled == true' "$LOCKDOWN_STATUS" >/dev/null
}

sealed() {
    protected_file "$SEAL_FILE" && [[ "$(stat -c '%s' "$SEAL_FILE")" == 7 ]] &&
        [[ "$(cat "$SEAL_FILE")" == sealed ]]
}

valid_links_state() {
    local size
    local final_byte

    protected_file "$LINKS_FILE" || return 1
    size=$(stat -c '%s' "$LINKS_FILE") || return 1
    (( size <= 4096 )) || return 1
    if (( size > 0 )); then
        final_byte=$(tail -c 1 "$LINKS_FILE" | od -An -tx1 | tr -d '[:space:]') || return 1
        [[ "$final_byte" == 0a ]] || return 1
    fi
    awk '
        length($0) == 0 || length($0) > 15 || $0 == "lo" ||
        $0 !~ /^[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-]+$/ ||
        $0 ~ /\.\./ || seen[$0]++ { exit 1 }
    ' "$LINKS_FILE"
}

invalid_lockdown_state() {
    if [[ -e "$SEAL_FILE" || -L "$SEAL_FILE" ]]; then
        sealed || return 0
        valid_links_state || return 0
    elif [[ -e "$LINKS_FILE" || -L "$LINKS_FILE" ]]; then
        return 0
    fi
    if [[ -e "$LOCKDOWN_STATUS" || -L "$LOCKDOWN_STATUS" ]]; then
        valid_lockdown_status || return 0
    fi
    return 1
}

lockdown_requested() {
    invalid_lockdown_state || status_lockdown || sealed
}

valid_interface() {
    local iface=$1

    [[ -n "$iface" && ${#iface} -lt 16 && "$iface" != lo && "$iface" != */* &&
       "$iface" != *..* && "$iface" != *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-]* &&
       -d "/sys/class/net/$iface/device" ]]
}

valid_runtime() {
    protected_file "$MANIFEST" &&
        protected_file "$OBJECT" &&
        protected_file "$LOADER" &&
        protected_file "$NATIVE" &&
    (cd / && sha256sum --check --status --strict "$MANIFEST")
}

clear_ready() {
    rm -f "$READY_FILE" || return 1
}

force_physical_links_down() {
    local path
    local iface

    for path in /sys/class/net/*; do
        [[ -d "$path/device" ]] || continue
        iface=${path##*/}
        ip link set dev "$iface" down >/dev/null 2>&1 || true
    done
}

watch_cleanup() {
    clear_ready || true
    force_physical_links_down
}

publish_ready() {
    local interfaces=$1
    local profile=$2
    local temporary
    local uptime_seconds

    temporary=$(mktemp "$STATE_DIR/.packet-transformation-engine-guard-ready.XXXXXX") || return 1
    uptime_seconds=$(cut -d. -f1 /proc/uptime) || return 1
    [[ "$uptime_seconds" =~ ^[0-9]+$ ]] || return 1
    printf 'STATUS=ready\nPROFILE=%s\nINTERFACES=%s\nUPTIME_SECONDS=%s\n' \
        "$profile" "$interfaces" "$uptime_seconds" > "$temporary" || return 1
    chmod 0644 "$temporary" || return 1
    mv -f "$temporary" "$READY_FILE" || return 1
}

has_clsact() {
    local iface=$1

    tc -j qdisc show dev "$iface" | jq -e 'any(.[]; .kind == "clsact")' >/dev/null
}

tc_program_identity() {
    local iface=$1

    tc -j -details filter show dev "$iface" egress | jq -er '
        [.[] | select(
            .protocol == "all" and .pref == 1 and .kind == "bpf" and .chain == 0 and
            .options != null and .options.handle == "0x1" and
            .options["direct-action"] == true and .options.prog != null
        ) | {
            id: .options.prog.id,
            nested_tag: (.options.prog.tag // null),
            top_level_tag: (.options.tag // null)
        }] as $programs |
        if ($programs | length) == 1 and
           ($programs[0].id | type) == "number" and
           (($programs[0].nested_tag // $programs[0].top_level_tag) | type) == "string" and
           ($programs[0].nested_tag == null or $programs[0].top_level_tag == null or
            $programs[0].nested_tag == $programs[0].top_level_tag)
        then
            "PROGRAM_ID=\($programs[0].id)\nPROGRAM_TAG=\($programs[0].nested_tag // $programs[0].top_level_tag)"
        else
            error("invalid Packet Transformation Engine classifier identity")
        end
    '
}

interface_identity() {
    local iface=$1

    ip -j link show dev "$iface" | jq -er '
        if length == 1 and (.[0].ifindex | type) == "number" and
           (.[0].address | type) == "string"
        then
            "IFINDEX=\(.[0].ifindex)\nMAC=\(.[0].address | gsub(":"; ""))"
        else
            error("invalid interface identity")
        end
    '
}

direct_filters_valid() {
    local iface=$1

    identity_valid "$iface" || return 1
    tc -j -details filter show dev "$iface" egress | jq -e '
        [.[] | select(.options != null)] as $filters |
        ($filters | length) == 2 and
        ([$filters[] | select(
            .protocol == "all" and .pref == 1 and .kind == "bpf" and .chain == 0 and
            .options.handle == "0x1" and .options["direct-action"] == true
        )] | length) == 1 and
        ([$filters[] | select(
            .protocol == "all" and .pref == 2 and .kind == "matchall" and .chain == 0 and
            (.options.actions | length) == 1 and
            .options.actions[0].kind == "gact" and
            .options.actions[0].control_action.type == "drop"
        )] | length) == 1
    ' >/dev/null
}

identity_file() {
    printf '%s/packet-transformation-engine-guard-%s.identity\n' "$STATE_DIR" "$1"
}

publish_identity() {
    local iface=$1
    local identity=$2
    local program_id
    local program_tag
    local ifindex
    local mode
    local mac
    local hostname
    local object_hash
    local tc_identity
    local tc_program_id
    local tc_program_tag
    local temporary

    program_id=$(printf '%s\n' "$identity" | awk -F= '$1 == "PROGRAM_ID" {count++; value=$2} END {if (count != 1) exit 1; print value}') || return 1
    program_tag=$(printf '%s\n' "$identity" | awk -F= '$1 == "PROGRAM_TAG" {count++; value=$2} END {if (count != 1) exit 1; print value}') || return 1
    ifindex=$(printf '%s\n' "$identity" | awk -F= '$1 == "IFINDEX" {count++; value=$2} END {if (count != 1) exit 1; print value}') || return 1
    mode=$(printf '%s\n' "$identity" | awk -F= '$1 == "MODE" {count++; value=$2} END {if (count != 1) exit 1; print value}') || return 1
    mac=$(printf '%s\n' "$identity" | awk -F= '$1 == "MAC" {count++; value=$2} END {if (count != 1) exit 1; print value}') || return 1
    hostname=$(printf '%s\n' "$identity" | awk -F= '$1 == "HOSTNAME" {count++; value=$2} END {if (count != 1) exit 1; print value}') || return 1
    [[ "$program_id" =~ ^[1-9][0-9]*$ && "$program_tag" =~ ^[0-9a-f]{16}$ &&
       "$ifindex" =~ ^[1-9][0-9]*$ && "$mode" =~ ^[01]$ &&
       "$mac" =~ ^[0-9a-f]{12}$ && ${#hostname} -ge 1 && ${#hostname} -le 32 &&
       "$hostname" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
    tc_identity=$(tc_program_identity "$iface") || return 1
    tc_program_id=$(printf '%s\n' "$tc_identity" | awk -F= '$1 == "PROGRAM_ID" {count++; value=$2} END {if (count != 1) exit 1; print value}') || return 1
    tc_program_tag=$(printf '%s\n' "$tc_identity" | awk -F= '$1 == "PROGRAM_TAG" {count++; value=$2} END {if (count != 1) exit 1; print value}') || return 1
    [[ "$tc_program_id" == "$program_id" && "$tc_program_tag" == "$program_tag" ]] || return 1
    object_hash=$(sha256sum "$OBJECT" | awk '{print $1}') || return 1
    [[ "$object_hash" =~ ^[0-9a-f]{64}$ ]] || return 1
    temporary=$(mktemp "$STATE_DIR/.packet-transformation-engine-guard-identity.XXXXXX") || return 1
    printf 'PROGRAM_ID=%s\nPROGRAM_TAG=%s\nOBJECT_SHA256=%s\nIFINDEX=%s\nMODE=%s\nMAC=%s\nHOSTNAME=%s\n' \
        "$program_id" "$program_tag" "$object_hash" "$ifindex" "$mode" "$mac" \
        "$hostname" > "$temporary" || return 1
    chmod 0600 "$temporary" || return 1
    mv -f "$temporary" "$(identity_file "$iface")" || return 1
}

identity_valid() {
    local iface=$1
    local file
    local expected_id
    local expected_tag
    local expected_hash
    local expected_ifindex
    local expected_mode
    local expected_mac
    local expected_hostname
    local current_hash
    local current_interface
    local current_ifindex
    local current_mode
    local current_mac
    local current_hostname
    local identity
    local current_id
    local current_tag

    file=$(identity_file "$iface")
    protected_file "$file" || return 1
    [[ "$(wc -l < "$file")" == 7 ]] || return 1
    expected_id=$(state_value PROGRAM_ID "$file") || return 1
    expected_tag=$(state_value PROGRAM_TAG "$file") || return 1
    expected_hash=$(state_value OBJECT_SHA256 "$file") || return 1
    expected_ifindex=$(state_value IFINDEX "$file") || return 1
    expected_mode=$(state_value MODE "$file") || return 1
    expected_mac=$(state_value MAC "$file") || return 1
    expected_hostname=$(state_value HOSTNAME "$file") || return 1
    [[ "$expected_id" =~ ^[1-9][0-9]*$ && "$expected_tag" =~ ^[0-9a-f]{16}$ &&
       "$expected_hash" =~ ^[0-9a-f]{64}$ && "$expected_ifindex" =~ ^[1-9][0-9]*$ &&
       "$expected_mode" =~ ^[01]$ && "$expected_mac" =~ ^[0-9a-f]{12}$ &&
       ${#expected_hostname} -ge 1 && ${#expected_hostname} -le 32 &&
       "$expected_hostname" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
    current_hash=$(sha256sum "$OBJECT" | awk '{print $1}') || return 1
    [[ "$current_hash" == "$expected_hash" ]] || return 1
    normal_mode || return 1
    current_interface=$(interface_identity "$iface") || return 1
    current_ifindex=$(printf '%s\n' "$current_interface" | awk -F= '$1 == "IFINDEX" {count++; value=$2} END {if (count != 1) exit 1; print value}') || return 1
    [[ "$current_ifindex" =~ ^[1-9][0-9]*$ ]] || return 1
    case "$(cat "$MODE_FILE")" in
        linux) current_mode=0 ;;
        windows) current_mode=1 ;;
        *) return 1 ;;
    esac
    current_mac=$(printf '%s\n' "$current_interface" | awk -F= '$1 == "MAC" {count++; value=$2} END {if (count != 1) exit 1; print value}') || return 1
    [[ "$current_mac" =~ ^[0-9a-f]{12}$ ]] || return 1
    protected_file /etc/hostname || return 1
    current_hostname=$(cat /etc/hostname) || return 1
    [[ "$(stat -c '%s' /etc/hostname)" == "$(( ${#current_hostname} + 1 ))" &&
       ${#current_hostname} -ge 1 && ${#current_hostname} -le 32 &&
       "$current_hostname" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
    [[ "$current_ifindex" == "$expected_ifindex" && "$current_mode" == "$expected_mode" &&
       "$current_mac" == "$expected_mac" && "$current_hostname" == "$expected_hostname" ]] || return 1
    identity=$(tc_program_identity "$iface") || return 1
    current_id=$(printf '%s\n' "$identity" | awk -F= '$1 == "PROGRAM_ID" {count++; value=$2} END {if (count != 1) exit 1; print value}') || return 1
    current_tag=$(printf '%s\n' "$identity" | awk -F= '$1 == "PROGRAM_TAG" {count++; value=$2} END {if (count != 1) exit 1; print value}') || return 1
    [[ "$current_id" == "$expected_id" && "$current_tag" == "$expected_tag" ]]
}

lockdown_filter_valid() {
    local iface=$1

    tc -j -details filter show dev "$iface" egress | jq -e '
        [.[] | select(.options != null)] as $filters |
        ($filters | length) == 1 and
        $filters[0].protocol == "all" and $filters[0].pref == 2 and
        $filters[0].kind == "matchall" and $filters[0].chain == 0 and
        ($filters[0].options.actions | length) == 1 and
        $filters[0].options.actions[0].kind == "gact" and
        $filters[0].options.actions[0].control_action.type == "drop"
    ' >/dev/null
}

verify_direct_locked() {
    local iface=$1

    normal_mode && valid_runtime && has_clsact "$iface" && direct_filters_valid "$iface"
}

verify_lockdown_locked() {
    local iface=$1

    normal_mode && has_clsact "$iface" && lockdown_filter_valid "$iface"
}

verify_desired_locked() {
    local iface=$1

    if lockdown_requested; then
        verify_lockdown_locked "$iface"
    else
        verify_direct_locked "$iface"
    fi
}

attach_locked() {
    local iface=$1
    local restore_up=${2:-1}
    local was_up=0
    local identity

    if ip -o link show dev "$iface" | grep -q '<[^>]*UP[^>]*>'; then
        was_up=1
    fi
    ip link set dev "$iface" down || return 1
    if ! has_clsact "$iface"; then
        tc qdisc add dev "$iface" clsact || return 1
    fi
    rm -f "$(identity_file "$iface")" || return 1
    tc filter del dev "$iface" egress >/dev/null 2>&1 || true
    tc filter add dev "$iface" egress pref 2 protocol all matchall action drop || return 1
    if ! valid_runtime || ! identity=$("$LOADER" attach "$iface") ||
       ! publish_identity "$iface" "$identity" || ! verify_direct_locked "$iface"; then
        ip link set dev "$iface" down >/dev/null 2>&1 || true
        return 1
    fi
    if (( restore_up && was_up )); then
        ip link set dev "$iface" up || return 1
    fi
}

lockdown_locked() {
    local iface=$1

    ip link set dev "$iface" down || return 1
    if ! has_clsact "$iface"; then
        tc qdisc add dev "$iface" clsact || return 1
    fi
    rm -f "$(identity_file "$iface")" || return 1
    tc filter del dev "$iface" egress >/dev/null 2>&1 || true
    tc filter add dev "$iface" egress pref 2 protocol all matchall action drop || return 1
    verify_lockdown_locked "$iface" || {
        ip link set dev "$iface" down >/dev/null 2>&1 || true
        return 1
    }
}

run_interface_action() {
    local action=$1
    local iface=$2
    local lock_file

    normal_mode || return 1
    valid_interface "$iface" || return 1
    protected_directory "$STATE_DIR" || return 1
    if [[ "${PH4NTXM_PACKET_TRANSFORMATION_ENGINE_GLOBAL_HELD:-0}" != 1 ]]; then
        exec 8>"$STATE_DIR/packet-transformation-engine-guard-global.lock" || return 1
        flock -s 8 || return 1
    fi
    lock_file="$STATE_DIR/packet-transformation-engine-guard-$iface.lock"
    exec 9>"$lock_file" || return 1
    flock -x 9 || return 1
    case "$action" in
        attach) ! lockdown_requested && attach_locked "$iface" ;;
        prepare) attach_locked "$iface" 0 ;;
        lockdown) lockdown_locked "$iface" ;;
        enforce)
            if lockdown_requested; then lockdown_locked "$iface"; else attach_locked "$iface"; fi
            ;;
        verify) verify_desired_locked "$iface" ;;
        stats) ! lockdown_requested && valid_runtime && "$LOADER" stats "$iface" ;;
        *) return 2 ;;
    esac
}

seal_all() {
    normal_mode || return 1
    protected_directory "$STATE_DIR" || return 1
    clear_ready || return 1
    (
        exec 8>"$STATE_DIR/packet-transformation-engine-guard-global.lock" || exit 1
        flock -x 8 || exit 1
        seal_all_locked || exit 1
    )
}

seal_all_locked() {
    local path
    local iface
    local temporary

    if ! sealed; then
        temporary=$(mktemp "$STATE_DIR/.packet-transformation-engine-guard-links.XXXXXX") || return 1
        for path in /sys/class/net/*; do
            [[ -d "$path/device" ]] || continue
            iface=${path##*/}
            if ip -o link show dev "$iface" | grep -q '<[^>]*UP[^>]*>'; then
                printf '%s\n' "$iface" >> "$temporary" || return 1
            fi
        done
        chmod 0600 "$temporary" || return 1
        mv -f "$temporary" "$LINKS_FILE" || return 1
        temporary=$(mktemp "$STATE_DIR/.packet-transformation-engine-guard-sealed.XXXXXX") || return 1
        printf 'sealed\n' > "$temporary" || return 1
        chmod 0600 "$temporary" || return 1
        mv -f "$temporary" "$SEAL_FILE" || return 1
    fi
    for path in /sys/class/net/*; do
        [[ -d "$path/device" ]] || continue
        iface=${path##*/}
        ip link set dev "$iface" down || return 1
    done
    for path in /sys/class/net/*; do
        [[ -d "$path/device" ]] || continue
        iface=${path##*/}
        PH4NTXM_PACKET_TRANSFORMATION_ENGINE_GLOBAL_HELD=1 "$0" lockdown "$iface" || return 1
    done
}

unseal_all() {
    normal_mode || return 1
    protected_directory "$STATE_DIR" || return 1
    if [[ -e "$LOCKDOWN_STATUS" || -L "$LOCKDOWN_STATUS" ]]; then
        valid_lockdown_status || return 1
        status_lockdown && return 1
    fi
    invalid_lockdown_state && return 1
    sealed || return 0
    clear_ready || return 1
    (
        exec 8>"$STATE_DIR/packet-transformation-engine-guard-global.lock" || exit 1
        flock -x 8 || exit 1
        unseal_all_locked || exit 1
    )
}

unseal_all_locked() {
    local path
    local iface

    sealed || return 1
    valid_links_state || return 1
    for path in /sys/class/net/*; do
        [[ -d "$path/device" ]] || continue
        iface=${path##*/}
        ip link set dev "$iface" down || return 1
    done
    for path in /sys/class/net/*; do
        [[ -d "$path/device" ]] || continue
        iface=${path##*/}
        PH4NTXM_PACKET_TRANSFORMATION_ENGINE_GLOBAL_HELD=1 "$0" prepare "$iface" || return 1
    done
    while IFS= read -r iface; do
        valid_interface "$iface" || continue
        if ! verify_direct_locked "$iface" || ! ip link set dev "$iface" up; then
            reseal_after_restore_failure_locked || true
            return 1
        fi
    done < "$LINKS_FILE"
    if ! rm -f "$SEAL_FILE" || ! rm -f "$LINKS_FILE"; then
        reseal_after_restore_failure_locked || true
        return 1
    fi
}

reseal_after_restore_failure_locked() {
    local path
    local iface
    local temporary
    local seal_ok=1

    if ! sealed; then
        temporary=$(mktemp "$STATE_DIR/.packet-transformation-engine-guard-sealed.XXXXXX") || seal_ok=0
        if (( seal_ok )); then
            printf 'sealed\n' > "$temporary" || seal_ok=0
        fi
        if (( seal_ok )); then
            chmod 0600 "$temporary" || seal_ok=0
        fi
        if (( seal_ok )); then
            mv -f "$temporary" "$SEAL_FILE" || seal_ok=0
        fi
    fi
    for path in /sys/class/net/*; do
        [[ -d "$path/device" ]] || continue
        iface=${path##*/}
        ip link set dev "$iface" down >/dev/null 2>&1 || true
    done
    for path in /sys/class/net/*; do
        [[ -d "$path/device" ]] || continue
        iface=${path##*/}
        PH4NTXM_PACKET_TRANSFORMATION_ENGINE_GLOBAL_HELD=1 "$0" lockdown "$iface" >/dev/null 2>&1 || true
    done
    (( seal_ok ))
}

publish_transition_ack() {
    local profile=$1
    local token=$2
    local temporary

    temporary=$(mktemp "$STATE_DIR/.packet-transformation-engine-guard-transition.XXXXXX") || return 1
    printf 'STATUS=complete\nPROFILE=%s\nTOKEN=%s\n' "$profile" "$token" > "$temporary" || return 1
    chmod 0600 "$temporary" || return 1
    mv -f "$temporary" "$ACK_FILE" || return 1
}

ensure_desired_all() {
    local path
    local iface

    for path in /sys/class/net/*; do
        [[ -d "$path/device" ]] || continue
        iface=${path##*/}
        if ! PH4NTXM_PACKET_TRANSFORMATION_ENGINE_GLOBAL_HELD=1 "$0" verify "$iface"; then
            PH4NTXM_PACKET_TRANSFORMATION_ENGINE_GLOBAL_HELD=1 "$0" enforce "$iface" || return 1
            PH4NTXM_PACKET_TRANSFORMATION_ENGINE_GLOBAL_HELD=1 "$0" verify "$iface" || return 1
        fi
    done
}

process_transition_request() {
    protected_file "$REQUEST_FILE" || return 0
    clear_ready || return 1
    (
        exec 8>"$STATE_DIR/packet-transformation-engine-guard-global.lock" || exit 1
        flock -x 8 || exit 1
        process_transition_request_locked || exit 1
    )
}

process_transition_request_locked() {
    local profile
    local token

    protected_file "$REQUEST_FILE" || return 0
    [[ "$(wc -l < "$REQUEST_FILE")" == 2 ]] || return 1
    profile=$(state_value PROFILE "$REQUEST_FILE") || return 1
    token=$(state_value TOKEN "$REQUEST_FILE") || return 1
    [[ "$token" =~ ^[0-9a-f]{32}$ ]] || return 1
    case "$profile" in
        lockdown)
            seal_all_locked || return 1
            ;;
        normal)
            invalid_lockdown_state && return 1
            status_lockdown && return 1
            if sealed; then
                unseal_all_locked || return 1
            fi
            ;;
        *)
            return 1
            ;;
    esac
    ensure_desired_all || return 1
    publish_transition_ack "$profile" "$token" || return 1
    if protected_file "$REQUEST_FILE" && \
       [[ "$(state_value PROFILE "$REQUEST_FILE" 2>/dev/null || true)" == "$profile" ]] && \
       [[ "$(state_value TOKEN "$REQUEST_FILE" 2>/dev/null || true)" == "$token" ]]; then
        rm -f "$REQUEST_FILE" || return 1
    fi
}

cancel_transition_requests() {
    normal_mode || return 1
    protected_directory "$STATE_DIR" || return 1
    (
        exec 8>"$STATE_DIR/packet-transformation-engine-guard-global.lock" || exit 1
        flock -x 8 || exit 1
        rm -f "$REQUEST_FILE" "$ACK_FILE" || exit 1
    )
}

watch_interfaces() {
    local healthy
    local interfaces
    local path
    local iface
    local profile
    local ready_sent=0

    protected_directory "$STATE_DIR" || return 1
    trap watch_cleanup EXIT
    trap 'exit 1' HUP INT TERM
    normal_mode || return 1
    while true; do
        normal_mode || return 1
        healthy=1
        interfaces=0
        if ! process_transition_request; then
            if ! seal_all; then
                force_physical_links_down
            fi
            healthy=0
        fi
        if lockdown_requested && ! sealed; then
            if ! seal_all; then
                force_physical_links_down
                healthy=0
            fi
        fi
        if lockdown_requested; then profile=lockdown; else profile=normal; fi
        for path in /sys/class/net/*; do
            [[ -d "$path/device" ]] || continue
            iface=${path##*/}
            ((interfaces += 1))
            if ! "$0" verify "$iface"; then
                if ! "$0" enforce "$iface"; then
                    ip link set dev "$iface" down >/dev/null 2>&1 || true
                    healthy=0
                fi
            fi
        done
        if [[ "$profile" == lockdown ]] && ! lockdown_requested; then healthy=0; fi
        if [[ "$profile" == normal ]] && lockdown_requested; then healthy=0; fi
        if (( healthy )); then
            publish_ready "$interfaces" "$profile" || return 1
            if (( ! ready_sent )); then
                systemd-notify --ready --status="Packet Transformation Engine guard healthy" WATCHDOG=1 || return 1
                ready_sent=1
            else
                systemd-notify --status="Packet Transformation Engine guard healthy" WATCHDOG=1 || return 1
            fi
        else
            clear_ready || return 1
            systemd-notify --status="Packet Transformation Engine guard degraded; affected links held down" || return 1
        fi
        sleep "$SLEEP_SECONDS" || return 1
    done
}

case "${1:-}" in
    runtime)
        [[ $# == 1 ]] || exit 2
        normal_mode
        protected_directory "$STATE_DIR"
        valid_runtime
        ;;
    attach|prepare|lockdown|enforce|verify|stats)
        [[ $# == 2 ]] || exit 2
        run_interface_action "$1" "$2"
        ;;
    seal|unseal|cancel)
        [[ $# == 1 ]] || exit 2
        case "$1" in
            seal) seal_all ;;
            unseal) unseal_all ;;
            cancel) cancel_transition_requests ;;
        esac
        ;;
    watch)
        [[ $# == 1 ]] || exit 2
        watch_interfaces
        ;;
    *)
        exit 2
        ;;
esac
