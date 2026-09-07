#!/usr/bin/env bash
set -euo pipefail

readonly ALERT_DIR="/run/ph4ntxm-opsec-connwatch"
readonly STATS_FILE="$ALERT_DIR/connwatch-stats.log"
readonly ALERT_LOG="$ALERT_DIR/connwatch-alerts.history"
readonly ALERT_THRESHOLD=50
readonly ALERT_INTERVAL=300
readonly MAX_TRACKED_SOURCES=2048
readonly MAX_PORTS_PER_SOURCE=32
readonly MAX_HISTORY_LINES=4096
readonly HISTORY_TRIM_BATCH=256
readonly NOTIFICATION_INTERVAL=30

install -d -o root -g ph4ntxm -m 0750 "$ALERT_DIR"
install -o root -g ph4ntxm -m 0640 /dev/null "$STATS_FILE"
touch "$ALERT_LOG"
chown root:ph4ntxm "$ALERT_LOG"
chmod 0640 "$ALERT_LOG"

trim_history() {
    local tmp
    tmp=$(mktemp "$ALERT_DIR/.connwatch-history.XXXXXX")
    chown root:ph4ntxm "$tmp"
    chmod 0640 "$tmp"
    tail -n "$MAX_HISTORY_LINES" "$ALERT_LOG" > "$tmp"
    mv -f "$tmp" "$ALERT_LOG"
    history_lines=$MAX_HISTORY_LINES
}

history_lines=$(wc -l < "$ALERT_LOG")
if (( history_lines > MAX_HISTORY_LINES )); then
    trim_history
fi

declare -A hit_count=()
declare -A window_start=()
declare -A last_seen=()
declare -A ports_seen=()
declare -A ports_list=()
declare -A port_count=()
declare -A last_alert_time=()
tracked_sources=0

last_update=0
last_address_refresh=0
last_notification_time=0
packet_re='IP6?[[:space:]]+(.+)[[:space:]]+[>][[:space:]]+(.+):[[:space:]]+Flags'

declare -a local_addresses=()

refresh_local_addresses() {
    mapfile -t local_addresses < <(
        ip -o addr show 2>/dev/null | awk '$2 != "lo" {print $4}' | cut -d/ -f1
    )
    last_address_refresh=$(date +%s)
}

refresh_local_addresses

notify_session() {
    local uid runtime
    uid=$(id -u ph4ntxm 2>/dev/null) || return 0
    runtime="/run/user/$uid"
    [[ -S "$runtime/bus" ]] || return 0

    runuser -u ph4ntxm -- env \
        DISPLAY="${DISPLAY:-:0}" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" \
        notify-send --urgency=critical --app-name="PH4NTXM OpSec ConnWatch" \
        "Inbound activity notice" \
        "High inbound SYN volume was recorded in five minutes. Open ConnWatch for details." \
        >/dev/null 2>&1 || true
}

evict_oldest_source() {
    local addr oldest_addr= oldest_time=9223372036854775807 port key
    for addr in "${!last_seen[@]}"; do
        if (( last_seen[$addr] < oldest_time )); then
            oldest_addr=$addr
            oldest_time=${last_seen[$addr]}
        fi
    done
    [[ -n "$oldest_addr" ]] || return 1
    IFS=',' read -r -a old_ports <<< "${ports_list[$oldest_addr]:-}"
    for port in "${old_ports[@]}"; do
        [[ -n "$port" ]] || continue
        key="$oldest_addr:$port"
        unset 'ports_seen[$key]'
    done
    unset 'hit_count[$oldest_addr]' 'window_start[$oldest_addr]' \
        'last_seen[$oldest_addr]' 'ports_list[$oldest_addr]' \
        'port_count[$oldest_addr]' 'last_alert_time[$oldest_addr]'
    ((--tracked_sources))
}

write_stats() {
    local tmp addr ports displayed_hits now
    now=$(date +%s)
    tmp=$(mktemp "$ALERT_DIR/.connwatch-stats.XXXXXX")
    chown root:ph4ntxm "$tmp"
    chmod 0640 "$tmp"
    {
        printf '%s\n' "IP ADDRESS      | 5M HITS | TARGET PORTS"
        printf '%s\n' "----------------|------|-------------------------"
        while IFS= read -r addr; do
            ports=${ports_list[$addr]%,}
            [[ -n "$ports" ]] || ports="-"
            ((${#ports} <= 25)) || ports="${ports:0:22}..."
            displayed_hits=${hit_count[$addr]}
            (( now - window_start[$addr] < ALERT_INTERVAL )) || displayed_hits=0
            printf '%-15s | %7d | %s\n' "$addr" "$displayed_hits" "$ports"
        done < <(printf '%s\n' "${!hit_count[@]}" | sort -V)
    } > "$tmp"
    mv -f "$tmp" "$STATS_FILE"
}

echo "PH4NTXM OPSEC CONNWATCH: monitor active"

while IFS= read -r line; do
    [[ "$line" =~ $packet_re ]] || continue
    src_endpoint=${BASH_REMATCH[1]}
    dst_endpoint=${BASH_REMATCH[2]}
    [[ "$src_endpoint" =~ ^(.+)\.([0-9]+)$ ]] || continue
    src_ip=${BASH_REMATCH[1]}
    [[ "$dst_endpoint" =~ ^(.+)\.([0-9]+)$ ]] || continue
    dst_ip=${BASH_REMATCH[1]}
    dst_port=${BASH_REMATCH[2]}

    now=$(date +%s)
    if (( now - last_address_refresh >= 30 )); then
        refresh_local_addresses
    fi

    inbound=false
    for local_ip in "${local_addresses[@]}"; do
        if [[ "$dst_ip" == "$local_ip" ]]; then
            inbound=true
            break
        fi
    done
    [[ "$inbound" == true && "$src_ip" != "127.0.0.1" && "$src_ip" != "::1" ]] || continue

    if [[ -z "${hit_count[$src_ip]+present}" ]]; then
        if (( tracked_sources >= MAX_TRACKED_SOURCES )); then
            evict_oldest_source || continue
        fi
        hit_count[$src_ip]=0
        window_start[$src_ip]=$now
        last_seen[$src_ip]=$now
        port_count[$src_ip]=0
        ((++tracked_sources))
    fi

    if (( now - window_start["$src_ip"] >= ALERT_INTERVAL )); then
        hit_count[$src_ip]=0
        window_start[$src_ip]=$now
    fi

    (( hit_count["$src_ip"] += 1 ))
    last_seen[$src_ip]=$now
    key="$src_ip:$dst_port"
    if [[ -z "${ports_seen[$key]:-}" ]] && \
       (( port_count["$src_ip"] < MAX_PORTS_PER_SOURCE )); then
        ports_seen[$key]=1
        ports_list[$src_ip]="${ports_list[$src_ip]:-}$dst_port,"
        (( port_count["$src_ip"] += 1 ))
    fi

    previous_alert=${last_alert_time[$src_ip]:-0}
    if (( hit_count["$src_ip"] > ALERT_THRESHOLD && now - previous_alert >= ALERT_INTERVAL )); then
        last_alert_time[$src_ip]=$now
        printf '[VOLUME] %s exceeded five-minute threshold (%s)\n' "$src_ip" "$(date --iso-8601=seconds)" >> "$ALERT_LOG"
        ((++history_lines))
        if (( history_lines > MAX_HISTORY_LINES + HISTORY_TRIM_BATCH )); then
            trim_history
        fi
        if (( now - last_notification_time >= NOTIFICATION_INTERVAL )); then
            last_notification_time=$now
            notify_session &
        fi
    fi

    if (( now > last_update )); then
        last_update=$now
        write_stats
    fi
done < <(exec tcpdump -t -l -U -i any -nn \
    'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0' 2>/dev/null)

printf 'ph4ntxm-opsec-connwatch: packet capture ended unexpectedly\n' >&2
exit 1
