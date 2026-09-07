#!/usr/bin/env bash
set -euo pipefail

MODE_FILE=/run/ph4ntxm/mode
SEED_FILE=/run/ph4ntxm/lonewolf_seed
SYSCTL=/usr/sbin/sysctl

[[ -r "$MODE_FILE" ]]
MODE=$(tr -d '\n' < "$MODE_FILE")
[[ "$MODE" == lonewolf ]] || exit 0
[[ -x "$SYSCTL" ]]
[[ -f "$SEED_FILE" && ! -L "$SEED_FILE" && "$(stat -c '%u' "$SEED_FILE")" == 0 ]]
SEED=$(tr -d '\n' < "$SEED_FILE")
[[ "$SEED" =~ ^[0-9a-f]{64}$ ]]

seeded_random() {
    local maximum=$1 salt=$2 hash
    (( maximum > 0 ))
    hash=$(printf '%s:%s' "$SEED" "$salt" | sha256sum | cut -c1-8)
    printf '%s\n' "$((16#$hash % maximum))"
}

random_range() {
    local minimum=$1 maximum=$2 salt=$3
    printf '%s\n' "$((minimum + $(seeded_random "$((maximum - minimum + 1))" "$salt")))"
}

apply_value() {
    local key=$1 expected=$2 actual
    "$SYSCTL" -q -w "$key=$expected"
    actual=$("$SYSCTL" -n "$key")
    [[ "$actual" == "$expected" ]]
}

apply_bounded_value() {
    local key=$1 requested=$2 minimum=$3 maximum=$4 actual
    "$SYSCTL" -q -w "$key=$requested"
    actual=$("$SYSCTL" -n "$key")
    [[ "$actual" =~ ^[0-9]+$ ]]
    (( actual >= minimum && actual <= maximum ))
}

PORT_LOW=$(random_range 30000 42000 port-low)
SYN_RETRIES=$(random_range 4 6 syn-retries)
SYNACK_RETRIES=$(random_range 4 6 synack-retries)
FIN_TIMEOUT=$(random_range 20 40 fin-timeout)
KEEP_TIME=$(random_range 1800 5400 keepalive-time)
ICMP_RATE=$(random_range 500 1500 icmp-rate)

apply_value net.ipv4.ip_default_ttl 64
"$SYSCTL" -q -w "net.ipv4.ip_local_port_range=$PORT_LOW 60999"
read -r PORT_ACTUAL_LOW PORT_ACTUAL_HIGH < /proc/sys/net/ipv4/ip_local_port_range
[[ "$PORT_ACTUAL_LOW" == "$PORT_LOW" && "$PORT_ACTUAL_HIGH" == 60999 ]]
apply_value net.ipv4.tcp_syn_retries "$SYN_RETRIES"
apply_value net.ipv4.tcp_synack_retries "$SYNACK_RETRIES"
apply_value net.ipv4.tcp_fin_timeout "$FIN_TIMEOUT"
apply_value net.ipv4.tcp_keepalive_time "$KEEP_TIME"
apply_value net.ipv4.tcp_keepalive_intvl 30
apply_value net.ipv4.tcp_keepalive_probes 5
apply_value net.ipv4.tcp_mtu_probing 1
apply_value net.ipv4.tcp_fastopen 0
apply_value net.ipv4.tcp_ecn 0
apply_value net.ipv4.tcp_congestion_control cubic
apply_bounded_value net.ipv4.icmp_ratelimit "$ICMP_RATE" 500 1500
apply_value net.ipv6.conf.all.disable_ipv6 1
apply_value net.ipv6.conf.default.disable_ipv6 1
apply_value net.ipv6.conf.lo.disable_ipv6 1
apply_value net.ipv4.tcp_timestamps 0
apply_value net.ipv4.tcp_sack 1
apply_value net.ipv4.tcp_window_scaling 1

for interface_setting in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    [[ -f "$interface_setting" ]]
    printf '1\n' > "$interface_setting"
    [[ "$(tr -d '\n' < "$interface_setting")" == 1 ]]
done
