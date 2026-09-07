#!/usr/bin/env bash
set -euo pipefail

MODE_FILE="/run/ph4ntxm/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' < "$MODE_FILE")"

case "$MODE" in
  linux|windows) ;;
  lonewolf) exit 0 ;;
  *) exit 1 ;;
esac

BASE_DIR=/run/ph4ntxm/net
PERSONA_SEED_FILE=/run/ph4ntxm/persona_seed
JITTER_FILE=/run/ph4ntxm/boot_jitter
RTT_MAP=$BASE_DIR/rtt_map

SYSCTL=$(command -v sysctl || true)
IP=$(command -v ip || true)

[[ -x "$SYSCTL" ]] || exit 1
[[ -x "$IP" ]] || exit 1

normalize_sysctl_value() {
  awk '{$1=$1; print}' <<< "$1"
}

set_sysctl_required() {
  local key=$1 expected=$2 actual
  if ! "$SYSCTL" -q -w "$key=$expected" >/dev/null 2>&1; then
    printf 'ph4ntxm-net-randomization: unable to set %s\n' "$key" >&2
    return 1
  fi
  if ! actual=$("$SYSCTL" -n "$key" 2>/dev/null); then
    printf 'ph4ntxm-net-randomization: unable to read %s\n' "$key" >&2
    return 1
  fi
  if [[ "$(normalize_sysctl_value "$actual")" != "$(normalize_sysctl_value "$expected")" ]]; then
    printf 'ph4ntxm-net-randomization: verification failed for %s\n' "$key" >&2
    return 1
  fi
}

set_sysctl_if_present() {
  local key=$1 expected=$2
  if "$SYSCTL" -n "$key" >/dev/null 2>&1; then
    set_sysctl_required "$key" "$expected"
  fi
}

install -d -o root -g root -m 0755 "$BASE_DIR"
touch "$RTT_MAP"
chmod 0600 "$RTT_MAP"

for i in {1..5}; do
  $IP link show >/dev/null 2>&1 && break
  sleep 1
done

[[ -s "$PERSONA_SEED_FILE" && -s "$JITTER_FILE" ]] || exit 1
PERSONA_SEED=$(tr -d '\n' < "$PERSONA_SEED_FILE")
BOOT_JITTER=$(tr -d '\n' < "$JITTER_FILE")
[[ "$PERSONA_SEED" =~ ^[0-9a-f]{64}$ ]] || exit 1
[[ "$BOOT_JITTER" =~ ^[0-9a-f]{8,16}$ ]] || exit 1
SEED_HEX="$(printf '%s%snet' "$PERSONA_SEED" "$BOOT_JITTER" | sha256sum | cut -c1-15)"
[[ "$SEED_HEX" =~ ^[0-9a-f]{15}$ ]] || exit 1

SEED=$((16#$SEED_HEX ^ $(date +%s)))
SEED=$((SEED ^ $(cut -d' ' -f1 /proc/uptime | tr -d '.')))
SEED=$((SEED ^ $(od -An -N2 -tu2 /dev/urandom)))
TIME_SLICE=$(( $(date +%s) / 60 ))
SEED=$((SEED ^ TIME_SLICE))

rand() {
  local mix
  mix=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ' || echo 0)
  SEED=$(( (SEED ^ mix ^ $$ ^ $(date +%s%N)) & 0xffffffff ))
  SEED=$(( (SEED * 1664525 + 1013904223) & 0xffffffff ))
  echo "$SEED"
}

rand_range() {
  local min=$1 max=$2
  local range=$((max - min + 1))
  (( range <= 0 )) && range=1
  local r=$(rand)
  echo $(( min + (r % range) ))
}

clamp() {
  local val=$1 min=$2 max=$3
  (( val < min )) && val=$min
  (( val > max )) && val=$max
  echo "$val"
}

jitter() {
  local base=$1 spread=$2
  local delta=$(rand_range -"$spread" "$spread")
  echo $(( base + delta ))
}

case "$MODE" in
 linux)
    IP_TTL=64 IPV6_HOP_LIMIT=64
    PORT_LOW_BASE=25000 PORT_HIGH=64000
    SYN_RETRIES_BASE=6 SYNACK_RETRIES_BASE=6 FIN_TIMEOUT_BASE=40
    KEEP_TIME_BASE=5400 KEEP_INTVL=15 KEEP_PROBES=5
    MTU_PROBING=1 FASTOPEN=1 ECN=0 CC="cubic"
    ICMP_RATE=1000 RTT_BASE=20
    ;;
 windows)
    IP_TTL=128 IPV6_HOP_LIMIT=128
    PORT_LOW_BASE=49152 PORT_HIGH=65535
    SYN_RETRIES_BASE=3 SYNACK_RETRIES_BASE=3 FIN_TIMEOUT_BASE=45
    KEEP_TIME_BASE=7200 KEEP_INTVL=1 KEEP_PROBES=10
    MTU_PROBING=0 FASTOPEN=0 ECN=0 CC="cubic"
    ICMP_RATE=1000 RTT_BASE=25
    ;;
 *)
    exit 0
    ;;
esac

if [[ "$MODE" == "windows" ]]; then
    PORT_LOW=$(clamp "$(jitter 49152 100)" 49152 49200)
    ADV_WIN_SCALE=2
else
    PORT_LOW=$(clamp "$(jitter "$PORT_LOW_BASE" 4000)" 20000 60000)
    ADV_WIN_SCALE=2
fi

SYN_RETRIES=$(clamp "$(jitter "$SYN_RETRIES_BASE" 1)" 1 10)
SYNACK_RETRIES=$(clamp "$(jitter "$SYNACK_RETRIES_BASE" 1)" 1 10)
FIN_TIMEOUT=$(clamp "$(jitter "$FIN_TIMEOUT_BASE" 10)" 10 120)
KEEP_TIME=$(clamp "$(jitter "$KEEP_TIME_BASE" 600)" 300 10000)

RWIN_MIN=$(clamp "$(jitter 4096 2048)" 2048 16384)
RWIN_DEF=$(clamp "$(jitter 131072 65536)" 65536 1048576)
RWIN_MAX=$(clamp "$(jitter 6291456 1048576)" 1048576 16777216)

WWIN_MIN=$(clamp "$(jitter 4096 2048)" 2048 16384)
WWIN_DEF=$(clamp "$(jitter 131072 65536)" 65536 1048576)
WWIN_MAX=$(clamp "$(jitter 6291456 1048576)" 1048576 16777216)

DELAY=$(clamp "$(jitter "$RTT_BASE" 5)" 1 200)
DST_IP=$($IP route get 1.1.1.1 2>/dev/null | awk '{print $1; exit}' || echo "")
[[ -n "$DST_IP" ]] || DST_IP="0.0.0.0"
KNOWN_RTT=$(grep "^$DST_IP " "$RTT_MAP" 2>/dev/null | awk '{print $2}' || true)

if [[ -n "$KNOWN_RTT" ]]; then
  DELAY=$(clamp "$(jitter "$KNOWN_RTT" 5)" 1 300)
else
  tmp=$(mktemp "$BASE_DIR/.rtt-map.XXXXXX")
  chmod 600 "$tmp"
  grep -v "^$DST_IP " "$RTT_MAP" > "$tmp" 2>/dev/null || true
  echo "$DST_IP $DELAY" >> "$tmp"
  mv "$tmp" "$RTT_MAP"
fi

tmp=$(mktemp "$BASE_DIR/.rtt-map.XXXXXX")
chmod 600 "$tmp"
if tail -n 100 "$RTT_MAP" > "$tmp" 2>/dev/null; then
  mv "$tmp" "$RTT_MAP"
else
  rm -f "$tmp"
fi

set_sysctl_required net.ipv4.ip_local_port_range "$PORT_LOW $PORT_HIGH"
set_sysctl_required net.ipv4.ip_default_ttl "$IP_TTL"
set_sysctl_required net.ipv6.conf.all.hop_limit "$IPV6_HOP_LIMIT"
set_sysctl_required net.ipv6.conf.default.hop_limit "$IPV6_HOP_LIMIT"
set_sysctl_required net.ipv4.tcp_syn_retries "$SYN_RETRIES"
set_sysctl_required net.ipv4.tcp_synack_retries "$SYNACK_RETRIES"
set_sysctl_required net.ipv4.tcp_fin_timeout "$FIN_TIMEOUT"
set_sysctl_required net.ipv4.tcp_keepalive_time "$KEEP_TIME"
set_sysctl_required net.ipv4.tcp_keepalive_intvl "$KEEP_INTVL"
set_sysctl_required net.ipv4.tcp_keepalive_probes "$KEEP_PROBES"
set_sysctl_required net.ipv4.tcp_mtu_probing "$MTU_PROBING"
set_sysctl_required net.ipv4.tcp_fastopen "$FASTOPEN"
set_sysctl_required net.ipv4.tcp_ecn "$ECN"
set_sysctl_required net.ipv4.tcp_no_metrics_save 1
set_sysctl_required net.ipv4.tcp_window_scaling 1
set_sysctl_required net.ipv4.tcp_sack 1
set_sysctl_required net.ipv4.tcp_rmem "$RWIN_MIN $RWIN_DEF $RWIN_MAX"
set_sysctl_required net.ipv4.tcp_wmem "$WWIN_MIN $WWIN_DEF $WWIN_MAX"
set_sysctl_required net.ipv4.tcp_adv_win_scale "$ADV_WIN_SCALE"
set_sysctl_required net.ipv4.icmp_ratelimit "$ICMP_RATE"
set_sysctl_if_present net.mptcp.enabled 0

if [[ "$MODE" == "windows" ]]; then
  set_sysctl_if_present net.ipv4.tcp_fack 0
  set_sysctl_required net.ipv4.tcp_timestamps 0
else
  set_sysctl_required net.ipv4.tcp_timestamps 1
fi

AVAILABLE_CC=$("$SYSCTL" -n net.ipv4.tcp_available_congestion_control 2>/dev/null)
case " $AVAILABLE_CC " in
  *" $CC "*) ;;
  *)
    printf 'ph4ntxm-net-randomization: congestion control %s is unavailable\n' "$CC" >&2
    exit 1
    ;;
esac
set_sysctl_required net.ipv4.tcp_congestion_control "$CC"

exit 0
