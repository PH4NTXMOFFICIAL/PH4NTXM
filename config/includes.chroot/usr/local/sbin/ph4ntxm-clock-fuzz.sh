#!/usr/bin/env bash
set -euo pipefail

STATE_DIR=/run/ph4ntxm
LOCK_FILE=$STATE_DIR/clock-fuzz.lock
PROFILE_FILE=$STATE_DIR/clock-fuzz-profile
MODE_FILE=$STATE_DIR/mode

mkdir -p "$STATE_DIR"
exec 9>"$LOCK_FILE"
flock -n 9 || exit 0

[[ -r "$MODE_FILE" ]] || exit 1
MODE=$(tr -d '\n' < "$MODE_FILE")

case "$MODE" in
    linux)
        SEED_FILE=$STATE_DIR/persona_seed
        OFFSET_MIN=-20
        OFFSET_MAX=20
        MIN_TICK=9994
        MAX_TICK=10006
        SLEEP_MIN=720
        SLEEP_MAX=1500
        MICRO_CHANCE=40
        ;;
    windows)
        SEED_FILE=$STATE_DIR/persona_seed
        OFFSET_MIN=-60
        OFFSET_MAX=60
        MIN_TICK=9988
        MAX_TICK=10012
        SLEEP_MIN=480
        SLEEP_MAX=1200
        MICRO_CHANCE=25
        ;;
    lonewolf)
        SEED_FILE=$STATE_DIR/lonewolf_seed
        OFFSET_MIN=-90
        OFFSET_MAX=90
        MIN_TICK=9985
        MAX_TICK=10015
        SLEEP_MIN=420
        SLEEP_MAX=900
        MICRO_CHANCE=18
        ;;
    *)
        exit 1
        ;;
esac

[[ -s "$SEED_FILE" ]] || exit 1
SEED=$(cat "$SEED_FILE")
BOOT_ID=$(cat /proc/sys/kernel/random/boot_id)
COUNTER=0

seeded_random() {
    local max=$1
    local salt=$2
    local hash
    hash=$(printf '%s%s%s%s' "$SEED" "$BOOT_ID" "$COUNTER" "$salt" | sha256sum | cut -c1-8)
    printf '%s\n' $((16#$hash % max))
}

write_profile() {
    local tmp
    tmp=$(mktemp "$STATE_DIR/.clock-profile.XXXXXX")
    {
        printf 'MODE=%s\n' "$MODE"
        printf 'OFFSET_SECONDS=%s\n' "$OFFSET"
        printf 'INITIAL_TICK=%s\n' "$INITIAL_TICK"
        printf 'CURRENT_TICK=%s\n' "$CURRENT_TICK"
        printf 'MIN_TICK=%s\n' "$MIN_TICK"
        printf 'MAX_TICK=%s\n' "$MAX_TICK"
        printf 'SKEW_APPLIED=1\n'
    } > "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$PROFILE_FILE"
}

profile_value() {
    awk -F= -v key="$1" '$1 == key {print substr($0, index($0, "=") + 1); exit}' "$PROFILE_FILE"
}

timedatectl set-ntp false >/dev/null 2>&1 || true
RESUME=0
if [[ -r "$PROFILE_FILE" ]]; then
    SAVED_MODE=$(profile_value MODE)
    SAVED_OFFSET=$(profile_value OFFSET_SECONDS)
    SAVED_INITIAL_TICK=$(profile_value INITIAL_TICK)
    SAVED_CURRENT_TICK=$(profile_value CURRENT_TICK)
    SAVED_APPLIED=$(profile_value SKEW_APPLIED)
    if [[ "$SAVED_MODE" == "$MODE" ]] && \
       [[ "$SAVED_OFFSET" =~ ^-?[0-9]+$ ]] && \
       [[ "$SAVED_INITIAL_TICK" =~ ^[0-9]+$ ]] && \
       [[ "$SAVED_CURRENT_TICK" =~ ^[0-9]+$ ]] && \
       [[ "$SAVED_APPLIED" == 1 ]] && \
       (( SAVED_OFFSET >= OFFSET_MIN && SAVED_OFFSET <= OFFSET_MAX )) && \
       (( SAVED_INITIAL_TICK >= MIN_TICK && SAVED_INITIAL_TICK <= MAX_TICK )) && \
       (( SAVED_CURRENT_TICK >= MIN_TICK && SAVED_CURRENT_TICK <= MAX_TICK )); then
        OFFSET=$SAVED_OFFSET
        INITIAL_TICK=$SAVED_INITIAL_TICK
        CURRENT_TICK=$SAVED_CURRENT_TICK
        RESUME=1
    fi
fi

if (( RESUME == 0 )); then
    OFFSET=$((OFFSET_MIN + $(seeded_random $((OFFSET_MAX - OFFSET_MIN + 1)) initial-offset)))
    NOW=$(date +%s)
    date -s "@$((NOW + OFFSET))" >/dev/null
    COUNTER=$((COUNTER + 1))
    INITIAL_TICK=$((MIN_TICK + $(seeded_random $((MAX_TICK - MIN_TICK + 1)) initial-tick)))
    CURRENT_TICK=$INITIAL_TICK
fi

adjtimex -t "$CURRENT_TICK" >/dev/null
write_profile

if [[ -n "${NOTIFY_SOCKET:-}" ]]; then
    systemd-notify --ready --status="Clock fuzz active in $MODE mode"
fi

while true; do
    COUNTER=$((COUNTER + 1))
    SLEEP_FOR=$((SLEEP_MIN + $(seeded_random $((SLEEP_MAX - SLEEP_MIN + 1)) sleep)))
    sleep "$SLEEP_FOR"

    COUNTER=$((COUNTER + 1))
    STEP=$(seeded_random 3 tick-step)
    STEP=$((STEP - 1))
    CURRENT_TICK=$((CURRENT_TICK + STEP))
    ((CURRENT_TICK < MIN_TICK)) && CURRENT_TICK=$MIN_TICK
    ((CURRENT_TICK > MAX_TICK)) && CURRENT_TICK=$MAX_TICK
    adjtimex -t "$CURRENT_TICK" >/dev/null

    COUNTER=$((COUNTER + 1))
    if (( $(seeded_random "$MICRO_CHANCE" micro-chance) == 0 )); then
        COUNTER=$((COUNTER + 1))
        MICRO_US=$((10000 + $(seeded_random 31001 micro-size)))
        COUNTER=$((COUNTER + 1))
        (( $(seeded_random 2 micro-sign) == 0 )) && MICRO_US=$((-MICRO_US))
        adjtimex -o "$MICRO_US" >/dev/null
    fi

    write_profile
done
