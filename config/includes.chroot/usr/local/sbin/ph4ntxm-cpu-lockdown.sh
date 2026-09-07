#!/usr/bin/env bash
set -euo pipefail

readonly TEMP_LIMIT_MILLIC=85000
readonly HYSTERESIS_MILLIC=70000

declare -A saved_governor=()
saved_turbo=""
throttled=false

read_max_temperature() {
    local zone value maximum=0
    shopt -s nullglob
    for zone in /sys/class/thermal/thermal_zone*/temp; do
        read -r value < "$zone" 2>/dev/null || continue
        [[ "$value" =~ ^[0-9]+$ ]] || continue
        (( value < 1000 )) && value=$((value * 1000))
        (( value > maximum )) && maximum=$value
    done
    shopt -u nullglob
    printf '%s\n' "$maximum"
}

write_value() {
    local value=$1 path=$2
    [[ -w "$path" ]] || return 0
    printf '%s\n' "$value" > "$path" 2>/dev/null || true
}

save_baseline() {
    local policy governor_file
    shopt -s nullglob
    for policy in /sys/devices/system/cpu/cpufreq/policy*; do
        governor_file="$policy/scaling_governor"
        [[ -r "$governor_file" ]] || continue
        read -r saved_governor["$governor_file"] < "$governor_file" || true
    done
    shopt -u nullglob

    if [[ -r /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
        read -r saved_turbo < /sys/devices/system/cpu/intel_pstate/no_turbo || true
    elif [[ -r /sys/devices/system/cpu/cpufreq/boost ]]; then
        read -r saved_turbo < /sys/devices/system/cpu/cpufreq/boost || true
    fi
}

apply_throttle() {
    local governor_file
    for governor_file in "${!saved_governor[@]}"; do
        write_value powersave "$governor_file"
    done
    write_value 1 /sys/devices/system/cpu/intel_pstate/no_turbo
    write_value 0 /sys/devices/system/cpu/cpufreq/boost
    throttled=true
}

restore_baseline() {
    local governor_file
    for governor_file in "${!saved_governor[@]}"; do
        write_value "${saved_governor[$governor_file]}" "$governor_file"
    done
    if [[ -n "$saved_turbo" ]]; then
        if [[ -e /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
            write_value "$saved_turbo" /sys/devices/system/cpu/intel_pstate/no_turbo
        elif [[ -e /sys/devices/system/cpu/cpufreq/boost ]]; then
            write_value "$saved_turbo" /sys/devices/system/cpu/cpufreq/boost
        fi
    fi
    throttled=false
}

shutdown_guard() {
    trap - EXIT
    restore_baseline
    exit 0
}

save_baseline
trap 'restore_baseline' EXIT
trap 'shutdown_guard' INT TERM

while :; do
    max_temp=$(read_max_temperature)
    if (( max_temp >= TEMP_LIMIT_MILLIC )) && [[ "$throttled" == false ]]; then
        apply_throttle
    elif (( max_temp > 0 && max_temp <= HYSTERESIS_MILLIC )) && [[ "$throttled" == true ]]; then
        restore_baseline
    fi
    sleep 10
done
