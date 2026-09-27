#!/bin/sh
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -eu

[ "$(id -u)" -eq 0 ] || exit 1
[ -r /boot/nuke/vmlinuz-nuke ] && [ -r /boot/nuke/initrd-nuke.img ] || exit 1

fail() {
    printf 'PH4NTXM: %s. Nuke arming stopped\n' "$1" >&2
    exit 1
}

hex_number() {
    hex=${1#0x}
    case "$hex" in
        '' | *[!0-9a-fA-F]*) return 1 ;;
    esac
    [ "${#hex}" -le 16 ] || return 1
    number=$((0x$hex))
    [ "$number" -ge 0 ] || return 1
    printf '%s\n' "$number"
}

volatile_cxl_range() {
    for region in /sys/bus/cxl/devices/region[0-9]*; do
        [ -d "$region" ] || continue
        [ "$(cat "$region/mode" 2>/dev/null || true)" = ram ] || continue
        [ "$(cat "$region/commit" 2>/dev/null || true)" = 1 ] || continue
        resource=$(cat "$region/resource" 2>/dev/null || true)
        capacity=$(cat "$region/size" 2>/dev/null || true)
        region_start=$(hex_number "$resource") || continue
        region_size=$(hex_number "$capacity") || continue
        [ "$region_size" -gt 0 ] || continue
        region_end=$((region_start + region_size - 1))
        [ "$region_end" -ge "$region_start" ] || continue
        [ "$1" -ge "$region_start" ] && [ "$2" -le "$region_end" ] || continue
        [ "$(cat "$region/mode" 2>/dev/null || true)" = ram ] || continue
        [ "$(cat "$region/commit" 2>/dev/null || true)" = 1 ] || continue
        [ "$(cat "$region/resource" 2>/dev/null || true)" = "$resource" ] || continue
        [ "$(cat "$region/size" 2>/dev/null || true)" = "$capacity" ] || continue
        return 0
    done
    return 1
}

RAM_MAP=
while read -r range separator type; do
    case "$type" in
        'System RAM' | 'System RAM (kmem)') ;;
        'System RAM'*) fail 'Unsupported System RAM type' ;;
        *) continue ;;
    esac
    [ "$separator" = : ] || fail 'Invalid RAM map'
    start=${range%-*}
    end=${range#*-}
    [ "$start" != "$range" ] || fail 'Invalid RAM range'
    first=$(hex_number "$start") || fail 'Invalid RAM range'
    last=$(hex_number "$end") || fail 'Invalid RAM range'
    [ "$last" -ge "$first" ] || fail 'Invalid RAM range'
    if [ "$first" -eq 0 ] && [ "$last" -eq 0 ]; then
        [ "$type" = 'System RAM' ] || fail 'Driver-managed RAM addresses are unavailable'
        continue
    fi
    if [ "$type" = 'System RAM (kmem)' ]; then
        volatile_cxl_range "$first" "$last" \
            || fail 'Driver-managed RAM is not verified volatile CXL memory'
    fi
    RAM_MAP="$RAM_MAP ph4ntxm.memmap=$start-$end"
done </proc/iomem
if [ -z "$RAM_MAP" ] && [ -d /sys/firmware/memmap ]; then
    for entry in /sys/firmware/memmap/*; do
        [ -d "$entry" ] || continue
        [ "$(cat "$entry/type" 2>/dev/null || true)" = "System RAM" ] || continue
        start=$(cat "$entry/start" 2>/dev/null || true)
        end=$(cat "$entry/end" 2>/dev/null || true)
        start=${start#0x}
        end=${end#0x}
        case "$start:$end" in
            *[!0-9a-fA-F:]* | :* | *: | *:*:*) continue ;;
        esac
        printf '%s%s' "$start" "$end" | grep -q '[^0]' || continue
        RAM_MAP="$RAM_MAP ph4ntxm.memmap=$start-$end"
    done
fi
[ -n "$RAM_MAP" ] || exit 1
APPEND_LINE="init=/init root=/dev/ram0 rw quiet loglevel=3 iomem=relaxed nokaslr reset_devices maxcpus=1 irqpoll acpi=noirq init_on_free=1 page_alloc.shuffle=1$RAM_MAP"
[ "${#APPEND_LINE}" -le 1800 ] || exit 1

if ! /usr/sbin/kexec -p /boot/nuke/vmlinuz-nuke \
    --initrd=/boot/nuke/initrd-nuke.img \
    --append="$APPEND_LINE"; then
    logger -t ph4ntxm "Mandatory nuke crashkernel could not be armed"
    exit 1
fi

if ! printf '1\n' >/proc/sys/kernel/kexec_load_disabled 2>/dev/null; then
    logger -t ph4ntxm "Mandatory nuke crashkernel armed, but the loader could not be locked"
    exit 1
fi
