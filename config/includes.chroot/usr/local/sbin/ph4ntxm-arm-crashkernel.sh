#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || exit 1
[ -r /boot/nuke/vmlinuz-nuke ] && [ -r /boot/nuke/initrd-nuke.img ] || exit 1

RAM_MAP=$(awk '$3 == "System" && $4 == "RAM" && $1 ~ /^[0-9a-fA-F]+-[0-9a-fA-F]+$/ {split($1, range, "-"); if (range[1] ~ /^0+$/ && range[2] ~ /^0+$/) next; printf " ph4ntxm.memmap=%s", $1}' /proc/iomem)
if [ -z "$RAM_MAP" ] && [ -d /sys/firmware/memmap ]; then
    for entry in /sys/firmware/memmap/*; do
        [ -d "$entry" ] || continue
        [ "$(cat "$entry/type" 2>/dev/null || true)" = "System RAM" ] || continue
        start=$(cat "$entry/start" 2>/dev/null || true)
        end=$(cat "$entry/end" 2>/dev/null || true)
        start=${start#0x}
        end=${end#0x}
        case "$start:$end" in
            *[!0-9a-fA-F:]*|:*|*:|*:*:*) continue ;;
        esac
        printf '%s%s' "$start" "$end" | grep -q '[^0]' || continue
        RAM_MAP="$RAM_MAP ph4ntxm.memmap=$start-$end"
    done
fi
[ -n "$RAM_MAP" ] || exit 1
APPEND_LINE="init=/init root=/dev/ram0 rw quiet loglevel=3 noswap iomem=relaxed nokaslr nosmap nosmep reset_devices maxcpus=1 irqpoll acpi=noirq init_on_free=1 page_alloc.shuffle=1$RAM_MAP"
[ "${#APPEND_LINE}" -le 1800 ] || exit 1

if ! /usr/sbin/kexec -p /boot/nuke/vmlinuz-nuke \
    --initrd=/boot/nuke/initrd-nuke.img \
    --append="$APPEND_LINE"; then
    logger -t ph4ntxm "Mandatory nuke crashkernel could not be armed"
    exit 1
fi

if ! printf '1\n' > /proc/sys/kernel/kexec_load_disabled 2>/dev/null; then
    logger -t ph4ntxm "Mandatory nuke crashkernel armed, but the loader could not be locked"
    exit 1
fi
