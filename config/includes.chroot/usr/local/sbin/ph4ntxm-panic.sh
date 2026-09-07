#!/bin/sh
set -u

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USB_ARMED_FILE=/run/ph4ntxm/usb-nuke-armed
USB_TRIGGER_FILE=/run/ph4ntxm/usb-nuke-triggered

if [ "$(id -u)" -ne 0 ]; then
    exit 1
fi

restore_usb_arm() {
    if [ -e "$USB_TRIGGER_FILE" ]; then
        mv -f -- "$USB_TRIGGER_FILE" "$USB_ARMED_FILE" 2>/dev/null || true
    fi
}

trap 'restore_usb_arm; exit 1' HUP INT TERM

rfkill block all >/dev/null 2>&1 || true

for path in /sys/class/net/*; do
    [ -e "$path" ] || continue
    iface=${path##*/}
    [ "$iface" = lo ] && continue
    ip link set dev "$iface" down >/dev/null 2>&1 || true
done

/usr/local/sbin/ph4ntxm-nuke.sh

if [ "$(cat /sys/kernel/kexec_crash_loaded 2>/dev/null || echo 0)" = 1 ]; then
    printf '1\n' > /proc/sys/kernel/sysrq 2>/dev/null || true
    printf 'c\n' > /proc/sysrq-trigger 2>/dev/null || true
    sleep 3
fi

if systemctl poweroff --no-block; then
    restore_usb_arm
    trap - HUP INT TERM
    exit 0
fi

restore_usb_arm
exit 1
