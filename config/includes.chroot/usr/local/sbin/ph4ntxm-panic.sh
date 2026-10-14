#!/bin/sh
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -u

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [ "$(id -u)" -ne 0 ]; then
    exit 1
fi

trap 'exit 1' HUP INT TERM

/usr/bin/timeout -k 1 30 /usr/local/sbin/ph4ntxm-nuke.sh || true

if [ "$(cat /sys/kernel/kexec_crash_loaded 2>/dev/null || echo 0)" = 1 ]; then
    printf '1\n' >/proc/sys/kernel/sysrq 2>/dev/null || true
    printf 'c\n' >/proc/sysrq-trigger 2>/dev/null || true
    sleep 3
fi

if systemctl poweroff --no-block; then
    trap - HUP INT TERM
    exit 0
fi

exit 1
