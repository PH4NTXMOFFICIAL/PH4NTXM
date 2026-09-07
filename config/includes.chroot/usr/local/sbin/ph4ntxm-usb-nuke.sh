#!/bin/sh
set -eu

FLAG_FILE=/run/ph4ntxm/usb-nuke-armed
TRIGGER_FILE=/run/ph4ntxm/usb-nuke-triggered

if mv -- "$FLAG_FILE" "$TRIGGER_FILE" 2>/dev/null; then
    restore_arm() {
        if [ -e "$TRIGGER_FILE" ]; then
            mv -- "$TRIGGER_FILE" "$FLAG_FILE" 2>/dev/null || true
        fi
    }
    trap 'restore_arm; exit 1' HUP INT TERM
    if /bin/systemctl --no-block start ph4ntxm-panic.service; then
        trap - HUP INT TERM
    else
        restore_arm
        exit 1
    fi
fi
