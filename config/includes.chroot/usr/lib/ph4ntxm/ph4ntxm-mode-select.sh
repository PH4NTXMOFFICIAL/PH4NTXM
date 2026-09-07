#!/bin/sh
set -eu

MODE_FILE=/run/ph4ntxm/mode

if [ -f "$MODE_FILE" ]; then
    cat "$MODE_FILE"
else
    printf '%s\n' linux
fi