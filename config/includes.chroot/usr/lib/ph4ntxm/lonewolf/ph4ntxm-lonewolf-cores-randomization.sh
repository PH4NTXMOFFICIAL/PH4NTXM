#!/usr/bin/env bash
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -euo pipefail

STATE_DIR="/run/ph4ntxm"
OUT="$STATE_DIR/cores_env"
MODE_FILE="$STATE_DIR/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' <"$MODE_FILE")"
if [[ "$MODE" != "lonewolf" ]]; then
    exit 0
fi

[[ -r "$STATE_DIR/hardware_profile" ]] || exit 1
source "$STATE_DIR/hardware_profile"
[[ -n "${PROFILE_ID:-}" ]] || exit 1

if [[ -x /usr/bin/nproc-real ]]; then
    REAL_CORES=$(/usr/bin/nproc-real --all)
else
    REAL_CORES=$(/usr/bin/nproc --all)
fi
REAL_RAM_KB=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)

tmp=$(mktemp "$STATE_DIR/.cores-env.XXXXXX")
if ! /usr/bin/python3 /usr/lib/ph4ntxm/hardware/persona.py resources "$PROFILE_ID" "$REAL_CORES" "$REAL_RAM_KB" >"$tmp"; then
    rm -f "$tmp"
    exit 1
fi
chmod 0644 "$tmp"
mv -f "$tmp" "$OUT"

exit 0
