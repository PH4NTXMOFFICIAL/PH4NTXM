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
case "$MODE" in
    linux | windows) ;;
    lonewolf) exit 0 ;;
    *) exit 1 ;;
esac

[[ -r "$STATE_DIR/hardware_profile" ]] || exit 1
source "$STATE_DIR/hardware_profile"
[[ -n "${PROFILE_ID:-}" ]] || exit 1

tmp=$(mktemp "$STATE_DIR/.cores-env.XXXXXX")
if ! /usr/bin/python3 /usr/lib/ph4ntxm/hardware/persona.py resources "$PROFILE_ID" >"$tmp"; then
    rm -f "$tmp"
    exit 1
fi
chmod 0644 "$tmp"
mv -f "$tmp" "$OUT"

exit 0
