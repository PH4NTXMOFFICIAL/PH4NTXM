#!/usr/bin/env bash
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -euo pipefail

MODE_FILE="/run/ph4ntxm/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' <"$MODE_FILE")"

if [[ "$MODE" == "lonewolf" ]]; then
    exit 0
fi

[[ "$MODE" == "linux" || "$MODE" == "windows" ]] || exit 1

RULES=/etc/firewall/normal.nft
MANIFEST=/etc/firewall/rules.sha256
[[ -f "$RULES" && -f "$MANIFEST" ]]
/usr/bin/sha256sum --check --status --strict "$MANIFEST"
/usr/sbin/nft -c -f "$RULES"
/usr/sbin/nft -f "$RULES"
/usr/sbin/conntrack -F >/dev/null 2>&1 || true
