#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/run/ph4ntxm"
OUT="$STATE_DIR/browser_env"
MODE_FILE="$STATE_DIR/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' < "$MODE_FILE")"
if [[ "$MODE" != "lonewolf" ]]; then
    exit 0
fi

SCREEN_ENV="$STATE_DIR/screen_env"
SEED_FILE="$STATE_DIR/lonewolf_seed"

[[ -r "$SCREEN_ENV" ]] || exit 1
[[ -s "$SEED_FILE" ]] || exit 1

source "$SCREEN_ENV"
SEED=$(tr -d '\n' < "$SEED_FILE")
[[ "$SEED" =~ ^[0-9a-f]{64}$ ]] || exit 1

W=${PH4_DISPLAY_WIDTH:-1920}
H=${PH4_DISPLAY_HEIGHT:-1080}
DPR=${PH4_DEVICE_PIXEL_RATIO:-1.0}
PRIMARY=${PH4_PRIMARY_DISPLAY:-DISPLAY-1}
SECONDARY=${PH4_SECONDARY_DISPLAY:-none}

seeded_random() {
    local max=$1 salt=${2:-default}
    (( max > 0 )) || { echo 0; return; }
    local hash
    hash=$(printf "%s%s%s%s" "$SEED" "$W" "$H" "$salt" | sha256sum | cut -c1-8)
    echo $(( 16#$hash % max ))
}

clamp() {
    local val=$1 min=$2 max=$3
    (( val < min )) && echo "$min" && return
    (( val > max )) && echo "$max" && return
    echo "$val"
}

case "$W" in
    3???|4???)
        UI_H=$((90 + $(seeded_random 40 "uih")))
        ;;
    2???)
        UI_H=$((80 + $(seeded_random 30 "uih")))
        ;;
    *)
        UI_H=$((70 + $(seeded_random 20 "uih")))
        ;;
esac

UI_W=$(seeded_random 16 "uiw")

PHYS_W=$((W - UI_W))
PHYS_H=$((H - UI_H))

CSS_W=$(awk "BEGIN {printf \"%d\", $PHYS_W / $DPR}")
CSS_H=$(awk "BEGIN {printf \"%d\", $PHYS_H / $DPR}")

VIEW_W=$(clamp "$CSS_W" 320 "$W")
VIEW_H=$(clamp "$CSS_H" 200 "$H")

DISPLAY_COUNT=1
[[ "$SECONDARY" != "none" ]] && DISPLAY_COUNT=2

tmp=$(mktemp "$STATE_DIR/.browser-env.XXXXXX")
chmod 0600 "$tmp"
{
    printf 'export PH4_SCREEN_WIDTH=%q\n' "$W"
    printf 'export PH4_SCREEN_HEIGHT=%q\n' "$H"
    printf 'export PH4_VIEWPORT_WIDTH=%q\n' "$VIEW_W"
    printf 'export PH4_VIEWPORT_HEIGHT=%q\n' "$VIEW_H"
    printf 'export PH4_DEVICE_PIXEL_RATIO=%q\n' "$DPR"
    printf 'export PH4_DISPLAY_COUNT=%q\n' "$DISPLAY_COUNT"
    printf 'export PH4_PRIMARY_DISPLAY=%q\n' "$PRIMARY"
    printf 'export PH4_SECONDARY_DISPLAY=%q\n' "$SECONDARY"
} > "$tmp"

chmod 0644 "$tmp"
mv -f "$tmp" "$OUT"

exit 0
