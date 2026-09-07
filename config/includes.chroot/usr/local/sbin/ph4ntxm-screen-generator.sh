#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/run/ph4ntxm"
MODE_FILE="$STATE_DIR/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' < "$MODE_FILE")"
case "$MODE" in
    linux|windows) ;;
    lonewolf) exit 0 ;;
    *) exit 1 ;;
esac

SCREEN_ENV="$STATE_DIR/screen_env"
OUT="$STATE_DIR/browser_env"
PERSONA_SEED_FILE="$STATE_DIR/persona_seed"

[[ -r "$SCREEN_ENV" ]] || exit 1
[[ -s "$PERSONA_SEED_FILE" ]] || exit 1

source "$SCREEN_ENV"
SEED=$(cat "$PERSONA_SEED_FILE")

W=${PH4_DISPLAY_WIDTH:-1920}
H=${PH4_DISPLAY_HEIGHT:-1080}
PRIMARY=${PH4_PRIMARY_DISPLAY:-unknown}
SECONDARY=${PH4_SECONDARY_DISPLAY:-none}
PRESET_DPR=${PH4_DEVICE_PIXEL_RATIO:-1.0}

seeded_random() {
    local max=$1 salt=${2:-default}
    (( max > 0 )) || { echo 0; return; }

    local hash
    hash=$(printf "%s%s%s%s%s%s" "$SEED" "$PRIMARY" "$SECONDARY" "$W" "$H" "$salt" | sha256sum | cut -c1-8)
    echo $(( 16#$hash % max ))
}

clamp() {
    local val=$1 min=$2 max=$3
    (( val < min )) && echo "$min" && return
    (( val > max )) && echo "$max" && return
    echo "$val"
}

case "$PRESET_DPR" in
    1.0)
        DPR="1.0"
    ;;
    1.25)
        DPR="1.25"
    ;;
    1.5)
        (( $(seeded_random 100 "dpr_jitter") < 30 )) && DPR="1.25" || DPR="1.5"
    ;;
    2.0)
        DPR="1.5"
    ;;
    *)
        DPR="$PRESET_DPR"
    ;;
esac

UI_H=$((60 + $(seeded_random 40 "uih")))
UI_W=$(seeded_random 16 "uiw")

if (( $(seeded_random 100 "ui_spike") < 8 )); then
    UI_H=$((UI_H + 80))
fi

VIEW_W=$((W - UI_W))
VIEW_H=$((H - UI_H))
VIEW_W=$(clamp "$VIEW_W" 320 "$W")
VIEW_H=$(clamp "$VIEW_H" 200 "$H")

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
