#!/usr/bin/env bash
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -euo pipefail
safe() { "$@" >/dev/null 2>&1 || true; }

STATE_DIR="/run/ph4ntxm"
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

HARDWARE_PROFILE="$STATE_DIR/hardware_profile"
PERSONA_SEED="$STATE_DIR/persona_seed"
SCREEN_ENV="$STATE_DIR/screen_env"
GPU_ENV="$STATE_DIR/gpu_env"
CORES_ENV="$STATE_DIR/cores_env"

[[ -r "$GPU_ENV" ]] || exit 1
[[ -r "$CORES_ENV" ]] || exit 1
source "$GPU_ENV"
source "$CORES_ENV"

GPU_VENDOR="${PH4NTXM_GPU_VENDOR:-intel}"
PROFILE_CLASS="${PH4_DEVICE_CLASS:-desktop}"

[[ -r "$HARDWARE_PROFILE" ]] || exit 1
[[ -s "$PERSONA_SEED" ]] || exit 1

source "$HARDWARE_PROFILE"
SEED=$(cat "$PERSONA_SEED")

seeded_random() {
    local max=$1 salt=${2:-default}
    ((max > 0)) || {
        echo 0
        return
    }
    local hash=$(printf "%s%s" "$SEED" "$salt" | sha256sum | cut -c1-8)
    echo $((16#$hash % max))
}

case "$PROFILE_CLASS" in
    laptop) FORM_FACTOR="laptop" ;;
    desktop | server) FORM_FACTOR="desktop" ;;
    *) exit 1 ;;
esac

INTERNAL=""
EXTERNALS=()
case "$FORM_FACTOR" in
    laptop)
        INTERNAL="eDP-1"
        EXTERNALS=("HDMI-1" "DP-1")
        ;;
    desktop)
        INTERNAL=""
        [[ "$VENDOR" == "apple" ]] && EXTERNALS=("DP-1") || EXTERNALS=("HDMI-1" "DP-1")
        ;;
esac

(($(seeded_random 100 "no_ext") < 50)) && EXTERNALS=()

pick_internal_panel() {
    case "$GPU_VENDOR" in
        intel)
            echo "1920 1080 60"
            ;;
        amd | nvidia)
            case $(seeded_random 3 "int_hi") in
                0) echo "1920 1080 144" ;;
                1) echo "2560 1440 144" ;;
                2) echo "2560 1600 120" ;;
            esac
            ;;
        *)
            echo "1920 1080 60"
            ;;
    esac
}

pick_external_panel() {
    if [[ "$VENDOR" == "apple" ]]; then
        echo "2560 1440 60"
        return
    fi
    case "$GPU_VENDOR" in
        intel)
            echo "1920 1080 60"
            ;;
        amd | nvidia)
            case $(seeded_random 3 "ext_hi") in
                0) echo "2560 1440 144" ;;
                1) echo "3840 2160 60" ;;
                2) echo "2560 1440 165" ;;
            esac
            ;;
        *)
            echo "1920 1080 60"
            ;;
    esac
}

PRIMARY=""
SECONDARY=""
W=1920 H=1080 R=60

if [[ -n "$INTERNAL" ]]; then
    PANEL=$(pick_internal_panel)
    read W H R <<<"$PANEL"
    PRIMARY="$INTERNAL"
    if ((${#EXTERNALS[@]} > 0)) && (($(seeded_random 100 "dual") < 60)); then
        EXT="${EXTERNALS[0]}"
        PANEL2=$(pick_external_panel)
        read W2 H2 R2 <<<"$PANEL2"
        SECONDARY="$EXT"
        SECONDARY_RES="${W2}x${H2}@${R2}"
    fi
else
    if ((${#EXTERNALS[@]} > 0)); then
        EXT="${EXTERNALS[0]}"
        PANEL=$(pick_external_panel)
        read W H R <<<"$PANEL"
        PRIMARY="$EXT"
        if ((${#EXTERNALS[@]} > 1)) && (($(seeded_random 100 "dual_ext") < 40)); then
            EXT2="${EXTERNALS[1]}"
            PANEL2=$(pick_external_panel)
            read W2 H2 R2 <<<"$PANEL2"
            SECONDARY="$EXT2"
            SECONDARY_RES="${W2}x${H2}@${R2}"
        fi
    fi
fi

if [[ -z "$PRIMARY" ]]; then
    if [[ -n "$INTERNAL" ]]; then
        PRIMARY="$INTERNAL"
        PANEL=$(pick_internal_panel)
        read W H R <<<"$PANEL"
    else
        PRIMARY="HDMI-1"
        PANEL=$(pick_external_panel)
        read W H R <<<"$PANEL"
    fi
fi

if ((W >= 3800)); then
    DPR="1.5"
elif ((W >= 2500)); then
    DPR="1.5"
elif ((W >= 1920)); then
    DPR="1.25"
else
    DPR="1.0"
fi

tmp=$(mktemp "$STATE_DIR/.screen-env.XXXXXX")
chmod 0600 "$tmp"
{
    printf 'export PH4_PRIMARY_DISPLAY=%q\n' "$PRIMARY"
    printf 'export PH4_SECONDARY_DISPLAY=%q\n' "$SECONDARY"
    printf 'export PH4_DISPLAY_WIDTH=%q\n' "$W"
    printf 'export PH4_DISPLAY_HEIGHT=%q\n' "$H"
    printf 'export PH4_DISPLAY_REFRESH=%q\n' "$R"
    printf 'export PH4_DEVICE_PIXEL_RATIO=%q\n' "$DPR"
    printf 'export PH4_DEVICE_CLASS=%q\n' "$PROFILE_CLASS"
    printf 'export PH4_FORM_FACTOR=%q\n' "$FORM_FACTOR"
    if [[ -n "${SECONDARY_RES:-}" ]]; then
        printf 'export PH4_SECONDARY_RES=%q\n' "$SECONDARY_RES"
    fi
} >"$tmp"

chmod 0644 "$tmp"
mv -f "$tmp" "$SCREEN_ENV"

exit 0
