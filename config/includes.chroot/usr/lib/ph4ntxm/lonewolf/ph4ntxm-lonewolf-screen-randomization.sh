#!/usr/bin/env bash
set -euo pipefail
safe() { "$@" >/dev/null 2>&1 || true; }

STATE_DIR="/run/ph4ntxm"
MODE_FILE="$STATE_DIR/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' < "$MODE_FILE")"
if [[ "$MODE" != "lonewolf" ]]; then
    exit 0
fi

SEED_FILE="$STATE_DIR/lonewolf_seed"
JITTER_FILE="$STATE_DIR/boot_jitter"
SCREEN_ENV="$STATE_DIR/screen_env"
GPU_ENV="$STATE_DIR/gpu_env"
CORES_ENV="$STATE_DIR/cores_env"

[[ -s "$SEED_FILE" ]] || exit 1
[[ -s "$JITTER_FILE" ]] || exit 1

SEED=$(tr -d '\n' < "$SEED_FILE")
JITTER=$(tr -d '\n' < "$JITTER_FILE")
[[ "$SEED" =~ ^[0-9a-f]{64}$ ]] || exit 1
[[ "$JITTER" =~ ^[0-9a-f]{16}$ ]] || exit 1

mix_seed() {
    printf "%s%s%s" "$SEED" "$JITTER" "$1" | sha256sum | cut -c1-8
}

rand() {
    echo $((16#$(mix_seed "$1")))
}

rand_pick() {
    local salt="$1"; shift
    local arr=("$@")
    local idx=$(( $(rand "$salt") % ${#arr[@]} ))
    echo "${arr[$idx]}"
}

[[ -r "$GPU_ENV" && -r "$CORES_ENV" ]] || exit 1
source "$GPU_ENV"
source "$CORES_ENV"
GPU_VENDOR=${PH4NTXM_GPU_VENDOR:-unknown}
PROFILE_CLASS=${PH4_DEVICE_CLASS:-generic}

PRODUCT_FILE="$STATE_DIR/fake_dmi/product_name"
PRODUCT_NAME=$(cat "$PRODUCT_FILE" 2>/dev/null || echo "Generic")

DISPLAY_CLASS="generic"
case "$PRODUCT_NAME" in
    *EliteOne*|*Surface\ Studio*|*LG\ All-in-One*)
        DISPLAY_CLASS="allinone"
        ;;
    *ThinkPad*|*Latitude*|*EliteBook*|*ProBook*|*ExpertBook*|*Lifebook*|*Portege*|*Tecra*|*Dynabook*|*TravelMate*|*VAIO*)
        DISPLAY_CLASS="business"
        ;;
    *IdeaPad*|*VivoBook*|*Aspire*|*Pavilion*|*Inspiron*|*Envy*|*Galaxy\ Book*|*Notebook*|*Satellite*|*Flash*|*Modern*|*Chromebook*)
        DISPLAY_CLASS="consumer"
        ;;
    *Legion*|*TUF*|*Predator*|*ROG*|*Blade*|*Nitro*|*OMEN*|*Odyssey*|*Katana*|*GF63*|*Titan*|*Stealth*|*UltraGear*|*EON15*|*EON17*|*EVO15*)
        DISPLAY_CLASS="gaming"
        ;;
    *MacBookPro16,1*)
        DISPLAY_CLASS="apple_laptop"
        ;;
    *iMac20,1*|*Macmini8,1*)
        DISPLAY_CLASS="apple_desktop"
        ;;
    *ThinkCentre*|*IdeaCentre*|*OptiPlex*|*ProDesk*|*EliteDesk*|*Veriton*|*Esprimo*|*NUC*|*ThinkStation*|*Chronos*|*Millennium*|*Neuron*|*M-Class*)
        DISPLAY_CLASS="desktop"
        ;;
    *System\ x\ Server*)
        DISPLAY_CLASS="server"
        ;;
    *Surface*|*ZenBook*|*Yoga*|*ProArt*|*XPS*|*Gram*|*Precision*|*ZBook*|*Prestige*|*Summit*|*Razer\ Book*|*Pixelbook*|*Pixel\ Slate*)
        DISPLAY_CLASS="ultrabook"
        ;;
esac

pick_panel() {
    case "$DISPLAY_CLASS" in
        business)
            rand_pick "panel_biz" "1920 1080 60" "1366 768 60" "2560 1440 60"
            ;;
        consumer)
            rand_pick "panel_cons" "1920 1080 60" "1366 768 60" "1600 900 60"
            ;;
        gaming)
            rand_pick "panel_game" "1920 1080 144" "1920 1080 240" "2560 1440 165" "2560 1440 240"
            ;;
        ultrabook)
            rand_pick "panel_ultra" "1920 1080 60" "2560 1600 60" "2880 1800 90"
            ;;
        apple_laptop)
            rand_pick "panel_mac_l" "2560 1600 60" "3024 1964 120" "2880 1800 60"
            ;;
        apple_desktop)
            rand_pick "panel_mac_d" "3840 2160 60" "5120 2880 60" "2560 1440 60"
            ;;
        allinone)
            rand_pick "panel_aio" "1920 1080 60" "2560 1440 60" "3840 2160 60"
            ;;
        desktop)
            rand_pick "panel_desktop" "1920 1080 60" "2560 1440 60" "3840 2160 60"
            ;;
        server)
            echo "1920 1080 60"
            ;;
        *)
            echo "1920 1080 60"
            ;;
    esac
}

read W H R <<< "$(pick_panel)"

case "$GPU_VENDOR" in
    amd)
        if (( R > 165 )); then R=144; fi
        ;;
    nvidia)
        ;;
    apple)
        if (( R > 120 )); then R=120; fi
        ;;
    *)
        if (( R > 60 )); then R=60; fi
        ;;
esac

if [[ "$GPU_VENDOR" == "intel" && "$DISPLAY_CLASS" != "apple_desktop" ]] && (( W >= 3500 )); then
    W=2560; H=1440; R=60
fi

PRIMARY="DISPLAY-1"

DPR=1.0

case "$DISPLAY_CLASS" in
    desktop|server|apple_desktop|allinone)
        DPR=1.0
    ;;

    business|consumer)
        if (( W >= 1920 )); then DPR=1.0; fi
        if (( W >= 2500 )); then DPR=1.25; fi
    ;;

    ultrabook|apple_laptop)
        if (( W >= 2500 )); then
            DPR=1.5
        else
            DPR=1.25
        fi
    ;;

    gaming)
        if (( W >= 1920 )); then DPR=1.0; fi
        if (( W >= 2500 )); then DPR=1.25; fi
    ;;

    *)
        DPR=1.0
    ;;
esac

if [[ "$DISPLAY_CLASS" == "gaming" && "$DPR" != "1.0" ]]; then
    DPR=1.0
fi

tmp=$(mktemp "$STATE_DIR/.screen-env.XXXXXX")
chmod 0600 "$tmp"
{
    printf 'export PH4_DISPLAY_WIDTH=%q\n' "$W"
    printf 'export PH4_DISPLAY_HEIGHT=%q\n' "$H"
    printf 'export PH4_DEVICE_PIXEL_RATIO=%q\n' "$DPR"
    printf 'export PH4_PRIMARY_DISPLAY=%q\n' "$PRIMARY"
    printf 'export PH4_DEVICE_CLASS=%q\n' "$PROFILE_CLASS"
    printf 'export PH4_DISPLAY_CLASS=%q\n' "$DISPLAY_CLASS"
    printf 'export PH4_GPU_VENDOR=%q\n' "$GPU_VENDOR"
    printf 'export PH4_DISPLAY_REFRESH=%q\n' "$R"
} > "$tmp"

chmod 0644 "$tmp"
mv -f "$tmp" "$SCREEN_ENV"

exit 0
