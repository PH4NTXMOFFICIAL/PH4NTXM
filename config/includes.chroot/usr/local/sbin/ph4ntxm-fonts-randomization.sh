#!/usr/bin/env bash
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -euo pipefail

STATE_DIR=/run/ph4ntxm
EXTRA_DIR="/usr/share/fonts/extra"
WINDOWS_DIR="/usr/share/fonts/truetype/msttcorefonts"
ACTIVE_DIR="$STATE_DIR/fonts-active"
FC_CONF="$ACTIVE_DIR/fonts.conf"
MODE_FILE="$STATE_DIR/mode"

MODE="linux"
if [[ -r "$MODE_FILE" ]]; then
    MODE="$(tr -d '\n' <"$MODE_FILE")"
fi

FONTS=()
case "$MODE" in
    linux)
        COUNT=$((1 + RANDOM % 10))
        ;;
    windows)
        COUNT=$((1 + RANDOM % 5))
        [[ -d "$WINDOWS_DIR" ]] || exit 1
        mapfile -d '' -t FONTS < <(find "$WINDOWS_DIR" -type f -iname '*.ttf' -print0)
        ((${#FONTS[@]} > 0)) || exit 1
        ;;
    lonewolf)
        COUNT=$((1 + RANDOM % 3))
        ;;
    *)
        exit 0
        ;;
esac

[[ -d "$EXTRA_DIR" ]] || exit 1
mapfile -d '' -t EXTRA_FONTS < <(find "$EXTRA_DIR" -type f \
    \( -iname '*.ttf' -o -iname '*.otf' \) -print0)
((${#EXTRA_FONTS[@]} > 0)) || exit 1
FONT_CATALOG=$(fc-scan --format '%{family[0]}\t%{file}\n' "${EXTRA_FONTS[@]}")
declare -A FONT_FAMILIES=()
declare -A AVAILABLE_FAMILIES=()
declare -A SELECTED_FAMILIES=()

while IFS=$'\t' read -r family font; do
    [[ -n "$family" && -n "$font" ]] || continue
    if [[ "$family" == "Open Sans Condensed" ]]; then
        family="Open Sans"
    fi
    if [[ "$MODE" == windows ]]; then
        case "$family" in
            "Cascadia Code" | "Cascadia Mono")
                SELECTED_FAMILIES["$family"]=1
                ;;
            Arimo | Tinos | Cousine | "Open Sans" | Noto\ *)
                AVAILABLE_FAMILIES["$family"]=1
                ;;
            *) continue ;;
        esac
    else
        AVAILABLE_FAMILIES["$family"]=1
    fi
    FONT_FAMILIES["$font"]="$family"
done <<<"$FONT_CATALOG"

((${#FONT_FAMILIES[@]} > 0)) || exit 1
if ((${#AVAILABLE_FAMILIES[@]} > 0)); then
    CHOSEN_FAMILIES=$(printf '%s\n' "${!AVAILABLE_FAMILIES[@]}" | LC_ALL=C sort | shuf -n "$COUNT")
    while IFS= read -r family; do
        SELECTED_FAMILIES["$family"]=1
    done <<<"$CHOSEN_FAMILIES"
fi

for font in "${!FONT_FAMILIES[@]}"; do
    family=${FONT_FAMILIES[$font]}
    if [[ -n "${SELECTED_FAMILIES[$family]:-}" ]]; then
        FONTS+=("$font")
    fi
done

mkdir -p "$ACTIVE_DIR"
rm -f "$ACTIVE_DIR"/*
for font in "${FONTS[@]}"; do
    ln -s -- "$font" "$ACTIVE_DIR/"
done

cat <<EOF >"$FC_CONF"
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
    <dir>$ACTIVE_DIR</dir>

    $([ "$MODE" != "windows" ] && echo "
    <dir>/usr/share/fonts/truetype</dir>
    <dir>/usr/share/fonts/opentype</dir>
    <selectfont>
        <rejectfont>
            <glob>/usr/share/fonts/truetype/msttcorefonts/*</glob>
            <glob>/usr/local/share/fonts/*</glob>
            <glob>~/.fonts/*</glob>
            <glob>~/.local/share/fonts/*</glob>
        </rejectfont>
    </selectfont>
    ")

    $([ "$MODE" = "windows" ] && echo "
    <selectfont>
        <rejectfont>
            <glob>/usr/share/fonts/truetype/ancient-scripts/*</glob>
            <glob>/usr/share/fonts/truetype/dejavu/*</glob>
            <glob>/usr/share/fonts/truetype/droid/*</glob>
            <glob>/usr/share/fonts/truetype/liberation/*</glob>
            <glob>/usr/share/fonts/truetype/lyx/*</glob>
            <glob>/usr/share/fonts/truetype/quicksand/*</glob>
            <glob>/usr/share/fonts/opentype/*</glob>
            <glob>/usr/share/fonts/type1/*</glob>
            <glob>/usr/share/fonts/X11/*</glob>
            <glob>/usr/share/fonts/cmap/*</glob>
            <glob>/usr/share/fonts/cMap/*</glob>
            <glob>~/.fonts/*</glob>
            <glob>~/.local/share/fonts/*</glob>
        </rejectfont>
    </selectfont>
    ")
</fontconfig>
EOF

FONTCONFIG_PATH="$ACTIVE_DIR" \
    FONTCONFIG_FILE="$FC_CONF" \
    fc-cache -f >/dev/null 2>&1
