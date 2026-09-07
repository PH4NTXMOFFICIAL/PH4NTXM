#!/usr/bin/env bash
set -euo pipefail

STATE_DIR=/run/ph4ntxm
EXTRA_DIR="/usr/share/fonts/extra"
WINDOWS_DIR="/usr/share/fonts/truetype/msttcorefonts"
ACTIVE_DIR="$STATE_DIR/fonts-active"
FC_CONF="$ACTIVE_DIR/fonts.conf"
MODE_FILE="$STATE_DIR/mode"

mkdir -p "$ACTIVE_DIR"
rm -f "$ACTIVE_DIR"/*

MODE="linux"
if [[ -r "$MODE_FILE" ]]; then
    MODE="$(tr -d '\n' < "$MODE_FILE")"
fi

case "$MODE" in
    linux)
        COUNT=$((1 + RANDOM % 10))
        FONTS=$(find "$EXTRA_DIR" -type f | shuf -n "$COUNT")
        ;;
    windows)
        COUNT=$((1 + RANDOM % 5))
        MS_FONTS=$(find "$WINDOWS_DIR" -type f)
        EXTRA_SAFE=$(find "$EXTRA_DIR" -type f | grep -iE 'arimo|tinos|cousine|noto|opensans' | shuf -n "$COUNT")
        FONTS="$MS_FONTS"$'\n'"$EXTRA_SAFE"
        ;;
    lonewolf)
        COUNT=$((1 + RANDOM % 3))
        FONTS=$(find "$EXTRA_DIR" -type f | shuf -n "$COUNT")
        ;;
    *)
        exit 0
        ;;
esac

for f in $FONTS; do
    ln -s "$f" "$ACTIVE_DIR"/ 2>/dev/null || true
done

cat <<EOF > "$FC_CONF"
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
    <dir>$ACTIVE_DIR</dir>

    $( [ "$MODE" != "windows" ] && echo "
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
    " )

    $( [ "$MODE" = "windows" ] && echo "
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
    " )
</fontconfig>
EOF

FONTCONFIG_PATH="$ACTIVE_DIR" \
FONTCONFIG_FILE="$FC_CONF" \
fc-cache -f >/dev/null 2>&1