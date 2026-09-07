#!/usr/bin/env bash
set -euo pipefail

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

MODE_FILE=/run/ph4ntxm/mode
METADATA_DIR=/usr/lib/ph4ntxm/browser-mode
TARGET=/home/ph4ntxm/.config/panel/launcher-9/firefox-esr.desktop

[[ "$(id -u)" == 0 ]]
[[ -f "$MODE_FILE" && ! -L "$MODE_FILE" && "$(stat -c '%u' "$MODE_FILE")" == 0 ]]
MODE=$(tr -d '\n' < "$MODE_FILE")
case "$MODE" in
    lonewolf)
        SOURCE=$METADATA_DIR/tor-panel.desktop
        [[ -f /run/ph4ntxm/tor-browser-verified ]]
        ;;
    linux|windows)
        SOURCE=$METADATA_DIR/firefox-panel.desktop
        ;;
    *)
        exit 1
        ;;
esac

IFS=: read -r USER_NAME _ USER_ID GROUP_ID _ USER_HOME _ < <(getent passwd ph4ntxm)
[[ "$USER_NAME" == ph4ntxm ]]
[[ "$USER_ID" =~ ^[1-9][0-9]*$ ]]
[[ "$GROUP_ID" =~ ^[0-9]+$ ]]
[[ "$USER_HOME" == /home/ph4ntxm ]]
[[ -d "$USER_HOME" && ! -L "$USER_HOME" ]]
for directory in "$USER_HOME/.config" "$USER_HOME/.config/panel" "$USER_HOME/.config/panel/launcher-9"; do
    [[ ! -e "$directory" || -d "$directory" && ! -L "$directory" ]]
done
install -d -o "$USER_ID" -g "$GROUP_ID" -m 0755 "$USER_HOME/.config" "$USER_HOME/.config/panel" "$USER_HOME/.config/panel/launcher-9"
[[ "$(readlink -f "$USER_HOME/.config/panel/launcher-9")" == "$USER_HOME/.config/panel/launcher-9" ]]
[[ -f "$SOURCE" && ! -L "$SOURCE" && "$(stat -c '%u' "$SOURCE")" == 0 ]]
TMP=$(mktemp "$USER_HOME/.config/panel/launcher-9/.firefox-esr.desktop.XXXXXX")
install -o "$USER_ID" -g "$GROUP_ID" -m 0644 "$SOURCE" "$TMP"
mv -f "$TMP" "$TARGET"
