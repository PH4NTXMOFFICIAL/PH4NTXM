#!/bin/sh
set -eu
set -f

RUN_DIR=/run/ph4ntxm
MODE_FILE="$RUN_DIR/mode"

mkdir -p "$RUN_DIR"

mode="linux"

for arg in $(cat /proc/cmdline); do
    case "$arg" in
        ph4ntxm.mode=*)
            mode="${arg#ph4ntxm.mode=}"
            ;;
    esac
done

case "$mode" in
    windows|linux|lonewolf)
        ;;
    *)
        mode="linux"
        ;;
esac

rm -f "$RUN_DIR/mode-normal" "$RUN_DIR/mode-lonewolf"
mode_tmp=$(mktemp "$RUN_DIR/.mode.XXXXXX")
printf '%s\n' "$mode" > "$mode_tmp"
chmod 0644 "$mode_tmp"
mv -f "$mode_tmp" "$MODE_FILE"

case "$mode" in
    lonewolf) marker="$RUN_DIR/mode-lonewolf" ;;
    linux|windows) marker="$RUN_DIR/mode-normal" ;;
esac
marker_tmp=$(mktemp "$RUN_DIR/.mode-marker.XXXXXX")
chmod 0644 "$marker_tmp"
mv -f "$marker_tmp" "$marker"
