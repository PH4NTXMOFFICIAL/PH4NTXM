#!/bin/sh
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

MODE_FILE=/run/ph4ntxm/mode

if [ -r "$MODE_FILE" ]; then
    IFS= read -r PH4NTXM_MODE <"$MODE_FILE" || PH4NTXM_MODE=linux
else
    PH4NTXM_MODE=linux
fi

case "$PH4NTXM_MODE" in
    linux | windows | lonewolf) ;;
    *) PH4NTXM_MODE=linux ;;
esac

export PH4NTXM_MODE
