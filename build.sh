#!/bin/bash
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
EDITION="abyss"
PREPARE_ONLY=0
BUILD_ARGS=()

while (($#)); do
    case "$1" in
        --edition)
            if (($# < 2)); then
                printf '%s\n' 'Missing edition. Use abyss or ghost.' >&2
                exit 2
            fi
            EDITION="$2"
            shift 2
            ;;
        --prepare-only)
            PREPARE_ONLY=1
            shift
            ;;
        --)
            shift
            BUILD_ARGS=("$@")
            break
            ;;
        --help|-h)
            printf '%s\n' 'Usage: ./build.sh [--edition abyss|ghost] [--prepare-only] [-- live-build options]'
            exit 0
            ;;
        *)
            printf 'Unknown option: %s\n' "$1" >&2
            exit 2
            ;;
    esac
done

case "$EDITION" in
    abyss|ghost) ;;
    *)
        printf 'Unknown edition: %s\n' "$EDITION" >&2
        exit 2
        ;;
esac

if ((PREPARE_ONLY == 0 && EUID != 0)); then
    printf '%s\n' 'Run the build with sudo, or use --prepare-only to inspect its configuration.' >&2
    exit 1
fi

for tool in python3 flock; do
    command -v "$tool" >/dev/null
done
if ((PREPARE_ONLY == 0)); then
    command -v lb >/dev/null
fi

python3 "$ROOT/tools/prepare-edition.py" --edition "$EDITION" --check
mkdir -p -- "$ROOT/build"
exec 9>"$ROOT/build/.$EDITION.lock"
if ! flock -n 9; then
    printf 'A %s build is already running.\n' "$EDITION" >&2
    exit 1
fi

WORK="$ROOT/build/$EDITION"
python3 "$ROOT/tools/prepare-edition.py" --edition "$EDITION" --check
if [[ -d "$WORK/.build" || -d "$WORK/chroot" || -d "$WORK/binary" ]]; then
    if ((PREPARE_ONLY)); then
        printf '%s\n' 'An earlier live-build exists. Run the normal build to clean it before preparing again.' >&2
        exit 1
    fi
    (cd -- "$WORK" && lb clean)
fi

python3 "$ROOT/tools/prepare-edition.py" --edition "$EDITION"
if ((PREPARE_ONLY)); then
    printf 'Prepared %s configuration: %s/config\n' "$EDITION" "$WORK"
    exit 0
fi

(
    cd -- "$WORK"
    lb config
    lb build "${BUILD_ARGS[@]}"
)

python3 "$ROOT/tools/prepare-edition.py" --edition "$EDITION" --publish
