#!/usr/bin/env bash
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

set -euo pipefail

STATE_DIR="/run/ph4ntxm"
MODE_FILE="$STATE_DIR/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' <"$MODE_FILE")"
if [[ "$MODE" != "lonewolf" ]]; then
    exit 0
fi

SEED_FILE="$STATE_DIR/lonewolf_seed"
JITTER_FILE="$STATE_DIR/boot_jitter"
GPU_ENV_FILE="$STATE_DIR/gpu_env"

[[ -s "$SEED_FILE" ]] || exit 1
[[ -s "$JITTER_FILE" ]] || exit 1

SEED=$(tr -d '\n' <"$SEED_FILE")
JITTER=$(tr -d '\n' <"$JITTER_FILE")
[[ "$SEED" =~ ^[0-9a-f]{64}$ ]] || exit 1
[[ "$JITTER" =~ ^[0-9a-f]{16}$ ]] || exit 1

[[ -r "$STATE_DIR/hardware_profile" ]] || exit 1
source "$STATE_DIR/hardware_profile"
[[ -n "${PROFILE_ID:-}" && -n "${GPU_MODEL:-}" ]] || exit 1

case "$GPU_VENDOR:$GPU_FAMILY" in
    intel:uhd) WEBGL_VENDOR="Intel Inc." ;;
    intel:iris | intel:xe) WEBGL_VENDOR="Intel Open Source Technology Center" ;;
    amd:*) WEBGL_VENDOR="AMD" ;;
    nvidia:*) WEBGL_VENDOR="NVIDIA Corporation" ;;
    aspeed:*) WEBGL_VENDOR="ASPEED Technology, Inc." ;;
    matrox:*) WEBGL_VENDOR="Matrox Graphics Inc." ;;
    *) WEBGL_VENDOR="Mesa" ;;
esac

case "$GPU_VENDOR:$GPU_FAMILY" in
    intel:*)
        GPU_STACK="mesa"
        GL_VERSION="4.6"
        GLSL_VERSION="460"
        EXT_MASK="-GL_NV_shader_buffer_load"
        ;;
    amd:*)
        GPU_STACK="mesa-radv"
        GL_VERSION="4.6"
        GLSL_VERSION="460"
        EXT_MASK="-GL_NV_shader_buffer_load"
        ;;
    nvidia:*)
        GL_VERSION="4.6"
        GLSL_VERSION="460"
        EXT_MASK="-GL_ARB_parallel_shader_compile"
        if [[ -d /sys/module/nvidia ]] \
            && ldconfig -p 2>/dev/null | grep -q 'libGLX_nvidia\.so'; then
            GPU_STACK="nvidia"
        else
            GPU_STACK="mesa"
        fi
        ;;
    aspeed:* | matrox:*)
        GPU_STACK="mesa"
        GL_VERSION="3.1"
        GLSL_VERSION="140"
        EXT_MASK="-GL_ARB_tessellation_shader"
        ;;
    *)
        GPU_STACK="mesa"
        GL_VERSION="4.6"
        GLSL_VERSION="460"
        EXT_MASK="-GL_ARB_get_program_binary"
        ;;
esac

tmp=$(mktemp "$STATE_DIR/.gpu-env.XXXXXX")
chmod 0600 "$tmp"
{
    printf 'export MESA_GL_VERSION_OVERRIDE=%q\n' "$GL_VERSION"
    printf 'export MESA_GLSL_VERSION_OVERRIDE=%q\n' "$GLSL_VERSION"
    printf 'export MESA_EXTENSION_OVERRIDE=%q\n' "$EXT_MASK"
    printf 'export __GL_VENDOR=%q\n' "$WEBGL_VENDOR"
    printf 'export __GL_RENDERER_STRING=%q\n' "$GPU_MODEL"
    printf 'export MESA_VENDOR_OVERRIDE=%q\n' "$WEBGL_VENDOR"
    printf 'export MESA_RENDERER_OVERRIDE=%q\n' "$GPU_MODEL"
    if [[ "$GPU_STACK" == nvidia ]]; then
        printf 'export __GLX_VENDOR_LIBRARY_NAME=%q\n' nvidia
    fi
    printf 'export PH4NTXM_GPU_VENDOR=%q\n' "$GPU_VENDOR"
    printf 'export PH4NTXM_GPU_FAMILY=%q\n' "$GPU_FAMILY"
    printf 'export PH4NTXM_GPU_MODEL=%q\n' "$GPU_MODEL"
    printf 'export PH4NTXM_GPU_STACK=%q\n' "$GPU_STACK"
    printf 'export PH4NTXM_GL_VENDOR=%q\n' "$WEBGL_VENDOR"
    printf 'export PH4NTXM_GL_RENDERER=%q\n' "$GPU_MODEL"
    printf '%s\n' 'case ":${LD_PRELOAD:-}:" in *:/usr/local/lib/libph4ntxm-gl-spoof.so:*) ;; *) export LD_PRELOAD="/usr/local/lib/libph4ntxm-gl-spoof.so${LD_PRELOAD:+:$LD_PRELOAD}" ;; esac'
} >"$tmp"

chmod 0644 "$tmp"
mv -f "$tmp" "$GPU_ENV_FILE"

exit 0
