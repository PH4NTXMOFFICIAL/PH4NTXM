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
case "$MODE" in
    linux | windows) ;;
    lonewolf) exit 0 ;;
    *) exit 1 ;;
esac

HARDWARE_PROFILE_FILE="$STATE_DIR/hardware_profile"
PERSONA_SEED_FILE="$STATE_DIR/persona_seed"
GPU_ENV_FILE="$STATE_DIR/gpu_env"

[[ -r "$HARDWARE_PROFILE_FILE" ]] || exit 1
[[ -s "$PERSONA_SEED_FILE" ]] || exit 1

source "$HARDWARE_PROFILE_FILE"
SEED=$(cat "$PERSONA_SEED_FILE")

seeded_random() {
    local max=$1 salt=${2:-default}
    local hash=$(printf "%s%s" "$SEED" "$salt" | sha256sum | cut -c1-8)
    ((max > 0)) || {
        echo 0
        return
    }
    echo $((16#$hash % max))
}

[[ -n "${PROFILE_ID:-}" && -n "${GPU_MODEL:-}" ]] || exit 1

unset GL_VERSION GLSL_VERSION GLES_VERSION EXT_MASK GPU_STACK

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
    apple:intel)
        GPU_STACK="mesa"
        GL_VERSION="4.1"
        GLSL_VERSION="410"
        EXT_MASK="-GL_ARB_tessellation_shader"
        ;;
    apple:*)
        GPU_STACK="mesa-asahi"
        GL_VERSION="4.1"
        GLSL_VERSION="410"
        EXT_MASK="-GL_ARB_tessellation_shader"
        ;;
    aspeed:* | matrox:*)
        GPU_STACK="mesa"
        GL_VERSION="3.1"
        GLSL_VERSION="140"
        EXT_MASK="-GL_ARB_tessellation_shader"
        ;;
esac

case "$GPU_VENDOR:$GPU_FAMILY" in
    intel:*) GL_VENDOR_STR="Intel" ;;
    amd:*) GL_VENDOR_STR="AMD" ;;
    nvidia:*) GL_VENDOR_STR="NVIDIA Corporation" ;;
    apple:intel) GL_VENDOR_STR="Intel Inc." ;;
    apple:*) GL_VENDOR_STR="Apple" ;;
    aspeed:*) GL_VENDOR_STR="ASPEED Technology, Inc." ;;
    matrox:*) GL_VENDOR_STR="Matrox Graphics Inc." ;;
    *) GL_VENDOR_STR="Unknown" ;;
esac

case $(seeded_random 2 "extmask") in
    0) BASE_EXT="-GL_ARB_get_program_binary" ;;
    1) BASE_EXT="-GL_EXT_framebuffer_object" ;;
esac

tmp=$(mktemp "$STATE_DIR/.gpu-env.XXXXXX")
chmod 0600 "$tmp"
{
    if [[ "$GPU_STACK" == nvidia ]]; then
        printf 'export __GLX_VENDOR_LIBRARY_NAME=%q\n' nvidia
        printf 'export __GL_VENDOR=%q\n' "$GL_VENDOR_STR"
        printf 'export __GL_RENDERER_STRING=%q\n' "$GPU_MODEL"
    else
        [[ -n "${GL_VERSION:-}" ]] && printf 'export MESA_GL_VERSION_OVERRIDE=%q\n' "$GL_VERSION"
        [[ -n "${GLSL_VERSION:-}" ]] && printf 'export MESA_GLSL_VERSION_OVERRIDE=%q\n' "$GLSL_VERSION"
        [[ -n "${GLES_VERSION:-}" ]] && printf 'export MESA_GLES_VERSION_OVERRIDE=%q\n' "$GLES_VERSION"
        printf 'export MESA_EXTENSION_OVERRIDE=%q\n' "$EXT_MASK $BASE_EXT"
        printf 'export MESA_VENDOR_OVERRIDE=%q\n' "$GL_VENDOR_STR"
        printf 'export MESA_RENDERER_OVERRIDE=%q\n' "$GPU_MODEL"
    fi

    printf 'export PH4NTXM_GPU_VENDOR=%q\n' "$GPU_VENDOR"
    printf 'export PH4NTXM_GPU_FAMILY=%q\n' "$GPU_FAMILY"
    printf 'export PH4NTXM_GPU_MODEL=%q\n' "$GPU_MODEL"
    printf 'export PH4NTXM_GPU_STACK=%q\n' "$GPU_STACK"
    printf 'export PH4NTXM_GL_VENDOR=%q\n' "$GL_VENDOR_STR"
    printf 'export PH4NTXM_GL_RENDERER=%q\n' "$GPU_MODEL"
    printf '%s\n' 'case ":${LD_PRELOAD:-}:" in *:/usr/local/lib/libph4ntxm-gl-spoof.so:*) ;; *) export LD_PRELOAD="/usr/local/lib/libph4ntxm-gl-spoof.so${LD_PRELOAD:+:$LD_PRELOAD}" ;; esac'
} >"$tmp"

chmod 0644 "$tmp"
mv -f "$tmp" "$GPU_ENV_FILE"

exit 0
