#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/run/ph4ntxm"
MODE_FILE="$STATE_DIR/mode"

if [[ ! -r "$MODE_FILE" ]]; then
    exit 1
fi

MODE="$(tr -d '\n' < "$MODE_FILE")"
case "$MODE" in
    linux|windows) ;;
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
    (( max > 0 )) || { echo 0; return; }
    echo $(( 16#$hash % max ))
}

declare -A GPU_MODELS=(
  [intel_uhd]="UHD Graphics 620|UHD Graphics 630|UHD Graphics 750"
  [intel_iris]="Iris Plus Graphics 655|Iris Xe Graphics"
  [amd_vega]="Radeon RX Vega 8|Radeon RX Vega 10"
  [amd_rdna]="Radeon RX 6600M|Radeon RX 6800M"
  [nvidia_gtx]="GeForce GTX 1050|GeForce GTX 1650"
  [nvidia_rtx]="GeForce RTX 3050|GeForce RTX 3060|GeForce RTX 3070"
  [nvidia_mx]="GeForce MX250|GeForce MX350|GeForce MX450"
  [apple_intel]="Intel Iris Plus Graphics 640|Intel Iris Plus Graphics 655"
  [apple_m1]="Apple M1"
  [apple_m2]="Apple M2"
  [aspeed_bmc]="ASPEED Graphics Family|Matrox G200e"
)

case "$VENDOR" in
    lenovo|dell|hp|asus|acer|msi|razer|fujitsu|toshiba|samsung|google|lg|microsoft|intel|ibm|origin)
    case "$FAMILY" in
        x3550|x3650)
            GPU_VENDOR="aspeed"; GPU_FAMILY="bmc"
        ;;
        thinkpad|latitude|elitebook|probook|expertbook|lifebook|portege|gram|surface|pixelbook|chromebook-pixel|pixel-slate|nuc|prodesk|elitedesk|eliteone|veriton|travelmate|business)
            biz_roll=$(seeded_random 100 "biz_gpu")
            if (( biz_roll < 85 )); then
                GPU_VENDOR="intel"; GPU_FAMILY="uhd"
            else
                GPU_VENDOR="intel"; GPU_FAMILY="iris"
            fi
        ;;
        ideapad|vivobook|swift|aspire|pavilion|inspiron|envy|notebook|flash|modern|prestige)
            case $(seeded_random 2 "gpu_mid") in
                0) GPU_VENDOR="intel"; GPU_FAMILY="uhd" ;;
                1) GPU_VENDOR="intel"; GPU_FAMILY="iris" ;;
            esac
        ;;
        legion|xps|precision|zbook|proart|tuf|rog|predator|stealth|titan|katana|gf63|blade|origin|omen|odyssey|nitro|ultra-gear|chronos|millennium|neuron|eon15|eon17|evo15)
            case $(seeded_random 3 "gpu_high") in
                0) GPU_VENDOR="nvidia"; GPU_FAMILY="rtx" ;;
                1) GPU_VENDOR="amd"; GPU_FAMILY="rdna" ;;
                2) GPU_VENDOR="intel"; GPU_FAMILY="iris" ;;
            esac
        ;;
        thinkcentre|optiplex|prodesk|elitedesk|veriton|thinkstation|nuc|macmini|mac-studio|imac)
            case $(seeded_random 2 "desktop_gpu") in
                0) GPU_VENDOR="intel"; GPU_FAMILY="uhd" ;;
                1) GPU_VENDOR="nvidia"; GPU_FAMILY="gtx" ;;
            esac
        ;;
        *)
            GPU_VENDOR="intel"
            GPU_FAMILY="uhd"
        ;;
    esac
;;
apple)
    GPU_VENDOR="apple"
    case "${SKU,,}" in
        *-m2*) GPU_FAMILY="m2" ;;
        *-m1*|*-16-2021*|*studio*) GPU_FAMILY="m1" ;;
        *) GPU_FAMILY="intel" ;;
    esac
;;
*)
    GPU_VENDOR="intel"
    GPU_FAMILY="uhd"
;;
esac

key="${GPU_VENDOR}_${GPU_FAMILY}"
IFS='|' read -ra models <<< "${GPU_MODELS[$key]:-}"

if (( ${#models[@]} == 0 )); then
    GPU_MODEL="Generic Renderer"
else
    idx=$(seeded_random ${#models[@]} "gpu_model")
    GPU_MODEL="${models[$idx]}"
    GPU_MODEL="$(echo "$GPU_MODEL" | sed 's/^ *//;s/ *$//')"
fi

unset GL_VERSION GLSL_VERSION GLES_VERSION EXT_MASK GPU_STACK

case "$GPU_VENDOR:$GPU_FAMILY" in
    intel:*)
        GPU_STACK="mesa"; GL_VERSION="4.6"; GLSL_VERSION="460"; EXT_MASK="-GL_NV_shader_buffer_load"
    ;;
    amd:*)
        GPU_STACK="mesa-radv"; GL_VERSION="4.6"; GLSL_VERSION="460"; EXT_MASK="-GL_NV_shader_buffer_load"
    ;;
    nvidia:*)
        GL_VERSION="4.6"; GLSL_VERSION="460"; EXT_MASK="-GL_ARB_parallel_shader_compile"
        if [[ -d /sys/module/nvidia ]] && \
           ldconfig -p 2>/dev/null | grep -q 'libGLX_nvidia\.so'; then
            GPU_STACK="nvidia"
        else
            GPU_STACK="mesa"
        fi
    ;;
    apple:intel)
        GPU_STACK="mesa"; GL_VERSION="4.1"; GLSL_VERSION="410"; EXT_MASK="-GL_ARB_tessellation_shader"
    ;;
    apple:*)
        GPU_STACK="mesa-asahi"; GL_VERSION="4.1"; GLSL_VERSION="410"; EXT_MASK="-GL_ARB_tessellation_shader"
    ;;
    aspeed:*)
        GPU_STACK="mesa"; GL_VERSION="3.1"; GLSL_VERSION="140"; EXT_MASK="-GL_ARB_tessellation_shader"
    ;;
esac

case "$GPU_VENDOR:$GPU_FAMILY" in
    intel:*)     GL_VENDOR_STR="Intel" ;;
    amd:*)       GL_VENDOR_STR="AMD" ;;
    nvidia:*)    GL_VENDOR_STR="NVIDIA Corporation" ;;
    apple:intel) GL_VENDOR_STR="Intel Inc." ;;
    apple:*)     GL_VENDOR_STR="Apple" ;;
    aspeed:*)    GL_VENDOR_STR="ASPEED Technology, Inc." ;;
    *)         GL_VENDOR_STR="Unknown" ;;
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
} > "$tmp"

chmod 0644 "$tmp"
mv -f "$tmp" "$GPU_ENV_FILE"

exit 0
