#!/usr/bin/env bash
set -euo pipefail

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
GPU_ENV_FILE="$STATE_DIR/gpu_env"

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

rand_range() {
    local min=$1 max=$2 salt="$3"
    local r
    r=$(rand "$salt")
    echo $(( min + (r % (max - min + 1)) ))
}

pick() {
    local salt="$1"; shift
    local arr=("$@")
    local idx
    idx=$(rand_range 0 $((${#arr[@]} - 1)) "$salt")
    echo "${arr[$idx]}"
}

PRODUCT_FILE="$STATE_DIR/fake_dmi/product_name"
PRODUCT_NAME=$(cat "$PRODUCT_FILE" 2>/dev/null || echo "")

DEVICE_CLASS="generic"
[[ -z "$PRODUCT_NAME" ]] && DEVICE_CLASS="generic"
case "$PRODUCT_NAME" in
    *EliteOne*|*Surface\ Studio*|*LG\ All-in-One*)
        DEVICE_CLASS="desktop"
        ;;
    *ThinkPad*|*Latitude*|*EliteBook*|*ProBook*|*ExpertBook*|*Lifebook*|*Portege*|*Tecra*|*Dynabook*|*TravelMate*|*VAIO*)
        DEVICE_CLASS="business"
        ;;
    *XPS*|*ZenBook*|*Yoga*|*ProArt*|*Surface*|*Gram*|*Prestige*|*Summit*|*Razer\ Book*|*Pixelbook*|*Pixel\ Slate*)
        DEVICE_CLASS="ultrabook"
        ;;
    *Legion*|*TUF*|*Predator*|*ROG*|*Blade*|*Nitro*|*OMEN*|*Odyssey*|*Katana*|*GF63*|*Titan*|*Stealth*|*UltraGear*|*EON15*|*EON17*|*EVO15*)
        DEVICE_CLASS="gaming"
        ;;
    *IdeaPad*|*VivoBook*|*Aspire*|*Pavilion*|*Inspiron*|*Envy*|*Galaxy\ Book*|*Notebook*|*Satellite*|*Chromebook*|*Flash*)
        DEVICE_CLASS="consumer"
        ;;
    *MacBookPro16,1*|*iMac20,1*|*Macmini8,1*)
        DEVICE_CLASS="apple"
        ;;
    *ThinkCentre*|*IdeaCentre*|*OptiPlex*|*ProDesk*|*EliteDesk*|*Veriton*|*Esprimo*|*NUC*|*ThinkStation*|*Chronos*|*Millennium*|*Neuron*|*M-Class*)
        DEVICE_CLASS="desktop"
        ;;
    *System\ x\ Server*)
        DEVICE_CLASS="server"
        ;;
esac

SYS_VENDOR_FILE="$STATE_DIR/fake_dmi/sys_vendor"
SYS_VENDOR=$(cat "$SYS_VENDOR_FILE" 2>/dev/null || echo "Generic")

case "$SYS_VENDOR" in
    "Apple Inc.")
        case "$PRODUCT_NAME" in
            MacBookPro16,1|iMac20,1) GPU_ALLOWED=("amd") ;;
            Macmini8,1) GPU_ALLOWED=("intel") ;;
            *) exit 1 ;;
        esac
        ;;
    *)
        GPU_ALLOWED=("intel" "amd" "nvidia")
        ;;
esac

case "$DEVICE_CLASS" in
    business)
        GPU_ALLOWED=("intel" "intel" "amd")
        ;;
    ultrabook)
        GPU_ALLOWED=("intel")
        ;;
    gaming)
        GPU_ALLOWED=("nvidia" "nvidia" "amd")
        ;;
    consumer)
        GPU_ALLOWED=("intel" "amd")
        ;;
    apple)
        case "$PRODUCT_NAME" in
            MacBookPro16,1|iMac20,1) GPU_ALLOWED=("amd") ;;
            Macmini8,1) GPU_ALLOWED=("intel") ;;
            *) exit 1 ;;
        esac
        ;;
    desktop)
        GPU_ALLOWED=("intel" "intel" "nvidia")
        ;;
    server)
        GPU_ALLOWED=("aspeed")
        ;;
esac

GPU_VENDOR=$(pick "gpu-vendor" "${GPU_ALLOWED[@]}")

GPU_MODELS_intel_uhd=("UHD Graphics 620" "UHD Graphics 630" "UHD Graphics 750")
GPU_MODELS_intel_iris=("Iris Plus Graphics 655" "Iris Xe Graphics")
GPU_MODELS_intel_xe=("Iris Xe Graphics" "Iris Xe")
GPU_MODELS_intel_applemini=("UHD Graphics 630")
GPU_MODELS_amd_vega=("Radeon RX Vega 8" "Radeon RX Vega 10")
GPU_MODELS_amd_rdna=("Radeon RX 6600M" "Radeon RX 6800M")
GPU_MODELS_amd_macbook=("Radeon Pro 5300M" "Radeon Pro 5500M")
GPU_MODELS_amd_imac=("Radeon Pro 5300" "Radeon Pro 5500 XT" "Radeon Pro 5700")
GPU_MODELS_nvidia_gtx=("GeForce GTX 1050" "GeForce GTX 1650")
GPU_MODELS_nvidia_rtx=("GeForce RTX 3050" "GeForce RTX 3060" "GeForce RTX 3070")
GPU_MODELS_aspeed_bmc=("ASPEED Graphics Family" "Matrox G200e")

case "$GPU_VENDOR:$DEVICE_CLASS" in
    intel:apple)
        GPU_FAMILY="applemini"
        ;;
    amd:apple)
        case "$PRODUCT_NAME" in
            MacBookPro16,1) GPU_FAMILY="macbook" ;;
            iMac20,1) GPU_FAMILY="imac" ;;
            *) exit 1 ;;
        esac
        ;;
    intel:*)
        GPU_FAMILY=$(pick "gpu-family" uhd iris xe)
        ;;
    nvidia:gaming)
        GPU_FAMILY=$(pick "gpu-family" gtx rtx)
        ;;
    nvidia:*)
        GPU_FAMILY="gtx"
        ;;
    amd:gaming)
        GPU_FAMILY="rdna"
        ;;
    amd:*)
        GPU_FAMILY="vega"
        ;;
    aspeed:*)
        GPU_FAMILY="bmc"
        ;;
    *)
        GPU_FAMILY="generic"
        ;;
esac

models_var="GPU_MODELS_${GPU_VENDOR}_${GPU_FAMILY}[@]"
models=("${!models_var}")

if [[ ${#models[@]} -eq 0 ]]; then
    GPU_MODEL="Generic Renderer"
else
    GPU_MODEL=$(pick "gpu-model-$GPU_VENDOR-$GPU_FAMILY" "${models[@]}")
fi

case "$GPU_VENDOR:$GPU_FAMILY" in
    intel:uhd) WEBGL_VENDOR="Intel Inc." ;;
    intel:iris|intel:xe) WEBGL_VENDOR="Intel Open Source Technology Center" ;;
    amd:*) WEBGL_VENDOR="AMD" ;;
    nvidia:*) WEBGL_VENDOR="NVIDIA Corporation" ;;
    aspeed:*) WEBGL_VENDOR="ASPEED Technology, Inc." ;;
    *) WEBGL_VENDOR="Mesa" ;;
esac

case "$GPU_VENDOR:$GPU_FAMILY" in
    intel:*)
        GPU_STACK="mesa"; GL_VERSION="4.6"; GLSL_VERSION="460"; EXT_MASK="-GL_NV_shader_buffer_load"
    ;;
    amd:*)
        GPU_STACK="mesa-radv"; GL_VERSION="4.6"; GLSL_VERSION="460"; EXT_MASK="-GL_NV_shader_buffer_load"
    ;;
    nvidia:*)
        GL_VERSION="4.6"
        GLSL_VERSION="460"
        EXT_MASK="-GL_ARB_parallel_shader_compile"
        if [[ "$DEVICE_CLASS" == "gaming" && -d /sys/module/nvidia ]] && \
           ldconfig -p 2>/dev/null | grep -q 'libGLX_nvidia\.so'; then
            GPU_STACK="nvidia"
        else
            GPU_STACK="mesa"
        fi
    ;;
    aspeed:*)
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
} > "$tmp"

chmod 0644 "$tmp"
mv -f "$tmp" "$GPU_ENV_FILE"

exit 0
