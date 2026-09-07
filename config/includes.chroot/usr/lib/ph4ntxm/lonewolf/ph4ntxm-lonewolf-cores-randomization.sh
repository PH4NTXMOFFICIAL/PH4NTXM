#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/run/ph4ntxm"
OUT="$STATE_DIR/cores_env"
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

[[ -s "$SEED_FILE" ]] || exit 1
[[ -s "$JITTER_FILE" ]] || exit 1

SEED=$(tr -d '\n' < "$SEED_FILE")
JITTER=$(tr -d '\n' < "$JITTER_FILE")
[[ "$SEED" =~ ^[0-9a-f]{64}$ ]] || exit 1
[[ "$JITTER" =~ ^[0-9a-f]{16}$ ]] || exit 1

seeded_random() {
    local max=${1:-1} salt=${2:-default}
    local hash val
    hash=$(printf "%s%s%s" "$SEED" "$JITTER" "$salt" | sha256sum | cut -c1-8)
    [[ "$hash" =~ ^[0-9a-f]{8}$ ]] || exit 1
    (( max > 0 )) || max=1
    val=$((16#$hash % max))
    echo "$val"
}

PRODUCT_FILE="$STATE_DIR/fake_dmi/product_name"
SKU=$(cat "$PRODUCT_FILE" 2>/dev/null || echo "Generic-PC")
[[ -n "$SKU" ]] || SKU="Generic-PC"

detect_era() {
    local s="${1,,}"

    if [[ "$s" =~ (m1|m2|macstudio|mac13|mac14|macbookpro17|macmini9) ]]; then
        echo "new"
    elif [[ "$s" =~ (2020|2021|2022|2023|2024|2025|2026|g7|g8|g9) ]]; then
        echo "new"
    elif [[ "$s" =~ (t460|t470|t480|9300|2016|2017|2018|2019) ]]; then
        echo "mid"
    elif [[ "$s" =~ (x220|x230|t420|t430|2012|2013|2014) ]]; then
        echo "old"
    else
        echo "mid"
    fi
}

ERA=$(detect_era "$SKU")
DEVICE_CLASS="generic"
PH4_CPU_ARCHITECTURE="x86_64"

case "$SKU" in
    *EliteOne*|*Surface\ Studio*|*LG\ All-in-One*)
        DEVICE_CLASS="desktop"
        BASE_CORES=8; BASE_RAM=16
        ;;
    *ThinkPad*|*Latitude*|*EliteBook*|*ProBook*|*ExpertBook*|*Lifebook*|*Portege*|*Tecra*|*Dynabook*|*TravelMate*|*VAIO*)
        DEVICE_CLASS="business"
        BASE_CORES=8; BASE_RAM=16
        ;;
    *XPS*|*ZenBook*|*Yoga*|*ProArt*|*Surface*|*Gram*|*Prestige*|*Summit*|*Razer\ Book*|*Pixelbook*|*Pixel\ Slate*)
        DEVICE_CLASS="ultrabook"
        BASE_CORES=8; BASE_RAM=16
        ;;
    *Legion*|*ROG*|*TUF*|*Predator*|*Blade*|*Titan*|*Stealth*|*Nitro*|*OMEN*|*Odyssey*|*Katana*|*GF63*|*UltraGear*|*EON15*|*EON17*|*EVO15*)
        DEVICE_CLASS="gaming"
        BASE_CORES=12; BASE_RAM=32
        ;;
    *IdeaPad*|*VivoBook*|*Aspire*|*Swift*|*Pavilion*|*Inspiron*|*Galaxy\ Book*|*Notebook*|*Satellite*|*Flash*|*Chromebook*)
        DEVICE_CLASS="consumer"
        BASE_CORES=4; BASE_RAM=8
        ;;
    *MacBookPro16,1*|*iMac20,1*|*Macmini8,1*)
        DEVICE_CLASS="apple"
        BASE_CORES=8; BASE_RAM=16
        ;;
    *ThinkCentre*|*IdeaCentre*|*OptiPlex*|*ProDesk*|*EliteDesk*|*Veriton*|*Esprimo*|*NUC*|*ThinkStation*|*Chronos*|*Millennium*|*Neuron*|*M-Class*)
        DEVICE_CLASS="desktop"
        BASE_CORES=8; BASE_RAM=16
        ;;
    *System\ x\ Server*)
        DEVICE_CLASS="server"
        BASE_CORES=12; BASE_RAM=32
        ;;
    *)
        DEVICE_CLASS="generic"
        BASE_CORES=4; BASE_RAM=8
        ;;
esac

case "$DEVICE_CLASS" in
    business)
        MIN_CORES=4; MAX_CORES=8; RAM_ALLOWED=(8 16 32)
        ;;
    ultrabook)
        MIN_CORES=4; MAX_CORES=8; RAM_ALLOWED=(8 16)
        ;;
    gaming)
        MIN_CORES=8; MAX_CORES=16; RAM_ALLOWED=(16 32)
        ;;
    consumer)
        MIN_CORES=2; MAX_CORES=6; RAM_ALLOWED=(4 8 16)
        ;;
    apple)
        case "$SKU" in
            MacBookPro16,1) MIN_CORES=6; MAX_CORES=6; RAM_ALLOWED=(16 32) ;;
            iMac20,1) MIN_CORES=8; MAX_CORES=8; RAM_ALLOWED=(16 32 64) ;;
            Macmini8,1) MIN_CORES=6; MAX_CORES=6; RAM_ALLOWED=(8 16 32) ;;
            *) exit 1 ;;
        esac
        ;;
    desktop)
        MIN_CORES=4; MAX_CORES=12; RAM_ALLOWED=(8 16 32)
        ;;
    server)
        MIN_CORES=8; MAX_CORES=16; RAM_ALLOWED=(16 32 64)
        ;;
    *)
        MIN_CORES=2; MAX_CORES=6; RAM_ALLOWED=(4 8 16)
        ;;
esac

case "$ERA" in
    old)
        MAX_CORES=$(( MAX_CORES / 2 ))
        ;;
esac

(( MAX_CORES < MIN_CORES )) && MIN_CORES=$MAX_CORES

[[ "$MIN_CORES" =~ ^[0-9]+$ ]] || MIN_CORES=2
[[ "$MAX_CORES" =~ ^[0-9]+$ ]] || MAX_CORES=4

RANGE=$(( MAX_CORES - MIN_CORES + 1 ))
core_offset=$(seeded_random "$RANGE" "cores")
FINAL_CORES=$(( MIN_CORES + core_offset ))

if [[ -x /usr/bin/nproc-real ]]; then
    REAL_CORES=$(/usr/bin/nproc-real --all)
else
    REAL_CORES=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
fi
[[ "$REAL_CORES" =~ ^[0-9]+$ ]] || REAL_CORES=1
(( REAL_CORES < 1 )) && REAL_CORES=1
(( FINAL_CORES > REAL_CORES )) && FINAL_CORES=$REAL_CORES
(( FINAL_CORES < 1 )) && FINAL_CORES=1

REAL_RAM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null)
[[ "$REAL_RAM_KB" =~ ^[0-9]+$ ]] || REAL_RAM_KB=0

REAL_RAM_GB=$(( REAL_RAM_KB / 1024 / 1024 ))
(( REAL_RAM_GB <= 0 )) && REAL_RAM_GB=1

RAM_PICK=$(seeded_random "${#RAM_ALLOWED[@]}" "ram")
FINAL_RAM=${RAM_ALLOWED[$RAM_PICK]}

if (( FINAL_RAM > REAL_RAM_GB )); then
    FINAL_RAM=$REAL_RAM_GB
fi

if   (( FINAL_RAM >= 64 )); then FINAL_RAM=64
elif (( FINAL_RAM >= 32 )); then FINAL_RAM=32
elif (( FINAL_RAM >= 16 )); then FINAL_RAM=16
elif (( FINAL_RAM >= 8 ));  then FINAL_RAM=8
elif (( FINAL_RAM >= 4 ));  then FINAL_RAM=4
elif (( FINAL_RAM >= 2 ));  then FINAL_RAM=2
else FINAL_RAM=1
fi

(( FINAL_RAM > REAL_RAM_GB )) && FINAL_RAM=$REAL_RAM_GB
(( FINAL_RAM < 1 )) && FINAL_RAM=1

SYS_VENDOR=$(cat "$STATE_DIR/fake_dmi/sys_vendor" 2>/dev/null || echo Generic)
if [[ "$SYS_VENDOR" == "Apple Inc." ]]; then
    case "$SKU" in
        MacBookPro16,1)
            PH4_CPU_VENDOR_ID="GenuineIntel"
            PH4_CPU_FAMILY=6
            PH4_CPU_STEPPING=10
            PH4_CPU_MODEL_ID=158
            PH4_CPU_MODEL_NAME="Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz"
            ;;
        iMac20,1)
            PH4_CPU_VENDOR_ID="GenuineIntel"
            PH4_CPU_FAMILY=6
            PH4_CPU_MODEL_ID=165
            PH4_CPU_STEPPING=5
            PH4_CPU_MODEL_NAME="Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz"
            ;;
        Macmini8,1)
            PH4_CPU_VENDOR_ID="GenuineIntel"
            PH4_CPU_FAMILY=6
            PH4_CPU_STEPPING=10
            PH4_CPU_MODEL_ID=158
            PH4_CPU_MODEL_NAME="Intel(R) Core(TM) i7-8700B CPU @ 3.20GHz"
            ;;
        *)
            PH4_CPU_VENDOR_ID="GenuineIntel"
            PH4_CPU_FAMILY=6
            PH4_CPU_STEPPING=10
            PH4_CPU_MODEL_ID=142
            PH4_CPU_MODEL_NAME="Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz"
            ;;
    esac
elif [[ "$DEVICE_CLASS" == "server" ]]; then
    PH4_CPU_VENDOR_ID="GenuineIntel"
    PH4_CPU_FAMILY=6
    PH4_CPU_MODEL_ID=79
    PH4_CPU_STEPPING=1
    PH4_CPU_MODEL_NAME="Intel(R) Xeon(R) CPU E5-2690 v4 @ 2.60GHz"
elif [[ "$SYS_VENDOR" =~ ^(Intel|Microsoft|Sony|Google) ]] || \
     (( $(seeded_random 100 "cpu-vendor") < 65 )); then
    PH4_CPU_VENDOR_ID="GenuineIntel"
    case "$ERA" in
        old)
            PH4_CPU_FAMILY=6; PH4_CPU_MODEL_ID=42; PH4_CPU_STEPPING=7
            PH4_CPU_MODEL_NAME="Intel(R) Core(TM) i5-2520M CPU @ 2.50GHz" ;;
        new)
            PH4_CPU_FAMILY=6; PH4_CPU_MODEL_ID=140; PH4_CPU_STEPPING=1
            PH4_CPU_MODEL_NAME="11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz" ;;
        *)
            PH4_CPU_FAMILY=6; PH4_CPU_MODEL_ID=142; PH4_CPU_STEPPING=10
            PH4_CPU_MODEL_NAME="Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz" ;;
    esac
else
    PH4_CPU_VENDOR_ID="AuthenticAMD"
    case "$ERA" in
        old)
            PH4_CPU_FAMILY=21; PH4_CPU_MODEL_ID=16; PH4_CPU_STEPPING=1
            PH4_CPU_MODEL_NAME="AMD A10-5800K APU with Radeon(tm) HD Graphics" ;;
        new)
            PH4_CPU_FAMILY=25; PH4_CPU_MODEL_ID=80; PH4_CPU_STEPPING=0
            PH4_CPU_MODEL_NAME="AMD Ryzen 7 5800U with Radeon Graphics" ;;
        *)
            PH4_CPU_FAMILY=23; PH4_CPU_MODEL_ID=24; PH4_CPU_STEPPING=1
            PH4_CPU_MODEL_NAME="AMD Ryzen 5 3500U with Radeon Vega Mobile Gfx" ;;
    esac
fi

if (( FINAL_CORES >= 4 && FINAL_CORES % 2 == 0 )); then
    PH4_THREADS_PER_CORE=2
    PH4_CPU_FLAGS="fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht tm pbe syscall nx rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid pni pclmulqdq ssse3 cx16 sse4_1 sse4_2 x2apic popcnt aes xsave avx f16c rdrand hypervisor"
else
    PH4_THREADS_PER_CORE=1
    PH4_CPU_FLAGS="fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht tm pbe syscall nx rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid pni pclmulqdq ssse3 cx16 sse4_1 sse4_2 x2apic popcnt aes xsave avx f16c rdrand hypervisor"
fi

tmp=$(mktemp "$STATE_DIR/.cores-env.XXXXXX")
chmod 0600 "$tmp"
{
    printf 'export PH4_REPORTED_CORES=%q\n' "$FINAL_CORES"
    printf 'export PH4_REPORTED_RAM=%q\n' "$FINAL_RAM"
    printf 'export PH4_HARDWARE_MODEL=%q\n' "$SKU"
    printf 'export PH4_HARDWARE_ERA=%q\n' "$ERA"
    printf 'export PH4_DEVICE_CLASS=%q\n' "$DEVICE_CLASS"
    printf 'export PH4_CPU_ARCHITECTURE=%q\n' "$PH4_CPU_ARCHITECTURE"
    printf 'export PH4_CPU_VENDOR_ID=%q\n' "$PH4_CPU_VENDOR_ID"
    printf 'export PH4_CPU_FAMILY=%q\n' "$PH4_CPU_FAMILY"
    printf 'export PH4_CPU_MODEL_ID=%q\n' "$PH4_CPU_MODEL_ID"
    printf 'export PH4_CPU_STEPPING=%q\n' "$PH4_CPU_STEPPING"
    printf 'export PH4_CPU_MODEL_NAME=%q\n' "$PH4_CPU_MODEL_NAME"
    printf 'export PH4_THREADS_PER_CORE=%q\n' "$PH4_THREADS_PER_CORE"
    printf 'export PH4_CPU_FLAGS=%q\n' "$PH4_CPU_FLAGS"
} > "$tmp"

chmod 0644 "$tmp"
mv -f "$tmp" "$OUT"

exit 0
