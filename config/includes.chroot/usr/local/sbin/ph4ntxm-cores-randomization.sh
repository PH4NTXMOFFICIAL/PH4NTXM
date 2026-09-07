#!/usr/bin/env bash
set -euo pipefail

STATE_DIR="/run/ph4ntxm"
OUT="$STATE_DIR/cores_env"

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

[[ -r "$STATE_DIR/hardware_profile" ]] || exit 1
[[ -s "$STATE_DIR/persona_seed" ]] || exit 1
source "$STATE_DIR/hardware_profile"
SEED=$(cat "$STATE_DIR/persona_seed")

seeded_random() {
    local max=$1 salt=${2:-default}
    local hash=$(printf "%s%s" "$SEED" "$salt" | sha256sum | cut -c1-8)
    echo $(( 16#$hash % max ))
}

detect_era() {
    local s="${1,,}"

    if [[ "$s" =~ (m1|m2|macstudio) ]]; then
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
PH4_CPU_ARCHITECTURE="x86_64"

case "$FAMILY" in
    thinkpad|ideapad|yoga|xps|latitude|precision|inspiron|elitebook|probook|zbook|pavilion|envy|zenbook|vivobook|expertbook|chromebook|proart|swift|aspire|travelmate|galaxybook|notebook|flash|gram|surface|lifebook|satellite|portege|tecra|dynabook|modern|prestige|summit|blade|book|vaio|pixelbook|chromebook-pixel|pixel-slate|macbook)
        DEVICE_CLASS="laptop" ;;
    legion|rog|tuf|predator|nitro|omen|stealth|titan|katana|gf63|odyssey|ultra-gear|eon15|eon17|evo15)
        DEVICE_CLASS="gaming" ;;
    x3550|x3650)
        DEVICE_CLASS="server" ;;
    *)
        DEVICE_CLASS="desktop" ;;
esac

    case "$FAMILY" in
        thinkpad|latitude|elitebook|probook|lifebook|portege|expertbook|macbook|surface|zenbook|xps|gram|thinkcentre|ideacentre|optiplex|elitedesk|eliteone|prodesk|veriton|esprimo|allinone|travelmate|summit|envy|modern|prestige|imac|macmini)
            BASE_CORES=8; BASE_RAM=16 ;;
        legion|rog|tuf|predator|blade|stealth|titan|zbook|precision|proart|omen|origin|nitro|odyssey|katana|gf63|ultra-gear|mac-studio|thinkstation|chronos|millennium|neuron|eon15|eon17|evo15|x3550|x3650)
            BASE_CORES=12; BASE_RAM=32 ;;
        *)
            BASE_CORES=4; BASE_RAM=8 ;;
    esac

    case "${SKU,,}" in
        *x1-carbon*|*xps-13*|*zenbook*|*gram*|*surface*) BASE_CORES=8; BASE_RAM=16 ;;
        *xps-15*|*blade*|*titan*|*zbook*|*legion*|*predator*|*origin*|*omen*|*studio*) BASE_CORES=12; BASE_RAM=32 ;;
        *ideapad*|*aspire*|*vivobook*|*inspiron*|*flash*) BASE_CORES=4; BASE_RAM=8 ;;
        *nuc*|*mini*) BASE_CORES=8; BASE_RAM=16 ;;
    esac

    case "$ERA" in
        old) MAX_CORES=$(( BASE_CORES / 2 )); MAX_RAM=$(( BASE_RAM / 2 )) ;;
        mid|new) MAX_CORES=$BASE_CORES; MAX_RAM=$BASE_RAM ;;
    esac
    JITTER=$(seeded_random 2 "jitter")
    FINAL_CORES=$(( MAX_CORES - (JITTER * 2) ))

if [[ -x /usr/bin/nproc-real ]]; then
    REAL_CORES=$(/usr/bin/nproc-real --all)
else
    REAL_CORES=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
fi
[[ "$REAL_CORES" =~ ^[0-9]+$ ]] || REAL_CORES=1
(( REAL_CORES < 1 )) && REAL_CORES=1
(( FINAL_CORES > REAL_CORES )) && FINAL_CORES=$REAL_CORES
(( FINAL_CORES < 1 )) && FINAL_CORES=1

REAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
REAL_RAM_GB=$(( REAL_RAM_KB / 1024 / 1024 ))
(( REAL_RAM_GB < 1 )) && REAL_RAM_GB=1
TEMP_RAM=$(( MAX_RAM > REAL_RAM_GB ? REAL_RAM_GB : MAX_RAM ))

    if   (( TEMP_RAM >= 64 )); then FINAL_RAM=64
    elif (( TEMP_RAM >= 32 )); then FINAL_RAM=32
    elif (( TEMP_RAM >= 16 )); then FINAL_RAM=16
    elif (( TEMP_RAM >= 8 ));  then FINAL_RAM=8
    elif (( TEMP_RAM >= 4 ));  then FINAL_RAM=4
    elif (( TEMP_RAM >= 2 ));  then FINAL_RAM=2
    else FINAL_RAM=1; fi

if [[ "$VENDOR" == "apple" ]]; then
    case "${SKU,,}" in
        *-m2*)
            PH4_CPU_ARCHITECTURE="aarch64"
            PH4_CPU_VENDOR_ID="Apple"
            PH4_CPU_FAMILY=8
            PH4_CPU_MODEL_ID=2
            PH4_CPU_STEPPING=0
            PH4_CPU_MODEL_NAME="Apple M2"
            ;;
        *-m1*|*-16-2021*|*studio*)
            PH4_CPU_ARCHITECTURE="aarch64"
            PH4_CPU_VENDOR_ID="Apple"
            PH4_CPU_FAMILY=8
            PH4_CPU_MODEL_ID=1
            PH4_CPU_STEPPING=0
            PH4_CPU_MODEL_NAME="Apple M1"
            ;;
        *)
            PH4_CPU_VENDOR_ID="GenuineIntel"
            PH4_CPU_FAMILY=6
            PH4_CPU_STEPPING=10
            case "$FAMILY" in
                macbook)
                    PH4_CPU_MODEL_ID=158
                    PH4_CPU_MODEL_NAME="Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz"
                    ;;
                imac)
                    PH4_CPU_MODEL_ID=165
                    PH4_CPU_STEPPING=5
                    PH4_CPU_MODEL_NAME="Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz"
                    ;;
                macmini)
                    PH4_CPU_MODEL_ID=158
                    PH4_CPU_MODEL_NAME="Intel(R) Core(TM) i7-8700B CPU @ 3.20GHz"
                    ;;
                *)
                    PH4_CPU_MODEL_ID=142
                    PH4_CPU_MODEL_NAME="Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz"
                    ;;
            esac
            ;;
    esac
elif [[ "$FAMILY" =~ ^(x3550|x3650)$ ]]; then
    PH4_CPU_VENDOR_ID="GenuineIntel"
    PH4_CPU_FAMILY=6
    PH4_CPU_MODEL_ID=79
    PH4_CPU_STEPPING=1
    PH4_CPU_MODEL_NAME="Intel(R) Xeon(R) CPU E5-2690 v4 @ 2.60GHz"
elif [[ "$VENDOR" =~ ^(intel|microsoft|sony|google)$ ]] || \
     (( $(seeded_random 100 "cpu-vendor") < 65 )); then
    PH4_CPU_VENDOR_ID="GenuineIntel"
    case "$ERA" in
        old)
            PH4_CPU_FAMILY=6; PH4_CPU_MODEL_ID=42; PH4_CPU_STEPPING=7
            PH4_CPU_MODEL_NAME="Intel(R) Core(TM) i5-2520M CPU @ 2.50GHz"
            ;;
        new)
            PH4_CPU_FAMILY=6; PH4_CPU_MODEL_ID=140; PH4_CPU_STEPPING=1
            PH4_CPU_MODEL_NAME="11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz"
            ;;
        *)
            PH4_CPU_FAMILY=6; PH4_CPU_MODEL_ID=142; PH4_CPU_STEPPING=10
            PH4_CPU_MODEL_NAME="Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz"
            ;;
    esac
else
    PH4_CPU_VENDOR_ID="AuthenticAMD"
    case "$ERA" in
        old)
            PH4_CPU_FAMILY=21; PH4_CPU_MODEL_ID=16; PH4_CPU_STEPPING=1
            PH4_CPU_MODEL_NAME="AMD A10-5800K APU with Radeon(tm) HD Graphics"
            ;;
        new)
            PH4_CPU_FAMILY=25; PH4_CPU_MODEL_ID=80; PH4_CPU_STEPPING=0
            PH4_CPU_MODEL_NAME="AMD Ryzen 7 5800U with Radeon Graphics"
            ;;
        *)
            PH4_CPU_FAMILY=23; PH4_CPU_MODEL_ID=24; PH4_CPU_STEPPING=1
            PH4_CPU_MODEL_NAME="AMD Ryzen 5 3500U with Radeon Vega Mobile Gfx"
            ;;
    esac
fi

if [[ "$PH4_CPU_ARCHITECTURE" == "aarch64" ]]; then
    PH4_THREADS_PER_CORE=1
    PH4_CPU_FLAGS="fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp"
elif (( FINAL_CORES >= 4 && FINAL_CORES % 2 == 0 )); then
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
