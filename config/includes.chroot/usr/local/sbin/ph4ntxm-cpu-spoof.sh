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

[[ -r "$STATE_DIR/cores_env" ]] || exit 1
[[ -s "$STATE_DIR/persona_seed" ]] || exit 1
source "$STATE_DIR/cores_env"
[[ "${PH4_REPORTED_CORES:-}" =~ ^[1-9][0-9]*$ ]] || exit 1
RANDOM=$((16#$(printf '%s%s' "$(cat "$STATE_DIR/persona_seed")" cpuinfo | sha256sum | cut -c1-4) & 32767))

FAKE_CPUINFO="$STATE_DIR/fake_cpuinfo"
: > "$FAKE_CPUINFO"

MODEL="${PH4_CPU_MODEL_NAME:-Generic x86_64 CPU}"
CPU_ARCHITECTURE="${PH4_CPU_ARCHITECTURE:-x86_64}"
VENDOR_ID="${PH4_CPU_VENDOR_ID:-GenuineIntel}"
CPU_FAMILY="${PH4_CPU_FAMILY:-6}"
CPU_MODEL_ID="${PH4_CPU_MODEL_ID:-142}"
CPU_STEPPING="${PH4_CPU_STEPPING:-10}"
CPU_FLAGS="${PH4_CPU_FLAGS:-fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht tm pbe syscall nx rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid pni pclmulqdq ssse3 cx16 sse4_1 sse4_2 x2apic popcnt aes xsave avx f16c rdrand hypervisor}"
THREADS_PER_CORE="${PH4_THREADS_PER_CORE:-1}"
(( THREADS_PER_CORE > 0 )) || THREADS_PER_CORE=1
CPU_CORES=$((PH4_REPORTED_CORES / THREADS_PER_CORE))
(( CPU_CORES > 0 )) || CPU_CORES=1

if [[ "$CPU_ARCHITECTURE" == "aarch64" ]]; then
    for i in $(seq 0 $((PH4_REPORTED_CORES - 1))); do
        if [[ "$MODEL" == "Apple M2" ]]; then
            EFFICIENT_PART="0x024"
            PERFORMANCE_PART="0x025"
        else
            EFFICIENT_PART="0x022"
            PERFORMANCE_PART="0x023"
        fi
        if (( i < PH4_REPORTED_CORES / 2 )); then
            CPU_PART="$EFFICIENT_PART"
        else
            CPU_PART="$PERFORMANCE_PART"
        fi
        cat <<EOF >> "$FAKE_CPUINFO"
processor	: $i
model name	: $MODEL
BogoMIPS	: $((4000 + RANDOM % 900)).00
Features	: $CPU_FLAGS
CPU implementer	: 0x61
CPU architecture: 8
CPU variant	: 0x0
CPU part	: $CPU_PART
CPU revision	: $CPU_STEPPING

EOF
    done
else
for i in $(seq 0 $((PH4_REPORTED_CORES - 1))); do
    cat <<EOF >> "$FAKE_CPUINFO"
processor	: $i
vendor_id	: $VENDOR_ID
cpu family	: $CPU_FAMILY
model		: $CPU_MODEL_ID
model name	: $MODEL
stepping	: $CPU_STEPPING
microcode	: 0xca
cpu MHz		: $((2000 + RANDOM % 1000)).$((RANDOM % 1000))
cache size	: 8192 KB
physical id	: 0
siblings	: $PH4_REPORTED_CORES
core id		: $((i / THREADS_PER_CORE))
cpu cores	: $CPU_CORES
apicid		: $i
initial apicid	: $i
fpu		: yes
fpu_exception	: yes
cpuid level	: 22
wp		: yes
flags		: $CPU_FLAGS
bugs		: 
bogomips	: $((4000 + RANDOM % 900)).00
clflush size	: 64
cache_alignment	: 64
address sizes	: 40 bits physical, 48 bits virtual
power management:

EOF
done
fi

FAKE_SYSFS="$STATE_DIR/fake_online"
MAX_CORE_IDX=$((PH4_REPORTED_CORES - 1))

if (( MAX_CORE_IDX == 0 )); then
    printf '0\n' > "$FAKE_SYSFS"
else
    printf '0-%d\n' "$MAX_CORE_IDX" > "$FAKE_SYSFS"
fi
chmod 0444 "$FAKE_CPUINFO" "$FAKE_SYSFS"

mounted_targets=()
cleanup_partial_mounts() {
    local target
    for ((idx=${#mounted_targets[@]} - 1; idx>=0; idx--)); do
        target=${mounted_targets[$idx]}
        umount "$target" >/dev/null 2>&1 || true
    done
}
trap cleanup_partial_mounts ERR

bind_readonly() {
    local source_file=$1 target=$2
    umount "$target" >/dev/null 2>&1 || true
    mount --bind "$source_file" "$target"
    mounted_targets+=("$target")
    mount -o remount,ro,bind "$target"
}

bind_readonly "$FAKE_CPUINFO" /proc/cpuinfo
bind_readonly "$FAKE_SYSFS" /sys/devices/system/cpu/online
bind_readonly "$FAKE_SYSFS" /sys/devices/system/cpu/present
bind_readonly "$FAKE_SYSFS" /sys/devices/system/cpu/possible

trap - ERR
