#!/usr/bin/env bash
set -euo pipefail

safe() { "$@" >/dev/null 2>&1 || true; }

STATE_DIR="/run/ph4ntxm"
mkdir -p "$STATE_DIR"

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

IDENTITY_READY_FILE="$STATE_DIR/identity-ready"
exec 9>"$STATE_DIR/identity.lock"
flock -x 9
if [[ -r "$IDENTITY_READY_FILE" ]] && \
   [[ "$(tr -d '\n' < "$IDENTITY_READY_FILE")" == "$MODE" ]]; then
    exit 0
fi

BOOT_MAC_FILE="$STATE_DIR/boot_mac"
BOOT_MID_FILE="$STATE_DIR/boot_machine_id"
BOOT_HOST_FILE="$STATE_DIR/boot_hostname"
PERSONA_SEED_FILE="$STATE_DIR/persona_seed"
HARDWARE_PROFILE_FILE="$STATE_DIR/hardware_profile"

SKULIST_FILE="/etc/ph4ntxm-skulist"
NAMELIST_FILE="/etc/ph4ntxm-namelist"

if [[ ! -s "$BOOT_MID_FILE" ]]; then
    BOOT_MID=$(tr -d '\n' < /etc/machine-id 2>/dev/null || true)
    [[ "$BOOT_MID" =~ ^[0-9a-f]{32}$ ]] || exit 1
    [[ "$BOOT_MID" != "00000000000000000000000000000000" ]] || exit 1
    mid_tmp=$(mktemp "$STATE_DIR/.boot-machine-id.XXXXXX")
    printf '%s\n' "$BOOT_MID" > "$mid_tmp"
    chmod 0644 "$mid_tmp"
    mv -f "$mid_tmp" "$BOOT_MID_FILE"
fi
BOOT_MID=$(tr -d '\n' < "$BOOT_MID_FILE")
[[ "$BOOT_MID" =~ ^[0-9a-f]{32}$ ]] || exit 1
[[ "$(tr -d '\n' < /etc/machine-id 2>/dev/null || true)" == "$BOOT_MID" ]] || exit 1

if [[ ! -s "$PERSONA_SEED_FILE" ]]; then
    seed_tmp=$(mktemp "$STATE_DIR/.persona-seed.XXXXXX")
    {
        head -c 32 /dev/urandom
        printf '%s' "$BOOT_MID"
    } | sha256sum | awk '{print $1}' > "$seed_tmp"
    chmod 0600 "$seed_tmp"
    mv -f "$seed_tmp" "$PERSONA_SEED_FILE"
fi
SEED=$(tr -d '\n' < "$PERSONA_SEED_FILE")
[[ "$SEED" =~ ^[0-9a-f]{64}$ ]] || exit 1

case "$MODE" in
    linux)
        vendors=(lenovo dell hp asus acer msi razer fujitsu toshiba samsung apple google microsoft lg intel ibm sony origin)
        ;;
    windows)
        vendors=(lenovo dell hp asus acer msi razer fujitsu toshiba samsung microsoft lg intel ibm sony origin)
        ;;
    *)
        exit 1
        ;;
esac

seeded_random() {
    local max=$1
    local salt=${2:-default}
    local hash
    hash=$(printf "%s%s" "$SEED" "$salt" | sha256sum | cut -c1-8)
    local val=$((16#$hash))
    echo $(( val % max ))
}

declare -A hardware_families=(
  [lenovo]="thinkpad ideapad legion yoga thinkcentre ideacentre thinkstation"
  [dell]="xps latitude inspiron precision optiplex"
  [hp]="elitebook pavilion omen probook zbook envy prodesk elitedesk eliteone"
  [asus]="zenbook vivobook rog tuf expertbook chromebook proart"
  [acer]="swift aspire predator nitro chromebook veriton travelmate"
  [samsung]="galaxybook notebook chromebook flash odyssey"
  [apple]="macbook imac macmini mac-studio"
  [google]="pixelbook chromebook-pixel pixel-slate"
  [microsoft]="surface"
  [msi]="stealth titan prestige modern katana gf63 summit"
  [razer]="blade book"
  [lg]="gram ultra-gear allinone"
  [sony]="vaio"
  [intel]="nuc"
  [ibm]="thinkcentre thinkstation x3550 x3650"
  [origin]="chronos millennium neuron eon15 eon17 evo15 m-class"
  [toshiba]="satellite portege tecra dynabook"
  [fujitsu]="lifebook esprimo"
)

V="${vendors[$(seeded_random ${#vendors[@]} vendor)]}"
families=(${hardware_families[$V]:-generic})
[[ ${#families[@]} -eq 0 ]] && families=(generic)
F="${families[$(seeded_random ${#families[@]} family)]}"

pick_from_file() {
    local file=$1
    [[ ! -f "$file" ]] && echo "user" && return
    mapfile -t lines < <(grep -v '^#' "$file" | sed '/^$/d')
    [[ ${#lines[@]} -eq 0 ]] && echo "user" && return
    echo "${lines[$(seeded_random ${#lines[@]} "name")]}"
}

pick_sku_by_vendor() {
    local vendor=$1
    local family=$2
    local file=$3
    [[ ! -f "$file" ]] && echo "$F" && return

    mapfile -t skus < <(
        awk -v vendor="$vendor" '
            BEGIN {wanted=tolower(vendor)}
            /^#/ {
                header=$0
                sub(/^#[[:space:]]*/, "", header)
                key=tolower(header)
                gsub(/[[:space:]_-]/, "", key)
                active=(key == wanted ||
                        (wanted == "lenovo" && key == "lenovopc") ||
                        (wanted == "hp" && key == "hpdesk"))
                next
            }
            active && NF {print}
        ' "$file"
    )
    mapfile -t family_skus < <(
        printf '%s\n' "${skus[@]}" | grep -Ei "^${family}([_-]|$)" || true
    )
    if [[ ${#family_skus[@]} -eq 0 ]]; then
        echo "$family"
    else
        echo "${family_skus[$(seeded_random ${#family_skus[@]} "sku-$vendor-$family")]}"
    fi
}

SKU=$(pick_sku_by_vendor "$V" "$F" "$SKULIST_FILE")

declare -A OUI_POOL=(
  [lenovo_thinkpad]="3c:52:82 00:21:6a"
  [lenovo_ideapad]="54:ee:75 70:8b:cd"
  [lenovo_legion]="a4:bb:6d 28:d2:44"
  [lenovo_thinkcentre]="3c:52:82 00:21:6a"
  [lenovo_ideacentre]="54:ee:75 70:8b:cd"
  [lenovo_thinkstation]="3c:52:82 00:21:6a"
  [lenovo_yoga]="7c:67:a2 90:2b:34"
  [dell_xps]="f8:b1:56 3c:2c:30"
  [dell_latitude]="14:18:77 9c:b6:d0"
  [dell_precision]="d4:ae:52 a0:36:9f"
  [dell_inspiron]="ec:f4:bb 18:03:73"
  [dell_optiplex]="98:90:96 70:85:c2"
  [hp_elitebook]="3c:d9:2b 5c:8d:4e"
  [hp_probook]="38:63:bb 7c:2a:31"
  [hp_zbook]="b4:99:ba 40:b0:34"
  [hp_pavilion]="c8:d3:a3 10:1f:74"
  [hp_omen]="48:0f:cf b4:b6:76"
  [hp_envy]="d8:97:ba b4:b5:2f"
  [hp_prodesk]="3c:d9:2b 5c:8d:4e"
  [hp_elitedesk]="3c:d9:2b 5c:8d:4e"
  [hp_eliteone]="3c:d9:2b 5c:8d:4e"
  [asus_zenbook]="2c:56:dc 04:d4:c4"
  [asus_vivobook]="10:bf:48 08:62:66"
  [asus_tuf]="60:45:bd 38:d5:47"
  [asus_rog]="60:45:bd 38:d5:47"
  [asus_expertbook]="b8:6b:23 50:46:5d"
  [asus_chromebook]="b8:6b:23 50:46:5d"
  [asus_proart]="2c:56:dc 04:d4:c4"
  [acer_swift]="20:6a:8a 88:ae:dd"
  [acer_aspire]="30:85:a9 94:de:80"
  [acer_predator]="d0:67:e5 68:1c:a2"
  [acer_nitro]="d0:67:e5 68:1c:a2"
  [acer_chromebook]="20:6a:8a 88:ae:dd"
  [acer_veriton]="30:85:a9 94:de:80"
  [acer_travelmate]="30:85:a9 94:de:80"
  [msi_prestige]="d8:cb:8a 00:02:c7"
  [msi_stealth]="9c:5c:8e 14:da:e9"
  [msi_titan]="f4:6d:04 70:4d:7b"
  [msi_modern]="d8:cb:8a 00:02:c7"
  [msi_katana]="f4:6d:04 70:4d:7b"
  [msi_gf63]="f4:6d:04 70:4d:7b"
  [msi_summit]="d8:cb:8a 00:02:c7"
  [razer_blade]="ec:aa:a0 24:04:a7"
  [razer_book]="ec:aa:a0 24:04:a7"
  [fujitsu_lifebook]="00:07:e9 00:0e:0c"
  [fujitsu_esprimo]="00:14:5e 00:1f:29"
  [toshiba_satellite]="00:08:9b 00:15:5d"
  [toshiba_portege]="00:1c:7e 00:22:43"
  [toshiba_tecra]="00:08:9b 00:15:5d"
  [toshiba_dynabook]="00:1c:7e 00:22:43"
  [samsung_galaxybook]="3c:5a:b4 28:39:26"
  [samsung_notebook]="3c:5a:b4 28:39:26"
  [samsung_chromebook]="00:12:47 5c:0a:5b"
  [samsung_flash]="00:12:47 5c:0a:5b"
  [samsung_odyssey]="3c:5a:b4 28:39:26"
  [apple_macbook]="f0:18:98 3c:22:fb d0:03:4b"
  [apple_imac]="a8:66:7f 28:cf:e9"
  [apple_macmini]="ac:bc:32 60:f4:45"
  [apple_mac-studio]="ac:bc:32 60:f4:45"
  [google_pixelbook]="00:1a:11 f4:f5:d8"
  [google_chromebook-pixel]="00:1a:11 f4:f5:d8"
  [google_pixel-slate]="00:1a:11 f4:f5:d8"
  [microsoft_surface]="7c:1e:52 28:18:78"
  [lg_gram]="a0:39:f7 78:64:c0"
  [lg_ultra-gear]="a0:39:f7 78:64:c0"
  [lg_allinone]="a0:39:f7 78:64:c0"
  [intel_nuc]="b4:b6:76 3c:fd:fe"
  [ibm_thinkcentre]="b0:4e:26 60:f8:1d"
  [ibm_thinkstation]="b0:4e:26 60:f8:1d"
  [ibm_x3550]="00:04:ac 00:06:29"
  [ibm_x3650]="00:04:ac 00:06:29"
  [origin_chronos]="00:1e:67 00:15:5d"
  [origin_millennium]="00:1e:67 00:15:5d"
  [origin_neuron]="00:1e:67 00:15:5d"
  [origin_eon15]="00:1e:67 00:15:5d"
  [origin_eon17]="00:1e:67 00:15:5d"
  [origin_evo15]="00:1e:67 00:15:5d"
  [origin_m-class]="00:1e:67 00:15:5d"
  [sony_vaio]="00:19:c5 44:6d:57"
  [default]="3c:52:82 00:21:6a f8:b1:56 14:18:77"
)
if [[ ! -s "$BOOT_HOST_FILE" ]]; then
    SUFFIX=$(printf "%s%s" "$SEED" suffix | sha256sum | cut -c1-4)
    NAME=$(pick_from_file "$NAMELIST_FILE")
    CHANCE=$(seeded_random 100 template)

    if (( CHANCE < 50 )); then
        HOST="${F}-${SUFFIX}"
    elif (( CHANCE < 70 )); then
        HOST="${F}-${NAME}-${SUFFIX}"
    elif (( CHANCE < 90 )); then
        HOST="${NAME}-${SUFFIX}"
    else
        if [[ "$SKU" == *"$F"* ]]; then
            HOST="${SKU}-${SUFFIX}"
        else
            HOST="${F}-${SKU}-${SUFFIX}"
        fi
    fi

    host_tmp=$(mktemp "$STATE_DIR/.boot-hostname.XXXXXX")
    echo "${HOST:0:32}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' > "$host_tmp"
    chmod 0600 "$host_tmp"
    mv -f "$host_tmp" "$BOOT_HOST_FILE"
fi
HOST=$(cat "$BOOT_HOST_FILE")

if [[ ! -s "$BOOT_MAC_FILE" ]]; then
    key="${V}_${F}"
    pool="${OUI_POOL[$key]:-${OUI_POOL[default]}}"
    read -ra OUIS <<< "$pool"
    OUI="${OUIS[$(seeded_random ${#OUIS[@]} oui)]}"

    if [[ "$pool" == "${OUI_POOL[default]}" ]]; then
        first_byte=$(printf "%02x" $(( (0x${OUI:0:2} | 0x02) & 0xfe )))
        OUI="${first_byte}${OUI:2}"
    fi

    M_END=$(printf "%s%s" "$SEED" mac | sha256sum | sed 's/\(..\)\(..\)\(..\).*/\1:\2:\3/')
    mac_tmp=$(mktemp "$STATE_DIR/.boot-mac.XXXXXX")
    echo "${OUI}:${M_END}" | tr '[:upper:]' '[:lower:]' > "$mac_tmp"
    chmod 0600 "$mac_tmp"
    mv -f "$mac_tmp" "$BOOT_MAC_FILE"
fi
BOOT_MAC=$(cat "$BOOT_MAC_FILE")

install -d -m 0755 /var/lib/dbus
ln -sf /etc/machine-id /var/lib/dbus/machine-id

echo "$HOST" > /etc/hostname
hostname "$HOST"

if grep -q '^127\.0\.1\.1' /etc/hosts; then
    sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$HOST/" /etc/hosts
else
    printf '127.0.1.1\t%s\n' "$HOST" >> /etc/hosts
fi

declare -A TARGET_MACS
for dev in /sys/class/net/*; do
    iface=$(basename "$dev")
    [[ "$iface" =~ ^(lo|docker.*|veth.*|br.*|virbr.*|tun.*|tap.*|vbr.*|virbr.*)$ ]] && continue
    [[ -d "$dev/device" ]] || continue
    
    OUI_PREFIX=$(echo "$BOOT_MAC" | cut -d: -f1-3)
    m4=$(printf "%02x" $(seeded_random 256 "m4-$iface"))
    m5=$(printf "%02x" $(seeded_random 256 "m5-$iface"))
    m6=$(printf "%02x" $(seeded_random 256 "m6-$iface"))
    TARGET_MACS["$iface"]="${OUI_PREFIX}:${m4}:${m5}:${m6}"
done

apply_mac() {
    local iface=$1 target=$2 attempt current
    for attempt in {1..10}; do
        if ip link set "$iface" down 2>/dev/null && \
           ip link set "$iface" address "$target" 2>/dev/null; then
            current=$(tr -d '\n' < "/sys/class/net/$iface/address" 2>/dev/null || true)
            [[ "$current" == "$target" ]] && return 0
        fi
        udevadm settle --timeout=2 >/dev/null 2>&1 || true
        sleep 0.5
    done
    return 1
}

mac_failed=0
for if_name in "${!TARGET_MACS[@]}"; do
    if ! apply_mac "$if_name" "${TARGET_MACS[$if_name]}"; then
        printf 'ph4ntxm-identity: failed to set protected MAC on %s\n' "$if_name" >&2
        mac_failed=1
    fi
done

(( mac_failed == 0 )) || exit 1

if [[ ! -s "$HARDWARE_PROFILE_FILE" ]]; then
    tmp=$(mktemp "$STATE_DIR/.hardware-profile.XXXXXX")
    chmod 0600 "$tmp"
    printf "VENDOR=%q\nFAMILY=%q\nSKU=%q\n" \
        "$V" "$F" "$SKU" > "$tmp"
    mv "$tmp" "$HARDWARE_PROFILE_FILE"
    chmod 0644 "$HARDWARE_PROFILE_FILE"
    safe sync
fi

safe udevadm trigger --action=change --subsystem-match=net
safe udevadm settle --timeout=10

ready_tmp=$(mktemp "$STATE_DIR/.identity-ready.XXXXXX")
printf '%s\n' "$MODE" > "$ready_tmp"
chmod 0644 "$ready_tmp"
mv "$ready_tmp" "$IDENTITY_READY_FILE"

sleep 1

exit 0
