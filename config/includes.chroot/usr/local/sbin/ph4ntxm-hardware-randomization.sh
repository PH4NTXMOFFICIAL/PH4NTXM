#!/usr/bin/env bash
set -euo pipefail
safe() { "$@" >/dev/null 2>&1 || true; }

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

PERSONA_SEED_FILE="$STATE_DIR/persona_seed"
HARDWARE_PROFILE_FILE="$STATE_DIR/hardware_profile"
[[ -f "$PERSONA_SEED_FILE" ]] || exit 1
[[ -f "$HARDWARE_PROFILE_FILE" ]] || exit 1

SEED=$(cat "$PERSONA_SEED_FILE")
source "$HARDWARE_PROFILE_FILE"

BOOT_JITTER_FILE="$STATE_DIR/boot_jitter"

if [[ ! -s "$BOOT_JITTER_FILE" ]]; then
    tmp=$(mktemp "$STATE_DIR/.boot-jitter.XXXXXX")
    chmod 0600 "$tmp"
    hexdump -n 8 -e '8/1 "%02x"' /dev/urandom 2>/dev/null > "$tmp" || printf '%s\n' deadbeef > "$tmp"
    mv -f "$tmp" "$BOOT_JITTER_FILE"
fi

BOOT_JITTER=$(cat "$BOOT_JITTER_FILE")

get_id() {
    local salt="$1" len="$2" layer="${3:-session}"
    case "$layer" in
        stable)  echo -n "$SEED$salt" | sha256sum | cut -c1-"$len" ;;
        *)       echo -n "$SEED$salt$BOOT_JITTER" | sha256sum | cut -c1-"$len" ;;
    esac | tr '[:lower:]' '[:upper:]'
}

UUID_RAW=$(get_id "uuid-base" 32 "session")
VAR_CHARS="89AB"
VAR_PICK=${VAR_CHARS:$((16#$(get_id "u-var" 1 "session") % 4)):1}
UUID="${UUID_RAW:0:8}-${UUID_RAW:8:4}-4${UUID_RAW:13:3}-${VAR_PICK}${UUID_RAW:17:3}-${UUID_RAW:20:12}"
BIOS_VENDOR="Generic"
BIOS_VERSION="1.$((10 + 16#$(get_id "b" 2 "stable") % 10)).0"

case "$VENDOR" in
lenovo)
    SYS_VENDOR="LENOVO"; BIOS_VENDOR="LENOVO"; BIOS_VERSION="R1$((100 + 16#$(get_id "b" 2 "stable") % 900))WW"
    case "$FAMILY" in
        thinkpad)   PRODUCT_NAME="ThinkPad T480"; BOARD_NAME="20L5";;
        ideapad)    PRODUCT_NAME="IdeaPad 3 15ARE05"; BOARD_NAME="LNVNB161216";;
        legion)     PRODUCT_NAME="Legion 5 15ACH6"; BOARD_NAME="LNVNB161216";;
        yoga)       PRODUCT_NAME="Yoga Slim 7"; BOARD_NAME="LNVNB161216";;
        thinkcentre)PRODUCT_NAME="ThinkCentre M720"; BOARD_NAME="M720";;
        ideacentre) PRODUCT_NAME="IdeaCentre 5"; BOARD_NAME="LNVNB161216";;
        thinkstation) PRODUCT_NAME="ThinkStation P520"; BOARD_NAME="1036";;
        *)          PRODUCT_NAME="ThinkPad L14"; BOARD_NAME="20U1";;
    esac
    ;;
dell)
    SYS_VENDOR="Dell Inc."; BIOS_VENDOR="Dell Inc."; BIOS_VERSION="1.$((10 + 16#$(get_id "b" 2 "stable") % 20)).0"
    case "$FAMILY" in
        xps)        PRODUCT_NAME="XPS 13 9380"; BOARD_NAME="0KTW76";;
        latitude)   PRODUCT_NAME="Latitude 5410"; BOARD_NAME="08H9R4";;
        precision)  PRODUCT_NAME="Precision 3541"; BOARD_NAME="0FH2KX";;
        inspiron)   PRODUCT_NAME="Inspiron 5502"; BOARD_NAME="0XYZ12";;
        optiplex)   PRODUCT_NAME="OptiPlex 7070"; BOARD_NAME="0Y7WYT";;
        *)          PRODUCT_NAME="OptiPlex 3050"; BOARD_NAME="0ABC12";;
    esac
    ;;
hp)
    SYS_VENDOR="HP"; BIOS_VENDOR="HP"; BIOS_VERSION="F.$((20 + 16#$(get_id "b" 2 "stable") % 80))"
    case "$FAMILY" in
        elitebook)  PRODUCT_NAME="HP EliteBook 840 G7"; BOARD_NAME="8723";;
        probook)    PRODUCT_NAME="HP ProBook 450 G8"; BOARD_NAME="87B1";;
        zbook)      PRODUCT_NAME="HP ZBook Firefly 15"; BOARD_NAME="89AB";;
        pavilion)   PRODUCT_NAME="HP Pavilion 15"; BOARD_NAME="86F1";;
        omen)       PRODUCT_NAME="HP OMEN 15"; BOARD_NAME="8607";;
        envy)       PRODUCT_NAME="HP Envy x360"; BOARD_NAME="87C4";;
        prodesk)    PRODUCT_NAME="HP ProDesk 600 G6"; BOARD_NAME="8717";;
        elitedesk)  PRODUCT_NAME="HP EliteDesk 800 G6"; BOARD_NAME="870E";;
        eliteone)   PRODUCT_NAME="HP EliteOne 800 G6"; BOARD_NAME="8712";;
        *)          PRODUCT_NAME="HP 250 G7"; BOARD_NAME="85A1";;
    esac
    ;;
asus)
    SYS_VENDOR="ASUSTeK COMPUTER INC."; BIOS_VENDOR="American Megatrends Inc."; BIOS_VERSION="$((200 + 16#$(get_id "b" 2 "stable") % 200))"
    case "$FAMILY" in
        zenbook)    PRODUCT_NAME="ZenBook UX425EA"; BOARD_NAME="UX425EA";;
        vivobook)   PRODUCT_NAME="VivoBook 15 M513"; BOARD_NAME="M513UA";;
        tuf)        PRODUCT_NAME="TUF Gaming A15"; BOARD_NAME="FA506";;
        rog)        PRODUCT_NAME="ROG Strix G15"; BOARD_NAME="G513";;
        expertbook) PRODUCT_NAME="ExpertBook B1"; BOARD_NAME="B1400";;
        chromebook) PRODUCT_NAME="ASUS Chromebook Flip"; BOARD_NAME="C434TA";;
        proart)     PRODUCT_NAME="ProArt Studiobook"; BOARD_NAME="H7604";;
        *)          PRODUCT_NAME="ASUS Laptop"; BOARD_NAME="ASUS123";;
    esac
    ;;
acer)
    SYS_VENDOR="Acer Inc."; BIOS_VENDOR="Insyde Corp."; BIOS_VERSION="V$((100 + 16#$(get_id "b" 2 "stable") % 200))"
    case "$FAMILY" in
        swift)      PRODUCT_NAME="Swift 3"; BOARD_NAME="SF314";;
        aspire)     PRODUCT_NAME="Aspire 5"; BOARD_NAME="A515";;
        predator)   PRODUCT_NAME="Predator Helios 300"; BOARD_NAME="PH315";;
        nitro)      PRODUCT_NAME="Nitro 5"; BOARD_NAME="AN515";;
        chromebook) PRODUCT_NAME="Acer Chromebook Spin"; BOARD_NAME="CP713";;
        veriton)    PRODUCT_NAME="Veriton Z4860G"; BOARD_NAME="VZ4860G";;
        travelmate) PRODUCT_NAME="TravelMate P6"; BOARD_NAME="TMP614";;
        *)          PRODUCT_NAME="Aspire E15"; BOARD_NAME="E15";;
    esac
    ;;
msi)
    SYS_VENDOR="Micro-Star International"; BIOS_VENDOR="American Megatrends Inc."; BIOS_VERSION="E$((10 + 16#$(get_id "b" 2 "stable") % 90))"
    case "$FAMILY" in
        prestige)   PRODUCT_NAME="Prestige 14"; BOARD_NAME="MS-14";;
        modern)     PRODUCT_NAME="Modern 15"; BOARD_NAME="MS-15";;
        summit)     PRODUCT_NAME="Summit E16"; BOARD_NAME="MS-1592";;
        stealth)    PRODUCT_NAME="GS66 Stealth"; BOARD_NAME="MS-16";;
        titan)      PRODUCT_NAME="GT77 Titan"; BOARD_NAME="MS-17";;
        katana)     PRODUCT_NAME="Katana GF66"; BOARD_NAME="MS-1581";;
        gf63)       PRODUCT_NAME="GF63 Thin"; BOARD_NAME="MS-16R6";;
        *)          PRODUCT_NAME="MSI Laptop"; BOARD_NAME="MS-XX";;
    esac
    ;;
razer)
    SYS_VENDOR="Razer"; BIOS_VENDOR="American Megatrends Inc."; BIOS_VERSION="E$((10 + 16#$(get_id "b" 2 "stable") % 90))"
    case "$FAMILY" in
        book) PRODUCT_NAME="Razer Book 13"; BOARD_NAME="RZ09-0357";;
        *)    PRODUCT_NAME="Blade 15"; BOARD_NAME="RZ09-$(get_id "rz" 4 "stable")";;
    esac
    ;;
fujitsu)
    SYS_VENDOR="FUJITSU"; BIOS_VENDOR="FUJITSU"; BIOS_VERSION="V$((100 + 16#$(get_id "b" 2 "stable") % 200))"
    case "$FAMILY" in
        lifebook)   PRODUCT_NAME="Lifebook U7410"; BOARD_NAME="FJNB2D5";;
        esprimo)    PRODUCT_NAME="Esprimo Q7010"; BOARD_NAME="D3823";;
        *)          PRODUCT_NAME="Fujitsu Device"; BOARD_NAME="FJNBXXX";;
    esac
    ;;
toshiba)
    SYS_VENDOR="TOSHIBA"; BIOS_VENDOR="TOSHIBA"; BIOS_VERSION="V$((100 + 16#$(get_id "b" 2 "stable") % 200))"
    case "$FAMILY" in
        satellite) PRODUCT_NAME="Satellite Pro C50"; BOARD_NAME="SY10";;
        tecra)     PRODUCT_NAME="Tecra A50"; BOARD_NAME="SY12";;
        portege)   PRODUCT_NAME="Portege X30W"; BOARD_NAME="SY11";;
        dynabook)  PRODUCT_NAME="Dynabook B65"; BOARD_NAME="DB65";;
        *)          PRODUCT_NAME="Toshiba Device"; BOARD_NAME="SYXX";;
    esac
    ;;
samsung)
    SYS_VENDOR="Samsung Electronics"; BIOS_VENDOR="Samsung"; BIOS_VERSION="P$((10 + 16#$(get_id "b" 2 "stable") % 90))"
    case "$FAMILY" in
        galaxybook) PRODUCT_NAME="Galaxy Book Pro"; BOARD_NAME="NP950";;
        notebook)   PRODUCT_NAME="Notebook 9"; BOARD_NAME="NP900";;
        odyssey)    PRODUCT_NAME="Notebook Odyssey Z"; BOARD_NAME="NP850";;
        chromebook) PRODUCT_NAME="Samsung Chromebook 4"; BOARD_NAME="XE310";;
        flash)      PRODUCT_NAME="Notebook Flash"; BOARD_NAME="NT530";;
        *)          PRODUCT_NAME="Samsung Device"; BOARD_NAME="NPXXX";;
    esac
    ;;
apple)
    SYS_VENDOR="Apple Inc."; BIOS_VENDOR="Apple Inc."; BIOS_VERSION="$((1000 + 16#$(get_id "b" 2 "stable") % 2000)).$((50 + 16#$(get_id "b" 1 "stable") % 50)).$((5 + 16#$(get_id "b" 1 "stable") % 10))"
    case "$FAMILY" in
        macbook)
            case "${SKU,,}" in
                *-m2*) PRODUCT_NAME="Mac14,7"; BOARD_NAME="Mac-827FAC58A8FDFA22" ;;
                *-m1*) PRODUCT_NAME="MacBookPro17,1"; BOARD_NAME="Mac-189A3D4F975D5FFC" ;;
                *-16-2021*) PRODUCT_NAME="MacBookPro18,1"; BOARD_NAME="Mac-EE2EBD4B90B839A8" ;;
                *air-2020*) PRODUCT_NAME="MacBookAir9,1"; BOARD_NAME="Mac-0CFF9C7C2B63DF8D" ;;
                *) PRODUCT_NAME="MacBookPro16,1"; BOARD_NAME="Mac-E1008331FDC96864" ;;
            esac
            ;;
        imac)
            case "${SKU,,}" in
                *pro*) PRODUCT_NAME="iMacPro1,1"; BOARD_NAME="Mac-7BA5B2D9E42DDD94" ;;
                *) PRODUCT_NAME="iMac20,1"; BOARD_NAME="Mac-CFF7D910A743CAAF" ;;
            esac
            ;;
        macmini)
            case "${SKU,,}" in
                *-m1*) PRODUCT_NAME="Macmini9,1"; BOARD_NAME="Mac-7BA5B2D9E42DDD94" ;;
                *) PRODUCT_NAME="Macmini8,1"; BOARD_NAME="Mac-7BA5B2DFE22DDD8C" ;;
            esac
            ;;
        mac-studio) PRODUCT_NAME="Mac13,1"; BOARD_NAME="Mac-7BA5B2D9E42DDD94";;
        *)          PRODUCT_NAME="MacBookAir9,1"; BOARD_NAME="Mac-066C15030E235D5C";;
    esac
    ;;
google)
    SYS_VENDOR="Google"; BIOS_VENDOR="coreboot"; BIOS_VERSION="Google_$(get_id "gb" 8 "stable")"
    case "$FAMILY" in
        pixelbook)        PRODUCT_NAME="Pixelbook Go"; BOARD_NAME="atlas";;
        chromebook-pixel) PRODUCT_NAME="Chromebook Pixel"; BOARD_NAME="samus";;
        pixel-slate)      PRODUCT_NAME="Pixel Slate"; BOARD_NAME="nocturne";;
        *)                PRODUCT_NAME="Pixelbook"; BOARD_NAME="eve";;
    esac
    ;;
    microsoft)
    SYS_VENDOR="Microsoft Corporation"; BIOS_VENDOR="Microsoft Corporation"; BIOS_VERSION="$((100 + 16#$(get_id "b" 2 "stable") % 200))"
    case "${SKU,,}" in
        *surface-pro*)       PRODUCT_NAME="Surface Pro 8"; BOARD_NAME="Surface_Pro_8";;
        *surface-go*)        PRODUCT_NAME="Surface Go 3"; BOARD_NAME="Surface_Go_3";;
        *surface-book*)      PRODUCT_NAME="Surface Book 3"; BOARD_NAME="Surface_Book_3";;
        *surface-studio*)    PRODUCT_NAME="Surface Studio 2"; BOARD_NAME="Surface_Studio_2";;
        *surface-laptop-go*) PRODUCT_NAME="Surface Laptop Go"; BOARD_NAME="Surface_Laptop_Go";;
        *)                   PRODUCT_NAME="Surface Laptop 4"; BOARD_NAME="Surface_Laptop_4";;
    esac
    ;;
lg)
    SYS_VENDOR="LG Electronics"; BIOS_VENDOR="LG Electronics"; BIOS_VERSION="V$((100 + 16#$(get_id "b" 2 "stable") % 200))"
    case "$FAMILY" in
        ultra-gear) PRODUCT_NAME="LG UltraGear 17"; BOARD_NAME="17G90Q";;
        allinone)   PRODUCT_NAME="LG All-in-One 24V50N"; BOARD_NAME="24V50N";;
        *)          PRODUCT_NAME="LG Gram 17"; BOARD_NAME="17Z90P";;
    esac
    ;;
intel)
    SYS_VENDOR="Intel Corporation"; BIOS_VENDOR="Intel Corporation"; BIOS_VERSION="$((100 + 16#$(get_id "b" 2 "stable") % 200))"; PRODUCT_NAME="NUC11PAHi7"; BOARD_NAME="NUC11PAH";;
ibm)
    SYS_VENDOR="IBM"; BIOS_VENDOR="IBM"; BIOS_VERSION="V$((100 + 16#$(get_id "b" 2 "stable") % 200))"
    case "$FAMILY" in
        thinkcentre) PRODUCT_NAME="ThinkCentre M920s"; BOARD_NAME="10SJ";;
        thinkstation) PRODUCT_NAME="ThinkStation P330"; BOARD_NAME="10SC";;
        x3550|x3650) PRODUCT_NAME="System x Server"; BOARD_NAME="IBM-SERVER";;
        *) PRODUCT_NAME="ThinkPad X60"; BOARD_NAME="1706";;
    esac
    ;;
origin)
    SYS_VENDOR="Origin PC"
    BIOS_VENDOR="American Megatrends Inc."
    BIOS_VERSION="5.$((10 + 16#$(get_id "b" 2 "stable") % 20))"

    case "$FAMILY" in
        chronos)
            PRODUCT_NAME="Chronos V3"
            BOARD_NAME="Origin-Chronos"
            ;;
        millennium)
            PRODUCT_NAME="Millennium"
            BOARD_NAME="Origin-Millennium"
            ;;
        neuron)
            PRODUCT_NAME="Neuron"
            BOARD_NAME="Origin-Neuron"
            ;;
        eon15)
            PRODUCT_NAME="EON15-X"
            BOARD_NAME="Origin-EON15"
            ;;
        eon17)
            PRODUCT_NAME="EON17-X"
            BOARD_NAME="Origin-EON17"
            ;;
        evo15)
            PRODUCT_NAME="EVO15-S"
            BOARD_NAME="Origin-EVO15"
            ;;
        m-class)
            PRODUCT_NAME="M-Class"
            BOARD_NAME="Origin-M-Class"
            ;;
        *)
            PRODUCT_NAME="Origin PC"
            BOARD_NAME="Origin-Board"
            ;;
    esac
    ;;
sony)
    SYS_VENDOR="Sony"; BIOS_VENDOR="Sony"; BIOS_VERSION="V$((10 + 16#$(get_id "b" 2 "stable") % 90))"
    case "$FAMILY" in
        vaio)
            PRODUCT_NAME="VAIO SX14"
            BOARD_NAME="VAIO-SX14"
            ;;
        *)
            PRODUCT_NAME="Sony Device"
            BOARD_NAME="SONY"
            ;;
    esac
;;
*)
    SYS_VENDOR="Generic"; BIOS_VENDOR="Generic"; BIOS_VERSION="1.$((10 + 16#$(get_id "b" 2 "stable") % 20)).0"; PRODUCT_NAME="PC-$(get_id "gen" 4 "stable")"; BOARD_NAME="GENERIC";;
esac

case "$SYS_VENDOR" in
    "LENOVO")                   SERIAL="PF$(get_id "s1" 8 "session")" ;;
    "Dell Inc.")                SERIAL="CN$(get_id "s1" 12 "session")" ;;
    "HP")                       SERIAL="5CG$(get_id "s1" 8 "session")" ;;
    "ASUSTeK COMPUTER INC.")    SERIAL="M$(get_id "s1" 11 "session")" ;;
    "Acer Inc.")                SERIAL="NX$(get_id "s1" 10 "session")" ;;
    "Micro-Star International") SERIAL="9S6$(get_id "s1" 9 "session")" ;;
    "Razer")                    SERIAL="BY$(get_id "s1" 10 "session")" ;;
    "FUJITSU")                  SERIAL="DS$(get_id "s1" 10 "session")" ;;
    "TOSHIBA")                  SERIAL="Z$(get_id "s1" 11 "session")" ;;
    "Samsung Electronics")      SERIAL="S$(get_id "s1" 11 "session")" ;;
    "Apple Inc.")               SERIAL="C02$(get_id "s1" 9 "session")" ;;
    "Google")                   SERIAL="GGL$(get_id "s1" 9 "session")" ;;
    "Sony")                     SERIAL="S$(get_id "s1" 11 "session")" ;;
    "Microsoft Corporation")    SERIAL="$(get_id "s1" 12 "session")" ;;
    "LG Electronics")           SERIAL="S$(get_id "s1" 11 "session")" ;;
    "Intel Corporation")        SERIAL="G$(get_id "s1" 11 "session")" ;;
    "IBM")                      SERIAL="LV$(get_id "s1" 10 "session")" ;;
    "Origin PC")                SERIAL="OPC$(get_id "s1" 9 "session")" ;;
    *)                          SERIAL="$(get_id "s1" 12 "session")" ;;
esac

BOARD_SERIAL="MB-${SERIAL:0:10}"
DMI_DIR="$STATE_DIR/fake_dmi"
mkdir -p "$DMI_DIR"

case "$FAMILY" in
    pixel-slate)
        CHASSIS_TYPE="30"
        ;;
    eliteone|imac|allinone)
        CHASSIS_TYPE="13"
        ;;
    thinkcentre|ideacentre|optiplex|veriton|esprimo|prodesk|elitedesk|macmini|mac-studio|nuc|thinkstation|chronos|millennium|neuron|m-class)
        CHASSIS_TYPE="3"
        ;;
    x3550|x3650)
        CHASSIS_TYPE="23"
        ;;
    *)
        CHASSIS_TYPE="10"
        ;;
esac

[[ "$PRODUCT_NAME" == "Surface Studio 2" ]] && CHASSIS_TYPE="13"

PRODUCT_VERSION="${PRODUCT_VERSION:-1.0}"
BOARD_VERSION="${BOARD_VERSION:-1.0}"

case "${SKU,,}" in
    *2012*|*2013*|*2014*|*x220*|*x230*|*t420*|*t430*) BIOS_DATE="05/12/2012" ;;
    *2020*|*2021*|*2022*|*-m1*|*-m2*|*g7*|*g8*) BIOS_DATE="10/24/2023" ;;
    *) BIOS_DATE="03/15/2018" ;;
esac

BIOS_RELEASE="1.0"
EC_FIRMWARE_RELEASE="1.0"
PRODUCT_FAMILY="$FAMILY"
PRODUCT_SKU="$SKU"
BOARD_ASSET_TAG="Not Specified"
CHASSIS_ASSET_TAG="Not Specified"
CHASSIS_VERSION="1.0"

modalias_token() {
    printf '%s' "$1" | tr -cd '[:alnum:].,_-'
}

MODALIAS="dmi:bvn$(modalias_token "$BIOS_VENDOR"):bvr$(modalias_token "$BIOS_VERSION"):bd$(modalias_token "$BIOS_DATE"):br$(modalias_token "$BIOS_RELEASE"):efr$(modalias_token "$EC_FIRMWARE_RELEASE"):svn$(modalias_token "$SYS_VENDOR"):pn$(modalias_token "$PRODUCT_NAME"):pvr$(modalias_token "$PRODUCT_VERSION"):rvn$(modalias_token "$SYS_VENDOR"):rn$(modalias_token "$BOARD_NAME"):rvr$(modalias_token "$BOARD_VERSION"):cvn$(modalias_token "$SYS_VENDOR"):ct$(modalias_token "$CHASSIS_TYPE"):cvr$(modalias_token "$CHASSIS_VERSION"):sku$(modalias_token "$PRODUCT_SKU"):"

declare -A DMI_VALS=(
    [product_name]="$PRODUCT_NAME"
    [product_serial]="$SERIAL"
    [product_uuid]="$UUID"
    [product_version]="$PRODUCT_VERSION"
    [product_family]="$PRODUCT_FAMILY"
    [product_sku]="$PRODUCT_SKU"

    [board_serial]="$BOARD_SERIAL"
    [board_name]="$BOARD_NAME"
    [board_vendor]="$SYS_VENDOR"
    [board_version]="$BOARD_VERSION"
    [board_asset_tag]="$BOARD_ASSET_TAG"

    [bios_vendor]="$BIOS_VENDOR"
    [bios_version]="$BIOS_VERSION"
    [bios_date]="$BIOS_DATE"
    [bios_release]="$BIOS_RELEASE"
    [ec_firmware_release]="$EC_FIRMWARE_RELEASE"

    [sys_vendor]="$SYS_VENDOR"

    [chassis_serial]="$SERIAL"
    [chassis_vendor]="$SYS_VENDOR"
    [chassis_type]="$CHASSIS_TYPE"
    [chassis_version]="$CHASSIS_VERSION"
    [chassis_asset_tag]="$CHASSIS_ASSET_TAG"
    [modalias]="$MODALIAS"
    [uevent]="MODALIAS=$MODALIAS"
)

for key in "${!DMI_VALS[@]}"; do
    echo -n "${DMI_VALS[$key]}" > "$DMI_DIR/$key"
    chmod 0444 "$DMI_DIR/$key"
done

mounted_targets=()
cleanup_partial_mounts() {
    local target
    for ((idx=${#mounted_targets[@]} - 1; idx>=0; idx--)); do
        target=${mounted_targets[$idx]}
        umount "$target" >/dev/null 2>&1 || true
    done
}
trap cleanup_partial_mounts ERR

for key in "${!DMI_VALS[@]}"; do
    target="/sys/class/dmi/id/$key"
    [[ -f "$target" ]] || continue
    umount "$target" >/dev/null 2>&1 || true
    mount --bind "$DMI_DIR/$key" "$target"
    mounted_targets+=("$target")
    mount -o remount,ro,bind "$target"
done

trap - ERR

exit 0
