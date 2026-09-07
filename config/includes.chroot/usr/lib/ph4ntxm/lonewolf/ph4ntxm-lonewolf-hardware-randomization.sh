#!/usr/bin/env bash
set -euo pipefail
safe() { "$@" >/dev/null 2>&1 || true; }

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

[[ -s "$SEED_FILE" ]] || exit 1
SEED=$(tr -d '\n' < "$SEED_FILE")
[[ "$SEED" =~ ^[0-9a-f]{64}$ ]] || exit 1

if [[ -s "$JITTER_FILE" ]]; then
    BOOT_JITTER=$(tr -d '\n' < "$JITTER_FILE")
else
    BOOT_JITTER=$(hexdump -n 8 -e '8/1 "%02x"' /dev/urandom)
    jitter_tmp=$(mktemp "$STATE_DIR/.boot-jitter.XXXXXX")
    printf '%s\n' "$BOOT_JITTER" > "$jitter_tmp"
    chmod 0600 "$jitter_tmp"
    mv -f "$jitter_tmp" "$JITTER_FILE"
fi
[[ "$BOOT_JITTER" =~ ^[0-9a-f]{16}$ ]] || exit 1

get_id() {
    local salt="$1" len="$2"
    echo -n "$SEED$salt$BOOT_JITTER" | sha256sum | cut -c1-"$len" | tr '[:lower:]' '[:upper:]'
}

UUID_RAW=$(get_id "uuid-base" 32)
VAR_CHARS="89AB"
VAR_PICK=${VAR_CHARS:$((16#${UUID_RAW:0:1} % 4)):1}
UUID="${UUID_RAW:0:8}-${UUID_RAW:8:4}-4${UUID_RAW:13:3}-${VAR_PICK}${UUID_RAW:17:3}-${UUID_RAW:20:12}"

VENDORS=(lenovo dell hp asus acer msi razer fujitsu toshiba samsung apple google microsoft lg intel ibm sony origin)
V_IDX=$(( 16#$(get_id "vendor-choice" 4) % ${#VENDORS[@]} ))
VENDOR=${VENDORS[$V_IDX]}

BIOS_VENDOR="Generic"
BIOS_VERSION="1.$((10 + 16#$(get_id "b" 2) % 90)).0"

case "$VENDOR" in
lenovo)
    SYS_VENDOR="LENOVO"; BIOS_VENDOR="LENOVO"; BIOS_VERSION="R1$((100 + 16#$(get_id "b" 2) % 900))WW"
    FAMS=(thinkpad ideapad legion yoga thinkcentre ideacentre)
    F_IDX=$(( 16#$(get_id "fam-len" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    case "$FAMILY" in
        thinkpad)   PRODUCT_NAME="ThinkPad T480"; BOARD_NAME="20L5";;
        ideapad)    PRODUCT_NAME="IdeaPad 3 15ARE05"; BOARD_NAME="LNVNB161216";;
        legion)     PRODUCT_NAME="Legion 5 15ACH6"; BOARD_NAME="LNVNB161216";;
        yoga)       PRODUCT_NAME="Yoga Slim 7"; BOARD_NAME="LNVNB161216";;
        thinkcentre)PRODUCT_NAME="ThinkCentre M720"; BOARD_NAME="M720";;
        ideacentre) PRODUCT_NAME="IdeaCentre 5"; BOARD_NAME="LNVNB161216";;
    esac
    ;;
dell)
    SYS_VENDOR="Dell Inc."; BIOS_VENDOR="Dell Inc."; BIOS_VERSION="1.$((10 + 16#$(get_id "b" 2) % 20)).0"
    FAMS=(xps latitude precision inspiron optiplex)
    F_IDX=$(( 16#$(get_id "fam-del" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    case "$FAMILY" in
        xps)        PRODUCT_NAME="XPS 13 9380"; BOARD_NAME="0KTW76";;
        latitude)   PRODUCT_NAME="Latitude 5410"; BOARD_NAME="08H9R4";;
        precision)  PRODUCT_NAME="Precision 3541"; BOARD_NAME="0FH2KX";;
        inspiron)   PRODUCT_NAME="Inspiron 5502"; BOARD_NAME="0XYZ12";;
        optiplex)   PRODUCT_NAME="OptiPlex 7070"; BOARD_NAME="0Y7WYT";;
    esac
    ;;
hp)
    SYS_VENDOR="HP"; BIOS_VENDOR="HP"; BIOS_VERSION="F.$((20 + 16#$(get_id "b" 2) % 80))"
    FAMS=(elitebook probook zbook pavilion omen envy prodesk elitedesk eliteone)
    F_IDX=$(( 16#$(get_id "fam-hp" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
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
    esac
    ;;
asus)
    SYS_VENDOR="ASUSTeK COMPUTER INC."; BIOS_VENDOR="American Megatrends Inc."; BIOS_VERSION="$((200 + 16#$(get_id "b" 2) % 200))"
    FAMS=(zenbook vivobook tuf rog expertbook chromebook proart)
    F_IDX=$(( 16#$(get_id "fam-asu" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    case "$FAMILY" in
        zenbook)    PRODUCT_NAME="ZenBook UX425EA"; BOARD_NAME="UX425EA";;
        vivobook)   PRODUCT_NAME="VivoBook 15 M513"; BOARD_NAME="M513UA";;
        tuf)        PRODUCT_NAME="TUF Gaming A15"; BOARD_NAME="FA506";;
        rog)        PRODUCT_NAME="ROG Strix G15"; BOARD_NAME="G513";;
        expertbook) PRODUCT_NAME="ExpertBook B1"; BOARD_NAME="B1400";;
        chromebook) PRODUCT_NAME="ASUS Chromebook Flip"; BOARD_NAME="C434TA";;
        proart)     PRODUCT_NAME="ProArt Studiobook"; BOARD_NAME="H7604";;
    esac
    ;;
acer)
    SYS_VENDOR="Acer Inc."; BIOS_VENDOR="Insyde Corp."; BIOS_VERSION="V$((100 + 16#$(get_id "b" 2) % 200))"
    FAMS=(swift aspire predator nitro chromebook veriton travelmate)
    F_IDX=$(( 16#$(get_id "fam-ace" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    case "$FAMILY" in
        swift)      PRODUCT_NAME="Swift 3"; BOARD_NAME="SF314";;
        aspire)     PRODUCT_NAME="Aspire 5"; BOARD_NAME="A515";;
        predator)   PRODUCT_NAME="Predator Helios 300"; BOARD_NAME="PH315";;
        nitro)      PRODUCT_NAME="Nitro 5"; BOARD_NAME="AN515";;
        chromebook) PRODUCT_NAME="Acer Chromebook Spin"; BOARD_NAME="CP713";;
        veriton)    PRODUCT_NAME="Veriton Z4860G"; BOARD_NAME="VZ4860G";;
        travelmate) PRODUCT_NAME="TravelMate P6"; BOARD_NAME="TMP614";;
    esac
    ;;
msi)
    SYS_VENDOR="Micro-Star International"; BIOS_VENDOR="American Megatrends Inc."; BIOS_VERSION="E$((10 + 16#$(get_id "b" 2) % 90))"
    FAMS=(prestige modern summit stealth titan katana gf63)
    F_IDX=$(( 16#$(get_id "fam-msi" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    case "$FAMILY" in
        prestige)   PRODUCT_NAME="Prestige 14"; BOARD_NAME="MS-14";;
        modern)     PRODUCT_NAME="Modern 15"; BOARD_NAME="MS-15";;
        summit)     PRODUCT_NAME="Summit E16"; BOARD_NAME="MS-1592";;
        stealth)    PRODUCT_NAME="GS66 Stealth"; BOARD_NAME="MS-16";;
        titan)      PRODUCT_NAME="GT77 Titan"; BOARD_NAME="MS-17";;
        katana)     PRODUCT_NAME="Katana GF66"; BOARD_NAME="MS-1581";;
        gf63)       PRODUCT_NAME="GF63 Thin"; BOARD_NAME="MS-16R6";;
    esac
    ;;
razer)
    SYS_VENDOR="Razer"; BIOS_VENDOR="American Megatrends Inc."; BIOS_VERSION="E$((10 + 16#$(get_id "b" 2) % 90))"
    FAMS=(blade book)
    F_IDX=$(( 16#$(get_id "fam-raz" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    case "$FAMILY" in
        blade) PRODUCT_NAME="Blade 15"; BOARD_NAME="RZ09-$(get_id "rz" 4)";;
        book)  PRODUCT_NAME="Razer Book 13"; BOARD_NAME="RZ09-0357";;
    esac
    ;;
fujitsu)
    SYS_VENDOR="FUJITSU"; BIOS_VENDOR="FUJITSU"; BIOS_VERSION="V$((100 + 16#$(get_id "b" 2) % 200))"
    FAMS=(lifebook esprimo)
    F_IDX=$(( 16#$(get_id "fam-fuj" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    case "$FAMILY" in
        lifebook)   PRODUCT_NAME="Lifebook U7410"; BOARD_NAME="FJNB2D5";;
        esprimo)    PRODUCT_NAME="Esprimo Q7010"; BOARD_NAME="D3823";;
    esac
    ;;
toshiba)
    SYS_VENDOR="TOSHIBA"; BIOS_VENDOR="TOSHIBA"; BIOS_VERSION="V$((100 + 16#$(get_id "b" 2) % 200))"
    FAMS=(satellite tecra portege dynabook)
    F_IDX=$(( 16#$(get_id "fam-tos" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    case "$FAMILY" in
        satellite) PRODUCT_NAME="Satellite Pro C50"; BOARD_NAME="SY10";;
        tecra)     PRODUCT_NAME="Tecra A50"; BOARD_NAME="SY12";;
        portege)   PRODUCT_NAME="Portege X30W"; BOARD_NAME="SY11";;
        dynabook)  PRODUCT_NAME="Dynabook B65"; BOARD_NAME="DB65";;
    esac
    ;;
samsung)
    SYS_VENDOR="Samsung Electronics"; BIOS_VENDOR="Samsung"; BIOS_VERSION="P$((10 + 16#$(get_id "b" 2) % 90))"
    FAMS=(galaxybook notebook chromebook flash odyssey)
    F_IDX=$(( 16#$(get_id "fam-sam" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    case "$FAMILY" in
        galaxybook) PRODUCT_NAME="Galaxy Book Pro"; BOARD_NAME="NP950";;
        notebook)   PRODUCT_NAME="Notebook 9"; BOARD_NAME="NP900";;
        chromebook) PRODUCT_NAME="Samsung Chromebook 4"; BOARD_NAME="XE310";;
        flash)      PRODUCT_NAME="Notebook Flash"; BOARD_NAME="NT530";;
        odyssey)    PRODUCT_NAME="Notebook Odyssey Z"; BOARD_NAME="NP850";;
    esac
    ;;
apple)
    SYS_VENDOR="Apple Inc."; BIOS_VENDOR="Apple Inc."
    BIOS_VERSION="$((1000 + 16#$(get_id "b" 2) % 2000)).$((50 + 16#$(get_id "b" 1) % 50)).$((5 + 16#$(get_id "b" 1) % 10))"
    FAMS=(macbook imac macmini)
    F_IDX=$(( 16#$(get_id "fam-app" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    case "$FAMILY" in
        macbook)    PRODUCT_NAME="MacBookPro16,1"; BOARD_NAME="Mac-E1008331FDC96864";;
        imac)       PRODUCT_NAME="iMac20,1"; BOARD_NAME="Mac-CFF7D910A743CAAF";;
        macmini)    PRODUCT_NAME="Macmini8,1"; BOARD_NAME="Mac-7BA5B2DFE22DDD8C";;
    esac
    ;;
google)
    SYS_VENDOR="Google"; BIOS_VENDOR="coreboot"; BIOS_VERSION="Google_$(get_id "gb" 8)"
    FAMS=(pixelbook chromebook-pixel pixel-slate)
    F_IDX=$(( 16#$(get_id "fam-google" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    case "$FAMILY" in
        pixelbook)        PRODUCT_NAME="Pixelbook Go"; BOARD_NAME="atlas";;
        chromebook-pixel) PRODUCT_NAME="Chromebook Pixel"; BOARD_NAME="samus";;
        pixel-slate)      PRODUCT_NAME="Pixel Slate"; BOARD_NAME="nocturne";;
    esac
    ;;
microsoft)
    SYS_VENDOR="Microsoft Corporation"; BIOS_VENDOR="Microsoft Corporation"
    FAMILY="surface"
    case $((16#$(get_id "model-ms" 2) % 6)) in
        0) PRODUCT_NAME="Surface Pro 8"; BOARD_NAME="Surface_Pro_8";;
        1) PRODUCT_NAME="Surface Go 3"; BOARD_NAME="Surface_Go_3";;
        2) PRODUCT_NAME="Surface Book 3"; BOARD_NAME="Surface_Book_3";;
        3) PRODUCT_NAME="Surface Studio 2"; BOARD_NAME="Surface_Studio_2";;
        4) PRODUCT_NAME="Surface Laptop Go"; BOARD_NAME="Surface_Laptop_Go";;
        5) PRODUCT_NAME="Surface Laptop 4"; BOARD_NAME="Surface_Laptop_4";;
    esac
    BIOS_VERSION="$((100 + 16#$(get_id "b" 2) % 200))"
    ;;
lg)
    SYS_VENDOR="LG Electronics"; BIOS_VENDOR="LG Electronics"
    FAMS=(gram ultra-gear allinone)
    F_IDX=$(( 16#$(get_id "fam-lg" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    case "$FAMILY" in
        gram)       PRODUCT_NAME="LG Gram 17"; BOARD_NAME="17Z90P";;
        ultra-gear) PRODUCT_NAME="LG UltraGear 17"; BOARD_NAME="17G90Q";;
        allinone)   PRODUCT_NAME="LG All-in-One 24V50N"; BOARD_NAME="24V50N";;
    esac
    BIOS_VERSION="V$((100 + 16#$(get_id "b" 2) % 200))"
    ;;
intel)
    SYS_VENDOR="Intel Corporation"; BIOS_VENDOR="Intel Corporation"
    FAMILY="nuc"
    PRODUCT_NAME="NUC11PAHi7"; BOARD_NAME="NUC11PAH"
    BIOS_VERSION="$((100 + 16#$(get_id "b" 2) % 200))"
    ;;
ibm)
    SYS_VENDOR="IBM"; BIOS_VENDOR="IBM"; BIOS_VERSION="V$((100 + 16#$(get_id "b" 2) % 200))"
    FAMS=(thinkcentre thinkstation x3550 x3650)
    F_IDX=$(( 16#$(get_id "fam-ibm" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    case "$FAMILY" in
        thinkcentre) PRODUCT_NAME="ThinkCentre M920s"; BOARD_NAME="10SJ";;
        thinkstation) PRODUCT_NAME="ThinkStation P330"; BOARD_NAME="10SC";;
        x3550|x3650) PRODUCT_NAME="System x Server"; BOARD_NAME="IBM-SERVER";;
    esac
    ;;
sony)
    SYS_VENDOR="Sony"; BIOS_VENDOR="Sony"; BIOS_VERSION="V$((10 + 16#$(get_id "b" 2) % 90))"
    FAMILY="vaio"
    PRODUCT_NAME="VAIO SX14"; BOARD_NAME="VAIO-SX14"
    ;;
origin)
    SYS_VENDOR="Origin PC"; BIOS_VENDOR="American Megatrends Inc."
    FAMS=(chronos millennium neuron eon15 eon17 evo15 m-class)
    F_IDX=$(( 16#$(get_id "fam-origin" 2) % ${#FAMS[@]} ))
    FAMILY=${FAMS[$F_IDX]}
    BIOS_VERSION="5.$((10 + 16#$(get_id "b" 2) % 20))"
    case "$FAMILY" in
        chronos)    PRODUCT_NAME="Chronos V3"; BOARD_NAME="Origin-Chronos";;
        millennium) PRODUCT_NAME="Millennium"; BOARD_NAME="Origin-Millennium";;
        neuron)     PRODUCT_NAME="Neuron"; BOARD_NAME="Origin-Neuron";;
        eon15)      PRODUCT_NAME="EON15-X"; BOARD_NAME="Origin-EON15";;
        eon17)      PRODUCT_NAME="EON17-X"; BOARD_NAME="Origin-EON17";;
        evo15)      PRODUCT_NAME="EVO15-S"; BOARD_NAME="Origin-EVO15";;
        m-class)    PRODUCT_NAME="M-Class"; BOARD_NAME="Origin-M-Class";;
    esac
    ;;
*)
    SYS_VENDOR="Generic"; BIOS_VENDOR="Generic"
    FAMILY="generic"
    BIOS_VERSION="1.$((10 + 16#$(get_id "b" 2) % 90)).0"
    PRODUCT_NAME="PC-$(get_id "gen" 4)"; BOARD_NAME="GENERIC"
    ;;
esac

case "$SYS_VENDOR" in
    "LENOVO")                   SERIAL="PF$(get_id "s1" 8)" ;;
    "Dell Inc.")                SERIAL="CN$(get_id "s1" 12)" ;;
    "HP")                       SERIAL="5CG$(get_id "s1" 8)" ;;
    "ASUSTeK COMPUTER INC.")    SERIAL="M$(get_id "s1" 11)" ;;
    "Acer Inc.")                SERIAL="NX$(get_id "s1" 10)" ;;
    "Micro-Star International") SERIAL="9S6$(get_id "s1" 9)" ;;
    "Razer")                    SERIAL="BY$(get_id "s1" 10)" ;;
    "FUJITSU")                  SERIAL="DS$(get_id "s1" 10)" ;;
    "TOSHIBA")                  SERIAL="Z$(get_id "s1" 11)" ;;
    "Samsung Electronics")      SERIAL="S$(get_id "s1" 11)" ;;
    "Apple Inc.")               SERIAL="C02$(get_id "s1" 9)" ;;
    "Google")                   SERIAL="GGL$(get_id "s1" 9)" ;;
    "Microsoft Corporation")    SERIAL="$(get_id "s1" 12)" ;;
    "LG Electronics")           SERIAL="S$(get_id "s1" 11)" ;;
    "Intel Corporation")        SERIAL="G$(get_id "s1" 11)" ;;
    "IBM")                      SERIAL="LV$(get_id "s1" 10)" ;;
    "Sony")                     SERIAL="S$(get_id "s1" 11)" ;;
    "Origin PC")               SERIAL="OPC$(get_id "s1" 9)" ;;
    *)                          SERIAL="$(get_id "s1" 12)" ;;
esac

BOARD_SERIAL="MB-$(get_id "brd" 12)"
DMI_DIR="$STATE_DIR/fake_dmi"
mkdir -p "$DMI_DIR"

FAMILY=${FAMILY:-generic}

case "$FAMILY" in
    pixel-slate)
        CHASSIS_TYPE=30
        ;;
    thinkpad|ideapad|legion|yoga|xps|latitude|precision|inspiron|elitebook|probook|zbook|pavilion|omen|envy|zenbook|vivobook|tuf|rog|expertbook|chromebook|proart|swift|aspire|predator|nitro|travelmate|lifebook|satellite|tecra|portege|dynabook|galaxybook|notebook|flash|odyssey|modern|prestige|summit|stealth|titan|katana|gf63|blade|book|pixelbook|chromebook-pixel|macbook|surface|gram|ultra-gear|vaio|eon15|eon17|evo15)
        CHASSIS_TYPE=$(( (16#$(get_id "ct" 2) % 3) + 8 ))
        ;;
    eliteone|imac|allinone)
        CHASSIS_TYPE=13
        ;;
    thinkcentre|ideacentre|optiplex|elitedesk|prodesk|veriton|esprimo|macmini|mac-studio|nuc|thinkstation|chronos|millennium|neuron|m-class)
        CHASSIS_TYPE=3
        ;;
    x3550|x3650)
        CHASSIS_TYPE=23
        ;;
    *)
        CHASSIS_TYPE=$(( (16#$(get_id "ct" 2) % 8) + 3 ))
        ;;
esac

[[ "$PRODUCT_NAME" == "Surface Studio 2" ]] && CHASSIS_TYPE=13

PRODUCT_VERSION="$(printf "%d.%d" $((1 + 16#$(get_id "pv" 1) % 5)) $((16#$(get_id "pv" 1) % 10)))"
BOARD_VERSION="1.0"
BIOS_DATE="$(printf '%.2d/%.2d/%d' $((1 + 16#$(get_id "bdm" 2) % 12)) $((1 + 16#$(get_id "bdd" 2) % 28)) $((2018 + 16#$(get_id "bdy" 1) % 7)))"
BIOS_RELEASE="1.0"
EC_FIRMWARE_RELEASE="1.0"
PRODUCT_FAMILY="$FAMILY"
PRODUCT_SKU="${VENDOR}-${FAMILY}-$(get_id "sku" 4)"
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
    [board_vendor]="$SYS_VENDOR"
    [board_version]="$BOARD_VERSION"
    [board_asset_tag]="$BOARD_ASSET_TAG"
    [bios_vendor]="$BIOS_VENDOR"
    [bios_version]="$BIOS_VERSION"
    [bios_date]="$BIOS_DATE"
    [bios_release]="$BIOS_RELEASE"
    [ec_firmware_release]="$EC_FIRMWARE_RELEASE"
    [sys_vendor]="$SYS_VENDOR"
    [board_name]="$BOARD_NAME"
    [chassis_serial]="$SERIAL"
    [chassis_type]="$CHASSIS_TYPE"
    [chassis_vendor]="$SYS_VENDOR"
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
