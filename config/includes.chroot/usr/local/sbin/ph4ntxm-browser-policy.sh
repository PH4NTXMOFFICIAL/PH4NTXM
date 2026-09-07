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

POLICY_DIR="/etc/firefox/policies"
mkdir -p "$POLICY_DIR"
policy_tmp=$(mktemp "$POLICY_DIR/.policies.XXXXXX")

cat > "$policy_tmp" <<EOF
{
  "policies": {
    "DontCheckDefaultBrowser": true,
    "DisableAppUpdate": true,
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisableFeedbackCommands": true,
    "DisablePocket": true,
    "OverrideFirstRunPage": "",
    "DisplayBookmarksToolbar": "never",
    "PasswordManagerEnabled": false,
    "OfferToSaveLogins": false,
    "DisableFormHistory": true,
    "HardwareAcceleration": false,
    "DNSOverHTTPS": { "Enabled": false },
    "Permissions": {
      "Location": { "BlockNewRequests": true },
      "Notifications": { "BlockNewRequests": true }
    }
  }
}
EOF

chmod 0644 "$policy_tmp"
mv -f "$policy_tmp" "$POLICY_DIR/policies.json"
