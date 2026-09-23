# [ WIFI CONTROL ]

## [ OVERVIEW ]

Provides NetworkManager-backed Wi-Fi listing and connection requests for Boot Pilot.

## [ STARTUP ]

The helper exposes `list [--enable] [--rescan]` and `connect`, returning JSON for Boot Pilot. It uses NetworkManager's system D-Bus API rather than constructing shell commands from SSIDs or passwords.

At process startup it attempts to disable core dumps and process dumpability. Connection requests arrive on standard input and are limited to 8192 bytes.

## [ RUNTIME ]

Listing reports radio availability, wireless devices, the current connection and visible access points. Rescan waits up to six seconds for changed scan timestamps. Duplicate SSID/security entries prefer the active connection, then the strongest signal.

Supported networks include Open, Enhanced Open, WPA/WPA2 PSK and WPA3 SAE. Enterprise and WEP are reported as unsupported. Display SSIDs are decoded and control characters replaced, while their original bytes are retained as a hexadecimal identity.

Before connecting, the helper rereads the selected device and access point. SSID bytes, BSSID and key-management type must still match the request. A changed selection requires a rescan. Password format is checked according to PSK or SAE requirements.

The new NetworkManager connection is volatile, has autoconnect disabled, preserves the already prepared MAC, uses automatic IPv4 and disables IPv6. It is bound to the selected BSSID and created through `AddAndActivateConnection2`.

The helper waits up to 35 seconds for activation, reporting authentication/association failure, disappearance or timeout as JSON errors. NetworkManager authorization errors are also returned explicitly. A password is passed through the request and D-Bus settings, not placed on a command line or saved as a persistent connection by this helper.

## [ CHECKS ]

Use the returned error to distinguish radio state, stale scan data, unsupported authentication and activation failure. A scan result is not a successful association.

This helper establishes Wi-Fi connectivity. Firewall release, session identity and Tor readiness remain separate checks in Boot Pilot.

## [ SOURCE ]

[ph4ntxm-wifi-control](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-wifi-control)
