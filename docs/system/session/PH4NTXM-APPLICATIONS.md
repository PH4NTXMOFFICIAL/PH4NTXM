# [ APPLICATION GUIDE ]

## [ OVERVIEW ]

Introduces the live session's controls and status views. Appearance follows the selected [build edition](../../build/BUILD-EDITIONS.md).

## [ STARTUP ]

Applications share the PH4NTXM interface and call underlying services or helpers. Closing a window generally leaves system protection running. Start with Boot Pilot for readiness and follow findings to their component pages.

## [ RUNTIME ]

[Boot Pilot](BOOT-PILOT.md) refreshes protection checks, offers Wi-Fi controls and gates Continue/browser launch.

[Identity](IDENTITY.md) snapshots current identifiers. Its tray is a launcher, not an audit indicator.

[Health](HEALTH.md) provides grouped findings, a searchable full report and mode-aware Browser Check. The menu, Pilot and Identity open GTK. The terminal report remains available.

[Lockdown](LOCKDOWN.md) requests restrictive networking or restores the selected mode. Its status icon records control state. Guardian readiness verifies enforcement.

[USB Nuke](USB-NUKE.md) arms matching storage-removal triggers without selecting a drive serial.

[Panic](PANIC.md) requests the same emergency backend after confirmation.

[Dead Man's Switch](DEAD-MAN-SWITCH.md) arms a silent countdown with password-authenticated Arm, Renew and Disarm. Its root service continues after the window closes and requests Panic at expiry.

[Disk access](DISK-ACCESS.md) requires the session password when mounting an unmounted filesystem through the desktop. Unmount to require authentication again. The existing authentication dialog handles the request.

[USB Guard](USB-GUARD.md) optionally preserves existing USB connections and blocks new ones pending review. Enable, Allow and Disable require fresh passwords. Closing the window leaves enforcement running.

[Net Guard](NET-GUARD.md) optionally blocks outbound IP access until the exact running process is approved. Enable, Allow and Disable require fresh passwords. Closing the window leaves enforcement running.

[Session Guard](SESSION-GUARD.md) optionally checks session consistency every 10 seconds. Notifications offer details, dismissal and explicit Lockdown. Enable and Disable require fresh passwords. Closing the window leaves monitoring running.

[Clipboard Guard](CLIPBOARD-GUARD.md) optionally expires copied content after a chosen timeout. The clipboard is protected by default, with a separate option for selected text pasted through middle-click. Enable, Disable and Clear Now run without root or a password. Closing the window leaves enabled protection running. Startup disables the verified native Xfce clipboard component through a runtime xfsettingsd replacement that preserves its other settings functions. It can also stop this display's verified standalone Clipman instance. Cached clipboard content may be lost. Other managers must be closed manually. Existing history and autostart settings are unchanged, and Clipman is not restarted automatically.

[Browser Airlock](BROWSER-AIRLOCK.md) is a separate optional application in PH4NTXM Apps. It runs Firefox in Linux/Windows and Tor Browser in Lone Wolf inside an isolated desktop. Import Files supplies selected copies and Downloads supports explicit export after stopping. Usual browser shortcuts remain unchanged.

[Document Airlock](DOCUMENT-AIRLOCK.md) previews and exports raster PDFs from an offline guest.

[Archive Airlock](ARCHIVE-AIRLOCK.md) lists archives and opens selected files through isolated viewers.

[Media Viewers](MEDIA-VIEWERS.md) play original files read-only in offline sandboxes.

[App Airlock](APP-AIRLOCK.md) runs applications and scripts in an offline private desktop. Explicit imports enter a RAM workspace, and outputs can be exported after execution stops.

[Metadata Cleaner](METADATA-CLEANER.md) inspects metadata and creates cleaned copies in an offline sandbox. Before/After reports and isolated previews support review before explicit Export. Originals remain unchanged.

[Vault](VAULT.md) collects selected files in RAM and exports encrypted copies. Existing vaults unlock manually, with confirmation before discarding unexported changes.

The [OpSec Suite](PH4NTXM-OPSEC-SUITE.md) supplies Network, Kernel, Process, Radio, ConnWatch and Shredder. GTK reports support inspection and confirmed actions where available. Terminal workflows remain accessible.

## [ CHECKS ]

Trace findings to the relevant helper, service or isolation prerequisite. A displayed status, accepted request and completed backend operation are different milestones. Each component page describes its refresh, actions and failure behavior.

## [ SOURCE ]

[ph4ntxm-boot-pilot](../../../config/includes.chroot/usr/local/bin/ph4ntxm-boot-pilot)\
[ph4ntxm-health-gtk](../../../config/includes.chroot/usr/local/bin/ph4ntxm-health-gtk)\
[ph4ntxm-identity](../../../config/includes.chroot/usr/local/bin/ph4ntxm-identity)\
[ph4ntxm-lockdown](../../../config/includes.chroot/usr/local/bin/ph4ntxm-lockdown)\
[ph4ntxm-panic-button](../../../config/includes.chroot/usr/local/bin/ph4ntxm-panic-button)\
[ph4ntxm-usb-nuke](../../../config/includes.chroot/usr/local/bin/ph4ntxm-usb-nuke)\
[ph4ntxm-dead-man-switch](../../../config/includes.chroot/usr/local/bin/ph4ntxm-dead-man-switch)\
[ph4ntxm-usb-guard](../../../config/includes.chroot/usr/local/bin/ph4ntxm-usb-guard)\
[ph4ntxm-net-guard](../../../config/includes.chroot/usr/local/bin/ph4ntxm-net-guard)\
[ph4ntxm-session-guard](../../../config/includes.chroot/usr/local/bin/ph4ntxm-session-guard)\
[ph4ntxm-clipboard-guard](../../../config/includes.chroot/usr/local/bin/ph4ntxm-clipboard-guard)\
[ph4ntxm-document-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-document-airlock)\
[ph4ntxm-archive-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-archive-airlock)\
[ph4ntxm-media](../../../config/includes.chroot/usr/local/bin/ph4ntxm-media)\
[ph4ntxm-vault](../../../config/includes.chroot/usr/local/bin/ph4ntxm-vault)\
[ph4ntxm-metadata-cleaner](../../../config/includes.chroot/usr/local/bin/ph4ntxm-metadata-cleaner)\
[ph4ntxm-app-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-app-airlock)
