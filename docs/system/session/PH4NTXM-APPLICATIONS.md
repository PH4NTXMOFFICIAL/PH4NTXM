# [ APPLICATION GUIDE ]

## [ OVERVIEW ]

Introduces the live session's controls and status views. Appearance follows the selected [build edition](../../build/BUILD-EDITIONS.md).

## [ STARTUP ]

Applications share the PH4NTXM interface and call underlying services or helpers. Closing a window generally leaves system protection running. Start with Boot Pilot for readiness and follow findings to their component pages.

## [ RUNTIME ]

[Boot Pilot](BOOT-PILOT.md) refreshes protection checks, offers Wi-Fi controls and gates Continue/browser launch. [Identity](IDENTITY.md) snapshots current identifiers. Its tray is a launcher, not an audit indicator.

[Health](HEALTH.md) provides grouped findings, a searchable full report and mode-aware Browser Check. The menu, Pilot and Identity open GTK. The terminal report remains available.

[Lockdown](LOCKDOWN.md) requests restrictive networking or restores the selected mode. Its status icon records control state. Guardian readiness verifies enforcement.

[USB Nuke](USB-NUKE.md) arms matching storage-removal triggers without selecting a drive serial. [Panic](PANIC.md) requests the same emergency backend after confirmation.

[USB Guard](USB-GUARD.md) optionally preserves existing USB connections and blocks new ones pending review. [Net Guard](NET-GUARD.md) optionally blocks outbound IP access until the exact running process is approved. Enable, Allow and Disable require fresh passwords. Closing either window leaves enforcement running.

[Document Airlock](DOCUMENT-AIRLOCK.md) previews and exports raster PDFs from an offline guest. [Archive Airlock](ARCHIVE-AIRLOCK.md) lists archives and opens selected files through isolated viewers. [Media Viewers](MEDIA-VIEWERS.md) play original files read-only in offline sandboxes.

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
[ph4ntxm-usb-guard](../../../config/includes.chroot/usr/local/bin/ph4ntxm-usb-guard)\
[ph4ntxm-net-guard](../../../config/includes.chroot/usr/local/bin/ph4ntxm-net-guard)\
[ph4ntxm-document-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-document-airlock)\
[ph4ntxm-archive-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-archive-airlock)\
[ph4ntxm-media](../../../config/includes.chroot/usr/local/bin/ph4ntxm-media)\
[ph4ntxm-vault](../../../config/includes.chroot/usr/local/bin/ph4ntxm-vault)
