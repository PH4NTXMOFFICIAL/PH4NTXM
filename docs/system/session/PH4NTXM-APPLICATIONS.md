# [ APPLICATION GUIDE ]

## [ OVERVIEW ]

Provides the live session's controls and status views. Appearance follows the selected [build edition](../../build/BUILD-EDITIONS.md).

## [ STARTUP ]

The desktop applications expose session checks and explicit controls through the shared PH4NTXM interface. Their windows are clients of the underlying services and helpers. Closing a window generally does not stop a system protection service.

Boot Pilot is the starting view for readiness, while Health and Identity provide different levels of inspection.

## [ RUNTIME ]

Boot Pilot refreshes grouped identity, network and system checks and provides Wi-Fi selection. Continue and browser launch become available after its checks pass. Detailed Report opens the terminal Health report, which is a snapshot rather than another continuously updating dashboard.

Identity shows the hostname, machine ID, visible MACs and mode read when it opens. It's static and shows what assigned on boot. It does not regenerate identity. Its tray is a launcher, not a live audit indicator.

Lockdown requests restrictive networking through the privileged firewall helper. Disabling it restores the selected mode's policy. Its window and tray use a status record. Fresh guard readiness is the stronger check for completed enforcement.

USB Nuke arms or disarms matching storage-removal events. It does not select a particular drive serial. Panic Button instead presents an immediate confirmation action. Its tray's blinking state means that confirmation application is open. Both ultimately use the system emergency path.

Document Airlock converts supported local documents in a disposable KVM guest and lets you review/export a raster PDF. Media viewers open original local files in disposable offline sandboxes. Airlock exports a new artifact. Media viewers keep selected source files read-only.

Application errors should be traced to the relevant helper, service or isolation prerequisite. A displayed status, accepted action and completed backend operation are separate points in the flow.

## [ CHECKS ]

Use [Boot Pilot](BOOT-PILOT.md) for readiness, [Health](HEALTH.md) for detailed evidence and each application's page for its action and failure behavior.

For routine inspection, start with the readiness views and follow the reported component to its service journal.

## [ SOURCE ]

[ph4ntxm-boot-pilot](../../../config/includes.chroot/usr/local/bin/ph4ntxm-boot-pilot)  
[ph4ntxm-health](../../../config/includes.chroot/usr/local/bin/ph4ntxm-health)  
[ph4ntxm-identity](../../../config/includes.chroot/usr/local/bin/ph4ntxm-identity)  
[ph4ntxm-lockdown](../../../config/includes.chroot/usr/local/bin/ph4ntxm-lockdown)  
[ph4ntxm-panic-button](../../../config/includes.chroot/usr/local/bin/ph4ntxm-panic-button)  
[ph4ntxm-usb-nuke](../../../config/includes.chroot/usr/local/bin/ph4ntxm-usb-nuke)  
[ph4ntxm-document-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-document-airlock)  
[ph4ntxm-media](../../../config/includes.chroot/usr/local/bin/ph4ntxm-media)
