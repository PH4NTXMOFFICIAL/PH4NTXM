# [ APPLICATION GUIDE ]

## [ OVERVIEW ]

Provides the live session's controls and status views. Appearance follows the selected [build edition](../../build/BUILD-EDITIONS.md).

## [ STARTUP ]

Boot Pilot opens automatically. Other controls are available through desktop launchers and tray entries.

## [ RUNTIME ]

Boot Pilot checks readiness and offers Wi-Fi and browser controls. Identity and Health display session state.  
Lockdown controls network containment; Panic requests emergency termination; USB Removal Nuke arms or disarms its removal trigger.  
Document Airlock converts supported documents and images in an offline VM, with preview and explicit PDF export.  
Image Viewer and Media Player open selected local media in disposable offline sandboxes.  
Failed control requests are reported. The OpSec Suite provides detailed diagnostics.

## [ SOURCE ]

[ph4ntxm-boot-pilot](../../../config/includes.chroot/usr/local/bin/ph4ntxm-boot-pilot)  
[ph4ntxm-health](../../../config/includes.chroot/usr/local/bin/ph4ntxm-health)  
[ph4ntxm-identity](../../../config/includes.chroot/usr/local/bin/ph4ntxm-identity)  
[ph4ntxm-lockdown](../../../config/includes.chroot/usr/local/bin/ph4ntxm-lockdown)  
[ph4ntxm-panic-button](../../../config/includes.chroot/usr/local/bin/ph4ntxm-panic-button)  
[ph4ntxm-usb-nuke](../../../config/includes.chroot/usr/local/bin/ph4ntxm-usb-nuke)  
[ph4ntxm-document-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-document-airlock)  
[ph4ntxm-media](../../../config/includes.chroot/usr/local/bin/ph4ntxm-media)
