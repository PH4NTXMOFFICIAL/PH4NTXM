# [ BOOT FLOW ]

## [ OVERVIEW ]

Initializes the selected PH4NTXM mode and its protection chain before the live desktop becomes operational.

## [ STARTUP ]

GRUB selects Linux, Windows, or Lonewolf. The mode service records that choice and activates the matching startup dependencies.

## [ RUNTIME ]

Identity, hardware, CPU, GPU, display, browser, and network components prepare their runtime state.  
Physical links wait for identity, Nuke arming, packet-processing, firewall, and timing checks. Adapters receive their protected MAC before activation.  
After Xfce starts, Boot Pilot displays readiness and provides Wi-Fi selection. Continue closes Pilot; the separate browser action starts the selected browser after rechecking protection state.

## [ SOURCE ]

[ph4ntxm-mode.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/ph4ntxm-mode.sh)  
[ph4ntxm-link-unblock.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-link-unblock.sh)  
[ph4ntxm-boot-pilot](../../../config/includes.chroot/usr/local/bin/ph4ntxm-boot-pilot)
