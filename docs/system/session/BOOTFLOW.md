# [ BOOT FLOW ]

## [ OVERVIEW ]

Initializes the selected PH4NTXM mode and its protection chain before the live desktop becomes operational.

## [ STARTUP ]

The boot flow is a dependency graph of system services followed by desktop checks. Mode selection chooses Linux, Windows or Lone Wolf. The visual edition does not choose the network mode.

Early Link Block lowers physical adapters and disables swap. Crash-kernel arming loads the emergency image and locks further kexec loading before the network release gate can succeed.

## [ RUNTIME ]

Identity initialization validates the boot machine ID, saves the appropriate seed, applies hostname/MAC state and publishes `identity-ready`. Hardware selection and the GPU, core, CPU and screen stages create the related local views and browser environment. Their units express ordering. They are not all one serial shell script.

The network branch prepares mode-specific sysctls and DHCP state. Linux/Windows load normal nftables rules and start the packet worker. Lone Wolf installs its Tor redirect/filter policy and uses a separate firewall guard. Link Jitter and Net Prep supply their smaller timing/cleanup steps.

Link Unblock checks identity, emergency-kernel state and the selected protection prerequisites. It prepares physical devices through Net Hotplug, refreshes udev, verifies again and raises eligible interfaces. NetworkManager can then establish connections.

The normal engine guard watches physical egress after release. In Lone Wolf, connectivity lets Tor bootstrap. The DNS bridge then publishes fresh readiness after listener and control checks. Tor readiness therefore follows link release rather than being its prerequisite.

Browser preparation selects and validates the appropriate browser path. After the display server starts, LightDM runs the graphical session setup before starting XFCE. The setup screen uses the edition theme and asks for a new password and confirmation. A failed setup keeps the desktop closed. Desktop Boot Pilot combines service results, generated state and current guardian records before enabling its Continue/browser actions. Background guards, monitoring and thermal control retain their own lifecycle after that window closes.

## [ CHECKS ]

Trace a failure from the reported gate to its unit dependencies and runtime artifact. A completed one-shot may have no running process, while a running guardian can still lack valid readiness.

Avoid interpreting one marker or one green service as completion of the whole boot flow. Health supplies a broader snapshot, including termination wiring and the loaded/locked emergency path.

## [ SOURCE ]

[ph4ntxm-mode.sh](../../../config/includes.chroot/usr/lib/ph4ntxm/ph4ntxm-mode.sh)  
[ph4ntxm-link-unblock.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-link-unblock.sh)  
[ph4ntxm-boot-pilot](../../../config/includes.chroot/usr/local/bin/ph4ntxm-boot-pilot)
