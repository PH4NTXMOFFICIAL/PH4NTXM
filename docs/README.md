# [ DOCUMENTATION ]

Technical documentation for PH4NTXM's builds, runtime components and operation.

Start with the active mode, then follow the component involved. Session pages share OVERVIEW, STARTUP, RUNTIME, CHECKS and SOURCE sections so related components can be read side by side. Runtime paths refer to the booted live system. Source links point to the files used to build it.

Run session checks in the live environment. For one-shot services, inspect the completion result as well as the generated state. An exited process can be expected after successful setup. Long-running services and fresh readiness records need checking during operation.

## [ BUILD AND APPEARANCE ]

[BUILD EDITIONS](build/BUILD-EDITIONS.md)  
[INSTALLATION](../INSTALLATION.md)

## [ MODES ]

[LINUX](system/session/LINUX.md)  
[WINDOWS](system/session/WINDOWS.md)  
[LONE WOLF](system/session/LONEWOLF.md)

## [ BOOT AND SESSION ]

[BOOT FLOW](system/session/BOOTFLOW.md)  
[MODE](system/session/MODE.md)  
[COMMAND PATH](system/session/COMMAND-PATH.md)  
[SESSION PASSWORD](system/session/SESSION-PASSWORD.md)

## [ IDENTITY AND HARDWARE ]

[IDENTITY RANDOMIZATION](system/session/IDENTITY-RANDOMIZATION.md)  
[LONE WOLF IDENTITY RANDOMIZATION](system/session/LONEWOLF-IDENTITY-RANDOMIZATION.md)  
[HARDWARE RANDOMIZATION](system/session/HARDWARE-RANDOMIZATION.md)  
[LONE WOLF HARDWARE RANDOMIZATION](system/session/LONEWOLF-HARDWARE-RANDOMIZATION.md)  
[CORES RANDOMIZATION](system/session/CORES-RANDOMIZATION.md)  
[LONE WOLF CORES RANDOMIZATION](system/session/LONEWOLF-CORES-RANDOMIZATION.md)  
[CPU INFO SPOOF](system/session/CPU-INFO-SPOOF.md)  
[LONE WOLF CPU SPOOF](system/session/LONEWOLF-CPU-SPOOF.md)  
[HARDWARE VIEWS](system/session/HARDWARE-VIEWS.md)  
[CPU LOCKDOWN](system/session/CPU-LOCKDOWN.md)  
[GPU RANDOMIZATION](system/session/GPU-RANDOMIZATION.md)  
[LONE WOLF GPU RANDOMIZATION](system/session/LONEWOLF-GPU-RANDOMIZATION.md)  
[GPU ENVIRONMENT](system/session/GPU-ENVIRONMENT.md)  
[SCREEN RANDOMIZATION](system/session/SCREEN-RANDOMIZATION.md)  
[LONE WOLF SCREEN RANDOMIZATION](system/session/LONEWOLF-SCREEN-RANDOMIZATION.md)  
[SCREEN GENERATOR](system/session/SCREEN-GENERATOR.md)  
[LONE WOLF SCREEN GENERATOR](system/session/LONEWOLF-SCREEN-GENERATOR.md)  
[CLOCK FUZZ](system/session/CLOCK-FUZZ.md)  
[RAM SEEDING ENGINE](system/session/RAM-SEEDING-ENGINE.md)

## [ BROWSER ]

[BROWSER](system/session/BROWSER.md)  
[BROWSER MODE](system/session/BROWSER-MODE.md)  
[BROWSER POLICY](system/session/BROWSER-POLICY.md)  
[FONTS RANDOMIZATION](system/session/FONTS-RANDOMIZATION.md)  
[TOR BROWSER](system/session/TOR-BROWSER.md)

## [ NETWORK ]

[LINK BLOCK](system/session/LINK-BLOCK.md)  
[NET PREP](system/session/NET-PREP.md)  
[NET RANDOMIZATION](system/session/NET-RANDOMIZATION.md)  
[LONE WOLF NET RANDOMIZATION](system/session/LONEWOLF-NET-RANDOMIZATION.md)  
[DHCP SESSION GENERATOR](system/session/DHCP-SESSION-GENERATOR.md)  
[LONE WOLF DHCP SESSION GENERATOR](system/session/LONEWOLF-DHCP-SESSION-GENERATOR.md)  
[DHCP DISPATCHER](system/session/DHCP-DISPATCHER.md)  
[UNBOUND RANDOMIZATION](system/session/UNBOUND-RANDOMIZATION.md)  
[LONE WOLF DNS BRIDGE](system/session/LONEWOLF-DNS-BRIDGE.md)  
[TOR BOOTSTRAP READY](system/session/TOR-BOOTSTRAP-READY.md)  
[NFT RULES](system/session/NFT-RULES.md)  
[LONE WOLF SETUP](system/session/LONEWOLF-SETUP.md)  
[PACKET TRANSFORMATION ENGINE](system/session/PACKET-TRANSFORMATION-ENGINE.md)  
[PACKET TRANSFORMATION ENGINE GUARD](system/session/PACKET-TRANSFORMATION-ENGINE-GUARD.md)  
[FIREWALL GUARD](system/session/FIREWALL-GUARD.md)  
[LONE WOLF FIREWALL GUARD](system/session/LONEWOLF-FIREWALL-GUARD.md)  
[NET HOTPLUG](system/session/NET-HOTPLUG.md)  
[LINK JITTER](system/session/LINK-JITTER.md)  
[LINK UNBLOCK](system/session/LINK-UNBLOCK.md)  
[NET DRIFT](system/session/NET-DRIFT.md)  
[NET GHOST STACK](system/session/NET-GHOST-STACK.md)

## [ APPLICATIONS AND TOOLS ]

[PH4NTXM APPLICATIONS](system/session/PH4NTXM-APPLICATIONS.md)  
[BOOT PILOT](system/session/BOOT-PILOT.md)  
[HEALTH](system/session/HEALTH.md)  
[IDENTITY](system/session/IDENTITY.md)  
[DOCUMENT AIRLOCK](system/session/DOCUMENT-AIRLOCK.md)  
[MEDIA VIEWERS](system/session/MEDIA-VIEWERS.md)  
[WIFI CONTROL](system/session/WIFI-CONTROL.md)  
[OPERATIONAL TOOLS](system/session/OPERATIONAL-TOOLS.md)  
[PH4NTXM OPSEC SUITE](system/session/PH4NTXM-OPSEC-SUITE.md)  

## [ CONTAINMENT AND TERMINATION ]

[LOCKDOWN](system/session/LOCKDOWN.md)  
[ARM CRASHKERNEL](system/session/ARM-CRASHKERNEL.md)  
[NUKE KERNEL](system/session/NUKE-KERNEL.md)  
[RAM SCRUB](system/session/RAM-SCRUB.md)  
[PANIC](system/session/PANIC.md)  
[USB NUKE](system/session/USB-NUKE.md)  
