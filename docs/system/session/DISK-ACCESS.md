# [ DISK ACCESS ]

## [ OVERVIEW ]

The live user must enter the session password before mounting an ordinary filesystem through UDisks. Internal disks and permitted USB storage use the same desktop authentication dialog.

## [ STARTUP ]

The policy loads with Polkit. The password is the one chosen during session setup. It adds no application or service. Stock XFCE defaults leave automatic drive and media mounting disabled.

## [ RUNTIME ]

Open an unmounted disk in Thunar and authenticate to mount it normally. Cancelled or failed authentication leaves it unmounted. After unmounting, the next mount requests authentication again. Mounted files remain accessible with their normal filesystem permissions.

USB Guard independently approves hardware connections when enabled. New USB storage then needs two approvals, one for the connection and one for mounting. Non-storage USB devices remain USB Guard's responsibility. Encrypted volumes still need their own unlock key.

The policy targets ordinary UDisks filesystem mount actions for the live user. It does not encrypt media or restrict existing mounts, raw-device access, privileged operations or manual fstab mounts.

## [ CHECKS ]

Test cancelled authentication, a wrong password, successful mounting and writing, then unmount and verify another password request. With USB Guard enabled, verify blocked hardware remains unavailable until approved. Leave USB Nuke disarmed during hotplug tests.

## [ SOURCE ]

[Disk mount policy](../../../config/includes.chroot/usr/share/polkit-1/rules.d/00-ph4ntxm-disk-mount.rules)
