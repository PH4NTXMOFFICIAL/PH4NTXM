# [ PANIC BUTTON TRAY ]

## [ OVERVIEW ]

Provides the Panic Button tray entry.

## [ STARTUP ]

The tray process creates a GTK status icon and a menu containing `Nuke PH4NTXM` and Quit. It provides access to the separate confirmation application rather than executing the emergency service directly.

At startup, the icon uses its normal appearance and the PH4NTXM Panic Button tooltip.

## [ RUNTIME ]

Selecting Nuke launches `/usr/local/bin/ph4ntxm-panic-button` as a child. While that tracked child is open, a local flag prevents the same tray process from launching another confirmation window.

The tooltip changes to `Panic Confirmation Open`, and a 500 ms timer alternates the normal icon with a warning icon. This blinking state means the confirmation application is open. It does not mean Nuke has already been activated.

A child-watch callback clears the flag, restores the icon and returns the idle tooltip when the application exits. 

The duplicate protection is local to this tray instance. It does not impose a system-wide lock on confirmation windows started from another launcher.

Quit ends the tray's GTK loop. It does not disable the emergency service, disarm USB Nuke or cancel a child confirmation/application action that already exists. Activation still requires the explicit action in [Panic Button](PANIC-BUTTON.md).

## [ CHECKS ]

If the icon is blinking, check for the open confirmation window before assuming the emergency sequence is active. Canceling that initial window should let the child callback restore idle appearance.

For backend readiness or a returned activation failure, use the service checks rather than the icon. The tray reports its own child-window lifecycle only.

## [ SOURCE ]

[ph4ntxm-panic-button-tray](../../../config/includes.chroot/usr/local/bin/ph4ntxm-panic-button-tray)
