# [ PANIC ]

## [ OVERVIEW ]

Runs the privileged emergency termination path.

## [ STARTUP ]

Runs as root when the Panic service is requested by the operator or armed USB trigger.

## [ RUNTIME ]

Attempts immediate radio and link isolation, invokes the common Nuke script, and requests the armed crashkernel.  
Falls back to a system poweroff request if execution continues. USB trigger state is restored if execution returns through the recovery path.

## [ SOURCE ]

[ph4ntxm-panic.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-panic.sh)
