# [ NET GUARD ]

## [ OVERVIEW ]

Optional outbound IP approval for processes running as the live user. Protection is off at boot; opening the GTK window leaves it off. Enable, Allow and Disable each require a fresh session password.

## [ STARTUP ]

Enable starts the dedicated service and attaches BPF LSM and root-cgroup egress programs. Existing application sockets become invalid for the new activation: reconnect or restart the application, approve its request, then retry. Missing kernel support prevents activation.

The guard applies in every boot mode, including loopback DNS and Tor SOCKS connections. Approved traffic still passes through the mode's existing firewall, Packet Transformation Engine or Tor path. System services and other UIDs are outside the application approval policy.

## [ RUNTIME ]

Each approval belongs to one process execution, identified by kernel PID, start time and execution generation. Exit or exec ends its permission; reopening the same executable needs a new approval. Browser/helper processes may require separate approvals. Requests show the latest attempted destination; approval covers that execution's outbound IP traffic, rather than one site.

Attempts fail while awaiting approval; they are not suspended during password entry. Keep Blocked acknowledges the displayed request locally. Closing the window leaves enforcement running, and an authenticated action already in progress may finish. Generic notifications open the review window without approving anything.

Approvals, pending requests and pinned kernel objects live in RAM. Disable clears approvals. Restarting an active daemon preserves enforcement but invalidates grants and request tokens. Daemon exit blocks approved traffic; a hang expires its three-second kernel heartbeat. Overflow or unknown socket attribution never grants access.

This is an outbound client-socket control, not application sandboxing. Accepted sockets without tracked ownership cannot send while protection is on. Inherited or transferred sockets cannot be used by a different execution; open a new socket instead. Raw packet/XDP creation and sends are refused while enabled; pre-existing privileged packet rings, kernel-generated traffic and hardware/DMA are outside this policy. An approved application can still act on another process's IPC requests; browser extensions share their process's permission. Root/kernel compromise can bypass the guard.

## [ CHECKS ]

```bash
sudo -n /usr/local/sbin/ph4ntxm-net-guard-control snapshot
systemctl status ph4ntxm-net-guard.service --no-pager
```

Check cancelled authentication, retries after approval, helper processes, close/reopen and Enable/Disable cycles. Test daemon failure separately: traffic must remain denied until authenticated recovery or Disable. Reboot clears the optional guard.

## [ SOURCE ]

[GTK window](../../../config/includes.chroot/usr/local/bin/ph4ntxm-net-guard)\
[Control broker](../../../config/includes.chroot/usr/lib/ph4ntxm/net_guard.py)\
[Native daemon and BPF](../../../config/includes.chroot/usr/local/src/ph4ntxm-net-guard)\
[Service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-net-guard.service)\
[Build hook](../../../config/hooks/normal/0025-build-ph4ntxm-net-guard.chroot)
