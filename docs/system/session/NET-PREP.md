# [ NET PREP ]

## [ OVERVIEW ]

Prepares local network state during startup.

## [ STARTUP ]

Network preparation follows mode selection and Link Block, which it requires. The one-shot runs before network-pre and NetworkManager and remains active after completion.

It performs three local cleanup requests. It does not require an established connection or contact a remote endpoint.

## [ RUNTIME ]

First, `ip route flush cache` requests clearing cached routing information. This is not a deletion of the configured routing table or its default routes.

Next, `ip neigh flush all` clears neighbor entries. Required ARP or IPv6 neighbor information can be learned again when networking resumes. Existing entries disappearing here is expected and does not mean the adapter identity has changed.

Finally, the script requests `net.ipv4.tcp_no_metrics_save=1` to prevent saving TCP metrics through that kernel setting. This helper tolerates write failures and leaves readback to the stricter network configuration checks.

All three commands tolerate failure, and the script exits successfully after attempting them. Its service result therefore reports completion of a best-effort preparation pass, not proof that every requested operation took effect.

There is no readiness file, recurring loop or interface release inside this helper. The separate randomization stages apply their required sysctls with readback, and [Link Unblock](LINK-UNBLOCK.md) checks the release prerequisites. NetworkManager then handles connection setup.

## [ CHECKS ]

Check `ip route`, `ip neigh` and `sysctl net.ipv4.tcp_no_metrics_save` directly when a particular result matters. A successful unit status alone cannot verify the three tolerated commands.

For startup troubleshooting, distinguish this cleanup pass from the stricter stages around it. Link Block, DHCP generation and firewall setup have their own service results and outputs.

## [ SOURCE ]

[ph4ntxm-net-prep.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-prep.sh)
