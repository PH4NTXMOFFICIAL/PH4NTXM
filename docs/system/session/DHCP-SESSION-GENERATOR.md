# [ DHCP SESSION GENERATOR ]

## [ OVERVIEW ]

Prepares the Linux/Windows DHCP profile from the selected boot mode and session hostname. NetworkManager and dhclient receive matching client settings, while the protected MAC stays under the identity chain's control.

The generator does not draw another identity. It carries the existing session into network configuration.

## [ STARTUP ]

The one-shot service runs after mode selection and identity randomization, before `network-pre.target`. It requires the identity service and runs only when the normal-mode marker exists.

The script reads `/run/ph4ntxm/mode` and `/etc/hostname`. An unreadable mode file or unsupported mode stops execution. Lone Wolf exits without changes and uses its own generator. If reading the hostname fails, the script uses `unknown`.

## [ RUNTIME ]

Linux and Windows select different client settings:

| Setting | Linux | Windows |
| --- | --- | --- |
| Vendor class | `dhclient` | `MSFT 5.0` |
| DHCP timeout | 60 seconds | 45 seconds |
| IPv6 DHCP DUID setting | `ll` | `stable-uuid` |

Both NetworkManager profiles use `ipv4.dhcp-client-id=mac`, enable hostname advertisement and preserve the existing wired and wireless MAC addresses. The DUID setting belongs to IPv6 DHCP. The IPv4 client identifier follows the interface MAC.

The dhclient request lists also differ in order. Linux requests subnet mask, broadcast address, routers, domain name, DNS servers and hostname. Windows requests subnet mask, routers, DNS servers, hostname, domain name and broadcast address.

Three files carry the result:

- `/run/ph4ntxm/session_dhcp` records mode, vendor, hostname, timeout and DUID for the dispatcher. Permissions are `0600`.
- `/run/NetworkManager/conf.d/90-ph4ntxm-session.conf` supplies connection defaults, including MAC preservation and IPv6 privacy settings.
- `/etc/dhcp/dhclient.conf` supplies the hostname, vendor class, ordered request list and timeout for dhclient.

Each file is written through a temporary file and renamed into place. Replacement is atomic per file. The three replacements happen in sequence, without a shared rollback.

On `up` and `dhcp4-change`, the separate dispatcher reads the saved record and the interface's current MAC. It forms `01:<MAC>` as the IPv4 client identifier and applies the profile to the active NetworkManager device. A failed device update is tolerated in Linux/Windows. Lone Wolf uses a stricter disconnect path.

## [ CHECKS ]

Check the service's completion result before inspecting the generated files. This is a one-shot generator, so it does not remain running after successful setup.

Compare all three outputs with the selected mode. A write failure stops the script, but an earlier replacement may already have completed. One existing file does not prove the whole stage succeeded.

If the files agree but an active connection behaves differently, inspect NetworkManager's journal and the dispatcher event for that interface. Generating configuration, applying active-device settings and obtaining a lease are separate steps.

## [ SOURCE ]

[ph4ntxm-dhcp-session-generator.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-dhcp-session-generator.sh)  
[30-ph4ntxm-dhcp](../../../config/includes.chroot/etc/NetworkManager/dispatcher.d/30-ph4ntxm-dhcp)  
[ph4ntxm-dhcp-session-generator.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-dhcp-session-generator.service)
