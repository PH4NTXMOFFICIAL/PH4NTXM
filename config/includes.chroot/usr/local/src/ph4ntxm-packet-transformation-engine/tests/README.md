# [ NETWORKMANAGER DHCP REGRESSION ]

`networkmanager-dhcp-smoke.sh ROOTFS BUILD_DIR linux|windows` runs the real  
NetworkManager with the PH4NTXM DHCP session generator, a separate dnsmasq  
server, production nftables rules, the native NFQUEUE engine and the TC/eBPF  
classifier. Run both modes as root. BUILD_DIR must contain the matching  
`ph4ntxm-packet-transformation-engine-loader`, `packet-transformation-engine.bpf.o` and  
`ph4ntxm-packet-transformation-engine-native` artifacts.

ROOTFS must be a disposable Debian test rootfs with NetworkManager, D-Bus,  
Python, setpriv and the usual networking utilities installed. The host also  
needs dnsmasq, Python, iproute2, nftables and namespace support. The script  
uses private mount, network, PID and UTS namespaces, temporary mounts and  
test veth interfaces; it needs no external Internet connection. Udev  
initialization metadata is supplied only for the test interfaces.

Success requires a real DHCP lease and default gateway, ping, reconnect  
with unchanged MAC, a matching attached classifier, HTTP traffic through  
the protected path, and a still-running native engine. The classifier is  
loaded with only CAP_NET_ADMIN and CAP_BPF plus NoNewPrivileges.

`ebpf-smoke.sh` additionally checks canonical DHCP headers, option ordering,  
persona parameter lists, packet lengths and checksums for both the legacy  
and NetworkManager native request layouts. Malformed options, duplicate  
maximum-size options, fragments, zero checksums and marked DHCP attempts  
with unknown options must be dropped.

The eBPF object and loader use a dedicated `.rodata.ph4ntxm` section and  
must be rebuilt together. These tests do not replace final ISO boot and  
external packet-capture verification.
