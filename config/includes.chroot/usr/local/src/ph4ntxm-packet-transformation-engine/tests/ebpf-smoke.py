#!/usr/bin/python3
import fcntl
import os
import socket
import struct
import subprocess
import sys
import time


SO_MARK = 36
PACKET_TRANSFORMATION_ENGINE_MARK = 0x50544531


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def checksum(data):
    if len(data) & 1:
        data = bytes(data) + b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def interface_mac(interface):
    descriptor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        request = struct.pack("256s", interface.encode("ascii"))
        return fcntl.ioctl(descriptor.fileno(), 0x8927, request)[18:24]
    finally:
        descriptor.close()


def ipv4_packet(payload, source=b"\x0a\x00\x00\x01", destination=b"\x0a\x00\x00\x02",
                protocol=17, ttl=37, identification=0x1234, flags=0, tos=0):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, tos, 20 + len(payload), identification,
                         flags, ttl, protocol, 0, source, destination)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def raw_ipv4_frame(source_mac, destination_mac):
    payload = b"UNMARKED-Packet Transformation Engine-BYPASS"
    udp = struct.pack("!HHHH", 40000, 40001, 8 + len(payload), 0) + payload
    return destination_mac + source_mac + b"\x08\x00" + ipv4_packet(udp)


def arp_payload(source_mac, arp_source_mac=None):
    if arp_source_mac is None:
        arp_source_mac = source_mac
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, arp_source_mac,
                       b"\x00" * 4, b"\x00" * 6, b"\x0a\x00\x00\x02")


def arp_frame(source_mac, arp_source_mac=None):
    return b"\xff" * 6 + source_mac + b"\x08\x06" + arp_payload(source_mac, arp_source_mac)


def vlan_arp_frame(source_mac, depth):
    frame = b"\xff" * 6 + source_mac
    for index in range(depth):
        frame += b"\x81\x00" + struct.pack("!H", index + 1)
    return frame + b"\x08\x06" + arp_payload(source_mac)


def eapol_frame(source_mac, malformed=False):
    length = 1 if malformed else 0
    return b"\x01\x80\xc2\x00\x00\x03" + source_mac + b"\x88\x8e" + \
        struct.pack("!BBH", 2, 1, length)


def dhcp_frame(source_mac, mode="linux", client_mac=None, zero_checksum=False,
               unknown_option=False, dirty_reserved=False, wrong_hostname=False,
               wrong_vendor=False, wrong_parameter_list=False, duplicate_message=False,
               source_ip=None, client_address=None, message_type=1,
               native_client=False, native_max_size=576, duplicate_max_size=False,
               fragment_flags=None):
    if client_mac is None:
        client_mac = source_mac
    if source_ip is None:
        source_ip = b"\x00" * 4
    if client_address is None:
        client_address = b"\x00" * 4
    bootp = bytearray(236)
    bootp[0:4] = b"\x01\x01\x06\x00"
    bootp[4:8] = b"TEST"
    bootp[10:12] = struct.pack("!H", 0x8000)
    bootp[12:16] = client_address
    bootp[28:34] = client_mac
    if dirty_reserved:
        bootp[34] = 1
    with open("/etc/hostname", "rb") as source:
        hostname = source.read().strip()
    vendor = b"dhclient" if mode == "linux" else b"MSFT 5.0"
    parameter_list = (b"\x01\x1c\x03\x0f\x06\x0c" if mode == "linux" else
                      b"\x01\x03\x06\x0c\x0f\x1c")
    if wrong_hostname:
        hostname = b"incorrect-host"
    if wrong_vendor:
        vendor = b"BADVENDR"
    if wrong_parameter_list:
        parameter_list = bytes(reversed(parameter_list))
    options = (b"\x63\x82\x53\x63" + bytes((53, 1, message_type)) +
               bytes((12, len(hostname))) + hostname +
               b"\x37\x06" + parameter_list +
               b"\x3c\x08" + vendor + b"\x3d\x07\x01" + client_mac)
    if native_client:
        native_prl = bytes((1, 2, 6, 12, 15, 26, 28, 121, 3, 33, 40, 41, 42,
                            119, 249, 252, 17))
        options = (b"\x63\x82\x53\x63" + bytes((53, 1, message_type)) +
                   b"\x3d\x07\x01" + client_mac + b"\x37\x11" + native_prl +
                   b"\x39\x02" + struct.pack("!H", native_max_size) +
                   bytes((12, len(hostname))) + hostname + b"\x3c\x08" + vendor)
        if duplicate_max_size:
            options += b"\x39\x02\x02\x40"
    if duplicate_message:
        options += b"\x35\x01\x01"
    if unknown_option:
        options += b"\xc8\x01\x00"
    options += b"\xff"
    payload = bytes(bootp) + options
    udp_length = 8 + len(payload)
    destination_ip = b"\xff" * 4
    udp = struct.pack("!HHHH", 68, 67, udp_length, 0) + payload
    pseudo = source_ip + destination_ip + b"\x00\x11" + struct.pack("!H", udp_length)
    udp_checksum = checksum(pseudo + udp)
    if udp_checksum == 0:
        udp_checksum = 0xFFFF
    if zero_checksum:
        udp_checksum = 0
    udp = udp[:6] + struct.pack("!H", udp_checksum) + udp[8:]
    flags = (0x4000 if native_client else 0) if fragment_flags is None else fragment_flags
    packet = ipv4_packet(udp, source_ip, destination_ip, 17,
                         64 if native_client else 128, 0, flags, 0 if native_client else 0x10)
    return b"\xff" * 6 + source_mac + b"\x08\x00" + packet


def send_frame(outgoing, incoming, frame, timeout=0.35, mark=0):
    receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    receiver.bind((incoming, 0))
    receiver.settimeout(timeout)
    sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sender.bind((outgoing, 0))
    if mark:
        sender.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
    try:
        try:
            sender.send(frame)
        except OSError as error:
            if error.errno == 105:
                return None
            raise
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            candidate = receiver.recv(4096)
            if candidate[:14] == frame[:14] or \
                    (candidate[6:12] == frame[6:12] and frame[-28:] in candidate):
                return candidate
    except TimeoutError:
        return None
    finally:
        sender.close()
        receiver.close()
    return None


def send_marked_l3(outgoing, incoming, family, timeout=0.5):
    marker = b"Packet Transformation Engine-MARKED-" + (b"IPV4" if family == socket.AF_INET else b"IPV6")
    receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    receiver.bind((incoming, 0))
    receiver.settimeout(timeout)
    sender = socket.socket(family, socket.SOCK_DGRAM)
    sender.setsockopt(socket.SOL_SOCKET, SO_MARK, PACKET_TRANSFORMATION_ENGINE_MARK)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, outgoing.encode() + b"\0")
    source = "10.0.0.1" if family == socket.AF_INET else "2001:db8::1"
    destination = "10.0.0.2" if family == socket.AF_INET else "2001:db8::2"
    sender.bind((source, 40000))
    try:
        try:
            sender.sendto(marker, (destination, 40001))
        except OSError as error:
            if error.errno == 105:
                return None
            raise
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            candidate = receiver.recv(4096)
            if marker in candidate:
                return candidate
    except TimeoutError:
        return None
    finally:
        sender.close()
        receiver.close()
    return None


def validate_dhcp(frame, expected_ttl, expected_df):
    require(frame is not None, "valid DHCP was dropped")
    ip = frame[14:34]
    require(len(ip) == 20 and checksum(ip) == 0, "rewritten IPv4 checksum is invalid")
    identification, flags, ttl = struct.unpack("!HHB", ip[4:9])
    require(identification != 0, "rewritten IPv4 ID is zero")
    require(ttl == expected_ttl, f"unexpected DHCP persona TTL {ttl}")
    require(bool(flags & 0x4000) == expected_df, "unexpected DHCP persona DF")
    udp_length = struct.unpack("!H", frame[38:40])[0]
    udp = frame[34:34 + udp_length]
    pseudo = ip[12:20] + b"\x00\x11" + struct.pack("!H", udp_length)
    require(checksum(pseudo + udp) == 0, "rewritten DHCP UDP checksum is invalid")
    require(struct.unpack("!H", ip[2:4])[0] == len(frame) - 14,
            "canonical IPv4 length mismatch")
    require(udp_length == len(frame) - 34, "canonical UDP length mismatch")
    require(ip[1] == 0, "client TOS escaped normalization")
    options = frame[282:]
    parsed = []
    cursor = 0
    while cursor < len(options):
        code = options[cursor]
        cursor += 1
        if code == 255:
            require(not any(options[cursor:]), "nonzero DHCP trailing padding")
            break
        require(code != 0, "client-specific interior padding escaped")
        size = options[cursor]
        cursor += 1
        parsed.append((code, options[cursor:cursor + size]))
        cursor += size
    require([code for code, _ in parsed] == [53, 61, 12, 60, 55],
            "DHCP options not canonicalized")
    wanted_prl = bytes((1, 3, 6, 12, 15, 28) if expected_df else (1, 28, 3, 15, 6, 12))
    require(dict(parsed)[55] == wanted_prl, "native PRL escaped normalization")


def full_test(outgoing, incoming, loader):
    source_mac = interface_mac(outgoing)
    peer_mac = interface_mac(incoming)
    require(send_marked_l3(outgoing, incoming, socket.AF_INET) is not None,
            "marked IPv4 was dropped")
    require(send_marked_l3(outgoing, incoming, socket.AF_INET6) is not None,
            "marked IPv6 was dropped")
    require(send_frame(outgoing, incoming, raw_ipv4_frame(source_mac, peer_mac)) is None,
            "unmarked raw IPv4 escaped")
    require(send_frame(outgoing, incoming, arp_frame(source_mac)) is not None,
            "valid ARP was dropped")
    spoofed = b"\x02\xaa\xbb\xcc\xdd\xee"
    require(send_frame(outgoing, incoming, arp_frame(source_mac, spoofed)) is None,
            "ARP sender-MAC spoof escaped")
    require(send_frame(outgoing, incoming, vlan_arp_frame(source_mac, 1)) is not None,
            "valid VLAN ARP was dropped")
    require(send_frame(outgoing, incoming, vlan_arp_frame(source_mac, 3)) is None,
            "over-depth VLAN frame escaped")
    require(send_frame(outgoing, incoming, eapol_frame(source_mac)) is not None,
            "valid EAPOL-Start was dropped")
    require(send_frame(outgoing, incoming, eapol_frame(source_mac, True)) is None,
            "malformed EAPOL-Start escaped")
    validate_dhcp(send_frame(outgoing, incoming, dhcp_frame(source_mac)), 64, False)
    validate_dhcp(send_frame(outgoing, incoming, dhcp_frame(source_mac, native_client=True)),
                  64, False)
    validate_dhcp(send_frame(outgoing, incoming, dhcp_frame(source_mac, native_client=True),
                             mark=PACKET_TRANSFORMATION_ENGINE_MARK), 64, False)
    require(send_frame(outgoing, incoming,
                       dhcp_frame(source_mac, native_client=True, unknown_option=True),
                       mark=PACKET_TRANSFORMATION_ENGINE_MARK) is None, "marked DHCP bypassed option checks")
    for changes in ({"native_max_size": 575}, {"duplicate_max_size": True},
                    {"fragment_flags": 0x2000}, {"fragment_flags": 1},
                    {"fragment_flags": 0x8000}, {"zero_checksum": True},
                    {"unknown_option": True}):
        require(send_frame(outgoing, incoming,
                           dhcp_frame(source_mac, native_client=True, **changes)) is None,
                f"invalid native DHCP escaped: {changes}")
    assigned = socket.inet_aton("192.0.2.10")
    validate_dhcp(send_frame(outgoing, incoming,
                             dhcp_frame(source_mac, source_ip=assigned,
                                        client_address=assigned, message_type=3)),
                  64, False)
    require(send_frame(outgoing, incoming,
                       dhcp_frame(source_mac, source_ip=assigned,
                                  client_address=b"\x00" * 4, message_type=3)) is None,
            "DHCP source/ciaddr mismatch escaped")
    require(send_frame(outgoing, incoming, dhcp_frame(source_mac, client_mac=spoofed)) is None,
            "DHCP chaddr spoof escaped")
    require(send_frame(outgoing, incoming, dhcp_frame(source_mac, zero_checksum=True)) is None,
            "zero-checksum DHCP escaped")
    require(send_frame(outgoing, incoming, dhcp_frame(source_mac, unknown_option=True)) is None,
            "unknown DHCP option escaped")
    require(send_frame(outgoing, incoming, dhcp_frame(source_mac, dirty_reserved=True)) is None,
            "dirty DHCP reserved field escaped")
    require(send_frame(outgoing, incoming, dhcp_frame(source_mac, wrong_hostname=True)) is None,
            "wrong DHCP hostname escaped")
    require(send_frame(outgoing, incoming, dhcp_frame(source_mac, wrong_vendor=True)) is None,
            "wrong DHCP vendor escaped")
    require(send_frame(outgoing, incoming,
                       dhcp_frame(source_mac, wrong_parameter_list=True)) is None,
            "wrong DHCP parameter list escaped")
    require(send_frame(outgoing, incoming, dhcp_frame(source_mac, duplicate_message=True)) is None,
            "duplicate DHCP message type escaped")
    with open("/run/ph4ntxm/mode", "w", encoding="ascii") as destination:
        destination.write("windows\n")
    subprocess.run([loader, "attach", outgoing], check=True)
    subprocess.run([loader, "verify", outgoing], check=True)
    validate_dhcp(send_frame(outgoing, incoming, dhcp_frame(source_mac, mode="windows")),
                  128, True)
    validate_dhcp(send_frame(outgoing, incoming,
                             dhcp_frame(source_mac, mode="windows", native_client=True)),
                  128, True)


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--fallback":
        require(send_marked_l3("audit0", "audit1", socket.AF_INET) is None,
                "fallback allowed marked IPv4")
        print("fallback-drop: PASS")
        return
    if len(sys.argv) != 4:
        raise SystemExit("usage: ebpf-smoke.py OUT IN LOADER")
    full_test(sys.argv[1], sys.argv[2], sys.argv[3])
    print("marked-v4-v6 raw-drop arp vlan eapol dhcp-linux-windows negatives: PASS")


if __name__ == "__main__":
    main()
