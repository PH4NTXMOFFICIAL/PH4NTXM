#!/usr/bin/python3
import ctypes
import os
import random
import socket
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LIBRARY = Path(os.environ.get(
    "PH4NTXM_PACKET_TRANSFORMATION_ENGINE_NATIVE_LIBRARY",
    ROOT / "target/release/libph4ntxm_packet_transformation_engine_core.so",
))
SEED = bytes.fromhex("a5" * 32)


def checksum(data):
    if len(data) & 1:
        data = bytes(data) + b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def pseudo_checksum(family, source, destination, protocol, segment):
    if family == 4:
        pseudo = source + destination + bytes((0, protocol)) + struct.pack("!H", len(segment))
    else:
        pseudo = source + destination + struct.pack("!I", len(segment)) + b"\0\0\0" + bytes((protocol,))
    return checksum(pseudo + segment)


def ipv4(source, destination, protocol, payload):
    header = bytearray(struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1234, 0x4000,
        64, protocol, 0, source, destination,
    ))
    struct.pack_into("!H", header, 10, checksum(header))
    return bytes(header) + payload


def ipv6(source, destination, protocol, payload, hop_limit=64):
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), protocol, hop_limit,
                       source, destination) + payload


def udp(family, source, destination, payload):
    segment = bytearray(struct.pack("!HHHH", 49152, 443, 8 + len(payload), 0) + payload)
    value = pseudo_checksum(family, source, destination, 17, segment)
    struct.pack_into("!H", segment, 6, value or 0xFFFF)
    return bytes(segment)


def tcp(family, source, destination):
    options = b"\x02\x04\x05\xb4\x04\x02\x08\x0a" + struct.pack("!II", 1, 0)
    segment = bytearray(struct.pack(
        "!HHIIBBHHH", 49152, 443, 0x10203040, 0, 9 << 4, 2, 64240, 0, 0,
    ) + options)
    struct.pack_into("!H", segment, 16,
                     pseudo_checksum(family, source, destination, 6, segment))
    return bytes(segment)


def echo(family, source, destination):
    kind = 8 if family == 4 else 128
    segment = bytearray(struct.pack("!BBHHH", kind, 0, 0, 0x1234, 1) + b"ph4ntxm-fuzz")
    value = checksum(segment) if family == 4 else pseudo_checksum(
        6, source, destination, 58, segment,
    )
    struct.pack_into("!H", segment, 2, value)
    return bytes(segment)


def icmpv6(source, destination, kind, body):
    segment = bytearray(struct.pack("!BBH", kind, 0, 0) + body)
    struct.pack_into("!H", segment, 2,
                     pseudo_checksum(6, source, destination, 58, segment))
    return bytes(segment)


class Core:
    def __init__(self, mode):
        self.library = ctypes.CDLL(str(LIBRARY))
        self.library.ph4ntxm_packet_transformation_engine_new.argtypes = [
            ctypes.c_uint8, ctypes.c_void_p, ctypes.c_size_t,
        ]
        self.library.ph4ntxm_packet_transformation_engine_new.restype = ctypes.c_void_p
        self.library.ph4ntxm_packet_transformation_engine_free.argtypes = [ctypes.c_void_p]
        self.library.ph4ntxm_packet_transformation_engine_process.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint8,
            ctypes.c_uint32, ctypes.c_uint8, ctypes.c_void_p, ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t,
        ]
        seed = (ctypes.c_uint8 * len(SEED)).from_buffer_copy(SEED)
        self.engine = self.library.ph4ntxm_packet_transformation_engine_new(mode, seed, len(SEED))
        if not self.engine:
            raise RuntimeError("native engine creation failed")
        self.output = (ctypes.c_uint8 * 65535)()
        self.error = ctypes.create_string_buffer(192)

    def close(self):
        self.library.ph4ntxm_packet_transformation_engine_free(self.engine)

    def process(self, packet, outbound, interface, checksum_not_ready):
        source = (ctypes.c_uint8 * len(packet)).from_buffer_copy(packet)
        output_length = ctypes.c_size_t()
        self.error.raw = b"\0" * len(self.error)
        result = self.library.ph4ntxm_packet_transformation_engine_process(
            self.engine, source, len(packet), outbound, interface,
            checksum_not_ready, self.output, len(self.output),
            ctypes.byref(output_length), self.error, len(self.error),
        )
        if result not in (0, 1):
            raise RuntimeError(f"unexpected native result {result}")
        if result == 0:
            if output_length.value != 0:
                raise RuntimeError("drop returned a nonempty output")
            return None
        output = bytes(self.output[:output_length.value])
        validate_output(output, bool(outbound))
        return output


def validate_output(packet, outbound):
    if not packet or len(packet) > 65535:
        raise RuntimeError("accepted output has an invalid size")
    family = packet[0] >> 4
    if family == 4:
        if len(packet) < 20 or packet[0] != 0x45 or struct.unpack_from("!H", packet, 2)[0] != len(packet):
            raise RuntimeError("accepted output has an invalid IPv4 layout")
        if checksum(packet[:20]) != 0:
            raise RuntimeError("accepted output has an invalid IPv4 checksum")
        protocol = packet[9]
        offset = 20
        source, destination = packet[12:16], packet[16:20]
    elif family == 6:
        if len(packet) < 40 or 40 + struct.unpack_from("!H", packet, 4)[0] != len(packet):
            raise RuntimeError("accepted output has an invalid IPv6 layout")
        protocol = packet[6]
        offset = 40
        if protocol == 0:
            if len(packet) < 48:
                raise RuntimeError("accepted output has a truncated hop-by-hop header")
            offset += (packet[41] + 1) * 8
            protocol = packet[40]
        source, destination = packet[8:24], packet[24:40]
    else:
        raise RuntimeError("accepted output has an unknown IP version")
    segment = packet[offset:]
    if protocol == 6:
        if len(segment) < 20 or not 20 <= (segment[12] >> 4) * 4 <= min(60, len(segment)):
            raise RuntimeError("accepted output has an invalid TCP layout")
        if pseudo_checksum(family, source, destination, protocol, segment) != 0:
            raise RuntimeError("accepted output has an invalid TCP checksum")
    elif protocol == 17:
        if len(segment) < 8 or struct.unpack_from("!H", segment, 4)[0] != len(segment):
            raise RuntimeError("accepted output has an invalid UDP layout")
        received = struct.unpack_from("!H", segment, 6)[0]
        if received == 0 and (family == 6 or outbound):
            raise RuntimeError("accepted output has a forbidden zero UDP checksum")
        if received != 0 and pseudo_checksum(family, source, destination, protocol, segment) != 0:
            raise RuntimeError("accepted output has an invalid UDP checksum")
    elif protocol == 1:
        if len(segment) < 8 or checksum(segment) != 0:
            raise RuntimeError("accepted output has an invalid ICMP checksum")
    elif protocol == 58:
        if len(segment) < 8 or pseudo_checksum(family, source, destination, protocol, segment) != 0:
            raise RuntimeError("accepted output has an invalid ICMPv6 checksum")
    else:
        raise RuntimeError("accepted output has an unsupported protocol")


def corpus():
    source4 = socket.inet_aton("192.0.2.10")
    destination4 = socket.inet_aton("198.51.100.20")
    source6 = socket.inet_pton(socket.AF_INET6, "2001:db8::10")
    destination6 = socket.inet_pton(socket.AF_INET6, "2001:db8::20")
    link_source = socket.inet_pton(socket.AF_INET6, "fe80::1")
    link_target = socket.inet_pton(socket.AF_INET6, "fe80::2")
    solicited = socket.inet_pton(socket.AF_INET6, "ff02::1:ff00:2")
    mld_destination = socket.inet_pton(socket.AF_INET6, "ff02::16")
    neighbor_solicitation = icmpv6(
        link_source,
        solicited,
        135,
        b"\0" * 4 + link_target + b"\x01\x01\x02\x00\x00\x00\x00\x01",
    )
    mld_report = icmpv6(
        link_source,
        mld_destination,
        131,
        b"\0" * 4 + mld_destination,
    )
    router_alert = b"\x3a\x00\x05\x02\x00\x00\x01\x00"
    return [
        ipv4(source4, destination4, 17, udp(4, source4, destination4, b"udp")),
        ipv4(source4, destination4, 6, tcp(4, source4, destination4)),
        ipv4(source4, destination4, 1, echo(4, source4, destination4)),
        ipv6(source6, destination6, 17, udp(6, source6, destination6, b"udp6")),
        ipv6(source6, destination6, 6, tcp(6, source6, destination6)),
        ipv6(source6, destination6, 58, echo(6, source6, destination6)),
        ipv6(link_source, solicited, 58, neighbor_solicitation, hop_limit=255),
        ipv6(link_source, mld_destination, 0, router_alert + mld_report, hop_limit=1),
    ]


def exercise(mode):
    rng = random.Random(0x50484500 + mode)
    core = Core(mode)
    cases = 0
    try:
        for original in corpus():
            for length in range(1, len(original) + 2):
                core.process(original[:length], cases & 1, 2, cases % 3 == 0)
                cases += 1
            for index in range(len(original)):
                mutated = bytearray(original)
                mutated[index] ^= 1 << (index & 7)
                core.process(mutated, cases & 1, 2, cases % 3 == 0)
                cases += 1
            for extra in (b"\0", b"\0" * 16, bytes(range(64))):
                core.process(original + extra, cases & 1, 2, cases % 3 == 0)
                cases += 1
        for _ in range(20000):
            selector = rng.randrange(100)
            if selector < 70:
                length = rng.randrange(1, 257)
            elif selector < 98:
                length = rng.randrange(257, 2049)
            else:
                length = rng.choice((4095, 4096, 8191, 32767, 65531, 65535))
            packet = bytearray(rng.randbytes(length))
            if selector & 1:
                packet[0] = (packet[0] & 0x0F) | (0x40 if selector & 2 else 0x60)
            core.process(packet, selector & 1, rng.choice((0, 1, 2, 0xFFFFFFFF)), selector % 5 == 0)
            cases += 1
    finally:
        core.close()
    return cases


def main():
    if not LIBRARY.is_file():
        raise SystemExit("build the release native library before running fuzz smoke")
    total = exercise(0) + exercise(1)
    print(f"deterministic-parser-fuzz cases={total}: PASS")


if __name__ == "__main__":
    main()
