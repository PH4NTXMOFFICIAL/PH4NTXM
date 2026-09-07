#!/usr/bin/env python3
import ctypes
import os
import socket
import struct
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_REFERENCE_ENGINE = ROOT / "tests/reference_engine.py"
NATIVE_LIBRARY = Path(
    os.environ.get(
        "PH4NTXM_PACKET_TRANSFORMATION_ENGINE_NATIVE_LIBRARY",
        ROOT / "target/release/libph4ntxm_packet_transformation_engine_core.so",
    )
)
SEED_HEX = "11" * 32


def load_oracle(mode):
    source = PYTHON_REFERENCE_ENGINE.read_text(encoding="utf-8")
    source = source.replace("from netfilterqueue import NetfilterQueue", "class NetfilterQueue:\n    pass")
    start = source.index("MODE = read_required(MODE_FILE)")
    end = source.index("\nTCP_FLOWS =", start)
    replacement = f'MODE = {mode!r}\nSEED = {SEED_HEX!r}\nSEED_KEY = bytes.fromhex(SEED)\n'
    source = source[:start] + replacement + source[end:]
    module = types.ModuleType(f"packet_transformation_oracle_{mode}")
    module.__file__ = str(PYTHON_REFERENCE_ENGINE)
    exec(compile(source, str(PYTHON_REFERENCE_ENGINE), "exec"), module.__dict__)
    return module


class Native:
    def __init__(self, mode):
        self.library = ctypes.CDLL(str(NATIVE_LIBRARY))
        self.library.ph4ntxm_packet_transformation_engine_new.argtypes = [ctypes.c_uint8, ctypes.c_void_p, ctypes.c_size_t]
        self.library.ph4ntxm_packet_transformation_engine_new.restype = ctypes.c_void_p
        self.library.ph4ntxm_packet_transformation_engine_free.argtypes = [ctypes.c_void_p]
        self.library.ph4ntxm_packet_transformation_engine_process.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_uint8,
            ctypes.c_uint32,
            ctypes.c_uint8,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        seed = (ctypes.c_uint8 * 32).from_buffer_copy(bytes.fromhex(SEED_HEX))
        self.engine = self.library.ph4ntxm_packet_transformation_engine_new(0 if mode == "linux" else 1, seed, 32)
        if not self.engine:
            raise RuntimeError("native engine creation failed")

    def close(self):
        if self.engine:
            self.library.ph4ntxm_packet_transformation_engine_free(self.engine)
            self.engine = None

    def process(self, packet, direction, interface=2, checksum_not_ready=False):
        source = (ctypes.c_uint8 * len(packet)).from_buffer_copy(packet)
        output = (ctypes.c_uint8 * 65535)()
        output_length = ctypes.c_size_t()
        error = ctypes.create_string_buffer(192)
        result = self.library.ph4ntxm_packet_transformation_engine_process(
            self.engine,
            source,
            len(packet),
            1 if direction == "out" else 0,
            interface,
            1 if checksum_not_ready else 0,
            output,
            len(output),
            ctypes.byref(output_length),
            error,
            len(error),
        )
        if result != 1:
            raise ValueError(error.value.decode("ascii", "replace"))
        return bytes(output[: output_length.value])


def checksum(data):
    if len(data) & 1:
        data = bytes(data) + b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4(source, destination, protocol, payload, identifier=0x1234, flags=0x4000, ttl=64):
    source = socket.inet_aton(source)
    destination = socket.inet_aton(destination)
    header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), identifier, flags, ttl, protocol, 0, source, destination))
    struct.pack_into("!H", header, 10, checksum(header))
    return bytes(header) + payload


def ipv6(source, destination, protocol, payload, hop_limit=64):
    source = socket.inet_pton(socket.AF_INET6, source)
    destination = socket.inet_pton(socket.AF_INET6, destination)
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), protocol, hop_limit, source, destination) + payload


def pseudo_checksum(family, source, destination, protocol, segment):
    if family == 4:
        pseudo = socket.inet_aton(source) + socket.inet_aton(destination) + bytes((0, protocol)) + struct.pack("!H", len(segment))
    else:
        pseudo = socket.inet_pton(socket.AF_INET6, source) + socket.inet_pton(socket.AF_INET6, destination)
        pseudo += struct.pack("!I", len(segment)) + b"\0\0\0" + bytes((protocol,))
    return checksum(pseudo + segment)


def udp(family, source, destination, sport, dport, payload):
    segment = bytearray(struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload)
    value = pseudo_checksum(family, source, destination, 17, segment)
    struct.pack_into("!H", segment, 6, value or 0xFFFF)
    return bytes(segment)


def tcp(family, source, destination, sport, dport, sequence, acknowledgement, flags, window, options=b"", payload=b""):
    if len(options) % 4 or len(options) > 40:
        raise ValueError("invalid test TCP options")
    data_offset = (20 + len(options)) // 4
    segment = bytearray(
        struct.pack("!HHIIBBHHH", sport, dport, sequence, acknowledgement, data_offset << 4, flags, window, 0, 0)
        + options
        + payload
    )
    struct.pack_into("!H", segment, 16, pseudo_checksum(family, source, destination, 6, segment))
    return bytes(segment)


def icmp_echo(icmp_type, identifier, sequence, payload):
    segment = bytearray(struct.pack("!BBHHH", icmp_type, 0, 0, identifier, sequence) + payload)
    struct.pack_into("!H", segment, 2, checksum(segment))
    return bytes(segment)


def icmpv6_echo(source, destination, icmp_type, identifier, sequence, payload):
    segment = bytearray(struct.pack("!BBHHH", icmp_type, 0, 0, identifier, sequence) + payload)
    struct.pack_into("!H", segment, 2, pseudo_checksum(6, source, destination, 58, segment))
    return bytes(segment)


def icmp_error(icmp_type, code, quote):
    segment = bytearray(struct.pack("!BBHI", icmp_type, code, 0, 0) + quote)
    struct.pack_into("!H", segment, 2, checksum(segment))
    return bytes(segment)


def icmpv6_error(source, destination, icmp_type, code, quote):
    segment = bytearray(struct.pack("!BBHI", icmp_type, code, 0, 0) + quote)
    struct.pack_into("!H", segment, 2, pseudo_checksum(6, source, destination, 58, segment))
    return bytes(segment)


def assert_pair(oracle, native, packet, direction, interface=2):
    expected = oracle.process_packet(packet, direction, interface)
    actual = native.process(packet, direction, interface)
    if actual != expected:
        raise AssertionError(f"{direction} parity mismatch\npython={expected.hex()}\nrust={actual.hex()}")
    return actual


def run_udp_vectors(mode):
    oracle = load_oracle(mode)
    native = Native(mode)
    try:
        segment = udp(4, "192.0.2.10", "198.51.100.20", 53000, 53, b"ph4ntxm-dns")
        wire_udp = assert_pair(oracle, native, ipv4("192.0.2.10", "198.51.100.20", 17, segment), "out")
        error = ipv4("198.51.100.1", "192.0.2.10", 1, icmp_error(3, 3, wire_udp), flags=0)
        assert_pair(oracle, native, error, "in")
        local6 = "2001:db8::10"
        remote6 = "2001:db8::20"
        router6 = "2001:db8::1"
        segment = udp(6, local6, remote6, 53001, 443, b"ph4ntxm-quic")
        wire6 = assert_pair(oracle, native, ipv6(local6, remote6, 17, segment), "out")
        modern_error = ipv6(router6, local6, 58, icmpv6_error(router6, local6, 4, 10, wire6))
        assert_pair(oracle, native, modern_error, "in")
    finally:
        native.close()


def run_echo_vectors(mode):
    oracle = load_oracle(mode)
    native = Native(mode)
    try:
        request = ipv4("192.0.2.10", "198.51.100.20", 1, icmp_echo(8, 0x2345, 9, b"echo-payload"), flags=0)
        wire_request = assert_pair(oracle, native, request, "out")
        wire_icmp = bytearray(wire_request[20:])
        wire_icmp[0] = 0
        wire_icmp[2:4] = b"\0\0"
        struct.pack_into("!H", wire_icmp, 2, checksum(wire_icmp))
        reply = ipv4("198.51.100.20", "192.0.2.10", 1, wire_icmp, flags=0)
        assert_pair(oracle, native, reply, "in")

        error = ipv4("198.51.100.1", "192.0.2.10", 1, icmp_error(3, 1, wire_request), flags=0)
        assert_pair(oracle, native, error, "in")

        source6 = "2001:db8::10"
        destination6 = "2001:db8::20"
        request6 = ipv6(
            source6,
            destination6,
            58,
            icmpv6_echo(source6, destination6, 128, 0x3456, 17, b"echo-v6"),
        )
        wire_request6 = assert_pair(oracle, native, request6, "out")
        wire_icmp6 = bytearray(wire_request6[40:])
        wire_icmp6[0] = 129
        wire_icmp6[2:4] = b"\0\0"
        struct.pack_into("!H", wire_icmp6, 2, pseudo_checksum(6, destination6, source6, 58, wire_icmp6))
        reply6 = ipv6(destination6, source6, 58, wire_icmp6)
        assert_pair(oracle, native, reply6, "in")
    finally:
        native.close()


def timestamp(options):
    cursor = 0
    while cursor < len(options):
        kind = options[cursor]
        if kind == 0:
            break
        if kind == 1:
            cursor += 1
            continue
        length = options[cursor + 1]
        if kind == 8:
            return struct.unpack_from("!II", options, cursor + 2)
        cursor += length
    return None


def run_tcp_handshake(mode):
    oracle = load_oracle(mode)
    native = Native(mode)
    local = "192.0.2.10"
    remote = "198.51.100.20"
    sport = 49000
    dport = 443
    local_isn = 0x10203040
    remote_isn = 0x55667788
    syn_options = struct.pack("!BBH", 2, 4, 1460) + b"\x04\x02" + b"\x08\x0a" + struct.pack("!II", 1000, 0) + b"\x01\x03\x03\x07"
    try:
        syn = ipv4(local, remote, 6, tcp(4, local, remote, sport, dport, local_isn, 0, 0x02, 64240, syn_options))
        expected_wire = oracle.process_packet(syn, "out", 2)
        actual_wire = native.process(syn, "out", 2)
        if actual_wire != expected_wire:
            raise AssertionError("TCP SYN parity mismatch")
        wire_sequence = struct.unpack_from("!I", expected_wire, 24)[0]
        wire_header_length = (expected_wire[32] >> 4) * 4
        exposed_timestamp = timestamp(expected_wire[40 : 20 + wire_header_length])
        if mode == "linux":
            synack_options = struct.pack("!BBH", 2, 4, 1460) + b"\x04\x02" + b"\x08\x0a" + struct.pack("!II", 5000, exposed_timestamp[0]) + b"\x01\x03\x03\x07"
        else:
            synack_options = struct.pack("!BBH", 2, 4, 1460) + b"\x04\x02\x01\x03\x03\x08\x00\x00"
        synack = ipv4(
            remote,
            local,
            6,
            tcp(4, remote, local, dport, sport, remote_isn, wire_sequence + 1, 0x12, 65535, synack_options),
        )
        local_synack = assert_pair(oracle, native, synack, "in")
        visible_remote_sequence = struct.unpack_from("!I", local_synack, 24)[0]
        if mode == "linux":
            ack_options = b"\x08\x0a" + struct.pack("!II", 1001, 5000) + b"\x01\x01"
        else:
            ack_options = b""
        acknowledgement = ipv4(
            local,
            remote,
            6,
            tcp(4, local, remote, sport, dport, local_isn + 1, visible_remote_sequence + 1, 0x10, 32000, ack_options),
        )
        wire_acknowledgement = assert_pair(oracle, native, acknowledgement, "out")

        if mode == "linux":
            outbound_sack_options = (
                b"\x08\x0a"
                + struct.pack("!II", 1002, 5001)
                + b"\x05\x0a"
                + struct.pack("!II", visible_remote_sequence + 1, visible_remote_sequence + 33)
            )
        else:
            outbound_sack_options = (
                b"\x05\x0a"
                + struct.pack("!II", visible_remote_sequence + 1, visible_remote_sequence + 33)
                + b"\0\0"
            )
        outbound_sack = ipv4(
            local,
            remote,
            6,
            tcp(
                4,
                local,
                remote,
                sport,
                dport,
                local_isn + 1,
                visible_remote_sequence + 1,
                0x10,
                32000,
                outbound_sack_options,
            ),
        )
        wire_outbound_sack = assert_pair(oracle, native, outbound_sack, "out")

        if mode == "linux":
            wire_ack_header_length = (wire_acknowledgement[32] >> 4) * 4
            wire_ack_timestamp = timestamp(wire_acknowledgement[40 : 20 + wire_ack_header_length])[0]
            inbound_sack_options = (
                b"\x08\x0a"
                + struct.pack("!II", 5001, wire_ack_timestamp)
                + b"\x05\x0a"
                + struct.pack("!II", wire_sequence + 1, wire_sequence + 33)
            )
        else:
            inbound_sack_options = b"\x05\x0a" + struct.pack("!II", wire_sequence + 1, wire_sequence + 33) + b"\0\0"
        inbound_sack = ipv4(
            remote,
            local,
            6,
            tcp(
                4,
                remote,
                local,
                dport,
                sport,
                remote_isn + 1,
                wire_sequence + 1,
                0x10,
                32000,
                inbound_sack_options,
            ),
        )
        assert_pair(oracle, native, inbound_sack, "in")

        fragmented_quote = bytearray(wire_acknowledgement)
        struct.pack_into("!H", fragmented_quote, 6, 0x2000)
        struct.pack_into("!H", fragmented_quote, 10, 0)
        struct.pack_into("!H", fragmented_quote, 10, checksum(fragmented_quote[:20]))
        fragmented_error = ipv4(
            "198.51.100.1",
            local,
            1,
            icmp_error(3, 3, fragmented_quote),
            flags=0,
        )
        for implementation in (
            lambda: oracle.process_packet(fragmented_error, "in", 2),
            lambda: native.process(fragmented_error, "in", 2),
        ):
            try:
                implementation()
            except ValueError:
                pass
            else:
                raise AssertionError("fragmented IPv4 ICMP quotation was not dropped")

        error = ipv4("198.51.100.1", local, 1, icmp_error(3, 3, wire_acknowledgement), flags=0)
        assert_pair(oracle, native, error, "in")
        sack_error = ipv4(
            "198.51.100.1", local, 1, icmp_error(3, 3, wire_outbound_sack), flags=0
        )
        assert_pair(oracle, native, sack_error, "in")
    finally:
        native.close()


def run_drop_vectors(mode):
    oracle = load_oracle(mode)
    native = Native(mode)
    try:
        segment = udp(4, "192.0.2.10", "198.51.100.20", 53000, 53, b"drop")
        fragmented = ipv4("192.0.2.10", "198.51.100.20", 17, segment, flags=0x2000)
        for implementation in (
            lambda: oracle.process_packet(fragmented, "out", 2),
            lambda: native.process(fragmented, "out", 2),
        ):
            try:
                implementation()
            except ValueError:
                pass
            else:
                raise AssertionError("fragment was not dropped")

        unmapped_ack = ipv4(
            "192.0.2.10",
            "198.51.100.20",
            6,
            tcp(4, "192.0.2.10", "198.51.100.20", 49000, 443, 1, 1, 0x10, 4096),
        )
        for implementation in (
            lambda: oracle.process_packet(unmapped_ack, "out", 2),
            lambda: native.process(unmapped_ack, "out", 2),
        ):
            try:
                implementation()
            except ValueError:
                pass
            else:
                raise AssertionError("unmapped TCP packet was not dropped")

        bad_checksum = bytearray(ipv4("192.0.2.10", "198.51.100.20", 17, segment))
        bad_checksum[26] ^= 0x80
        try:
            native.process(bad_checksum, "out", 2)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid checksum was accepted without offload metadata")
        repaired = native.process(bad_checksum, "out", 2, checksum_not_ready=True)
        if checksum(repaired[:20]) != 0 or pseudo_checksum(
            4, "192.0.2.10", "198.51.100.20", 17, repaired[20:]
        ) != 0:
            raise AssertionError("checksum-offload packet was not fully repaired")
    finally:
        native.close()


def run_local_vectors(mode):
    oracle = load_oracle(mode)
    native = Native(mode)
    try:
        source = "192.0.2.10"
        destination = "127.0.0.1"
        segment = tcp(4, source, destination, 49001, 53, 0x10203040, 0, 0x02, 64240)
        packet = ipv4(source, destination, 6, segment)
        transformed = assert_pair(oracle, native, packet, "out")
        if transformed != packet:
            raise AssertionError("loopback-DNAT TCP packet received external transformation")

        segment = bytearray(udp(4, source, destination, 53001, 53, b"local-dns"))
        segment[6:8] = b"\0\0"
        packet = ipv4(source, destination, 17, segment)
        transformed = assert_pair(oracle, native, packet, "out")
        if transformed != packet:
            raise AssertionError("loopback-DNAT zero-checksum UDP packet was not preserved")
    finally:
        native.close()


def main():
    if not PYTHON_REFERENCE_ENGINE.is_file() or not NATIVE_LIBRARY.is_file():
        raise SystemExit("build the release native library before running differential tests")
    for mode in ("linux", "windows"):
        run_udp_vectors(mode)
        run_echo_vectors(mode)
        run_tcp_handshake(mode)
        run_drop_vectors(mode)
        run_local_vectors(mode)
    print("differential parity: PASS")


if __name__ == "__main__":
    main()
