#!/usr/bin/env python3
import hashlib
import os
import select
import socket
import stat
import struct
import threading
import time
from collections import OrderedDict

from netfilterqueue import NetfilterQueue

STATE_DIR = "/run/ph4ntxm"
MODE_FILE = f"{STATE_DIR}/mode"
SEED_FILE = f"{STATE_DIR}/persona_seed"
INBOUND_QUEUE = 1
OUTBOUND_QUEUE = 2
QUEUE_LENGTH = 4096
QUEUE_COPY_RANGE = 65535
MIN_EFFECTIVE_COPY_RANGE = 4000
QUEUE_HEALTH_INTERVAL = 5
TCP_FLOW_TIMEOUT = 432000
TCP_HALF_CLOSED_TIMEOUT = 432000
TCP_CLOSED_TIMEOUT = 240
UDP_FLOW_TIMEOUT = 300
ECHO_FLOW_TIMEOUT = 300
MAX_TCP_FLOWS = 65536
MAX_UDP_FLOWS = 65536
MAX_ECHO_FLOWS = 4096
ERROR_LOG_INTERVAL = 30
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58
ICMPV4_ALLOWED = {0, 3, 8, 11, 12}
ICMPV4_ERRORS = {3, 11, 12}
ICMPV6_ERRORS = {1, 2, 3, 4}
ICMPV6_ECHO = {128, 129}
ICMPV6_MLD = {130, 131, 132, 143}
ICMPV6_ND = {133, 134, 135, 136, 137}


def read_required(path):
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise RuntimeError(f"unsafe required state: {path}")
        chunks = []
        remaining = 1025
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > 1024:
            raise RuntimeError(f"oversized required state: {path}")
        value = value.decode("ascii", "strict").strip()
    finally:
        os.close(descriptor)
    if not value:
        raise RuntimeError(f"empty required state: {path}")
    return value


MODE = read_required(MODE_FILE)
SEED = read_required(SEED_FILE)
if MODE not in {"linux", "windows"}:
    raise SystemExit("invalid mode")
if len(SEED) != 64:
    raise SystemExit("invalid persona seed length")
try:
    SEED_KEY = bytes.fromhex(SEED)
except ValueError as error:
    raise SystemExit("invalid persona seed encoding") from error
if len(SEED_KEY) != 32 or SEED != SEED.lower():
    raise SystemExit("invalid persona seed")

TCP_FLOWS = OrderedDict()
UDP_FLOWS = OrderedDict()
ECHO_BY_LOCAL = OrderedDict()
ECHO_BY_WIRE = {}
STATE_LOCK = threading.RLock()
LAST_ERROR_LOG = 0.0
FLOW_GENERATION = 0
IPID_COUNTER = 0


def encode_part(value):
    if isinstance(value, bytes):
        data = value
    elif isinstance(value, int):
        if value < 0:
            raise ValueError("negative derivation value")
        size = max(1, (value.bit_length() + 7) // 8)
        data = value.to_bytes(size, "big")
    else:
        data = str(value).encode("ascii", "strict")
    return len(data).to_bytes(4, "big") + data


def derived_int(label, *parts, bits=32):
    size = max(1, (bits + 7) // 8)
    digest = hashlib.blake2s(key=SEED_KEY, digest_size=size)
    digest.update(encode_part(label))
    for part in parts:
        digest.update(encode_part(part))
    return int.from_bytes(digest.digest(), "big") & ((1 << bits) - 1)


def checksum(data):
    if len(data) & 1:
        data = bytes(data) + b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def transport_checksum(packet, meta, segment):
    length = len(segment)
    if meta["family"] == 4:
        pseudo = meta["src"] + meta["dst"] + bytes((0, meta["protocol"])) + struct.pack("!H", length)
    else:
        pseudo = meta["src"] + meta["dst"] + struct.pack("!I", length) + b"\x00\x00\x00" + bytes((meta["protocol"],))
    return checksum(pseudo + segment)


def parse_hop_by_hop(raw):
    if len(raw) < 48:
        raise ValueError("truncated hop-by-hop header")
    header_length = (raw[41] + 1) * 8
    end = 40 + header_length
    if header_length < 8 or end > len(raw):
        raise ValueError("invalid hop-by-hop length")
    if raw[40] != IPPROTO_ICMPV6:
        raise ValueError("unsupported extension-header chain")
    cursor = 42
    router_alert = 0
    while cursor < end:
        kind = raw[cursor]
        if kind == 0:
            cursor += 1
            continue
        if cursor + 2 > end:
            raise ValueError("truncated hop-by-hop option")
        option_length = raw[cursor + 1]
        option_end = cursor + 2 + option_length
        if option_end > end:
            raise ValueError("invalid hop-by-hop option length")
        value = raw[cursor + 2:option_end]
        if kind == 1:
            if any(value):
                raise ValueError("nonzero hop-by-hop padding")
        elif kind == 5:
            if option_length != 2 or value != b"\x00\x00":
                raise ValueError("unsupported router-alert option")
            router_alert += 1
        else:
            raise ValueError("unsupported hop-by-hop option")
        cursor = option_end
    if router_alert != 1:
        raise ValueError("missing MLD router-alert option")
    return end


def ipv6_requires_scope(source, destination):
    for address in (source, destination):
        if address[0] == 0xFE and address[1] & 0xC0 == 0x80:
            return True
        if address[0] == 0xFF and address[1] & 0x0F <= 2:
            return True
    return False


def parse_packet(raw, interface=0):
    if not raw:
        raise ValueError("empty packet")
    version = raw[0] >> 4
    if version == 4:
        if len(raw) < 20:
            raise ValueError("truncated IPv4 header")
        ihl = (raw[0] & 0x0F) * 4
        if ihl != 20:
            raise ValueError("IPv4 options are not permitted")
        total_length = struct.unpack_from("!H", raw, 2)[0]
        if total_length != len(raw) or total_length < 20:
            raise ValueError("IPv4 length mismatch")
        if checksum(raw[:20]) != 0:
            raise ValueError("invalid IPv4 header checksum")
        fragment = struct.unpack_from("!H", raw, 6)[0]
        if fragment & 0x8000:
            raise ValueError("invalid IPv4 reserved flag")
        if fragment & 0x3FFF:
            raise ValueError("IPv4 fragments are not permitted")
        protocol = raw[9]
        if protocol not in {IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP}:
            raise ValueError("unsupported IPv4 protocol")
        return {
            "family": 4,
            "protocol": protocol,
            "offset": 20,
            "src": raw[12:16],
            "dst": raw[16:20],
            "hop_by_hop": False,
            "scope": 0,
            "interface": interface,
        }
    if version == 6:
        if len(raw) < 40:
            raise ValueError("truncated IPv6 header")
        payload_length = struct.unpack_from("!H", raw, 4)[0]
        if payload_length == 0 and len(raw) != 40:
            raise ValueError("IPv6 jumbograms are not permitted")
        if 40 + payload_length != len(raw):
            raise ValueError("IPv6 length mismatch")
        next_header = raw[6]
        hop_by_hop = next_header == 0
        if hop_by_hop:
            offset = parse_hop_by_hop(raw)
            protocol = IPPROTO_ICMPV6
        else:
            offset = 40
            protocol = next_header
        if protocol not in {IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6}:
            raise ValueError("unsupported IPv6 next header")
        source = raw[8:24]
        destination = raw[24:40]
        scope = interface if ipv6_requires_scope(source, destination) else 0
        if ipv6_requires_scope(source, destination) and interface <= 0:
            raise ValueError("missing IPv6 scope interface")
        return {
            "family": 6,
            "protocol": protocol,
            "offset": offset,
            "src": source,
            "dst": destination,
            "hop_by_hop": hop_by_hop,
            "scope": scope,
            "interface": interface,
        }
    raise ValueError("unsupported IP version")


def validate_tcp_options(options, syn, ack, linux_mode=None):
    if linux_mode is None:
        linux_mode = MODE == "linux"
    parsed = []
    singletons = set()
    cursor = 0
    while cursor < len(options):
        kind = options[cursor]
        if kind == 0:
            if any(options[cursor + 1:]):
                raise ValueError("nonzero TCP option padding")
            parsed.append((0, b"\x00"))
            break
        if kind == 1:
            parsed.append((1, b"\x01"))
            cursor += 1
            continue
        if cursor + 2 > len(options):
            raise ValueError("truncated TCP option")
        option_length = options[cursor + 1]
        if option_length < 2 or cursor + option_length > len(options):
            raise ValueError("invalid TCP option length")
        value = options[cursor:cursor + option_length]
        if kind in {2, 3, 4, 5, 8, 34} and kind in singletons:
            raise ValueError("duplicate TCP option")
        if kind == 2:
            if option_length != 4 or not syn:
                raise ValueError("invalid MSS option")
            if struct.unpack_from("!H", value, 2)[0] == 0:
                raise ValueError("invalid MSS value")
        elif kind == 3:
            if option_length != 3 or not syn or value[2] > 14:
                raise ValueError("invalid window-scale option")
        elif kind == 4:
            if option_length != 2 or not syn:
                raise ValueError("invalid SACK-permitted option")
        elif kind == 5:
            if syn or not ack or option_length < 10 or option_length > 34 or (option_length - 2) % 8:
                raise ValueError("invalid SACK option")
        elif kind == 8:
            if option_length != 10:
                raise ValueError("invalid timestamp option")
        elif kind == 34:
            if not linux_mode or not syn or not (option_length == 2 or 6 <= option_length <= 18) or (option_length - 2) % 2:
                raise ValueError("invalid TCP Fast Open option")
        else:
            raise ValueError("unsupported TCP option")
        singletons.add(kind)
        parsed.append((kind, value))
        cursor += option_length
    return parsed


def validate_tcp(raw, meta, direction, linux_mode=None):
    offset = meta["offset"]
    segment = raw[offset:]
    if len(segment) < 20:
        raise ValueError("truncated TCP header")
    sport, dport = struct.unpack_from("!HH", segment, 0)
    if sport == 0 or dport == 0:
        raise ValueError("invalid TCP port")
    header_length = (segment[12] >> 4) * 4
    if header_length < 20 or header_length > 60 or header_length > len(segment):
        raise ValueError("invalid TCP header length")
    if segment[12] & 0x0F:
        raise ValueError("TCP reserved bits are not permitted")
    flags = segment[13]
    syn = bool(flags & 0x02)
    ack = bool(flags & 0x10)
    fin = bool(flags & 0x01)
    rst = bool(flags & 0x04)
    if not flags or (syn and (fin or rst)) or (fin and rst):
        raise ValueError("invalid TCP flag combination")
    if direction == "out" and flags & 0xC0:
        raise ValueError("outbound ECN flags are not permitted")
    urgent = struct.unpack_from("!H", segment, 18)[0]
    if not (flags & 0x20) and urgent:
        raise ValueError("TCP urgent pointer without URG")
    if transport_checksum(raw, meta, segment) != 0:
        raise ValueError("invalid TCP checksum")
    options = validate_tcp_options(segment[20:header_length], syn, ack, linux_mode)
    return {
        "sport": sport,
        "dport": dport,
        "header_length": header_length,
        "flags": flags,
        "syn": syn,
        "ack": ack,
        "fin": fin,
        "rst": rst,
        "options": options,
    }


def validate_udp(raw, meta, direction):
    offset = meta["offset"]
    segment = raw[offset:]
    if len(segment) < 8:
        raise ValueError("truncated UDP header")
    sport, dport, length, received_checksum = struct.unpack_from("!HHHH", segment, 0)
    if dport == 0 or length != len(segment) or length < 8:
        raise ValueError("invalid UDP header")
    if received_checksum == 0:
        if meta["family"] == 6 or direction == "out":
            raise ValueError("missing UDP checksum")
    elif transport_checksum(raw, meta, segment) != 0:
        raise ValueError("invalid UDP checksum")
    return {"sport": sport, "dport": dport, "zero_checksum": received_checksum == 0}


def validate_nd_options(segment, start, allowed):
    cursor = start
    while cursor < len(segment):
        if cursor + 2 > len(segment):
            raise ValueError("truncated ND option")
        units = segment[cursor + 1]
        if units == 0:
            raise ValueError("zero-length ND option")
        if segment[cursor] not in allowed:
            raise ValueError("unsupported ND option")
        cursor += units * 8
        if cursor > len(segment):
            raise ValueError("invalid ND option length")
    if cursor != len(segment):
        raise ValueError("invalid ND option padding")


def validate_mld(segment, icmp_type):
    if icmp_type == 130:
        if len(segment) == 24:
            return
        if len(segment) < 28:
            raise ValueError("truncated MLD query")
        sources = struct.unpack_from("!H", segment, 26)[0]
        if len(segment) != 28 + sources * 16:
            raise ValueError("invalid MLD query length")
        return
    if icmp_type in {131, 132}:
        if len(segment) != 24:
            raise ValueError("invalid MLDv1 message length")
        return
    if len(segment) < 8:
        raise ValueError("truncated MLDv2 report")
    records = struct.unpack_from("!H", segment, 6)[0]
    cursor = 8
    for _ in range(records):
        if cursor + 20 > len(segment):
            raise ValueError("truncated MLDv2 record")
        if segment[cursor] not in {1, 2, 3, 4, 5, 6}:
            raise ValueError("invalid MLDv2 record type")
        auxiliary_words = segment[cursor + 1]
        sources = struct.unpack_from("!H", segment, cursor + 2)[0]
        cursor += 20 + sources * 16 + auxiliary_words * 4
        if cursor > len(segment):
            raise ValueError("invalid MLDv2 record length")
    if cursor != len(segment):
        raise ValueError("invalid MLDv2 report length")


def validate_icmp(raw, meta, direction):
    segment = raw[meta["offset"]:]
    if len(segment) < 8:
        raise ValueError("truncated ICMP header")
    icmp_type = segment[0]
    code = segment[1]
    if meta["protocol"] == IPPROTO_ICMP:
        if checksum(segment) != 0:
            raise ValueError("invalid ICMP checksum")
        if icmp_type not in ICMPV4_ALLOWED:
            raise ValueError("unsupported ICMP type")
        if icmp_type in {0, 8} and code != 0:
            raise ValueError("invalid ICMP echo code")
        if icmp_type == 3 and code > 15:
            raise ValueError("invalid ICMP destination-unreachable code")
        if icmp_type == 11 and code > 1:
            raise ValueError("invalid ICMP time-exceeded code")
        if icmp_type == 12 and code > 2:
            raise ValueError("invalid ICMP parameter-problem code")
        return {"type": icmp_type, "code": code, "segment_length": len(segment)}
    if transport_checksum(raw, meta, segment) != 0:
        raise ValueError("invalid ICMPv6 checksum")
    if icmp_type in ICMPV6_ERRORS:
        if meta["hop_by_hop"]:
            raise ValueError("extension header on ICMPv6 error")
        limits = {1: 9, 2: 0, 3: 1, 4: 10}
        if code > limits[icmp_type]:
            raise ValueError("invalid ICMPv6 error code")
    elif icmp_type in ICMPV6_ECHO:
        if code != 0 or meta["hop_by_hop"]:
            raise ValueError("invalid ICMPv6 echo message")
    elif icmp_type in ICMPV6_MLD:
        if code != 0 or not meta["hop_by_hop"]:
            raise ValueError("invalid MLD envelope")
        if meta["dst"][0] != 0xFF:
            raise ValueError("invalid MLD destination")
        if raw[7] != 1:
            raise ValueError("invalid MLD hop limit")
        validate_mld(segment, icmp_type)
    elif icmp_type in ICMPV6_ND:
        if code != 0 or meta["hop_by_hop"]:
            raise ValueError("invalid Neighbor Discovery envelope")
        if raw[7] != 255:
            raise ValueError("invalid Neighbor Discovery hop limit")
        minimum = {133: 8, 134: 16, 135: 24, 136: 24, 137: 40}[icmp_type]
        if len(segment) < minimum:
            raise ValueError("truncated Neighbor Discovery message")
        allowed = {
            133: {1},
            134: {1, 3, 5, 24, 25, 31, 37, 38},
            135: {1},
            136: {2},
            137: {2, 4},
        }[icmp_type]
        validate_nd_options(segment, minimum, allowed)
        if icmp_type in {133, 135, 137} and any(segment[4:8]):
            raise ValueError("nonzero Neighbor Discovery reserved field")
        if icmp_type in {135, 136} and (not any(segment[8:24]) or segment[8] == 0xFF):
            raise ValueError("invalid Neighbor Discovery target")
        if icmp_type == 136 and struct.unpack_from("!I", segment, 4)[0] & 0x1FFFFFFF:
            raise ValueError("nonzero Neighbor Advertisement reserved bits")
        if direction == "out" and icmp_type in {134, 137}:
            raise ValueError("router-only Neighbor Discovery message")
    else:
        raise ValueError("unsupported ICMPv6 type")
    return {"type": icmp_type, "code": code, "segment_length": len(segment)}


def canonical_tcp_key(meta, sport, dport):
    left = (meta["src"], sport)
    right = (meta["dst"], dport)
    if left <= right:
        return meta["family"], meta.get("scope", 0), left, right
    return meta["family"], meta.get("scope", 0), right, left


def encode_tcp_key(key):
    family, scope, left, right = key
    return bytes((family,)) + struct.pack("!I", scope) + left[0] + struct.pack("!H", left[1]) + right[0] + struct.pack("!H", right[1])


def tcp_scale(options):
    for kind, value in options:
        if kind == 3:
            return value[2]
    return 0


def tcp_option_kinds(options):
    return {kind for kind, _ in options}


def create_tcp_flow(raw, meta, info, key):
    global FLOW_GENERATION
    FLOW_GENERATION += 1
    original_isn = struct.unpack_from("!I", raw, meta["offset"] + 4)[0]
    encoded_key = encode_tcp_key(key)
    nonce = derived_int("tcp-flow", encoded_key, original_isn, FLOW_GENERATION, bits=64)
    original_scale = tcp_scale(info["options"])
    target_scale = 8 if MODE == "windows" else original_scale
    if MODE == "windows":
        kinds = tcp_option_kinds(info["options"])
        if not {2, 3, 4}.issubset(kinds):
            raise ValueError("incomplete Windows SYN option basis")
    return {
        "local": (meta["src"], info["sport"]),
        "remote": (meta["dst"], info["dport"]),
        "orig_isn_out": original_isn,
        "nonce": nonce,
        "delta_out": (derived_int("tcp-isn-out", nonce) - original_isn) & 0xFFFFFFFF,
        "delta_in": 0,
        "delta_in_ready": False,
        "ts_delta_out": derived_int("tcp-ts-out", nonce),
        "orig_wscale_out": original_scale,
        "target_wscale_out": target_scale,
        "last": time.monotonic(),
        "fin_out": False,
        "fin_in": False,
        "reset": False,
    }


def verify_tcp_orientation(state, meta, info, direction):
    source = (meta["src"], info["sport"])
    destination = (meta["dst"], info["dport"])
    if direction == "out":
        valid = source == state["local"] and destination == state["remote"]
    else:
        valid = source == state["remote"] and destination == state["local"]
    if not valid:
        raise ValueError("TCP flow direction mismatch")


def translate_sack(value, delta):
    output = bytearray(value[:2])
    for cursor in range(2, len(value), 8):
        left, right = struct.unpack_from("!II", value, cursor)
        output.extend(struct.pack("!II", (left + delta) & 0xFFFFFFFF, (right + delta) & 0xFFFFFFFF))
    return bytes(output)


def pad_tcp_options(options):
    if len(options) > 40:
        raise ValueError("TCP options exceed header capacity")
    if len(options) % 4:
        options += b"\x00"
        options += b"\x00" * ((-len(options)) % 4)
    if len(options) > 40:
        raise ValueError("TCP options exceed header capacity")
    return options


def rewrite_tcp_options(info, direction, state, family):
    if MODE == "windows" and direction == "out" and info["syn"] and not info["ack"]:
        mss = None
        for kind, value in info["options"]:
            if kind == 2:
                mss = struct.unpack_from("!H", value, 2)[0]
                break
        if mss is None:
            raise ValueError("missing MSS option")
        ceiling = 1460 if family == 4 else 1440
        mss = min(max(mss, 536), ceiling)
        return struct.pack("!BBH", 2, 4, mss) + b"\x01\x03\x03\x08\x01\x01\x04\x02"
    output = bytearray()
    for kind, value in info["options"]:
        if kind == 0:
            break
        if kind == 8:
            if MODE == "windows":
                if direction == "in":
                    raise ValueError("unexpected inbound TCP timestamp")
                continue
            tsval, tsecr = struct.unpack_from("!II", value, 2)
            if direction == "out":
                tsval = (tsval + state["ts_delta_out"]) & 0xFFFFFFFF
            elif tsecr:
                tsecr = (tsecr - state["ts_delta_out"]) & 0xFFFFFFFF
            value = b"\x08\x0a" + struct.pack("!II", tsval, tsecr)
        elif kind == 5:
            if direction == "out":
                if not state["delta_in_ready"]:
                    raise ValueError("SACK before peer sequence mapping")
                value = translate_sack(value, -state["delta_in"])
            else:
                value = translate_sack(value, -state["delta_out"])
        output.extend(value)
    return pad_tcp_options(bytes(output))


def tcp_state_timeout(state):
    if state["reset"] or (state["fin_out"] and state["fin_in"]):
        return TCP_CLOSED_TIMEOUT
    if state["fin_out"] or state["fin_in"]:
        return TCP_HALF_CLOSED_TIMEOUT
    return TCP_FLOW_TIMEOUT


def transform_tcp(raw, meta, info, direction):
    key = canonical_tcp_key(meta, info["sport"], info["dport"])
    offset = meta["offset"]
    sequence = struct.unpack_from("!I", raw, offset + 4)[0]
    with STATE_LOCK:
        state = TCP_FLOWS.get(key)
        if direction == "out" and info["syn"] and not info["ack"] and (
            state is None
            or state["reset"]
            or (state["fin_out"] and state["fin_in"])
            or state["orig_isn_out"] != sequence
        ):
            if state is None and len(TCP_FLOWS) >= MAX_TCP_FLOWS:
                remove_stale_locked(time.monotonic())
                if len(TCP_FLOWS) >= MAX_TCP_FLOWS:
                    raise ValueError("TCP flow capacity reached")
            state = create_tcp_flow(raw, meta, info, key)
            TCP_FLOWS[key] = state
        if state is None:
            raise ValueError("unmapped TCP flow")
        verify_tcp_orientation(state, meta, info, direction)
        if direction == "in" and info["syn"] and not info["ack"]:
            raise ValueError("unsolicited or simultaneous-open SYN")
        if direction == "in" and info["syn"] and info["ack"] and not state["delta_in_ready"]:
            state["delta_in"] = (derived_int("tcp-isn-in", state["nonce"]) - sequence) & 0xFFFFFFFF
            state["delta_in_ready"] = True
        if direction == "in" and not state["delta_in_ready"] and not (info["rst"] and info["ack"]):
            raise ValueError("peer sequence mapping is not established")
        if direction == "out" and info["ack"] and not state["delta_in_ready"]:
            raise ValueError("outbound ACK before peer sequence mapping")
        state["last"] = time.monotonic()
        TCP_FLOWS.move_to_end(key)
        header = bytearray(raw[offset:offset + 20])
        payload = raw[offset + info["header_length"]:]
        options = rewrite_tcp_options(info, direction, state, meta["family"])
        if direction == "out":
            struct.pack_into("!I", header, 4, (sequence + state["delta_out"]) & 0xFFFFFFFF)
            if info["ack"]:
                acknowledgement = struct.unpack_from("!I", header, 8)[0]
                struct.pack_into("!I", header, 8, (acknowledgement - state["delta_in"]) & 0xFFFFFFFF)
        else:
            struct.pack_into("!I", header, 4, (sequence + state["delta_in"]) & 0xFFFFFFFF)
            if info["ack"]:
                acknowledgement = struct.unpack_from("!I", header, 8)[0]
                struct.pack_into("!I", header, 8, (acknowledgement - state["delta_out"]) & 0xFFFFFFFF)
        header[12] = ((20 + len(options)) // 4) << 4
        if direction == "out":
            if info["syn"] and not info["ack"]:
                struct.pack_into("!H", header, 14, 64240 if MODE == "windows" else 29200)
            elif state["orig_wscale_out"] != state["target_wscale_out"]:
                advertised = struct.unpack_from("!H", header, 14)[0]
                if advertised:
                    actual = advertised << state["orig_wscale_out"]
                    unit = 1 << state["target_wscale_out"]
                    advertised = min(65535, actual // unit)
                    struct.pack_into("!H", header, 14, advertised)
        if info["fin"]:
            state["fin_out" if direction == "out" else "fin_in"] = True
        if info["rst"]:
            state["reset"] = True
        header[16:18] = b"\x00\x00"
        return raw[:offset] + bytes(header) + options + payload


def udp_flow_key(meta, sport, dport):
    return meta["family"], meta.get("scope", 0), meta["src"], sport, meta["dst"], dport


def remember_udp_flow(meta, info):
    key = udp_flow_key(meta, info["sport"], info["dport"])
    with STATE_LOCK:
        if key not in UDP_FLOWS and len(UDP_FLOWS) >= MAX_UDP_FLOWS:
            remove_stale_locked(time.monotonic())
            if len(UDP_FLOWS) >= MAX_UDP_FLOWS:
                raise ValueError("UDP flow capacity reached")
        UDP_FLOWS[key] = time.monotonic()
        UDP_FLOWS.move_to_end(key)


def echo_local_key(meta, identifier):
    return meta["family"], meta.get("scope", 0), meta["dst"], identifier


def echo_wire_key(family, scope, remote, identifier):
    return family, scope, remote, identifier


def remove_echo_locked(local_key):
    state = ECHO_BY_LOCAL.pop(local_key, None)
    if state is not None:
        ECHO_BY_WIRE.pop(echo_wire_key(state["family"], state["scope"], state["remote"], state["wire_id"]), None)


def get_or_create_echo(meta, identifier):
    global FLOW_GENERATION
    local_key = echo_local_key(meta, identifier)
    state = ECHO_BY_LOCAL.get(local_key)
    if state is not None:
        state["last"] = time.monotonic()
        ECHO_BY_LOCAL.move_to_end(local_key)
        return state
    if len(ECHO_BY_LOCAL) >= MAX_ECHO_FLOWS:
        remove_stale_locked(time.monotonic())
        if len(ECHO_BY_LOCAL) >= MAX_ECHO_FLOWS:
            raise ValueError("ICMP echo flow capacity reached")
    FLOW_GENERATION += 1
    for attempt in range(65536):
        wire_id = derived_int("icmp-echo-id", meta["family"], meta["dst"], identifier, FLOW_GENERATION, attempt, bits=16)
        wire_key = echo_wire_key(meta["family"], meta.get("scope", 0), meta["dst"], wire_id)
        if wire_key not in ECHO_BY_WIRE:
            break
    else:
        raise ValueError("ICMP echo identifier capacity reached")
    state = {
        "family": meta["family"],
        "scope": meta.get("scope", 0),
        "remote": meta["dst"],
        "local_id": identifier,
        "wire_id": wire_id,
        "sequence_delta": derived_int("icmp-echo-sequence", wire_id, FLOW_GENERATION, bits=16),
        "payload_key": derived_int("icmp-echo-payload", wire_id, FLOW_GENERATION, bits=128).to_bytes(16, "big"),
        "last": time.monotonic(),
        "local_key": local_key,
    }
    ECHO_BY_LOCAL[local_key] = state
    ECHO_BY_WIRE[wire_key] = state
    return state


def xor_echo_payload(payload, state, wire_sequence):
    output = bytearray(len(payload))
    cursor = 0
    block = 0
    while cursor < len(payload):
        digest = hashlib.blake2s(key=state["payload_key"], digest_size=32)
        digest.update(struct.pack("!HI", wire_sequence, block))
        stream = digest.digest()
        size = min(len(stream), len(payload) - cursor)
        for index in range(size):
            output[cursor + index] = payload[cursor + index] ^ stream[index]
        cursor += size
        block += 1
    return bytes(output)


def transform_echo(raw, meta, icmp_type, direction):
    offset = meta["offset"]
    identifier, sequence = struct.unpack_from("!HH", raw, offset + 4)
    output = bytearray(raw)
    if (meta["family"] == 4 and icmp_type == 8) or (meta["family"] == 6 and icmp_type == 128):
        if direction != "out":
            return raw
        with STATE_LOCK:
            state = get_or_create_echo(meta, identifier)
            state["last"] = time.monotonic()
            wire_sequence = (sequence + state["sequence_delta"]) & 0xFFFF
            struct.pack_into("!HH", output, offset + 4, state["wire_id"], wire_sequence)
            output[offset + 8:] = xor_echo_payload(raw[offset + 8:], state, wire_sequence)
        return bytes(output)
    if direction != "in":
        return raw
    with STATE_LOCK:
        state = ECHO_BY_WIRE.get(echo_wire_key(meta["family"], meta.get("scope", 0), meta["src"], identifier))
        if state is None:
            raise ValueError("unmapped ICMP echo reply")
        state["last"] = time.monotonic()
        ECHO_BY_LOCAL.move_to_end(state["local_key"])
        local_sequence = (sequence - state["sequence_delta"]) & 0xFFFF
        struct.pack_into("!HH", output, offset + 4, state["local_id"], local_sequence)
        output[offset + 8:] = xor_echo_payload(raw[offset + 8:], state, sequence)
    return bytes(output)


def parse_quoted_packet(quote, interface):
    if not quote:
        raise ValueError("missing ICMP quotation")
    version = quote[0] >> 4
    if version == 4:
        if len(quote) < 28 or (quote[0] & 0x0F) != 5:
            raise ValueError("invalid quoted IPv4 packet")
        if checksum(quote[:20]) != 0:
            raise ValueError("invalid quoted IPv4 checksum")
        fragment = struct.unpack_from("!H", quote, 6)[0]
        if fragment & 0xBFFF:
            raise ValueError("invalid quoted IPv4 fragment")
        total_length = struct.unpack_from("!H", quote, 2)[0]
        if total_length < 28:
            raise ValueError("invalid quoted IPv4 length")
        if len(quote) > total_length:
            raise ValueError("unsupported quoted IPv4 trailing data")
        protocol = quote[9]
        if protocol not in {IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP}:
            raise ValueError("unsupported quoted IPv4 protocol")
        return {
            "family": 4,
            "protocol": protocol,
            "offset": 20,
            "src": quote[12:16],
            "dst": quote[16:20],
            "total_length": total_length,
            "scope": 0,
        }
    if version == 6:
        if len(quote) < 48:
            raise ValueError("invalid quoted IPv6 packet")
        protocol = quote[6]
        if protocol not in {IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6}:
            raise ValueError("unsupported quoted IPv6 next header")
        payload_length = struct.unpack_from("!H", quote, 4)[0]
        if payload_length == 0 or payload_length < 8:
            raise ValueError("invalid quoted IPv6 length")
        if len(quote) > 40 + payload_length:
            raise ValueError("unsupported quoted IPv6 trailing data")
        source = quote[8:24]
        destination = quote[24:40]
        scope = interface if ipv6_requires_scope(source, destination) else 0
        if ipv6_requires_scope(source, destination) and interface <= 0:
            raise ValueError("missing quoted IPv6 scope interface")
        return {
            "family": 6,
            "protocol": protocol,
            "offset": 40,
            "src": source,
            "dst": destination,
            "total_length": 40 + payload_length,
            "scope": scope,
        }
    raise ValueError("unsupported quoted IP version")


def reverse_quoted_tcp_options(output, offset, available, state, direction):
    if available < 20:
        return
    header_length = (output[offset + 12] >> 4) * 4
    if header_length < 20 or header_length > 60 or header_length > available:
        return
    cursor = offset + 20
    end = offset + header_length
    while cursor < end:
        kind = output[cursor]
        if kind == 0:
            break
        if kind == 1:
            cursor += 1
            continue
        if cursor + 2 > end:
            raise ValueError("truncated quoted TCP option")
        option_length = output[cursor + 1]
        if option_length < 2 or cursor + option_length > end:
            raise ValueError("invalid quoted TCP option length")
        if kind == 8 and option_length == 10 and MODE == "linux":
            tsval, tsecr = struct.unpack_from("!II", output, cursor + 2)
            if direction == "in":
                tsval = (tsval - state["ts_delta_out"]) & 0xFFFFFFFF
            elif tsecr:
                tsecr = (tsecr + state["ts_delta_out"]) & 0xFFFFFFFF
            struct.pack_into("!II", output, cursor + 2, tsval, tsecr)
        elif kind == 5 and option_length >= 10 and option_length <= 34 and (option_length - 2) % 8 == 0:
            if direction == "in":
                if not state["delta_in_ready"]:
                    raise ValueError("quoted SACK mapping is unavailable")
                delta = state["delta_in"]
            else:
                delta = state["delta_out"]
            for block in range(cursor + 2, cursor + option_length, 8):
                left, right = struct.unpack_from("!II", output, block)
                struct.pack_into("!II", output, block, (left + delta) & 0xFFFFFFFF, (right + delta) & 0xFFFFFFFF)
        cursor += option_length


def repair_complete_quoted_checksum(output, quote_start, quoted):
    if len(output) - quote_start < quoted["total_length"]:
        return
    offset = quote_start + quoted["offset"]
    end = quote_start + quoted["total_length"]
    segment = bytearray(output[offset:end])
    if quoted["protocol"] == IPPROTO_TCP:
        if len(segment) < 20:
            raise ValueError("truncated complete quoted TCP packet")
        segment[16:18] = b"\x00\x00"
        value = transport_checksum(bytes(output[quote_start:end]), quoted, bytes(segment))
        struct.pack_into("!H", segment, 16, value)
    elif quoted["protocol"] == IPPROTO_ICMP:
        segment[2:4] = b"\x00\x00"
        struct.pack_into("!H", segment, 2, checksum(bytes(segment)))
    elif quoted["protocol"] == IPPROTO_ICMPV6:
        segment[2:4] = b"\x00\x00"
        struct.pack_into("!H", segment, 2, transport_checksum(bytes(output[quote_start:end]), quoted, bytes(segment)))
    output[offset:end] = segment


def translate_quoted_tcp(output, quote_start, quoted, direction):
    offset = quote_start + quoted["offset"]
    sport, dport = struct.unpack_from("!HH", output, offset)
    if sport == 0 or dport == 0:
        raise ValueError("invalid quoted TCP port")
    meta = {
        "family": quoted["family"],
        "scope": quoted.get("scope", 0),
        "src": quoted["src"],
        "dst": quoted["dst"],
    }
    key = canonical_tcp_key(meta, sport, dport)
    with STATE_LOCK:
        state = TCP_FLOWS.get(key)
        if state is None:
            raise ValueError("unmapped quoted TCP flow")
        source = (quoted["src"], sport)
        destination = (quoted["dst"], dport)
        if direction == "in":
            valid = source == state["local"] and destination == state["remote"]
        else:
            valid = source == state["remote"] and destination == state["local"]
        if not valid:
            raise ValueError("quoted TCP flow direction mismatch")
        state["last"] = time.monotonic()
        TCP_FLOWS.move_to_end(key)
        sequence = struct.unpack_from("!I", output, offset + 4)[0]
        if direction == "in":
            sequence = (sequence - state["delta_out"]) & 0xFFFFFFFF
        else:
            if not state["delta_in_ready"]:
                raise ValueError("quoted peer sequence is not mapped")
            sequence = (sequence - state["delta_in"]) & 0xFFFFFFFF
        struct.pack_into("!I", output, offset + 4, sequence)
        available = len(output) - offset
        if available >= 14 and output[offset + 13] & 0x10:
            acknowledgement = struct.unpack_from("!I", output, offset + 8)[0]
            if direction == "in":
                if not state["delta_in_ready"]:
                    raise ValueError("quoted acknowledgement is not mapped")
                acknowledgement = (acknowledgement + state["delta_in"]) & 0xFFFFFFFF
            else:
                acknowledgement = (acknowledgement + state["delta_out"]) & 0xFFFFFFFF
            struct.pack_into("!I", output, offset + 8, acknowledgement)
        reverse_quoted_tcp_options(output, offset, available, state, direction)
    repair_complete_quoted_checksum(output, quote_start, quoted)


def validate_quoted_udp(quote, quoted, direction):
    offset = quoted["offset"]
    sport, dport = struct.unpack_from("!HH", quote, offset)
    if dport == 0:
        raise ValueError("invalid quoted UDP port")
    if direction != "in":
        return
    key = quoted["family"], quoted.get("scope", 0), quoted["src"], sport, quoted["dst"], dport
    with STATE_LOCK:
        last = UDP_FLOWS.get(key)
        if last is None or time.monotonic() - last > UDP_FLOW_TIMEOUT:
            raise ValueError("unmapped quoted UDP flow")
        UDP_FLOWS[key] = time.monotonic()
        UDP_FLOWS.move_to_end(key)


def translate_quoted_echo(output, quote_start, quoted, direction):
    if direction != "in":
        return
    offset = quote_start + quoted["offset"]
    icmp_type = output[offset]
    expected = 8 if quoted["family"] == 4 else 128
    if icmp_type != expected or output[offset + 1] != 0:
        raise ValueError("unsupported quoted ICMP message")
    wire_id, wire_sequence = struct.unpack_from("!HH", output, offset + 4)
    with STATE_LOCK:
        state = ECHO_BY_WIRE.get(
            echo_wire_key(quoted["family"], quoted.get("scope", 0), quoted["dst"], wire_id)
        )
        if state is None:
            raise ValueError("unmapped quoted ICMP echo")
        state["last"] = time.monotonic()
        struct.pack_into("!HH", output, offset + 4, state["local_id"], (wire_sequence - state["sequence_delta"]) & 0xFFFF)
        quoted_end = quote_start + quoted["total_length"]
        if quoted_end <= len(output):
            output[offset + 8:quoted_end] = xor_echo_payload(bytes(output[offset + 8:quoted_end]), state, wire_sequence)
    repair_complete_quoted_checksum(output, quote_start, quoted)


def translate_icmp_error(raw, meta, direction):
    quote_start = meta["offset"] + 8
    quote = raw[quote_start:]
    quoted = parse_quoted_packet(quote, meta.get("interface", 0))
    if quoted["protocol"] not in {IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, IPPROTO_ICMPV6}:
        raise ValueError("unsupported quoted protocol")
    output = bytearray(raw)
    if quoted["protocol"] == IPPROTO_TCP:
        translate_quoted_tcp(output, quote_start, quoted, direction)
    elif quoted["protocol"] == IPPROTO_UDP:
        validate_quoted_udp(quote, quoted, direction)
    else:
        translate_quoted_echo(output, quote_start, quoted, direction)
    return bytes(output)


def next_ipid(meta):
    global IPID_COUNTER
    with STATE_LOCK:
        IPID_COUNTER = (IPID_COUNTER + 1) & 0xFFFFFFFFFFFFFFFF
        counter = IPID_COUNTER
    if MODE == "windows":
        return (derived_int("windows-ipid-origin", bits=16) + counter) & 0xFFFF
    return derived_int("linux-ipid", counter, meta["src"], meta["dst"], meta["protocol"], bits=16)


def ipv6_flow_label(raw, meta, icmp_type):
    if MODE == "windows" or icmp_type in ICMPV6_ND or icmp_type in ICMPV6_MLD:
        return 0
    offset = meta["offset"]
    segment = raw[offset:]
    if meta["protocol"] in {IPPROTO_TCP, IPPROTO_UDP}:
        discriminator = segment[:4]
    elif icmp_type in ICMPV6_ECHO:
        discriminator = segment[:2] + segment[4:6]
    else:
        discriminator = segment[:2]
    value = derived_int(
        "ipv6-flow-label",
        meta.get("scope", 0),
        meta["src"],
        meta["dst"],
        meta["protocol"],
        discriminator,
        bits=20,
    )
    return value or 1


def transform_network(raw, meta, direction, icmp_type=-1):
    output = bytearray(raw)
    if direction != "out":
        return bytes(output)
    if meta["family"] == 4:
        output[1] = 0
        output[8] = 128 if MODE == "windows" else 64
        flags_fragment = struct.unpack_from("!H", output, 6)[0]
        if MODE == "windows":
            flags_fragment |= 0x4000
            struct.pack_into("!H", output, 4, next_ipid(meta))
        elif flags_fragment & 0x4000:
            struct.pack_into("!H", output, 4, 0)
        else:
            struct.pack_into("!H", output, 4, next_ipid(meta))
        struct.pack_into("!H", output, 6, flags_fragment)
    else:
        flow_label = ipv6_flow_label(raw, meta, icmp_type)
        struct.pack_into("!I", output, 0, (6 << 28) | flow_label)
        if icmp_type in ICMPV6_ND:
            output[7] = 255
        elif icmp_type in ICMPV6_MLD:
            output[7] = 1
        else:
            output[7] = 128 if MODE == "windows" else 64
    return bytes(output)


def finalize_packet(raw, meta, udp_zero_checksum=False):
    output = bytearray(raw)
    if meta["family"] == 4:
        if len(output) > 65535:
            raise ValueError("IPv4 packet exceeds maximum length")
        struct.pack_into("!H", output, 2, len(output))
    else:
        payload_length = len(output) - 40
        if payload_length < 0 or payload_length > 65535:
            raise ValueError("IPv6 packet exceeds maximum length")
        struct.pack_into("!H", output, 4, payload_length)
    offset = meta["offset"]
    segment = bytearray(output[offset:])
    if meta["protocol"] == IPPROTO_TCP:
        segment[16:18] = b"\x00\x00"
        value = transport_checksum(bytes(output), meta, bytes(segment))
        struct.pack_into("!H", segment, 16, value)
    elif meta["protocol"] == IPPROTO_UDP:
        struct.pack_into("!H", segment, 4, len(segment))
        segment[6:8] = b"\x00\x00"
        if not udp_zero_checksum:
            value = transport_checksum(bytes(output), meta, bytes(segment))
            struct.pack_into("!H", segment, 6, value or 0xFFFF)
    elif meta["protocol"] == IPPROTO_ICMP:
        segment[2:4] = b"\x00\x00"
        struct.pack_into("!H", segment, 2, checksum(bytes(segment)))
    elif meta["protocol"] == IPPROTO_ICMPV6:
        segment[2:4] = b"\x00\x00"
        struct.pack_into("!H", segment, 2, transport_checksum(bytes(output), meta, bytes(segment)))
    else:
        raise ValueError("unsupported transport protocol")
    output[offset:] = segment
    if meta["family"] == 4:
        output[10:12] = b"\x00\x00"
        struct.pack_into("!H", output, 10, checksum(bytes(output[:20])))
    return bytes(output)


def process_packet(raw, direction, interface=0):
    if direction not in {"in", "out"}:
        raise ValueError("invalid packet direction")
    meta = parse_packet(raw, interface)
    local_output = direction == "out" and (
        (meta["family"] == 4 and meta["dst"][0] == 127)
        or (meta["family"] == 6 and meta["dst"] == b"\x00" * 15 + b"\x01")
    )
    if local_output:
        udp_zero_checksum = False
        if meta["protocol"] == IPPROTO_TCP:
            validate_tcp(raw, meta, "in", linux_mode=True)
        elif meta["protocol"] == IPPROTO_UDP:
            udp_zero_checksum = validate_udp(raw, meta, "in")["zero_checksum"]
        else:
            validate_icmp(raw, meta, "in")
        return finalize_packet(raw, meta, udp_zero_checksum)
    udp_zero_checksum = False
    icmp_type = -1
    if meta["protocol"] == IPPROTO_TCP:
        info = validate_tcp(raw, meta, direction)
        raw = transform_tcp(raw, meta, info, direction)
    elif meta["protocol"] == IPPROTO_UDP:
        info = validate_udp(raw, meta, direction)
        if direction == "out":
            remember_udp_flow(meta, info)
        udp_zero_checksum = info["zero_checksum"] and direction == "in"
    else:
        info = validate_icmp(raw, meta, direction)
        icmp_type = info["type"]
        if (meta["protocol"] == IPPROTO_ICMP and icmp_type in ICMPV4_ERRORS) or (
            meta["protocol"] == IPPROTO_ICMPV6 and icmp_type in ICMPV6_ERRORS
        ):
            raw = translate_icmp_error(raw, meta, direction)
        elif icmp_type in {0, 8, 128, 129}:
            raw = transform_echo(raw, meta, icmp_type, direction)
    raw = transform_network(raw, meta, direction, icmp_type)
    return finalize_packet(raw, meta, udp_zero_checksum)


def remove_stale_locked(now):
    for key, state in list(TCP_FLOWS.items()):
        if now - state["last"] > tcp_state_timeout(state):
            TCP_FLOWS.pop(key, None)
    for key, last in list(UDP_FLOWS.items()):
        if now - last > UDP_FLOW_TIMEOUT:
            UDP_FLOWS.pop(key, None)
    for key, state in list(ECHO_BY_LOCAL.items()):
        if now - state["last"] > ECHO_FLOW_TIMEOUT:
            remove_echo_locked(key)


def cleanup_worker():
    while True:
        time.sleep(15)
        with STATE_LOCK:
            remove_stale_locked(time.monotonic())


def report_drop(error):
    global LAST_ERROR_LOG
    try:
        now = time.monotonic()
        with STATE_LOCK:
            if now - LAST_ERROR_LOG < ERROR_LOG_INTERVAL:
                return
            LAST_ERROR_LOG = now
        detail = str(error).replace("\n", " ")[:160]
        print(
            f"ph4ntxm-packet-transformation-engine: packet dropped: {type(error).__name__}: {detail}",
            file=os.sys.stderr,
            flush=True,
        )
    except BaseException:
        return


def modify(packet, direction):
    try:
        expected_hook = 0 if direction == "in" else 3
        if int(packet.hook) != expected_hook:
            raise ValueError("unexpected NFQUEUE hook")
        payload = packet.get_payload()
        if not payload:
            raise ValueError("empty NFQUEUE payload")
        version = payload[0] >> 4
        expected_protocol = 0x0800 if version == 4 else 0x86DD if version == 6 else -1
        if int(packet.hw_protocol) != expected_protocol:
            raise ValueError("NFQUEUE protocol mismatch")
        interface = int(packet.indev if direction == "in" else packet.outdev)
        payload = process_packet(payload, direction, interface)
        packet.set_payload(payload)
        packet.accept()
    except BaseException as error:
        try:
            packet.drop()
        finally:
            report_drop(error)
        if isinstance(error, (KeyboardInterrupt, SystemExit, MemoryError)):
            raise


def modify_inbound(packet):
    modify(packet, "in")


def modify_outbound(packet):
    modify(packet, "out")


def notify_ready():
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        raise RuntimeError("NOTIFY_SOCKET is unavailable")
    if address.startswith("@"):
        address = "\x00" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
        channel.connect(address)
        channel.sendall(b"READY=1\nSTATUS=NFQUEUE packet transformation active")


def queue_status():
    status = {}
    with open("/proc/net/netfilter/nfnetlink_queue", "r", encoding="ascii") as handle:
        for line in handle:
            fields = line.split()
            if not fields:
                continue
            if len(fields) < 8:
                raise RuntimeError("invalid NFQUEUE status format")
            values = [int(value, 10) for value in fields[:8]]
            status[values[0]] = {
                "queued": values[2],
                "copy_mode": values[3],
                "copy_range": values[4],
                "queue_dropped": values[5],
                "userspace_dropped": values[6],
            }
    return status


def verify_queue_bindings():
    status = queue_status()
    for queue_number in (INBOUND_QUEUE, OUTBOUND_QUEUE):
        entry = status.get(queue_number)
        if entry is None:
            raise RuntimeError(f"NFQUEUE {queue_number} is not registered")
        if entry["copy_mode"] != 2 or entry["copy_range"] < MIN_EFFECTIVE_COPY_RANGE:
            raise RuntimeError(f"NFQUEUE {queue_number} has unsafe copy settings")
        if entry["queue_dropped"] or entry["userspace_dropped"]:
            raise RuntimeError(f"NFQUEUE {queue_number} reported packet loss")


def startup_self_test():
    if checksum(b"\x00\x01\xf2\x03\xf4\xf5\xf6\xf7") != 0x220D:
        raise RuntimeError("checksum self-test failed")
    first = derived_int("startup-self-test", bits=32)
    second = derived_int("startup-self-test", bits=32)
    if first != second:
        raise RuntimeError("derivation self-test failed")


def main():
    startup_self_test()
    threading.Thread(target=cleanup_worker, daemon=True, name="ph4ntxm-packet-transformation-engine-cleanup").start()
    inbound = NetfilterQueue()
    outbound = NetfilterQueue()
    try:
        inbound.bind(INBOUND_QUEUE, modify_inbound, max_len=QUEUE_LENGTH, range=QUEUE_COPY_RANGE)
        outbound.bind(OUTBOUND_QUEUE, modify_outbound, max_len=QUEUE_LENGTH, range=QUEUE_COPY_RANGE)
        inbound_fd = inbound.get_fd()
        outbound_fd = outbound.get_fd()
        if inbound_fd < 0 or outbound_fd < 0 or inbound_fd == outbound_fd:
            raise RuntimeError("invalid NFQUEUE descriptors")
        poller = select.poll()
        events = select.POLLIN | select.POLLERR | select.POLLHUP | select.POLLNVAL
        poller.register(inbound_fd, events)
        poller.register(outbound_fd, events)
        queues = {inbound_fd: inbound, outbound_fd: outbound}
        verify_queue_bindings()
        notify_ready()
        last_health_check = time.monotonic()
        while True:
            for descriptor, event in poller.poll(1000):
                if event & (select.POLLERR | select.POLLHUP | select.POLLNVAL):
                    raise RuntimeError(f"NFQUEUE descriptor failure: {event}")
                if event & select.POLLIN:
                    queues[descriptor].run(block=False)
            now = time.monotonic()
            if now - last_health_check >= QUEUE_HEALTH_INTERVAL:
                verify_queue_bindings()
                last_health_check = now
    finally:
        inbound.unbind()
        outbound.unbind()


if __name__ == "__main__":
    raise SystemExit("Build-time reference fixture only; not a runtime engine")
