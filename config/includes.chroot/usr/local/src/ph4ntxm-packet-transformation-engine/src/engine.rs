use std::collections::HashMap;
use std::sync::atomic::{compiler_fence, Ordering};
use std::time::{Duration, Instant};

use crate::crypto::blake2s;
use crate::packet::{
    checksum, finalize_packet, parse_packet, parse_quoted_packet, read_u16, read_u32,
    transport_checksum, validate_icmp, validate_tcp, validate_udp, write_u16, write_u32, Address,
    IcmpInfo, Meta, PacketTransformationResult, QuotedMeta, TcpInfo, UdpInfo, ICMPV4_ERRORS, ICMPV6_ECHO,
    ICMPV6_ERRORS, ICMPV6_MLD, ICMPV6_ND, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP,
};

const TCP_FLOW_TIMEOUT: Duration = Duration::from_secs(432_000);
const TCP_HALF_CLOSED_TIMEOUT: Duration = Duration::from_secs(432_000);
const TCP_CLOSED_TIMEOUT: Duration = Duration::from_secs(240);
const UDP_FLOW_TIMEOUT: Duration = Duration::from_secs(300);
const ECHO_FLOW_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_TCP_FLOWS: usize = 65_536;
const MAX_UDP_FLOWS: usize = 65_536;
const MAX_ECHO_FLOWS: usize = 4_096;

fn secure_zero(value: &mut [u8]) {
    for byte in value {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Linux,
    Windows,
}

#[derive(Clone, Copy)]
enum DerivePart<'a> {
    Bytes(&'a [u8]),
    Integer(u128),
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Endpoint(Address, u16);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct TcpKey {
    family: u8,
    scope: u32,
    left: Endpoint,
    right: Endpoint,
}

#[derive(Clone)]
struct TcpFlow {
    local: Endpoint,
    remote: Endpoint,
    original_isn_out: u32,
    nonce: u64,
    delta_out: u32,
    delta_in: u32,
    delta_in_ready: bool,
    timestamp_delta_out: u32,
    original_window_scale_out: u8,
    target_window_scale_out: u8,
    last: Instant,
    fin_out: bool,
    fin_in: bool,
    reset: bool,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct UdpKey {
    family: u8,
    scope: u32,
    source: Address,
    sport: u16,
    destination: Address,
    dport: u16,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct EchoLocalKey {
    family: u8,
    scope: u32,
    remote: Address,
    identifier: u16,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct EchoWireKey {
    family: u8,
    scope: u32,
    remote: Address,
    identifier: u16,
}

#[derive(Clone)]
struct EchoFlow {
    family: u8,
    scope: u32,
    remote: Address,
    local_identifier: u16,
    wire_identifier: u16,
    sequence_delta: u16,
    payload_key: [u8; 16],
    last: Instant,
}

pub struct Engine {
    mode: Mode,
    seed: [u8; 32],
    tcp_flows: HashMap<TcpKey, TcpFlow>,
    udp_flows: HashMap<UdpKey, Instant>,
    echo_by_local: HashMap<EchoLocalKey, EchoFlow>,
    echo_by_wire: HashMap<EchoWireKey, EchoLocalKey>,
    flow_generation: u64,
    ipid_counter: u64,
}

impl Drop for Engine {
    fn drop(&mut self) {
        secure_zero(&mut self.seed);
        for state in self.echo_by_local.values_mut() {
            secure_zero(&mut state.payload_key);
        }
    }
}

impl Engine {
    pub fn new(mode: Mode, seed: [u8; 32]) -> Self {
        Self {
            mode,
            seed,
            tcp_flows: HashMap::new(),
            udp_flows: HashMap::new(),
            echo_by_local: HashMap::new(),
            echo_by_wire: HashMap::new(),
            flow_generation: 0,
            ipid_counter: 0,
        }
    }

    fn encode_integer(value: u128, output: &mut Vec<u8>) {
        let bytes = value.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        output.extend_from_slice(&((bytes.len() - first) as u32).to_be_bytes());
        output.extend_from_slice(&bytes[first..]);
    }

    fn encode_bytes(value: &[u8], output: &mut Vec<u8>) {
        output.extend_from_slice(&(value.len() as u32).to_be_bytes());
        output.extend_from_slice(value);
    }

    fn derive(&self, label: &str, parts: &[DerivePart<'_>], bits: usize) -> u128 {
        let mut message = Vec::new();
        Self::encode_bytes(label.as_bytes(), &mut message);
        for part in parts {
            match part {
                DerivePart::Bytes(value) => Self::encode_bytes(value, &mut message),
                DerivePart::Integer(value) => Self::encode_integer(*value, &mut message),
            }
        }
        let digest = blake2s(&self.seed, &message, bits.div_ceil(8));
        let mut value = 0u128;
        for byte in digest {
            value = (value << 8) | u128::from(byte);
        }
        if bits == 128 {
            value
        } else {
            value & ((1u128 << bits) - 1)
        }
    }

    fn tcp_key(meta: &Meta, sport: u16, dport: u16) -> TcpKey {
        let source = Endpoint(meta.src, sport);
        let destination = Endpoint(meta.dst, dport);
        let (left, right) = if source <= destination {
            (source, destination)
        } else {
            (destination, source)
        };
        TcpKey {
            family: meta.family,
            scope: meta.scope,
            left,
            right,
        }
    }

    fn encode_tcp_key(key: &TcpKey) -> Vec<u8> {
        let mut output = Vec::new();
        output.push(key.family);
        output.extend_from_slice(&key.scope.to_be_bytes());
        output.extend_from_slice(key.left.0.as_slice());
        output.extend_from_slice(&key.left.1.to_be_bytes());
        output.extend_from_slice(key.right.0.as_slice());
        output.extend_from_slice(&key.right.1.to_be_bytes());
        output
    }

    fn tcp_scale(info: &TcpInfo) -> u8 {
        info.options
            .iter()
            .find(|option| option.kind == 3)
            .map_or(0, |option| option.value[2])
    }

    fn create_tcp_flow(
        &mut self,
        raw: &[u8],
        meta: &Meta,
        info: &TcpInfo,
        key: &TcpKey,
    ) -> PacketTransformationResult<TcpFlow> {
        self.flow_generation = self
            .flow_generation
            .checked_add(1)
            .ok_or("flow generation exhausted")?;
        let original_isn = read_u32(raw, meta.offset + 4);
        let encoded_key = Self::encode_tcp_key(key);
        let nonce = self.derive(
            "tcp-flow",
            &[
                DerivePart::Bytes(&encoded_key),
                DerivePart::Integer(u128::from(original_isn)),
                DerivePart::Integer(u128::from(self.flow_generation)),
            ],
            64,
        ) as u64;
        let original_scale = Self::tcp_scale(info);
        let target_scale = if self.mode == Mode::Windows {
            8
        } else {
            original_scale
        };
        if self.mode == Mode::Windows {
            for required in [2, 3, 4] {
                if !info.options.iter().any(|option| option.kind == required) {
                    return Err("incomplete Windows SYN option basis");
                }
            }
        }
        let exposed_isn =
            self.derive("tcp-isn-out", &[DerivePart::Integer(u128::from(nonce))], 32) as u32;
        Ok(TcpFlow {
            local: Endpoint(meta.src, info.sport),
            remote: Endpoint(meta.dst, info.dport),
            original_isn_out: original_isn,
            nonce,
            delta_out: exposed_isn.wrapping_sub(original_isn),
            delta_in: 0,
            delta_in_ready: false,
            timestamp_delta_out: self.derive(
                "tcp-ts-out",
                &[DerivePart::Integer(u128::from(nonce))],
                32,
            ) as u32,
            original_window_scale_out: original_scale,
            target_window_scale_out: target_scale,
            last: Instant::now(),
            fin_out: false,
            fin_in: false,
            reset: false,
        })
    }

    fn verify_tcp_orientation(
        state: &TcpFlow,
        meta: &Meta,
        info: &TcpInfo,
        outbound: bool,
    ) -> PacketTransformationResult<()> {
        let source = Endpoint(meta.src, info.sport);
        let destination = Endpoint(meta.dst, info.dport);
        let valid = if outbound {
            source == state.local && destination == state.remote
        } else {
            source == state.remote && destination == state.local
        };
        if valid {
            Ok(())
        } else {
            Err("TCP flow direction mismatch")
        }
    }

    fn translate_sack(value: &[u8], delta: u32) -> Vec<u8> {
        let mut output = value[..2].to_vec();
        for block in value[2..].chunks_exact(8) {
            output.extend_from_slice(&read_u32(block, 0).wrapping_add(delta).to_be_bytes());
            output.extend_from_slice(&read_u32(block, 4).wrapping_add(delta).to_be_bytes());
        }
        output
    }

    fn pad_tcp_options(mut options: Vec<u8>) -> PacketTransformationResult<Vec<u8>> {
        if options.len() > 40 {
            return Err("TCP options exceed header capacity");
        }
        if options.len() % 4 != 0 {
            options.push(0);
            while options.len() % 4 != 0 {
                options.push(0);
            }
        }
        if options.len() > 40 {
            Err("TCP options exceed header capacity")
        } else {
            Ok(options)
        }
    }

    fn rewrite_tcp_options(
        mode: Mode,
        info: &TcpInfo,
        outbound: bool,
        state: &TcpFlow,
        family: u8,
    ) -> PacketTransformationResult<Vec<u8>> {
        if mode == Mode::Windows && outbound && info.syn && !info.ack {
            let mss = info
                .options
                .iter()
                .find(|option| option.kind == 2)
                .map(|option| read_u16(&option.value, 2))
                .ok_or("missing MSS option")?;
            let ceiling = if family == 4 { 1460 } else { 1440 };
            let mss = mss.clamp(536, ceiling);
            let mut output = vec![2, 4];
            output.extend_from_slice(&mss.to_be_bytes());
            output.extend_from_slice(&[1, 3, 3, 8, 1, 1, 4, 2]);
            return Ok(output);
        }
        let mut output = Vec::new();
        for option in &info.options {
            if option.kind == 0 {
                break;
            }
            let mut value = option.value.clone();
            if option.kind == 8 {
                if mode == Mode::Windows {
                    if !outbound {
                        return Err("unexpected inbound TCP timestamp");
                    }
                    continue;
                }
                let mut tsval = read_u32(&value, 2);
                let mut tsecr = read_u32(&value, 6);
                if outbound {
                    tsval = tsval.wrapping_add(state.timestamp_delta_out);
                } else if tsecr != 0 {
                    tsecr = tsecr.wrapping_sub(state.timestamp_delta_out);
                }
                write_u32(&mut value, 2, tsval);
                write_u32(&mut value, 6, tsecr);
            } else if option.kind == 5 {
                value = if outbound {
                    if !state.delta_in_ready {
                        return Err("SACK before peer sequence mapping");
                    }
                    Self::translate_sack(&value, state.delta_in.wrapping_neg())
                } else {
                    Self::translate_sack(&value, state.delta_out.wrapping_neg())
                };
            }
            output.extend_from_slice(&value);
        }
        Self::pad_tcp_options(output)
    }

    fn transform_tcp(
        &mut self,
        raw: Vec<u8>,
        meta: &Meta,
        info: &TcpInfo,
        outbound: bool,
    ) -> PacketTransformationResult<Vec<u8>> {
        let key = Self::tcp_key(meta, info.sport, info.dport);
        let sequence = read_u32(&raw, meta.offset + 4);
        let replace = outbound
            && info.syn
            && !info.ack
            && self.tcp_flows.get(&key).is_none_or(|state| {
                state.reset || (state.fin_out && state.fin_in) || state.original_isn_out != sequence
            });
        if replace {
            if !self.tcp_flows.contains_key(&key) && self.tcp_flows.len() >= MAX_TCP_FLOWS {
                self.remove_stale(Instant::now());
                if self.tcp_flows.len() >= MAX_TCP_FLOWS {
                    return Err("TCP flow capacity reached");
                }
            }
            let state = self.create_tcp_flow(&raw, meta, info, &key)?;
            self.tcp_flows.insert(key.clone(), state);
        }
        let nonce = self.tcp_flows.get(&key).ok_or("unmapped TCP flow")?.nonce;
        {
            let state = self.tcp_flows.get(&key).expect("flow checked above");
            Self::verify_tcp_orientation(state, meta, info, outbound)?;
        }
        if !outbound && info.syn && !info.ack {
            return Err("unsolicited or simultaneous-open SYN");
        }
        if !outbound && info.syn && info.ack && !self.tcp_flows[&key].delta_in_ready {
            let exposed =
                self.derive("tcp-isn-in", &[DerivePart::Integer(u128::from(nonce))], 32) as u32;
            let state = self.tcp_flows.get_mut(&key).expect("flow checked above");
            state.delta_in = exposed.wrapping_sub(sequence);
            state.delta_in_ready = true;
        }
        {
            let state = self.tcp_flows.get(&key).expect("flow checked above");
            if !(outbound || state.delta_in_ready || info.rst && info.ack) {
                return Err("peer sequence mapping is not established");
            }
            if outbound && info.ack && !state.delta_in_ready {
                return Err("outbound ACK before peer sequence mapping");
            }
        }
        let state_snapshot = self
            .tcp_flows
            .get(&key)
            .expect("flow checked above")
            .clone();
        let options =
            Self::rewrite_tcp_options(self.mode, info, outbound, &state_snapshot, meta.family)?;
        let mut header = raw[meta.offset..meta.offset + 20].to_vec();
        let payload = &raw[meta.offset + info.header_length..];
        if outbound {
            write_u32(
                &mut header,
                4,
                sequence.wrapping_add(state_snapshot.delta_out),
            );
            if info.ack {
                let acknowledgement = read_u32(&header, 8).wrapping_sub(state_snapshot.delta_in);
                write_u32(&mut header, 8, acknowledgement);
            }
        } else {
            write_u32(
                &mut header,
                4,
                sequence.wrapping_add(state_snapshot.delta_in),
            );
            if info.ack {
                let acknowledgement = read_u32(&header, 8).wrapping_sub(state_snapshot.delta_out);
                write_u32(&mut header, 8, acknowledgement);
            }
        }
        header[12] = (((20 + options.len()) / 4) as u8) << 4;
        if outbound {
            if info.syn && !info.ack {
                write_u16(
                    &mut header,
                    14,
                    if self.mode == Mode::Windows {
                        64_240
                    } else {
                        29_200
                    },
                );
            } else if state_snapshot.original_window_scale_out
                != state_snapshot.target_window_scale_out
            {
                let advertised = read_u16(&header, 14);
                if advertised != 0 {
                    let actual = u64::from(advertised) << state_snapshot.original_window_scale_out;
                    let unit = 1u64 << state_snapshot.target_window_scale_out;
                    write_u16(&mut header, 14, (actual / unit).min(65_535) as u16);
                }
            }
        }
        header[16..18].fill(0);
        let state = self.tcp_flows.get_mut(&key).expect("flow checked above");
        state.last = Instant::now();
        if info.fin {
            if outbound {
                state.fin_out = true
            } else {
                state.fin_in = true
            }
        }
        if info.rst {
            state.reset = true;
        }
        let mut output =
            Vec::with_capacity(meta.offset + header.len() + options.len() + payload.len());
        output.extend_from_slice(&raw[..meta.offset]);
        output.extend_from_slice(&header);
        output.extend_from_slice(&options);
        output.extend_from_slice(payload);
        Ok(output)
    }

    fn udp_key(meta: &Meta, sport: u16, dport: u16) -> UdpKey {
        UdpKey {
            family: meta.family,
            scope: meta.scope,
            source: meta.src,
            sport,
            destination: meta.dst,
            dport,
        }
    }

    fn remember_udp_flow(&mut self, meta: &Meta, info: UdpInfo) -> PacketTransformationResult<()> {
        let key = Self::udp_key(meta, info.sport, info.dport);
        if !self.udp_flows.contains_key(&key) && self.udp_flows.len() >= MAX_UDP_FLOWS {
            self.remove_stale(Instant::now());
            if self.udp_flows.len() >= MAX_UDP_FLOWS {
                return Err("UDP flow capacity reached");
            }
        }
        self.udp_flows.insert(key, Instant::now());
        Ok(())
    }

    fn echo_local_key(meta: &Meta, identifier: u16) -> EchoLocalKey {
        EchoLocalKey {
            family: meta.family,
            scope: meta.scope,
            remote: meta.dst,
            identifier,
        }
    }

    fn echo_wire_key(family: u8, scope: u32, remote: Address, identifier: u16) -> EchoWireKey {
        EchoWireKey {
            family,
            scope,
            remote,
            identifier,
        }
    }

    fn remove_echo(&mut self, local_key: &EchoLocalKey) {
        if let Some(state) = self.echo_by_local.remove(local_key) {
            let key = Self::echo_wire_key(
                state.family,
                state.scope,
                state.remote,
                state.wire_identifier,
            );
            self.echo_by_wire.remove(&key);
        }
    }

    fn get_or_create_echo(&mut self, meta: &Meta, identifier: u16) -> PacketTransformationResult<EchoLocalKey> {
        let local_key = Self::echo_local_key(meta, identifier);
        if let Some(state) = self.echo_by_local.get_mut(&local_key) {
            state.last = Instant::now();
            return Ok(local_key);
        }
        if self.echo_by_local.len() >= MAX_ECHO_FLOWS {
            self.remove_stale(Instant::now());
            if self.echo_by_local.len() >= MAX_ECHO_FLOWS {
                return Err("ICMP echo flow capacity reached");
            }
        }
        self.flow_generation = self
            .flow_generation
            .checked_add(1)
            .ok_or("flow generation exhausted")?;
        let generation = self.flow_generation;
        let mut selected = None;
        for attempt in 0..=u16::MAX {
            let wire_identifier = self.derive(
                "icmp-echo-id",
                &[
                    DerivePart::Integer(u128::from(meta.family)),
                    DerivePart::Bytes(meta.dst.as_slice()),
                    DerivePart::Integer(u128::from(identifier)),
                    DerivePart::Integer(u128::from(generation)),
                    DerivePart::Integer(u128::from(attempt)),
                ],
                16,
            ) as u16;
            let wire_key = Self::echo_wire_key(meta.family, meta.scope, meta.dst, wire_identifier);
            if !self.echo_by_wire.contains_key(&wire_key) {
                selected = Some((wire_identifier, wire_key));
                break;
            }
        }
        let (wire_identifier, wire_key) =
            selected.ok_or("ICMP echo identifier capacity reached")?;
        let sequence_delta = self.derive(
            "icmp-echo-sequence",
            &[
                DerivePart::Integer(u128::from(wire_identifier)),
                DerivePart::Integer(u128::from(generation)),
            ],
            16,
        ) as u16;
        let payload_value = self.derive(
            "icmp-echo-payload",
            &[
                DerivePart::Integer(u128::from(wire_identifier)),
                DerivePart::Integer(u128::from(generation)),
            ],
            128,
        );
        let state = EchoFlow {
            family: meta.family,
            scope: meta.scope,
            remote: meta.dst,
            local_identifier: identifier,
            wire_identifier,
            sequence_delta,
            payload_key: payload_value.to_be_bytes(),
            last: Instant::now(),
        };
        self.echo_by_wire.insert(wire_key, local_key.clone());
        self.echo_by_local.insert(local_key.clone(), state);
        Ok(local_key)
    }

    fn xor_echo_payload(payload: &[u8], state: &EchoFlow, wire_sequence: u16) -> Vec<u8> {
        let mut output = vec![0u8; payload.len()];
        let mut cursor = 0usize;
        let mut block = 0u32;
        while cursor < payload.len() {
            let mut input = Vec::with_capacity(6);
            input.extend_from_slice(&wire_sequence.to_be_bytes());
            input.extend_from_slice(&block.to_be_bytes());
            let stream = blake2s(&state.payload_key, &input, 32);
            let size = stream.len().min(payload.len() - cursor);
            for index in 0..size {
                output[cursor + index] = payload[cursor + index] ^ stream[index];
            }
            cursor += size;
            block = block.wrapping_add(1);
        }
        output
    }

    fn transform_echo(
        &mut self,
        raw: Vec<u8>,
        meta: &Meta,
        info: IcmpInfo,
        outbound: bool,
    ) -> PacketTransformationResult<Vec<u8>> {
        let identifier = read_u16(&raw, meta.offset + 4);
        let sequence = read_u16(&raw, meta.offset + 6);
        let request = (meta.family == 4 && info.icmp_type == 8)
            || (meta.family == 6 && info.icmp_type == 128);
        if request {
            if !outbound {
                return Ok(raw);
            }
            let local_key = self.get_or_create_echo(meta, identifier)?;
            let state = self
                .echo_by_local
                .get_mut(&local_key)
                .expect("echo state created");
            state.last = Instant::now();
            let wire_sequence = sequence.wrapping_add(state.sequence_delta);
            let transformed = Self::xor_echo_payload(&raw[meta.offset + 8..], state, wire_sequence);
            let mut output = raw;
            write_u16(&mut output, meta.offset + 4, state.wire_identifier);
            write_u16(&mut output, meta.offset + 6, wire_sequence);
            output[meta.offset + 8..].copy_from_slice(&transformed);
            return Ok(output);
        }
        if outbound {
            return Ok(raw);
        }
        let wire_key = Self::echo_wire_key(meta.family, meta.scope, meta.src, identifier);
        let local_key = self
            .echo_by_wire
            .get(&wire_key)
            .cloned()
            .ok_or("unmapped ICMP echo reply")?;
        let state = self
            .echo_by_local
            .get_mut(&local_key)
            .ok_or("inconsistent ICMP echo mapping")?;
        state.last = Instant::now();
        let local_sequence = sequence.wrapping_sub(state.sequence_delta);
        let transformed = Self::xor_echo_payload(&raw[meta.offset + 8..], state, sequence);
        let mut output = raw;
        write_u16(&mut output, meta.offset + 4, state.local_identifier);
        write_u16(&mut output, meta.offset + 6, local_sequence);
        output[meta.offset + 8..].copy_from_slice(&transformed);
        Ok(output)
    }

    fn quoted_meta(quoted: &QuotedMeta) -> Meta {
        Meta {
            family: quoted.family,
            protocol: quoted.protocol,
            offset: quoted.offset,
            src: quoted.src,
            dst: quoted.dst,
            hop_by_hop: false,
            scope: quoted.scope,
            interface: 0,
        }
    }

    fn reverse_quoted_tcp_options(
        mode: Mode,
        output: &mut [u8],
        offset: usize,
        available: usize,
        state: &TcpFlow,
        inbound: bool,
    ) -> PacketTransformationResult<()> {
        if available < 20 {
            return Ok(());
        }
        let header_length = usize::from(output[offset + 12] >> 4) * 4;
        if !(20..=60).contains(&header_length) || header_length > available {
            return Ok(());
        }
        let mut cursor = offset + 20;
        let end = offset + header_length;
        while cursor < end {
            let kind = output[cursor];
            if kind == 0 {
                break;
            }
            if kind == 1 {
                cursor += 1;
                continue;
            }
            if cursor + 2 > end {
                return Err("truncated quoted TCP option");
            }
            let length = usize::from(output[cursor + 1]);
            if length < 2 || cursor + length > end {
                return Err("invalid quoted TCP option length");
            }
            if kind == 8 && length == 10 && mode == Mode::Linux {
                let mut tsval = read_u32(output, cursor + 2);
                let mut tsecr = read_u32(output, cursor + 6);
                if inbound {
                    tsval = tsval.wrapping_sub(state.timestamp_delta_out);
                } else if tsecr != 0 {
                    tsecr = tsecr.wrapping_add(state.timestamp_delta_out);
                }
                write_u32(output, cursor + 2, tsval);
                write_u32(output, cursor + 6, tsecr);
            } else if kind == 5 && (10..=34).contains(&length) && (length - 2) % 8 == 0 {
                let delta = if inbound {
                    if !state.delta_in_ready {
                        return Err("quoted SACK mapping is unavailable");
                    }
                    state.delta_in
                } else {
                    state.delta_out
                };
                for block in (cursor + 2..cursor + length).step_by(8) {
                    write_u32(output, block, read_u32(output, block).wrapping_add(delta));
                    write_u32(
                        output,
                        block + 4,
                        read_u32(output, block + 4).wrapping_add(delta),
                    );
                }
            }
            cursor += length;
        }
        Ok(())
    }

    fn repair_complete_quoted_checksum(
        output: &mut [u8],
        quote_start: usize,
        quoted: &QuotedMeta,
    ) -> PacketTransformationResult<()> {
        if output.len() - quote_start < quoted.total_length {
            return Ok(());
        }
        let offset = quote_start + quoted.offset;
        let end = quote_start + quoted.total_length;
        let mut segment = output[offset..end].to_vec();
        let meta = Self::quoted_meta(quoted);
        match quoted.protocol {
            IPPROTO_TCP => {
                if segment.len() < 20 {
                    return Err("truncated complete quoted TCP packet");
                }
                segment[16..18].fill(0);
                let value = transport_checksum(&meta, &segment);
                write_u16(&mut segment, 16, value);
            }
            IPPROTO_ICMP => {
                segment[2..4].fill(0);
                let value = checksum(&segment);
                write_u16(&mut segment, 2, value);
            }
            IPPROTO_ICMPV6 => {
                segment[2..4].fill(0);
                let value = transport_checksum(&meta, &segment);
                write_u16(&mut segment, 2, value);
            }
            _ => return Ok(()),
        }
        output[offset..end].copy_from_slice(&segment);
        Ok(())
    }

    fn translate_quoted_tcp(
        &mut self,
        output: &mut [u8],
        quote_start: usize,
        quoted: &QuotedMeta,
        inbound: bool,
    ) -> PacketTransformationResult<()> {
        let offset = quote_start + quoted.offset;
        let sport = read_u16(output, offset);
        let dport = read_u16(output, offset + 2);
        if sport == 0 || dport == 0 {
            return Err("invalid quoted TCP port");
        }
        let meta = Self::quoted_meta(quoted);
        let key = Self::tcp_key(&meta, sport, dport);
        let state = self
            .tcp_flows
            .get_mut(&key)
            .ok_or("unmapped quoted TCP flow")?;
        let source = Endpoint(quoted.src, sport);
        let destination = Endpoint(quoted.dst, dport);
        let valid = if inbound {
            source == state.local && destination == state.remote
        } else {
            source == state.remote && destination == state.local
        };
        if !valid {
            return Err("quoted TCP flow direction mismatch");
        }
        state.last = Instant::now();
        write_u32(
            output,
            offset + 4,
            if inbound {
                read_u32(output, offset + 4).wrapping_sub(state.delta_out)
            } else {
                if !state.delta_in_ready {
                    return Err("quoted peer sequence is not mapped");
                }
                read_u32(output, offset + 4).wrapping_sub(state.delta_in)
            },
        );
        let available = output.len() - offset;
        if available >= 14 && output[offset + 13] & 0x10 != 0 {
            let acknowledgement = read_u32(output, offset + 8);
            let translated = if inbound {
                if !state.delta_in_ready {
                    return Err("quoted acknowledgement is not mapped");
                }
                acknowledgement.wrapping_add(state.delta_in)
            } else {
                acknowledgement.wrapping_add(state.delta_out)
            };
            write_u32(output, offset + 8, translated);
        }
        Self::reverse_quoted_tcp_options(self.mode, output, offset, available, state, inbound)?;
        Self::repair_complete_quoted_checksum(output, quote_start, quoted)
    }

    fn validate_quoted_udp(
        &mut self,
        quote: &[u8],
        quoted: &QuotedMeta,
        inbound: bool,
    ) -> PacketTransformationResult<()> {
        let sport = read_u16(quote, quoted.offset);
        let dport = read_u16(quote, quoted.offset + 2);
        if dport == 0 {
            return Err("invalid quoted UDP port");
        }
        if !inbound {
            return Ok(());
        }
        let key = UdpKey {
            family: quoted.family,
            scope: quoted.scope,
            source: quoted.src,
            sport,
            destination: quoted.dst,
            dport,
        };
        let last = self
            .udp_flows
            .get_mut(&key)
            .ok_or("unmapped quoted UDP flow")?;
        if last.elapsed() > UDP_FLOW_TIMEOUT {
            return Err("unmapped quoted UDP flow");
        }
        *last = Instant::now();
        Ok(())
    }

    fn translate_quoted_echo(
        &mut self,
        output: &mut [u8],
        quote_start: usize,
        quoted: &QuotedMeta,
        inbound: bool,
    ) -> PacketTransformationResult<()> {
        if !inbound {
            return Ok(());
        }
        let offset = quote_start + quoted.offset;
        let expected = if quoted.family == 4 { 8 } else { 128 };
        if output[offset] != expected || output[offset + 1] != 0 {
            return Err("unsupported quoted ICMP message");
        }
        let wire_identifier = read_u16(output, offset + 4);
        let wire_sequence = read_u16(output, offset + 6);
        let wire_key =
            Self::echo_wire_key(quoted.family, quoted.scope, quoted.dst, wire_identifier);
        let local_key = self
            .echo_by_wire
            .get(&wire_key)
            .cloned()
            .ok_or("unmapped quoted ICMP echo")?;
        let state = self
            .echo_by_local
            .get_mut(&local_key)
            .ok_or("inconsistent quoted ICMP mapping")?;
        state.last = Instant::now();
        write_u16(output, offset + 4, state.local_identifier);
        write_u16(
            output,
            offset + 6,
            wire_sequence.wrapping_sub(state.sequence_delta),
        );
        let quoted_end = quote_start + quoted.total_length;
        if quoted_end <= output.len() {
            let transformed =
                Self::xor_echo_payload(&output[offset + 8..quoted_end], state, wire_sequence);
            output[offset + 8..quoted_end].copy_from_slice(&transformed);
        }
        Self::repair_complete_quoted_checksum(output, quote_start, quoted)
    }

    fn translate_icmp_error(
        &mut self,
        raw: Vec<u8>,
        meta: &Meta,
        inbound: bool,
    ) -> PacketTransformationResult<Vec<u8>> {
        let quote_start = meta.offset + 8;
        let quote = &raw[quote_start..];
        let quoted = parse_quoted_packet(quote, meta.interface)?;
        if ![IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, IPPROTO_ICMPV6].contains(&quoted.protocol) {
            return Err("unsupported quoted protocol");
        }
        let mut output = raw;
        match quoted.protocol {
            IPPROTO_TCP => self.translate_quoted_tcp(&mut output, quote_start, &quoted, inbound)?,
            IPPROTO_UDP => self.validate_quoted_udp(&output[quote_start..], &quoted, inbound)?,
            _ => self.translate_quoted_echo(&mut output, quote_start, &quoted, inbound)?,
        }
        Ok(output)
    }

    fn next_ipid(&mut self, meta: &Meta) -> u16 {
        self.ipid_counter = self.ipid_counter.wrapping_add(1);
        if self.mode == Mode::Windows {
            (self.derive("windows-ipid-origin", &[], 16) as u16)
                .wrapping_add(self.ipid_counter as u16)
        } else {
            self.derive(
                "linux-ipid",
                &[
                    DerivePart::Integer(u128::from(self.ipid_counter)),
                    DerivePart::Bytes(meta.src.as_slice()),
                    DerivePart::Bytes(meta.dst.as_slice()),
                    DerivePart::Integer(u128::from(meta.protocol)),
                ],
                16,
            ) as u16
        }
    }

    fn ipv6_flow_label(&self, raw: &[u8], meta: &Meta, icmp_type: Option<u8>) -> u32 {
        if self.mode == Mode::Windows
            || icmp_type
                .is_some_and(|value| ICMPV6_ND.contains(&value) || ICMPV6_MLD.contains(&value))
        {
            return 0;
        }
        let segment = &raw[meta.offset..];
        let discriminator = if [IPPROTO_TCP, IPPROTO_UDP].contains(&meta.protocol) {
            segment[..4].to_vec()
        } else if icmp_type.is_some_and(|value| ICMPV6_ECHO.contains(&value)) {
            vec![segment[0], segment[1], segment[4], segment[5]]
        } else {
            segment[..2].to_vec()
        };
        let value = self.derive(
            "ipv6-flow-label",
            &[
                DerivePart::Integer(u128::from(meta.scope)),
                DerivePart::Bytes(meta.src.as_slice()),
                DerivePart::Bytes(meta.dst.as_slice()),
                DerivePart::Integer(u128::from(meta.protocol)),
                DerivePart::Bytes(&discriminator),
            ],
            20,
        ) as u32;
        if value == 0 {
            1
        } else {
            value
        }
    }

    fn transform_network(
        &mut self,
        mut raw: Vec<u8>,
        meta: &Meta,
        outbound: bool,
        icmp_type: Option<u8>,
    ) -> Vec<u8> {
        if !outbound {
            return raw;
        }
        if meta.family == 4 {
            raw[1] = 0;
            raw[8] = if self.mode == Mode::Windows { 128 } else { 64 };
            let mut flags_fragment = read_u16(&raw, 6);
            if self.mode == Mode::Windows {
                flags_fragment |= 0x4000;
                write_u16(&mut raw, 4, self.next_ipid(meta));
            } else if flags_fragment & 0x4000 != 0 {
                write_u16(&mut raw, 4, 0);
            } else {
                write_u16(&mut raw, 4, self.next_ipid(meta));
            }
            write_u16(&mut raw, 6, flags_fragment);
        } else {
            let flow_label = self.ipv6_flow_label(&raw, meta, icmp_type);
            write_u32(&mut raw, 0, (6u32 << 28) | flow_label);
            raw[7] = if icmp_type.is_some_and(|value| ICMPV6_ND.contains(&value)) {
                255
            } else if icmp_type.is_some_and(|value| ICMPV6_MLD.contains(&value)) {
                1
            } else if self.mode == Mode::Windows {
                128
            } else {
                64
            };
        }
        raw
    }

    pub fn process(
        &mut self,
        raw: &[u8],
        outbound: bool,
        interface: u32,
        checksum_not_ready: bool,
    ) -> PacketTransformationResult<Vec<u8>> {
        let meta = parse_packet(raw, interface, checksum_not_ready)?;
        if outbound && meta.dst.is_loopback() {
            let udp_zero_checksum = match meta.protocol {
                IPPROTO_TCP => {
                    validate_tcp(raw, &meta, false, checksum_not_ready, true)?;
                    false
                }
                IPPROTO_UDP => validate_udp(raw, &meta, false, checksum_not_ready)?.zero_checksum,
                _ => {
                    validate_icmp(raw, &meta, false, checksum_not_ready)?;
                    false
                }
            };
            return finalize_packet(raw.to_vec(), &meta, udp_zero_checksum);
        }
        let mut output = raw.to_vec();
        let mut udp_zero_checksum = false;
        let mut icmp_type = None;
        match meta.protocol {
            IPPROTO_TCP => {
                let info = validate_tcp(
                    raw,
                    &meta,
                    outbound,
                    checksum_not_ready,
                    self.mode == Mode::Linux,
                )?;
                output = self.transform_tcp(output, &meta, &info, outbound)?;
            }
            IPPROTO_UDP => {
                let info = validate_udp(raw, &meta, outbound, checksum_not_ready)?;
                if outbound {
                    self.remember_udp_flow(&meta, info)?;
                }
                udp_zero_checksum = info.zero_checksum && !outbound;
            }
            _ => {
                let info = validate_icmp(raw, &meta, outbound, checksum_not_ready)?;
                icmp_type = Some(info.icmp_type);
                if (meta.protocol == IPPROTO_ICMP && ICMPV4_ERRORS.contains(&info.icmp_type))
                    || (meta.protocol == IPPROTO_ICMPV6 && ICMPV6_ERRORS.contains(&info.icmp_type))
                {
                    output = self.translate_icmp_error(output, &meta, !outbound)?;
                } else if [0, 8, 128, 129].contains(&info.icmp_type) {
                    output = self.transform_echo(output, &meta, info, outbound)?;
                }
            }
        }
        output = self.transform_network(output, &meta, outbound, icmp_type);
        finalize_packet(output, &meta, udp_zero_checksum)
    }

    pub fn remove_stale(&mut self, now: Instant) {
        self.tcp_flows.retain(|_, state| {
            let timeout = if state.reset || (state.fin_out && state.fin_in) {
                TCP_CLOSED_TIMEOUT
            } else if state.fin_out || state.fin_in {
                TCP_HALF_CLOSED_TIMEOUT
            } else {
                TCP_FLOW_TIMEOUT
            };
            now.saturating_duration_since(state.last) <= timeout
        });
        self.udp_flows
            .retain(|_, last| now.saturating_duration_since(*last) <= UDP_FLOW_TIMEOUT);
        let stale: Vec<_> = self
            .echo_by_local
            .iter()
            .filter_map(|(key, state)| {
                (now.saturating_duration_since(state.last) > ECHO_FLOW_TIMEOUT)
                    .then_some(key.clone())
            })
            .collect();
        for key in stale {
            self.remove_echo(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DerivePart, Engine, Mode};
    use crate::packet::{checksum, read_u32, write_u32};

    fn ipv4_tcp(
        source: [u8; 4],
        destination: [u8; 4],
        sport: u16,
        dport: u16,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
    ) -> Vec<u8> {
        let mut segment = vec![0u8; 20];
        segment[0..2].copy_from_slice(&sport.to_be_bytes());
        segment[2..4].copy_from_slice(&dport.to_be_bytes());
        segment[4..8].copy_from_slice(&sequence.to_be_bytes());
        segment[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
        segment[12] = 5 << 4;
        segment[13] = flags;
        segment[14..16].copy_from_slice(&64_240u16.to_be_bytes());
        let mut pseudo = Vec::with_capacity(12 + segment.len());
        pseudo.extend_from_slice(&source);
        pseudo.extend_from_slice(&destination);
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(&segment);
        let transport_checksum = checksum(&pseudo);
        segment[16..18].copy_from_slice(&transport_checksum.to_be_bytes());

        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + segment.len()) as u16).to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        let header_checksum = checksum(&packet);
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        packet.extend_from_slice(&segment);
        packet
    }

    #[test]
    fn derivation_matches_python_contract() {
        let engine = Engine::new(Mode::Linux, [0x11; 32]);
        assert_eq!(engine.derive("startup-self-test", &[], 32), 0xdeef_c128);
        assert_eq!(
            engine.derive(
                "mixed",
                &[
                    DerivePart::Integer(0),
                    DerivePart::Integer(256),
                    DerivePart::Bytes(b"abc")
                ],
                64,
            ),
            0x13e6_157a_2703_7969
        );
    }

    #[test]
    fn tcp_state_maps_handshake_and_rejects_restart_ack() {
        let local = [192, 0, 2, 10];
        let remote = [198, 51, 100, 20];
        let local_isn = 0x1020_3040;
        let remote_isn = 0x5060_7080;
        let mut engine = Engine::new(Mode::Linux, [0x11; 32]);

        let syn = ipv4_tcp(local, remote, 49_000, 443, local_isn, 0, 0x02);
        let wire_syn = engine.process(&syn, true, 2, false).unwrap();
        let wire_local_isn = read_u32(&wire_syn, 24);
        assert_ne!(wire_local_isn, local_isn);

        let syn_ack = ipv4_tcp(
            remote,
            local,
            443,
            49_000,
            remote_isn,
            wire_local_isn.wrapping_add(1),
            0x12,
        );
        let local_syn_ack = engine.process(&syn_ack, false, 2, false).unwrap();
        let local_remote_isn = read_u32(&local_syn_ack, 24);
        assert_ne!(local_remote_isn, remote_isn);
        assert_eq!(read_u32(&local_syn_ack, 28), local_isn.wrapping_add(1));

        let ack = ipv4_tcp(
            local,
            remote,
            49_000,
            443,
            local_isn.wrapping_add(1),
            local_remote_isn.wrapping_add(1),
            0x10,
        );
        let wire_ack = engine.process(&ack, true, 2, false).unwrap();
        assert_eq!(read_u32(&wire_ack, 24), wire_local_isn.wrapping_add(1));
        assert_eq!(read_u32(&wire_ack, 28), remote_isn.wrapping_add(1));

        let mut restarted = Engine::new(Mode::Linux, [0x11; 32]);
        assert_eq!(
            restarted.process(&ack, true, 2, false).unwrap_err(),
            "unmapped TCP flow"
        );
    }

    #[test]
    fn quoted_sack_edges_are_translated_once() {
        let local = [192, 0, 2, 10];
        let remote = [198, 51, 100, 20];
        let local_isn = 0x1020_3040;
        let remote_isn = 0x5060_7080;
        let mut engine = Engine::new(Mode::Linux, [0x11; 32]);

        let syn = ipv4_tcp(local, remote, 49_000, 443, local_isn, 0, 0x02);
        let wire_syn = engine.process(&syn, true, 2, false).unwrap();
        let syn_ack = ipv4_tcp(
            remote,
            local,
            443,
            49_000,
            remote_isn,
            read_u32(&wire_syn, 24).wrapping_add(1),
            0x12,
        );
        engine.process(&syn_ack, false, 2, false).unwrap();
        let state = engine.tcp_flows.values().next().unwrap().clone();
        assert!(state.delta_in_ready);
        assert_ne!(state.delta_in, 0);

        let left = 0x1122_3344;
        let right = 0x5566_7788;
        let mut header = vec![0u8; 32];
        header[12] = 8 << 4;
        header[20] = 5;
        header[21] = 10;
        write_u32(&mut header, 22, left);
        write_u32(&mut header, 26, right);

        Engine::reverse_quoted_tcp_options(Mode::Linux, &mut header, 0, 32, &state, true).unwrap();
        assert_eq!(read_u32(&header, 22), left.wrapping_add(state.delta_in));
        assert_eq!(read_u32(&header, 26), right.wrapping_add(state.delta_in));
    }
}
