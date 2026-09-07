use std::cmp::Ordering;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const ICMPV4_ERRORS: [u8; 3] = [3, 11, 12];
pub const ICMPV6_ERRORS: [u8; 4] = [1, 2, 3, 4];
pub const ICMPV6_ECHO: [u8; 2] = [128, 129];
pub const ICMPV6_MLD: [u8; 4] = [130, 131, 132, 143];
pub const ICMPV6_ND: [u8; 5] = [133, 134, 135, 136, 137];

pub type PacketTransformationResult<T> = Result<T, &'static str>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Address {
    bytes: [u8; 16],
    length: u8,
}

impl Address {
    fn from_slice(value: &[u8]) -> Self {
        let mut bytes = [0u8; 16];
        bytes[..value.len()].copy_from_slice(value);
        Self {
            bytes,
            length: value.len() as u8,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }

    pub fn is_loopback(&self) -> bool {
        match self.length {
            4 => self.bytes[0] == 127,
            16 => self.bytes[..15].iter().all(|byte| *byte == 0) && self.bytes[15] == 1,
            _ => false,
        }
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug)]
pub struct Meta {
    pub family: u8,
    pub protocol: u8,
    pub offset: usize,
    pub src: Address,
    pub dst: Address,
    pub hop_by_hop: bool,
    pub scope: u32,
    pub interface: u32,
}

#[derive(Clone, Debug)]
pub struct TcpOption {
    pub kind: u8,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct TcpInfo {
    pub sport: u16,
    pub dport: u16,
    pub header_length: usize,
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub options: Vec<TcpOption>,
}

#[derive(Clone, Copy, Debug)]
pub struct UdpInfo {
    pub sport: u16,
    pub dport: u16,
    pub zero_checksum: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct IcmpInfo {
    pub icmp_type: u8,
}

#[derive(Clone, Debug)]
pub struct QuotedMeta {
    pub family: u8,
    pub protocol: u8,
    pub offset: usize,
    pub src: Address,
    pub dst: Address,
    pub total_length: usize,
    pub scope: u32,
}

#[inline]
pub fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

#[inline]
pub fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        data[offset..offset + 4]
            .try_into()
            .expect("four-byte range"),
    )
}

#[inline]
pub fn write_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

#[inline]
pub fn write_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut total = 0u64;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        total += u64::from(word);
    }
    while total >> 16 != 0 {
        total = (total & 0xffff) + (total >> 16);
    }
    !(total as u16)
}

pub fn transport_checksum(meta: &Meta, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + segment.len());
    pseudo.extend_from_slice(meta.src.as_slice());
    pseudo.extend_from_slice(meta.dst.as_slice());
    if meta.family == 4 {
        pseudo.extend_from_slice(&[0, meta.protocol]);
        pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    } else {
        pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, meta.protocol]);
    }
    pseudo.extend_from_slice(segment);
    checksum(&pseudo)
}

fn parse_hop_by_hop(raw: &[u8]) -> PacketTransformationResult<usize> {
    if raw.len() < 48 {
        return Err("truncated hop-by-hop header");
    }
    let header_length = (usize::from(raw[41]) + 1) * 8;
    let end = 40usize
        .checked_add(header_length)
        .ok_or("invalid hop-by-hop length")?;
    if header_length < 8 || end > raw.len() {
        return Err("invalid hop-by-hop length");
    }
    if raw[40] != IPPROTO_ICMPV6 {
        return Err("unsupported extension-header chain");
    }
    let mut cursor = 42;
    let mut router_alert = false;
    while cursor < end {
        let kind = raw[cursor];
        if kind == 0 {
            cursor += 1;
            continue;
        }
        if cursor + 2 > end {
            return Err("truncated hop-by-hop option");
        }
        let option_length = usize::from(raw[cursor + 1]);
        let option_end = cursor
            .checked_add(2 + option_length)
            .ok_or("invalid hop-by-hop option length")?;
        if option_end > end {
            return Err("invalid hop-by-hop option length");
        }
        let value = &raw[cursor + 2..option_end];
        match kind {
            1 if value.iter().any(|byte| *byte != 0) => return Err("nonzero hop-by-hop padding"),
            1 => {}
            5 if option_length == 2 && value == [0, 0] && !router_alert => router_alert = true,
            5 if option_length == 2 && value == [0, 0] => {
                return Err("duplicate router-alert option")
            }
            5 => return Err("unsupported router-alert option"),
            _ => return Err("unsupported hop-by-hop option"),
        }
        cursor = option_end;
    }
    if !router_alert {
        return Err("missing MLD router-alert option");
    }
    Ok(end)
}

fn ipv6_requires_scope(source: Address, destination: Address) -> bool {
    [source, destination].iter().any(|address| {
        let value = address.as_slice();
        (value[0] == 0xfe && value[1] & 0xc0 == 0x80) || (value[0] == 0xff && value[1] & 0x0f <= 2)
    })
}

pub fn parse_packet(raw: &[u8], interface: u32, checksum_not_ready: bool) -> PacketTransformationResult<Meta> {
    if raw.is_empty() {
        return Err("empty packet");
    }
    match raw[0] >> 4 {
        4 => {
            if raw.len() < 20 {
                return Err("truncated IPv4 header");
            }
            if usize::from(raw[0] & 0x0f) * 4 != 20 {
                return Err("IPv4 options are not permitted");
            }
            let total_length = usize::from(read_u16(raw, 2));
            if total_length != raw.len() || total_length < 20 {
                return Err("IPv4 length mismatch");
            }
            if !checksum_not_ready && checksum(&raw[..20]) != 0 {
                return Err("invalid IPv4 header checksum");
            }
            let fragment = read_u16(raw, 6);
            if fragment & 0x8000 != 0 {
                return Err("invalid IPv4 reserved flag");
            }
            if fragment & 0x3fff != 0 {
                return Err("IPv4 fragments are not permitted");
            }
            let protocol = raw[9];
            if ![IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP].contains(&protocol) {
                return Err("unsupported IPv4 protocol");
            }
            Ok(Meta {
                family: 4,
                protocol,
                offset: 20,
                src: Address::from_slice(&raw[12..16]),
                dst: Address::from_slice(&raw[16..20]),
                hop_by_hop: false,
                scope: 0,
                interface,
            })
        }
        6 => {
            if raw.len() < 40 {
                return Err("truncated IPv6 header");
            }
            let payload_length = usize::from(read_u16(raw, 4));
            if payload_length == 0 && raw.len() != 40 {
                return Err("IPv6 jumbograms are not permitted");
            }
            if 40usize.checked_add(payload_length) != Some(raw.len()) {
                return Err("IPv6 length mismatch");
            }
            let hop_by_hop = raw[6] == 0;
            let (offset, protocol) = if hop_by_hop {
                (parse_hop_by_hop(raw)?, IPPROTO_ICMPV6)
            } else {
                (40, raw[6])
            };
            if ![IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6].contains(&protocol) {
                return Err("unsupported IPv6 next header");
            }
            let src = Address::from_slice(&raw[8..24]);
            let dst = Address::from_slice(&raw[24..40]);
            let needs_scope = ipv6_requires_scope(src, dst);
            if needs_scope && interface == 0 {
                return Err("missing IPv6 scope interface");
            }
            Ok(Meta {
                family: 6,
                protocol,
                offset,
                src,
                dst,
                hop_by_hop,
                scope: if needs_scope { interface } else { 0 },
                interface,
            })
        }
        _ => Err("unsupported IP version"),
    }
}

fn validate_tcp_options(
    options: &[u8],
    syn: bool,
    ack: bool,
    linux_mode: bool,
) -> PacketTransformationResult<Vec<TcpOption>> {
    let mut parsed = Vec::new();
    let mut singletons = [false; 256];
    let mut cursor = 0usize;
    while cursor < options.len() {
        let kind = options[cursor];
        if kind == 0 {
            if options[cursor + 1..].iter().any(|byte| *byte != 0) {
                return Err("nonzero TCP option padding");
            }
            parsed.push(TcpOption {
                kind,
                value: vec![0],
            });
            break;
        }
        if kind == 1 {
            parsed.push(TcpOption {
                kind,
                value: vec![1],
            });
            cursor += 1;
            continue;
        }
        if cursor + 2 > options.len() {
            return Err("truncated TCP option");
        }
        let option_length = usize::from(options[cursor + 1]);
        if option_length < 2
            || cursor
                .checked_add(option_length)
                .is_none_or(|end| end > options.len())
        {
            return Err("invalid TCP option length");
        }
        let value = options[cursor..cursor + option_length].to_vec();
        if [2, 3, 4, 5, 8, 34].contains(&kind) && singletons[usize::from(kind)] {
            return Err("duplicate TCP option");
        }
        match kind {
            2 if option_length != 4 || !syn || read_u16(&value, 2) == 0 => {
                return Err("invalid MSS option")
            }
            2 => {}
            3 if option_length != 3 || !syn || value[2] > 14 => {
                return Err("invalid window-scale option")
            }
            3 => {}
            4 if option_length != 2 || !syn => return Err("invalid SACK-permitted option"),
            4 => {}
            5 if syn
                || !ack
                || !(10..=34).contains(&option_length)
                || (option_length - 2) % 8 != 0 =>
            {
                return Err("invalid SACK option")
            }
            5 => {}
            8 if option_length != 10 => return Err("invalid timestamp option"),
            8 => {}
            34 if !linux_mode
                || !syn
                || !(option_length == 2 || (6..=18).contains(&option_length))
                || (option_length - 2) % 2 != 0 =>
            {
                return Err("invalid TCP Fast Open option")
            }
            34 => {}
            _ => return Err("unsupported TCP option"),
        }
        singletons[usize::from(kind)] = true;
        parsed.push(TcpOption { kind, value });
        cursor += option_length;
    }
    Ok(parsed)
}

pub fn validate_tcp(
    raw: &[u8],
    meta: &Meta,
    outbound: bool,
    checksum_not_ready: bool,
    linux_mode: bool,
) -> PacketTransformationResult<TcpInfo> {
    let segment = &raw[meta.offset..];
    if segment.len() < 20 {
        return Err("truncated TCP header");
    }
    let sport = read_u16(segment, 0);
    let dport = read_u16(segment, 2);
    if sport == 0 || dport == 0 {
        return Err("invalid TCP port");
    }
    let header_length = usize::from(segment[12] >> 4) * 4;
    if !(20..=60).contains(&header_length) || header_length > segment.len() {
        return Err("invalid TCP header length");
    }
    if segment[12] & 0x0f != 0 {
        return Err("TCP reserved bits are not permitted");
    }
    let flags = segment[13];
    let syn = flags & 0x02 != 0;
    let ack = flags & 0x10 != 0;
    let fin = flags & 0x01 != 0;
    let rst = flags & 0x04 != 0;
    if flags == 0 || (syn && (fin || rst)) || (fin && rst) {
        return Err("invalid TCP flag combination");
    }
    if outbound && flags & 0xc0 != 0 {
        return Err("outbound ECN flags are not permitted");
    }
    if flags & 0x20 == 0 && read_u16(segment, 18) != 0 {
        return Err("TCP urgent pointer without URG");
    }
    if !checksum_not_ready && transport_checksum(meta, segment) != 0 {
        return Err("invalid TCP checksum");
    }
    let options = validate_tcp_options(&segment[20..header_length], syn, ack, linux_mode)?;
    Ok(TcpInfo {
        sport,
        dport,
        header_length,
        syn,
        ack,
        fin,
        rst,
        options,
    })
}

pub fn validate_udp(
    raw: &[u8],
    meta: &Meta,
    outbound: bool,
    checksum_not_ready: bool,
) -> PacketTransformationResult<UdpInfo> {
    let segment = &raw[meta.offset..];
    if segment.len() < 8 {
        return Err("truncated UDP header");
    }
    let sport = read_u16(segment, 0);
    let dport = read_u16(segment, 2);
    let length = usize::from(read_u16(segment, 4));
    let received_checksum = read_u16(segment, 6);
    if dport == 0 || length != segment.len() || length < 8 {
        return Err("invalid UDP header");
    }
    if received_checksum == 0 {
        if meta.family == 6 || outbound {
            return Err("missing UDP checksum");
        }
    } else if !checksum_not_ready && transport_checksum(meta, segment) != 0 {
        return Err("invalid UDP checksum");
    }
    Ok(UdpInfo {
        sport,
        dport,
        zero_checksum: received_checksum == 0,
    })
}

fn validate_nd_options(segment: &[u8], start: usize, allowed: &[u8]) -> PacketTransformationResult<()> {
    let mut cursor = start;
    while cursor < segment.len() {
        if cursor + 2 > segment.len() {
            return Err("truncated ND option");
        }
        let units = usize::from(segment[cursor + 1]);
        if units == 0 {
            return Err("zero-length ND option");
        }
        if !allowed.contains(&segment[cursor]) {
            return Err("unsupported ND option");
        }
        cursor = cursor
            .checked_add(units * 8)
            .ok_or("invalid ND option length")?;
        if cursor > segment.len() {
            return Err("invalid ND option length");
        }
    }
    if cursor != segment.len() {
        return Err("invalid ND option padding");
    }
    Ok(())
}

fn validate_mld(segment: &[u8], icmp_type: u8) -> PacketTransformationResult<()> {
    if icmp_type == 130 {
        if segment.len() == 24 {
            return Ok(());
        }
        if segment.len() < 28 {
            return Err("truncated MLD query");
        }
        let sources = usize::from(read_u16(segment, 26));
        if segment.len()
            != 28usize
                .checked_add(sources * 16)
                .ok_or("invalid MLD query length")?
        {
            return Err("invalid MLD query length");
        }
        return Ok(());
    }
    if [131, 132].contains(&icmp_type) {
        return if segment.len() == 24 {
            Ok(())
        } else {
            Err("invalid MLDv1 message length")
        };
    }
    if segment.len() < 8 {
        return Err("truncated MLDv2 report");
    }
    let records = usize::from(read_u16(segment, 6));
    let mut cursor = 8usize;
    for _ in 0..records {
        if cursor + 20 > segment.len() {
            return Err("truncated MLDv2 record");
        }
        if !(1..=6).contains(&segment[cursor]) {
            return Err("invalid MLDv2 record type");
        }
        let auxiliary_words = usize::from(segment[cursor + 1]);
        let sources = usize::from(read_u16(segment, cursor + 2));
        cursor = cursor
            .checked_add(20)
            .and_then(|value| value.checked_add(sources * 16))
            .and_then(|value| value.checked_add(auxiliary_words * 4))
            .ok_or("invalid MLDv2 record length")?;
        if cursor > segment.len() {
            return Err("invalid MLDv2 record length");
        }
    }
    if cursor != segment.len() {
        return Err("invalid MLDv2 report length");
    }
    Ok(())
}

pub fn validate_icmp(
    raw: &[u8],
    meta: &Meta,
    outbound: bool,
    checksum_not_ready: bool,
) -> PacketTransformationResult<IcmpInfo> {
    let segment = &raw[meta.offset..];
    if segment.len() < 8 {
        return Err("truncated ICMP header");
    }
    let icmp_type = segment[0];
    let code = segment[1];
    if meta.protocol == IPPROTO_ICMP {
        if !checksum_not_ready && checksum(segment) != 0 {
            return Err("invalid ICMP checksum");
        }
        if ![0, 3, 8, 11, 12].contains(&icmp_type) {
            return Err("unsupported ICMP type");
        }
        if [0, 8].contains(&icmp_type) && code != 0 {
            return Err("invalid ICMP echo code");
        }
        if (icmp_type == 3 && code > 15)
            || (icmp_type == 11 && code > 1)
            || (icmp_type == 12 && code > 2)
        {
            return Err("invalid ICMP code");
        }
        return Ok(IcmpInfo { icmp_type });
    }
    if !checksum_not_ready && transport_checksum(meta, segment) != 0 {
        return Err("invalid ICMPv6 checksum");
    }
    if ICMPV6_ERRORS.contains(&icmp_type) {
        let maximum_code = match icmp_type {
            1 => 9,
            2 => 0,
            3 => 1,
            4 => 10,
            _ => unreachable!(),
        };
        if meta.hop_by_hop || code > maximum_code {
            return Err("invalid ICMPv6 error");
        }
    } else if ICMPV6_ECHO.contains(&icmp_type) {
        if code != 0 || meta.hop_by_hop {
            return Err("invalid ICMPv6 echo message");
        }
    } else if ICMPV6_MLD.contains(&icmp_type) {
        if code != 0 || !meta.hop_by_hop || meta.dst.as_slice()[0] != 0xff || raw[7] != 1 {
            return Err("invalid MLD envelope");
        }
        validate_mld(segment, icmp_type)?;
    } else if ICMPV6_ND.contains(&icmp_type) {
        if code != 0 || meta.hop_by_hop || raw[7] != 255 {
            return Err("invalid Neighbor Discovery envelope");
        }
        let minimum = match icmp_type {
            133 => 8,
            134 => 16,
            135 | 136 => 24,
            137 => 40,
            _ => unreachable!(),
        };
        if segment.len() < minimum {
            return Err("truncated Neighbor Discovery message");
        }
        let allowed: &[u8] = match icmp_type {
            133 => &[1],
            134 => &[1, 3, 5, 24, 25, 31, 37, 38],
            135 => &[1],
            136 => &[2],
            137 => &[2, 4],
            _ => unreachable!(),
        };
        validate_nd_options(segment, minimum, allowed)?;
        if [133, 135, 137].contains(&icmp_type) && segment[4..8].iter().any(|byte| *byte != 0) {
            return Err("nonzero Neighbor Discovery reserved field");
        }
        if [135, 136].contains(&icmp_type)
            && (segment[8..24].iter().all(|byte| *byte == 0) || segment[8] == 0xff)
        {
            return Err("invalid Neighbor Discovery target");
        }
        if icmp_type == 136 && read_u32(segment, 4) & 0x1fff_ffff != 0 {
            return Err("nonzero Neighbor Advertisement reserved bits");
        }
        if outbound && [134, 137].contains(&icmp_type) {
            return Err("router-only Neighbor Discovery message");
        }
    } else {
        return Err("unsupported ICMPv6 type");
    }
    Ok(IcmpInfo { icmp_type })
}

pub fn parse_quoted_packet(quote: &[u8], interface: u32) -> PacketTransformationResult<QuotedMeta> {
    if quote.is_empty() {
        return Err("missing ICMP quotation");
    }
    match quote[0] >> 4 {
        4 => {
            if quote.len() < 28 || quote[0] & 0x0f != 5 {
                return Err("invalid quoted IPv4 packet");
            }
            if checksum(&quote[..20]) != 0 {
                return Err("invalid quoted IPv4 checksum");
            }
            if read_u16(quote, 6) & 0xbfff != 0 {
                return Err("invalid quoted IPv4 fragment");
            }
            let total_length = usize::from(read_u16(quote, 2));
            if total_length < 28 {
                return Err("invalid quoted IPv4 length");
            }
            if quote.len() > total_length {
                return Err("unsupported quoted IPv4 trailing data");
            }
            let protocol = quote[9];
            if ![IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP].contains(&protocol) {
                return Err("unsupported quoted IPv4 protocol");
            }
            Ok(QuotedMeta {
                family: 4,
                protocol,
                offset: 20,
                src: Address::from_slice(&quote[12..16]),
                dst: Address::from_slice(&quote[16..20]),
                total_length,
                scope: 0,
            })
        }
        6 => {
            if quote.len() < 48 {
                return Err("invalid quoted IPv6 packet");
            }
            let protocol = quote[6];
            if ![IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMPV6].contains(&protocol) {
                return Err("unsupported quoted IPv6 next header");
            }
            let payload_length = usize::from(read_u16(quote, 4));
            if payload_length < 8 {
                return Err("invalid quoted IPv6 length");
            }
            if quote.len() > 40 + payload_length {
                return Err("unsupported quoted IPv6 trailing data");
            }
            let src = Address::from_slice(&quote[8..24]);
            let dst = Address::from_slice(&quote[24..40]);
            let needs_scope = ipv6_requires_scope(src, dst);
            if needs_scope && interface == 0 {
                return Err("missing quoted IPv6 scope interface");
            }
            Ok(QuotedMeta {
                family: 6,
                protocol,
                offset: 40,
                src,
                dst,
                total_length: 40 + payload_length,
                scope: if needs_scope { interface } else { 0 },
            })
        }
        _ => Err("unsupported quoted IP version"),
    }
}

pub fn finalize_packet(
    mut raw: Vec<u8>,
    meta: &Meta,
    udp_zero_checksum: bool,
) -> PacketTransformationResult<Vec<u8>> {
    if meta.family == 4 {
        if raw.len() > u16::MAX as usize {
            return Err("IPv4 packet exceeds maximum length");
        }
        let length = raw.len() as u16;
        write_u16(&mut raw, 2, length);
    } else {
        let payload_length = raw
            .len()
            .checked_sub(40)
            .ok_or("invalid IPv6 packet length")?;
        if payload_length > u16::MAX as usize {
            return Err("IPv6 packet exceeds maximum length");
        }
        write_u16(&mut raw, 4, payload_length as u16);
    }
    let mut segment = raw[meta.offset..].to_vec();
    match meta.protocol {
        IPPROTO_TCP => {
            if segment.len() < 20 {
                return Err("truncated final TCP segment");
            }
            segment[16..18].fill(0);
            let value = transport_checksum(meta, &segment);
            write_u16(&mut segment, 16, value);
        }
        IPPROTO_UDP => {
            if segment.len() < 8 || segment.len() > u16::MAX as usize {
                return Err("invalid final UDP segment");
            }
            let length = segment.len() as u16;
            write_u16(&mut segment, 4, length);
            segment[6..8].fill(0);
            if !udp_zero_checksum {
                let value = transport_checksum(meta, &segment);
                write_u16(&mut segment, 6, if value == 0 { 0xffff } else { value });
            }
        }
        IPPROTO_ICMP => {
            segment[2..4].fill(0);
            let value = checksum(&segment);
            write_u16(&mut segment, 2, value);
        }
        IPPROTO_ICMPV6 => {
            segment[2..4].fill(0);
            let value = transport_checksum(meta, &segment);
            write_u16(&mut segment, 2, value);
        }
        _ => return Err("unsupported transport protocol"),
    }
    raw[meta.offset..].copy_from_slice(&segment);
    if meta.family == 4 {
        raw[10..12].fill(0);
        let value = checksum(&raw[..20]);
        write_u16(&mut raw, 10, value);
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::{
        checksum, parse_packet, parse_quoted_packet, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP,
    };

    #[test]
    fn internet_checksum_vector() {
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
    }

    #[test]
    fn rejects_fragments_and_options() {
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        packet[9] = 17;
        packet[10..12].fill(0);
        let value = checksum(&packet);
        packet[10..12].copy_from_slice(&value.to_be_bytes());
        assert_eq!(
            parse_packet(&packet, 0, false).unwrap_err(),
            "IPv4 fragments are not permitted"
        );
        packet[0] = 0x46;
        assert_eq!(
            parse_packet(&packet, 0, true).unwrap_err(),
            "IPv4 options are not permitted"
        );
    }

    #[test]
    fn quoted_ipv4_rejects_more_fragments_but_allows_df() {
        let mut quote = [0u8; 28];
        quote[0] = 0x45;
        quote[2..4].copy_from_slice(&28u16.to_be_bytes());
        quote[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        quote[9] = 17;
        let checksum_value = checksum(&quote[..20]);
        quote[10..12].copy_from_slice(&checksum_value.to_be_bytes());
        assert_eq!(
            parse_quoted_packet(&quote, 0).unwrap_err(),
            "invalid quoted IPv4 fragment"
        );

        quote[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        quote[10..12].fill(0);
        let checksum_value = checksum(&quote[..20]);
        quote[10..12].copy_from_slice(&checksum_value.to_be_bytes());
        assert!(parse_quoted_packet(&quote, 0).is_ok());
    }

    #[test]
    fn quoted_packets_reject_unprocessed_protocols_and_trailing_data() {
        let mut quote = vec![0u8; 28];
        quote[0] = 0x45;
        quote[2..4].copy_from_slice(&28u16.to_be_bytes());
        quote[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        quote[9] = IPPROTO_ICMPV6;
        let checksum_value = checksum(&quote[..20]);
        quote[10..12].copy_from_slice(&checksum_value.to_be_bytes());
        assert_eq!(
            parse_quoted_packet(&quote, 0).unwrap_err(),
            "unsupported quoted IPv4 protocol"
        );

        quote[9] = IPPROTO_TCP;
        quote[10..12].fill(0);
        let checksum_value = checksum(&quote[..20]);
        quote[10..12].copy_from_slice(&checksum_value.to_be_bytes());
        quote.push(0);
        assert_eq!(
            parse_quoted_packet(&quote, 0).unwrap_err(),
            "unsupported quoted IPv4 trailing data"
        );

        let mut quote6 = vec![0u8; 49];
        quote6[0] = 0x60;
        quote6[4..6].copy_from_slice(&8u16.to_be_bytes());
        quote6[6] = IPPROTO_UDP;
        assert_eq!(
            parse_quoted_packet(&quote6, 2).unwrap_err(),
            "unsupported quoted IPv6 trailing data"
        );
    }

    #[test]
    fn rejects_duplicate_ipv6_router_alert_without_counter_overflow() {
        let mut packet = [0u8; 56];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16u16.to_be_bytes());
        packet[6] = 0;
        packet[7] = 1;
        packet[40] = 58;
        packet[41] = 1;
        packet[42..56].copy_from_slice(&[5, 2, 0, 0, 5, 2, 0, 0, 1, 4, 0, 0, 0, 0]);
        assert_eq!(
            parse_packet(&packet, 2, false).unwrap_err(),
            "duplicate router-alert option"
        );
    }
}
