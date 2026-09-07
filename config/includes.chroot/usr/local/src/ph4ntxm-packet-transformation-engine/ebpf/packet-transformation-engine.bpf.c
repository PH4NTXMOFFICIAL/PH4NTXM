#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "packet-transformation-engine-shared.h"

#define DHCP_CLIENT_PORT 68U
#define DHCP_SERVER_PORT 67U
#define DHCP_FIXED_LENGTH 240U
#define DHCP_MIN_UDP_LENGTH (8U + DHCP_FIXED_LENGTH + 4U)
#define DHCP_MAX_IP_LENGTH 1500U
#define DHCP_OPTION_BYTES_MAX (DHCP_MAX_IP_LENGTH - 20U - 8U - DHCP_FIXED_LENGTH)
#define DHCP_OPTION_COUNT_MAX 32U
#define EAPOL_ETHERTYPE 0x888eU
#define EAPOL_HEADER_LENGTH 4U

struct ipv4_header {
    __u8 version_ihl;
    __u8 tos;
    __be16 total_length;
    __be16 identification;
    __be16 flags_fragment;
    __u8 ttl;
    __u8 protocol;
    __be16 checksum;
    __be32 source;
    __be32 destination;
};

struct udp_header {
    __be16 source;
    __be16 destination;
    __be16 length;
    __be16 checksum;
};

struct vlan_header {
    __be16 control;
    __be16 encapsulated_protocol;
};

struct __attribute__((packed)) arp_ether_ipv4 {
    __be16 hardware_type;
    __be16 protocol_type;
    __u8 hardware_length;
    __u8 protocol_length;
    __be16 operation;
    __u8 sender_hardware[6];
    __be32 sender_protocol;
    __u8 target_hardware[6];
    __be32 target_protocol;
};

_Static_assert(sizeof(struct ipv4_header) == 20, "IPv4 wire header size");
_Static_assert(sizeof(struct udp_header) == 8, "UDP wire header size");
_Static_assert(sizeof(struct vlan_header) == 4, "VLAN wire header size");
_Static_assert(sizeof(struct arp_ether_ipv4) == 28, "ARP wire payload size");

const volatile struct ph4ntxm_packet_transformation_engine_guard_config ph4ntxm_config SEC(".rodata.ph4ntxm") = {};

static __always_inline int load_mac_bytes(struct __sk_buff *skb, __u32 offset,
                                           void *destination, __u32 length)
{
    return bpf_skb_load_bytes_relative(skb, offset, destination, length,
                                       BPF_HDR_START_MAC);
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PACKET_TRANSFORMATION_ENGINE_DROP_REASON_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} ph4ntxm_drops SEC(".maps");

static __always_inline int record_drop(__u32 reason)
{
    __u64 *counter = bpf_map_lookup_elem(&ph4ntxm_drops, &reason);

    if (counter != NULL)
        __sync_fetch_and_add(counter, 1);
    return TC_ACT_SHOT;
}

static __always_inline int mac_equal(const __u8 left[6], const __u8 right[6])
{
    return left[0] == right[0] && left[1] == right[1] && left[2] == right[2] &&
           left[3] == right[3] && left[4] == right[4] && left[5] == right[5];
}

static __always_inline int mac_matches_config(const __u8 candidate[6])
{
    return candidate[0] == ph4ntxm_config.mac[0] && candidate[1] == ph4ntxm_config.mac[1] &&
           candidate[2] == ph4ntxm_config.mac[2] && candidate[3] == ph4ntxm_config.mac[3] &&
           candidate[4] == ph4ntxm_config.mac[4] && candidate[5] == ph4ntxm_config.mac[5];
}

struct zero_bytes_context {
    struct __sk_buff *skb;
    __u32 offset;
    __u32 length;
    __u8 failed;
};

static long zero_bytes_step(__u32 index, void *opaque)
{
    struct zero_bytes_context *context = opaque;
    __u8 value;

    if (index >= context->length)
        return 1;
    if (load_mac_bytes(context->skb, context->offset + index,
                       &value, sizeof(value)) < 0 || value != 0) {
        context->failed = 1;
        return 1;
    }
    return 0;
}

static __noinline int bytes_are_zero(struct __sk_buff *skb, __u32 offset, __u32 length,
                                     __u32 maximum)
{
    struct zero_bytes_context context = {
        .skb = skb,
        .offset = offset,
        .length = length,
    };

    if (length > maximum ||
        bpf_loop(maximum, zero_bytes_step, &context, 0) < 0 || context.failed)
        return 0;
    return 1;
}

static __always_inline __u32 fold_checksum(__u32 sum)
{
    sum = (sum & 0xffffU) + (sum >> 16);
    sum = (sum & 0xffffU) + (sum >> 16);
    return sum;
}

static __always_inline __u16 ipv4_checksum(const struct ipv4_header *header)
{
    const __u8 *bytes = (const __u8 *)header;
    __u32 sum = 0;

#pragma clang loop unroll(full)
    for (int index = 0; index < 20; index += 2)
        sum += ((__u16)bytes[index] << 8) | bytes[index + 1];
    return (__u16)(~fold_checksum(sum));
}

static __always_inline int ipv4_checksum_valid(const struct ipv4_header *header)
{
    const __u8 *bytes = (const __u8 *)header;
    __u32 sum = 0;

#pragma clang loop unroll(full)
    for (int index = 0; index < 20; index += 2)
        sum += ((__u16)bytes[index] << 8) | bytes[index + 1];
    return fold_checksum(sum) == 0xffffU;
}

struct udp_checksum_context {
    struct __sk_buff *skb;
    __u32 offset;
    __u32 length;
    __u32 sum;
    __u8 failed;
};

static long udp_checksum_step(__u32 index, void *opaque)
{
    struct udp_checksum_context *context = opaque;
    __u32 byte_offset = index * 2U;
    __be16 word;

    if (byte_offset + 1U >= context->length)
        return 1;
    if (load_mac_bytes(context->skb, context->offset + byte_offset,
                       &word, sizeof(word)) < 0) {
        context->failed = 1;
        return 1;
    }
    context->sum += bpf_ntohs(word);
    return 0;
}

static __noinline int udp_checksum_valid(struct __sk_buff *skb, __u32 udp_offset,
                                         const struct ipv4_header *ip,
                                         __u16 udp_length, int rewrite)
{
    __u32 source = bpf_ntohl(ip->source);
    __u32 destination = bpf_ntohl(ip->destination);
    struct udp_checksum_context context = {
        .skb = skb,
        .offset = udp_offset,
        .length = udp_length,
        .sum = (source >> 16) + (source & 0xffffU) +
               (destination >> 16) + (destination & 0xffffU) +
               IPPROTO_UDP + udp_length,
    };

    if (bpf_loop((DHCP_MAX_IP_LENGTH - 20U) / 2U, udp_checksum_step,
                 &context, 0) < 0 || context.failed)
        return 0;
    if ((udp_length & 1U) != 0) {
        __u8 last;

        if (load_mac_bytes(skb, udp_offset + udp_length - 1U, &last, sizeof(last)) < 0)
            return 0;
        context.sum += (__u16)last << 8;
    }
    if (rewrite) {
        __u16 value = (__u16)~fold_checksum(context.sum);
        __be16 wire = bpf_htons(value == 0 ? 0xffffU : value);

        return bpf_skb_store_bytes(skb, udp_offset + 6U, &wire, sizeof(wire),
                                   BPF_F_INVALIDATE_HASH) == 0;
    }
    return fold_checksum(context.sum) == 0xffffU;
}

static __always_inline int ipv4_layout_valid(struct __sk_buff *skb, __u32 network_offset,
                                              int exact, struct ipv4_header *ip)
{
    __u32 total_length;

    if (load_mac_bytes(skb, network_offset, ip, sizeof(*ip)) < 0 || ip->version_ihl != 0x45)
        return 0;
    total_length = bpf_ntohs(ip->total_length);
    if (total_length < sizeof(*ip) || network_offset + total_length > skb->len)
        return 0;
    if (exact && network_offset + total_length != skb->len)
        return 0;
    return ipv4_checksum_valid(ip);
}

static __always_inline int ipv6_layout_valid(struct __sk_buff *skb, __u32 network_offset)
{
    __u8 version;
    __be16 payload_length;

    if (load_mac_bytes(skb, network_offset, &version, sizeof(version)) < 0 ||
        (version >> 4) != 6)
        return 0;
    if (load_mac_bytes(skb, network_offset + 4U, &payload_length,
                       sizeof(payload_length)) < 0)
        return 0;
    return network_offset + 40U + bpf_ntohs(payload_length) == skb->len;
}

static __always_inline int validate_arp(struct __sk_buff *skb, __u32 offset,
                                        const __u8 source_mac[6], const __u8 destination_mac[6])
{
    struct arp_ether_ipv4 arp;
    __u16 operation;

    if (offset + sizeof(arp) != skb->len ||
        load_mac_bytes(skb, offset, &arp, sizeof(arp)) < 0)
        return PACKET_TRANSFORMATION_ENGINE_DROP_ARP_LAYOUT;
    if (arp.hardware_type != bpf_htons(1) || arp.protocol_type != bpf_htons(ETH_P_IP) ||
        arp.hardware_length != 6 || arp.protocol_length != 4)
        return PACKET_TRANSFORMATION_ENGINE_DROP_ARP_HEADER;
    if (!mac_equal(arp.sender_hardware, source_mac))
        return PACKET_TRANSFORMATION_ENGINE_DROP_ARP_SOURCE;
    operation = bpf_ntohs(arp.operation);
    if (operation == 1)
        return bytes_are_zero(skb, offset + 18U, 6U, 6U) ?
               PACKET_TRANSFORMATION_ENGINE_DROP_REASON_COUNT : PACKET_TRANSFORMATION_ENGINE_DROP_ARP_TARGET;
    if (operation == 2)
        return mac_equal(arp.target_hardware, destination_mac) &&
               (destination_mac[0] & 1U) == 0 ?
               PACKET_TRANSFORMATION_ENGINE_DROP_REASON_COUNT : PACKET_TRANSFORMATION_ENGINE_DROP_ARP_TARGET;
    return PACKET_TRANSFORMATION_ENGINE_DROP_ARP_HEADER;
}

static __always_inline int validate_eapol(struct __sk_buff *skb, __u32 offset)
{
    __u8 header[EAPOL_HEADER_LENGTH];
    __u16 payload_length;

    if (load_mac_bytes(skb, offset, header, sizeof(header)) < 0 ||
        header[0] < 1 || header[0] > 3 || header[1] > 4)
        return 0;
    payload_length = ((__u16)header[2] << 8) | header[3];
    if (offset + EAPOL_HEADER_LENGTH + payload_length != skb->len)
        return 0;
    if ((header[1] == 1 || header[1] == 2) && payload_length != 0)
        return 0;
    return 1;
}

static __always_inline int validate_client_identifier(struct __sk_buff *skb, __u32 offset,
                                                       __u8 length)
{
    __u8 value[7];

    if (length != sizeof(value) ||
        load_mac_bytes(skb, offset, value, sizeof(value)) < 0 || value[0] != 1)
        return 0;
    return mac_matches_config(&value[1]);
}

static __always_inline int validate_hostname(struct __sk_buff *skb, __u32 offset, __u8 length)
{
    if (length != ph4ntxm_config.hostname_length)
        return 0;
#pragma clang loop unroll(full)
    for (__u32 index = 0; index < PH4NTXM_PACKET_TRANSFORMATION_ENGINE_HOSTNAME_MAX; index++) {
        __u8 value;

        if (index >= length)
            break;
        if (load_mac_bytes(skb, offset + index, &value, sizeof(value)) < 0 ||
            value != ph4ntxm_config.hostname[index])
            return 0;
    }
    return 1;
}

static __always_inline int validate_vendor(struct __sk_buff *skb, __u32 offset, __u8 length)
{
    __u8 value[8];

    if (length != sizeof(value) || load_mac_bytes(skb, offset, value, sizeof(value)) < 0)
        return 0;
    if (ph4ntxm_config.mode == PH4NTXM_PACKET_TRANSFORMATION_ENGINE_MODE_LINUX)
        return value[0] == 'd' && value[1] == 'h' && value[2] == 'c' && value[3] == 'l' &&
               value[4] == 'i' && value[5] == 'e' && value[6] == 'n' && value[7] == 't';
    return value[0] == 'M' && value[1] == 'S' && value[2] == 'F' && value[3] == 'T' &&
           value[4] == ' ' && value[5] == '5' && value[6] == '.' && value[7] == '0';
}

static __always_inline int validate_parameter_request_list(struct __sk_buff *skb, __u32 offset,
                                                            __u8 length)
{
    __u8 value[6];
    const __u8 native[17] = {1, 2, 6, 12, 15, 26, 28, 121, 3, 33, 40, 41, 42,
                             119, 249, 252, 17};

    if (length == sizeof(native)) {
#pragma clang loop unroll(full)
        for (__u32 index = 0; index < sizeof(native); index++) {
            __u8 byte;
            if (load_mac_bytes(skb, offset + index, &byte, 1) < 0 || byte != native[index])
                return 0;
        }
        return 1;
    }

    if (length != sizeof(value) || load_mac_bytes(skb, offset, value, sizeof(value)) < 0 ||
        value[0] != 1)
        return 0;
    if (ph4ntxm_config.mode == PH4NTXM_PACKET_TRANSFORMATION_ENGINE_MODE_LINUX)
        return value[1] == 28 && value[2] == 3 && value[3] == 15 && value[4] == 6 &&
               value[5] == 12;
    return value[1] == 3 && value[2] == 6 && value[3] == 12 && value[4] == 15 &&
           value[5] == 28;
}

#define DHCP_SEEN_HOSTNAME (1U << 0)
#define DHCP_SEEN_REQUESTED_ADDRESS (1U << 1)
#define DHCP_SEEN_MESSAGE_TYPE (1U << 2)
#define DHCP_SEEN_SERVER_IDENTIFIER (1U << 3)
#define DHCP_SEEN_PARAMETER_LIST (1U << 4)
#define DHCP_SEEN_VENDOR (1U << 5)
#define DHCP_SEEN_CLIENT_IDENTIFIER (1U << 6)
#define DHCP_SEEN_MAX_SIZE (1U << 7)

struct dhcp_options_context {
    struct __sk_buff *skb;
    __u32 offset;
    __u32 length;
    __u32 cursor;
    __u16 seen;
    __u8 message_type;
    __u8 found_end;
    __u8 failed;
    __be32 requested_address;
    __be32 server_identifier;
};

static long dhcp_option_step(__u32 iteration, void *opaque)
{
    struct dhcp_options_context *context = opaque;
    __u8 option_length;
    __u8 code;

    (void)iteration;
    if (context->cursor >= context->length)
        return 1;
    if (load_mac_bytes(context->skb, context->offset + context->cursor,
                       &code, sizeof(code)) < 0) {
        context->failed = 1;
        return 1;
    }
    context->cursor++;
    if (code == 0)
        return 0;
    if (code == 255) {
        context->found_end = 1;
        return 1;
    }
    if (context->cursor >= context->length ||
        load_mac_bytes(context->skb, context->offset + context->cursor,
                       &option_length, sizeof(option_length)) < 0) {
        context->failed = 1;
        return 1;
    }
    context->cursor++;
    if ((__u32)option_length > context->length - context->cursor) {
        context->failed = 1;
        return 1;
    }
    switch (code) {
    case 12:
        if ((context->seen & DHCP_SEEN_HOSTNAME) != 0 ||
            !validate_hostname(context->skb, context->offset + context->cursor, option_length))
            context->failed = 1;
        context->seen |= DHCP_SEEN_HOSTNAME;
        break;
    case 50:
        if ((context->seen & DHCP_SEEN_REQUESTED_ADDRESS) != 0 || option_length != 4 ||
            load_mac_bytes(context->skb, context->offset + context->cursor,
                           &context->requested_address, 4) < 0)
            context->failed = 1;
        context->seen |= DHCP_SEEN_REQUESTED_ADDRESS;
        break;
    case 53: {
        __u8 value;

        if ((context->seen & DHCP_SEEN_MESSAGE_TYPE) != 0 || option_length != 1 ||
            load_mac_bytes(context->skb, context->offset + context->cursor,
                           &value, sizeof(value)) < 0 ||
            (value != 1 && value != 3 && value != 4 && value != 7 && value != 8))
            context->failed = 1;
        else
            context->message_type = value;
        context->seen |= DHCP_SEEN_MESSAGE_TYPE;
        break;
    }
    case 54:
        if ((context->seen & DHCP_SEEN_SERVER_IDENTIFIER) != 0 || option_length != 4 ||
            load_mac_bytes(context->skb, context->offset + context->cursor,
                           &context->server_identifier, 4) < 0)
            context->failed = 1;
        context->seen |= DHCP_SEEN_SERVER_IDENTIFIER;
        break;
    case 55:
        if ((context->seen & DHCP_SEEN_PARAMETER_LIST) != 0 ||
            !validate_parameter_request_list(context->skb,
                                             context->offset + context->cursor,
                                             option_length))
            context->failed = 1;
        context->seen |= DHCP_SEEN_PARAMETER_LIST;
        break;
    case 57: {
        __be16 size;
        if ((context->seen & DHCP_SEEN_MAX_SIZE) != 0 || option_length != 2 ||
            load_mac_bytes(context->skb, context->offset + context->cursor, &size, 2) < 0 ||
            bpf_ntohs(size) < 576)
            context->failed = 1;
        context->seen |= DHCP_SEEN_MAX_SIZE;
        break;
    }
    case 61:
        if ((context->seen & DHCP_SEEN_CLIENT_IDENTIFIER) != 0 ||
            !validate_client_identifier(context->skb, context->offset + context->cursor,
                                        option_length))
            context->failed = 1;
        context->seen |= DHCP_SEEN_CLIENT_IDENTIFIER;
        break;
    case 60:
        if ((context->seen & DHCP_SEEN_VENDOR) != 0 ||
            !validate_vendor(context->skb, context->offset + context->cursor, option_length))
            context->failed = 1;
        context->seen |= DHCP_SEEN_VENDOR;
        break;
    default:
        context->failed = 1;
        break;
    }
    if (context->failed)
        return 1;
    context->cursor += option_length;
    return 0;
}

static __noinline int write_dhcp_options(struct __sk_buff *skb, __u32 offset,
                                         const struct dhcp_options_context *context)
{
    /* Serialize a canonical profile; no client-specific order, padding or PRL escapes. */
    /* The longest encoding is 77 bytes; a fixed 80-byte area also bounds helper writes. */
    __u8 zero[80] = {};
    __u8 prefix[14] = {53, 1, context->message_type, 61, 7, 1};
    __u8 profile[18] = {60, 8, 'd','h','c','l','i','e','n','t',55,6,1,28,3,15,6,12};
    __u8 requested[6] = {50, 4};
    __u8 server[6] = {54, 4};
    __u8 end = 255;
    __u32 hostname_length = ph4ntxm_config.hostname_length;
    if (hostname_length == 0 || hostname_length > PH4NTXM_PACKET_TRANSFORMATION_ENGINE_HOSTNAME_MAX)
        return 0;
#pragma clang loop unroll(full)
    for (__u32 index = 0; index < 6; index++)
        prefix[6 + index] = ph4ntxm_config.mac[index];
    prefix[12] = 12;
    prefix[13] = hostname_length;
    if (ph4ntxm_config.mode == PH4NTXM_PACKET_TRANSFORMATION_ENGINE_MODE_WINDOWS) {
        const __u8 windows_profile[18] = {
            60,8,'M','S','F','T',' ','5','.','0',55,6,1,3,6,12,15,28
        };
        __builtin_memcpy(profile, windows_profile, sizeof(profile));
    }
    __builtin_memcpy(requested + 2, &context->requested_address, 4);
    __builtin_memcpy(server + 2, &context->server_identifier, 4);
    if (bpf_skb_change_tail(skb, offset + sizeof(zero), 0) < 0 ||
        bpf_skb_store_bytes(skb, offset, zero, sizeof(zero), BPF_F_INVALIDATE_HASH) < 0 ||
        bpf_skb_store_bytes(skb, offset, prefix, sizeof(prefix), BPF_F_INVALIDATE_HASH) < 0)
        return 0;
    __u32 cursor = offset + sizeof(prefix);
#pragma clang loop unroll(full)
    for (__u32 index = 0; index < PH4NTXM_PACKET_TRANSFORMATION_ENGINE_HOSTNAME_MAX; index++) {
        if (index < hostname_length) {
            __u8 byte = ph4ntxm_config.hostname[index];
            if (bpf_skb_store_bytes(skb, cursor + index, &byte, 1,
                                   BPF_F_INVALIDATE_HASH) < 0)
                return 0;
        }
    }
    cursor += hostname_length;
    if (bpf_skb_store_bytes(skb, cursor, profile, sizeof(profile), BPF_F_INVALIDATE_HASH) < 0)
        return 0;
    cursor += sizeof(profile);
    if (context->seen & DHCP_SEEN_REQUESTED_ADDRESS) {
        if (bpf_skb_store_bytes(skb, cursor, requested, sizeof(requested),
                               BPF_F_INVALIDATE_HASH) < 0)
            return 0;
        cursor += sizeof(requested);
    }
    if (context->seen & DHCP_SEEN_SERVER_IDENTIFIER) {
        if (bpf_skb_store_bytes(skb, cursor, server, sizeof(server),
                               BPF_F_INVALIDATE_HASH) < 0)
            return 0;
        cursor += sizeof(server);
    }
    return bpf_skb_store_bytes(skb, cursor, &end, 1, BPF_F_INVALIDATE_HASH) == 0;
}

static __noinline int normalize_dhcp_options(struct __sk_buff *skb, __u32 offset,
                                            __u32 length)
{
    struct dhcp_options_context context = {
        .skb = skb,
        .offset = offset,
        .length = length,
    };

    if (length > DHCP_OPTION_BYTES_MAX ||
        bpf_loop(DHCP_OPTION_COUNT_MAX, dhcp_option_step, &context, 0) < 0 ||
        context.failed || !context.found_end || context.message_type == 0)
        return 0;
    if (!bytes_are_zero(skb, offset + context.cursor, length - context.cursor,
                       DHCP_OPTION_BYTES_MAX))
        return 0;

    return write_dhcp_options(skb, offset, &context);
}

static __noinline int rewrite_dhcp_ipv4(struct __sk_buff *skb, __u32 network_offset)
{
    struct ipv4_header ip;
    __u16 identification;

    if (load_mac_bytes(skb, network_offset, &ip, sizeof(ip)) < 0)
        return 0;
    identification = (__u16)bpf_get_prandom_u32();
    if (identification == 0)
        identification = 1;
    ip.tos = 0;
    ip.total_length = bpf_htons(skb->len - network_offset);
    ip.ttl = ph4ntxm_config.mode == PH4NTXM_PACKET_TRANSFORMATION_ENGINE_MODE_WINDOWS ? 128 : 64;
    ip.identification = bpf_htons(identification);
    if (ph4ntxm_config.mode == PH4NTXM_PACKET_TRANSFORMATION_ENGINE_MODE_WINDOWS)
        ip.flags_fragment = bpf_htons(0x4000U);
    else
        ip.flags_fragment = 0;
    ip.checksum = 0;
    ip.checksum = bpf_htons(ipv4_checksum(&ip));
    return bpf_skb_store_bytes(skb, network_offset, &ip, sizeof(ip),
                               BPF_F_INVALIDATE_HASH) == 0;
}

static __always_inline int validate_and_transform_dhcp(struct __sk_buff *skb,
                                                       __u32 network_offset)
{
    struct ipv4_header ip;
    struct udp_header udp;
    __u32 udp_offset = network_offset + sizeof(ip);
    __u32 bootp_offset = udp_offset + sizeof(udp);
    __u32 options_offset = bootp_offset + DHCP_FIXED_LENGTH;
    __u16 udp_length;
    __u16 ip_length;
    __u8 bootp[4];
    __u8 client_mac[6];
    __be32 client_address;
    __be32 address;
    __be32 cookie;

    if (load_mac_bytes(skb, network_offset, &ip, sizeof(ip)) < 0 ||
        ip.version_ihl != 0x45)
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_IPV4_LAYOUT;
    ip_length = bpf_ntohs(ip.total_length);
    if (ip_length < sizeof(ip) || network_offset + ip_length != skb->len)
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_IPV4_LAYOUT;
    if (!ipv4_checksum_valid(&ip))
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_IPV4_CHECKSUM;
    if (ip.protocol != IPPROTO_UDP || ip.ttl == 0 ||
        (bpf_ntohs(ip.flags_fragment) & ~0x4000U) != 0)
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_IPV4;
    if (ip_length < 20U + DHCP_MIN_UDP_LENGTH || ip_length > DHCP_MAX_IP_LENGTH ||
        load_mac_bytes(skb, udp_offset, &udp, sizeof(udp)) < 0)
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_UDP;
    udp_length = bpf_ntohs(udp.length);
    if (udp.source != bpf_htons(DHCP_CLIENT_PORT) ||
        udp.destination != bpf_htons(DHCP_SERVER_PORT) ||
        udp_length != ip_length - sizeof(ip) || udp.checksum == 0 ||
        !udp_checksum_valid(skb, udp_offset, &ip, udp_length, 0))
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_UDP;
    if (load_mac_bytes(skb, bootp_offset, bootp, sizeof(bootp)) < 0 ||
        bootp[0] != 1 || bootp[1] != 1 || bootp[2] != 6 || bootp[3] != 0)
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_BOOTP;
    if (load_mac_bytes(skb, bootp_offset + 28U, client_mac, sizeof(client_mac)) < 0 ||
        !mac_matches_config(client_mac))
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_CLIENT;
    if (!bytes_are_zero(skb, bootp_offset + 34U, 10U, 10U) ||
        !bytes_are_zero(skb, bootp_offset + 44U, 192U, 192U))
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_RESERVED;
    if (load_mac_bytes(skb, bootp_offset + 16U, &address, sizeof(address)) < 0 ||
        address != 0 ||
        load_mac_bytes(skb, bootp_offset + 20U, &address, sizeof(address)) < 0 ||
        address != 0 ||
        load_mac_bytes(skb, bootp_offset + 24U, &address, sizeof(address)) < 0 ||
        address != 0)
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_ADDRESSES;
    if (load_mac_bytes(skb, bootp_offset + 12U, &client_address,
                       sizeof(client_address)) < 0 ||
        (ip.source == 0 && client_address != 0) ||
        (ip.source != 0 && client_address != ip.source))
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_ADDRESSES;
    if (load_mac_bytes(skb, bootp_offset + 236U, &cookie, sizeof(cookie)) < 0 ||
        cookie != bpf_htonl(0x63825363U) ||
        !normalize_dhcp_options(skb, options_offset,
                               udp_length - sizeof(udp) - DHCP_FIXED_LENGTH))
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_OPTIONS;
    if (ip.source == 0 && ip.destination != bpf_htonl(0xffffffffU))
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_ROUTE;

    udp_length = skb->len - udp_offset;
    udp.length = bpf_htons(udp_length);
    udp.checksum = 0;
    if (bpf_skb_store_bytes(skb, udp_offset, &udp, sizeof(udp), BPF_F_INVALIDATE_HASH) < 0 ||
        !udp_checksum_valid(skb, udp_offset, &ip, udp_length, 1) ||
        !rewrite_dhcp_ipv4(skb, network_offset))
        return PACKET_TRANSFORMATION_ENGINE_DROP_DHCP_STORE;
    return PACKET_TRANSFORMATION_ENGINE_DROP_REASON_COUNT;
}

SEC("classifier")
int ph4ntxm_guard(struct __sk_buff *skb)
{
    struct ethhdr ethernet;
    struct ipv4_header marked_ipv4;
    __u8 source_mac[6];
    __u8 destination_mac[6];
    __u16 protocol;
    __u32 network_offset = sizeof(ethernet);

    if (ph4ntxm_config.magic != PH4NTXM_PACKET_TRANSFORMATION_ENGINE_CONFIG_MAGIC ||
        ph4ntxm_config.ifindex == 0 || ph4ntxm_config.ifindex != skb->ifindex ||
        ph4ntxm_config.mode > PH4NTXM_PACKET_TRANSFORMATION_ENGINE_MODE_WINDOWS || ph4ntxm_config.hostname_length == 0 ||
        ph4ntxm_config.hostname_length > PH4NTXM_PACKET_TRANSFORMATION_ENGINE_HOSTNAME_MAX ||
        load_mac_bytes(skb, 0, &ethernet, sizeof(ethernet)) < 0)
        return record_drop(PACKET_TRANSFORMATION_ENGINE_DROP_CONFIGURATION);
#pragma clang loop unroll(full)
    for (int index = 0; index < 6; index++) {
        source_mac[index] = ethernet.h_source[index];
        destination_mac[index] = ethernet.h_dest[index];
    }
    if (!mac_matches_config(source_mac))
        return record_drop(PACKET_TRANSFORMATION_ENGINE_DROP_SOURCE_MAC);
    protocol = bpf_ntohs(ethernet.h_proto);
#pragma clang loop unroll(full)
    for (int depth = 0; depth < 2; depth++) {
        struct vlan_header vlan;

        if (protocol != ETH_P_8021Q && protocol != ETH_P_8021AD)
            break;
        if (load_mac_bytes(skb, network_offset, &vlan, sizeof(vlan)) < 0)
            return record_drop(PACKET_TRANSFORMATION_ENGINE_DROP_VLAN);
        protocol = bpf_ntohs(vlan.encapsulated_protocol);
        network_offset += sizeof(vlan);
    }
    if (protocol == ETH_P_8021Q || protocol == ETH_P_8021AD)
        return record_drop(PACKET_TRANSFORMATION_ENGINE_DROP_VLAN);

    if (skb->mark == PH4NTXM_PACKET_TRANSFORMATION_ENGINE_PROVENANCE_MARK) {
        if (skb->gso_segs > 1 ||
            (protocol == ETH_P_IP && !ipv4_layout_valid(skb, network_offset, 1,
                                                       &marked_ipv4)) ||
            (protocol == ETH_P_IPV6 && !ipv6_layout_valid(skb, network_offset)) ||
            (protocol != ETH_P_IP && protocol != ETH_P_IPV6))
            return record_drop(PACKET_TRANSFORMATION_ENGINE_DROP_MARKED_LAYOUT);
        if (protocol == ETH_P_IP && marked_ipv4.protocol == IPPROTO_UDP) {
            struct udp_header udp;
            if (load_mac_bytes(skb, network_offset + sizeof(marked_ipv4),
                               &udp, sizeof(udp)) < 0)
                return record_drop(PACKET_TRANSFORMATION_ENGINE_DROP_MARKED_LAYOUT);
            if (udp.source == bpf_htons(DHCP_CLIENT_PORT) &&
                udp.destination == bpf_htons(DHCP_SERVER_PORT)) {
                int reason = validate_and_transform_dhcp(skb, network_offset);
                if (reason != PACKET_TRANSFORMATION_ENGINE_DROP_REASON_COUNT)
                    return record_drop(reason);
            }
        }
        skb->mark = 0;
        return TC_ACT_OK;
    }
    if (skb->mark != 0)
        return record_drop(PACKET_TRANSFORMATION_ENGINE_DROP_UNEXPECTED_MARK);
    if (protocol == ETH_P_ARP) {
        int reason = validate_arp(skb, network_offset, source_mac, destination_mac);

        return reason == PACKET_TRANSFORMATION_ENGINE_DROP_REASON_COUNT ? TC_ACT_OK : record_drop(reason);
    }
    if (protocol == EAPOL_ETHERTYPE)
        return validate_eapol(skb, network_offset) ? TC_ACT_OK : record_drop(PACKET_TRANSFORMATION_ENGINE_DROP_EAPOL);
    if (protocol == ETH_P_IP) {
        int reason = validate_and_transform_dhcp(skb, network_offset);

        return reason == PACKET_TRANSFORMATION_ENGINE_DROP_REASON_COUNT ? TC_ACT_OK : record_drop(reason);
    }
    return record_drop(PACKET_TRANSFORMATION_ENGINE_DROP_OTHER_PROTOCOL);
}

char LICENSE[] SEC("license") = "GPL";
