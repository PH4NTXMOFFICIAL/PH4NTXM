/*
 * Copyright (C) PH4NTXM
 * Licensed under the GNU General Public License v3.0.
 */

#ifndef PH4_NET_GUARD_H
#define PH4_NET_GUARD_H

#include <linux/types.h>

#define GUARD_ABI 1U
#define GUARD_MAX_REQUESTS 256U
#define GUARD_MAX_EXECUTIONS 8192U
#define GUARD_LEASE_NS 3000000000ULL
#define GUARD_SOCKET_INET 2
#define GUARD_SOCKET_INET6 10
#define GUARD_SOCKET_PACKET 17
#define GUARD_SOCKET_XDP 44
#define GUARD_REASON_APPROVAL 1U
#define GUARD_REASON_RECONNECT 2U
#define GUARD_REASON_SHARED 3U
#define GUARD_REASON_UNAVAILABLE 4U

struct execution_key {
    __u32 tgid;
    __u32 padding;
    __u64 started_ns;
    __u64 exec_id;
};

struct guard_control {
    __u32 abi;
    __u32 enabled;
    __u32 guarded_uid;
    __u32 daemon_tgid;
    __u64 epoch;
    __u64 lease_ns;
    struct execution_key daemon;
};

struct socket_identity {
    struct execution_key execution;
    __u64 epoch;
    __u32 uid;
    __u32 guarded;
};

struct approval_value {
    __u64 epoch;
};

struct pending_request {
    struct execution_key execution;
    __u64 epoch;
    __u64 observed_ns;
    __u32 reason;
    __u16 family;
    __u16 port;
    __u8 protocol;
    __u8 destination[16];
    __u8 padding[7];
};

#endif
