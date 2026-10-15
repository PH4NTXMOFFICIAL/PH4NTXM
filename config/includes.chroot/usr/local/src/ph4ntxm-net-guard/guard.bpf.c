/*
 * Copyright (C) PH4NTXM
 * Licensed under the GNU General Public License v3.0.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "guard.h"
#include "core_types.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct guard_control);
} control SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, GUARD_MAX_EXECUTIONS);
    __type(key, __u32);
    __type(value, struct execution_key);
} executions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, GUARD_MAX_EXECUTIONS);
    __type(key, struct execution_key);
    __type(value, struct approval_value);
} approvals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, GUARD_MAX_REQUESTS);
    __type(key, struct execution_key);
    __type(value, struct pending_request);
} pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} overflow SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct socket_identity);
} sockets SEC(".maps");

static __always_inline struct guard_control *configuration(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&control, &zero);
}

static __always_inline int same_execution(const struct execution_key *a,
                                         const struct execution_key *b)
{
    return a->tgid == b->tgid && a->started_ns == b->started_ns &&
           a->exec_id == b->exec_id;
}

static __always_inline void record_overflow(void)
{
    __u32 zero = 0;
    __u64 *count = bpf_map_lookup_elem(&overflow, &zero);
    if (count)
        __sync_fetch_and_add(count, 1);
}

static __always_inline int current_execution(struct execution_key *identity)
{
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    if (!leader)
        return 0;
    identity->tgid = BPF_CORE_READ(leader, tgid);
    identity->padding = 0;
    identity->started_ns = BPF_CORE_READ(leader, start_boottime);
    identity->exec_id = BPF_CORE_READ(leader, self_exec_id);
    return identity->tgid != 0 && identity->started_ns != 0;
}

static __always_inline int is_guarded(struct guard_control *cfg)
{
    struct task_struct *task = (void *)bpf_get_current_task_btf();
    return BPF_CORE_READ(task, cred, uid.val) == cfg->guarded_uid ||
           BPF_CORE_READ(task, cred, euid.val) == cfg->guarded_uid;
}

static __always_inline int register_execution(struct execution_key *identity)
{
    if (bpf_map_update_elem(&executions, &identity->tgid, identity, BPF_ANY)) {
        record_overflow();
        return 0;
    }
    return 1;
}

static __always_inline int execution_live(const struct execution_key *identity)
{
    struct execution_key *live = bpf_map_lookup_elem(&executions, &identity->tgid);
    return live && same_execution(live, identity);
}

static __always_inline int operational(struct guard_control *cfg)
{
    return cfg && cfg->abi == GUARD_ABI && cfg->enabled == 1 &&
           cfg->lease_ns > bpf_ktime_get_ns() && execution_live(&cfg->daemon);
}

static __always_inline int permitted(struct guard_control *cfg,
                                     const struct execution_key *identity)
{
    struct approval_value *grant = bpf_map_lookup_elem(&approvals, identity);
    return operational(cfg) && execution_live(identity) && grant &&
           grant->epoch == cfg->epoch;
}

static __always_inline int internet_family(__u16 family)
{
    return family == GUARD_SOCKET_INET || family == GUARD_SOCKET_INET6 ||
           family == GUARD_SOCKET_PACKET || family == GUARD_SOCKET_XDP;
}

static __always_inline void request_approval(struct guard_control *cfg,
                                             const struct execution_key *identity,
                                             struct sock *sk,
                                             const void *address, int length,
                                             __u32 reason)
{
    struct pending_request event = {};
    event.execution = *identity;
    event.epoch = cfg->epoch;
    event.observed_ns = bpf_ktime_get_ns();
    event.reason = reason;
    if (sk) {
        event.family = BPF_CORE_READ(sk, __sk_common.skc_family);
        event.protocol = BPF_CORE_READ(sk, sk_protocol);
    }
    if (address && length >= (int)sizeof(__u16)) {
        __u16 family = 0;
        bpf_probe_read_kernel(&family, sizeof(family), address);
        if (family == GUARD_SOCKET_INET && length >= 16) {
            struct sockaddr_in in = {};
            if (!bpf_probe_read_kernel(&in, sizeof(in), address)) {
                event.family = family;
                event.port = bpf_ntohs(in.sin_port);
                __builtin_memcpy(event.destination, &in.sin_addr, 4);
            }
        } else if (family == GUARD_SOCKET_INET6 && length >= 28) {
            struct sockaddr_in6 in = {};
            if (!bpf_probe_read_kernel(&in, sizeof(in), address)) {
                event.family = family;
                event.port = bpf_ntohs(in.sin6_port);
                __builtin_memcpy(event.destination, in.sin6_addr, 16);
            }
        }
    }
    if (bpf_map_update_elem(&pending, identity, &event, BPF_ANY))
        record_overflow();
}

SEC("lsm/socket_post_create")
int guard_socket_create(unsigned long long *ctx)
{
    struct socket *sock = (void *)ctx[0];
    int family = (int)ctx[1];
    int prior = (int)ctx[5];
    struct guard_control *cfg = configuration();
    struct execution_key identity = {};
    if (prior)
        return prior;
    if (!cfg || cfg->abi != GUARD_ABI)
        return -13;
    int guarded = is_guarded(cfg);
    if (guarded || (__u32)(bpf_get_current_pid_tgid() >> 32) == cfg->daemon_tgid) {
        if (!current_execution(&identity) || !register_execution(&identity))
            return cfg->enabled && guarded ? -13 : 0;
    }
    if (!internet_family(family))
        return 0;
    struct sock *sk = sock->sk;
    if (!sk)
        return cfg->enabled && guarded ? -13 : 0;
    struct socket_identity initial = {};
    initial.execution = identity;
    initial.epoch = cfg->epoch;
    initial.uid = (__u32)bpf_get_current_uid_gid();
    initial.guarded = guarded;
    struct socket_identity *saved = bpf_sk_storage_get(&sockets, sk, &initial,
                                                       BPF_SK_STORAGE_GET_F_CREATE);
    if (!saved)
        return cfg->enabled && guarded ? -13 : 0;
    if (cfg->enabled && guarded &&
        (family == GUARD_SOCKET_PACKET || family == GUARD_SOCKET_XDP)) {
        request_approval(cfg, &identity, sk, 0, 0, GUARD_REASON_UNAVAILABLE);
        return -13;
    }
    return 0;
}

static __always_inline int check_socket(struct socket *sock,
                                        const void *address, int length,
                                        int prior)
{
    struct guard_control *cfg = configuration();
    struct execution_key identity = {};
    if (prior)
        return prior;
    if (!cfg || cfg->abi != GUARD_ABI)
        return -13;
    struct sock *sk = sock->sk;
    if (!sk)
        return cfg->enabled && is_guarded(cfg) ? -13 : 0;
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (!internet_family(family))
        return 0;
    int guarded = is_guarded(cfg);
    __u32 socket_uid = BPF_CORE_READ(sk, sk_uid.val);
    struct socket_identity *saved = bpf_sk_storage_get(&sockets, sk, 0, 0);
    if (!guarded && socket_uid != cfg->guarded_uid && (!saved || !saved->guarded))
        return 0;
    if (!current_execution(&identity) || !register_execution(&identity))
        return cfg->enabled ? -13 : 0;
    if (!cfg->enabled)
        return 0;
    __u32 reason = GUARD_REASON_APPROVAL;
    if (family == GUARD_SOCKET_PACKET || family == GUARD_SOCKET_XDP)
        reason = GUARD_REASON_UNAVAILABLE;
    else if (!saved || saved->epoch != cfg->epoch)
        reason = GUARD_REASON_RECONNECT;
    else if (!same_execution(&saved->execution, &identity))
        reason = GUARD_REASON_SHARED;
    else if (permitted(cfg, &identity))
        return 0;
    request_approval(cfg, &identity, sk, address, length, reason);
    return -13;
}

SEC("lsm/socket_connect")
int guard_socket_connect(unsigned long long *ctx)
{
    return check_socket((void *)ctx[0], (void *)ctx[1], (int)ctx[2], (int)ctx[3]);
}

SEC("lsm/socket_sendmsg")
int guard_socket_send(unsigned long long *ctx)
{
    struct msghdr *message = (void *)ctx[1];
    void *address = BPF_CORE_READ(message, msg_name);
    int length = BPF_CORE_READ(message, msg_namelen);
    return check_socket((void *)ctx[0], address, length, (int)ctx[3]);
}

SEC("cgroup_skb/egress")
int guard_egress(struct __sk_buff *skb)
{
    struct guard_control *cfg = configuration();
    if (!cfg || cfg->abi != GUARD_ABI)
        return 0;
    if (!cfg->enabled)
        return 1;
    struct bpf_sock *sk = skb->sk;
    if (!sk)
        return bpf_get_socket_uid(skb) != cfg->guarded_uid;
    sk = bpf_sk_fullsock(sk);
    if (!sk)
        return bpf_get_socket_uid(skb) != cfg->guarded_uid;
    struct socket_identity *saved = bpf_sk_storage_get(&sockets, sk, 0, 0);
    if (!saved)
        return bpf_get_socket_uid(skb) != cfg->guarded_uid;
    if (!saved->guarded && saved->uid != cfg->guarded_uid)
        return 1;
    if (saved->epoch != cfg->epoch || !permitted(cfg, &saved->execution))
        return 0;
    return 1;
}

SEC("tp_btf/sched_process_exec")
int guard_exec(unsigned long long *ctx)
{
    struct guard_control *cfg = configuration();
    struct execution_key identity = {};
    (void)ctx;
    if (!cfg)
        return 0;
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct execution_key *previous = bpf_map_lookup_elem(&executions, &tgid);
    if (previous) {
        struct execution_key old = *previous;
        bpf_map_delete_elem(&approvals, &old);
        bpf_map_delete_elem(&pending, &old);
        bpf_map_delete_elem(&executions, &tgid);
    }
    if ((is_guarded(cfg) || tgid == cfg->daemon_tgid) && current_execution(&identity))
        register_execution(&identity);
    return 0;
}

SEC("tp_btf/sched_process_exit")
int guard_exit(unsigned long long *ctx)
{
    struct task_struct *task = (void *)ctx[0];
    if (BPF_CORE_READ(task, signal, live.counter) != 0)
        return 0;
    __u32 tgid = BPF_CORE_READ(task, tgid);
    struct execution_key *existing = bpf_map_lookup_elem(&executions, &tgid);
    if (existing) {
        struct execution_key identity = *existing;
        bpf_map_delete_elem(&approvals, &identity);
        bpf_map_delete_elem(&pending, &identity);
        bpf_map_delete_elem(&executions, &tgid);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
