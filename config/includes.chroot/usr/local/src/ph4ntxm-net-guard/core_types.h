/*
 * Copyright (C) PH4NTXM
 * Licensed under the GNU General Public License v3.0.
 */

#ifndef PH4_NET_CORE_TYPES_H
#define PH4_NET_CORE_TYPES_H

#define CORE_TYPE __attribute__((preserve_access_index))

typedef struct { int counter; } atomic_t;
typedef struct { unsigned int val; } kuid_t;
struct cred { kuid_t uid; kuid_t euid; } CORE_TYPE;
struct signal_struct { atomic_t live; } CORE_TYPE;
struct task_struct {
    int pid;
    int tgid;
    struct task_struct *group_leader;
    __u64 start_boottime;
    __u64 self_exec_id;
    struct signal_struct *signal;
    const struct cred *cred;
} CORE_TYPE;
struct sock_common { unsigned short skc_family; } CORE_TYPE;
struct sock {
    struct sock_common __sk_common;
    kuid_t sk_uid;
    unsigned short sk_type;
    __u16 sk_protocol;
} CORE_TYPE;
struct socket { struct sock *sk; } CORE_TYPE;
struct sockaddr { unsigned short sa_family; char sa_data[14]; } CORE_TYPE;
struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    __u32 sin_addr;
    unsigned char sin_zero[8];
};
struct sockaddr_in6 {
    unsigned short sin6_family;
    unsigned short sin6_port;
    __u32 sin6_flowinfo;
    unsigned char sin6_addr[16];
    __u32 sin6_scope_id;
};
struct msghdr { void *msg_name; int msg_namelen; } CORE_TYPE;

#endif
