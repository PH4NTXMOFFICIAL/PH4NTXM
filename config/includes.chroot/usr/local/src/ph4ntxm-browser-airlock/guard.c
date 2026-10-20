#define _GNU_SOURCE
/* Copyright (C) PH4NTXM
 * Licensed under the GNU General Public License v3.0.
 */

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define DENY(call) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_##call, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)

static int write_filter(int offline)
{
    const struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        DENY(ptrace), DENY(process_vm_readv), DENY(process_vm_writev),
        DENY(bpf), DENY(perf_event_open), DENY(userfaultfd),
        DENY(keyctl), DENY(add_key), DENY(request_key),
        DENY(mount), DENY(umount2), DENY(pivot_root),
        DENY(fsopen), DENY(fsconfig), DENY(fsmount), DENY(move_mount),
        DENY(open_tree), DENY(mount_setattr), DENY(setns),
        DENY(open_by_handle_at), DENY(name_to_handle_at), DENY(fanotify_init),
        DENY(init_module), DENY(finit_module), DENY(delete_module),
        DENY(kexec_load), DENY(kexec_file_load), DENY(reboot),
        DENY(swapon), DENY(swapoff), DENY(iopl), DENY(ioperm),
        DENY(io_uring_setup), DENY(io_uring_enter), DENY(io_uring_register),
        DENY(pidfd_getfd),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 11),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, offline ? AF_UNIX : AF_INET, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, offline ? AF_UNIX : AF_INET6, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_DGRAM, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_SEQPACKET, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socketpair, 0, 9),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_DGRAM, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_SEQPACKET, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ioctl, 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCSTI, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCLINUX, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    if (fwrite(filter, sizeof(filter), 1, stdout) != 1 || fflush(stdout)) {
        perror("Browser Airlock syscall filter");
        return 1;
    }
    return 0;
}

static int close_descriptors(void)
{
#ifdef SYS_close_range
    if (!syscall(SYS_close_range, 3U, ~0U, 0))
        return 0;
    if (errno != ENOSYS && errno != EINVAL) {
        perror("Browser Airlock descriptor isolation");
        return -1;
    }
#endif
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_max == RLIM_INFINITY ||
        limit.rlim_max > INT32_MAX) {
        fputs("Browser Airlock descriptor limits are unavailable\n", stderr);
        return -1;
    }
    for (rlim_t fd = 3; fd < limit.rlim_max; fd++)
        close((int)fd);
    return 0;
}

static int scope_ipc(void)
{
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
        LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 6) {
        fputs("Browser Airlock requires Landlock ABI 6\n", stderr);
        return -1;
    }
    const struct landlock_ruleset_attr rules = {
        .scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL,
    };
    int descriptor = syscall(SYS_landlock_create_ruleset, &rules, sizeof(rules), 0);
    if (descriptor < 0) {
        perror("Browser Airlock IPC scope");
        return -1;
    }
    int result = syscall(SYS_landlock_restrict_self, descriptor, 0);
    close(descriptor);
    if (result) {
        perror("Browser Airlock IPC isolation");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "filter"))
        return write_filter(0);
    if (argc == 2 && !strcmp(argv[1], "offline-filter"))
        return write_filter(1);
    if (argc >= 4 && !strcmp(argv[1], "run") && !strcmp(argv[2], "--")) {
        const struct rlimit core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &core) ||
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
            perror("Browser Airlock process isolation");
            return 1;
        }
        if (scope_ipc() || close_descriptors())
            return 1;
        execvp(argv[3], &argv[3]);
        perror("Browser Airlock command");
        return 1;
    }
    fputs("Usage: guard filter|offline-filter\n"
        "       guard run -- command [arguments...]\n", stderr);
    return 2;
}
