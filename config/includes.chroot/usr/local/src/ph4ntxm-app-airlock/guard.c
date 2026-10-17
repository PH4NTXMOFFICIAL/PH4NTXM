#define _GNU_SOURCE
/* Copyright (C) PH4NTXM
 * Licensed under the GNU General Public License v3.0.
 */

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
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

static int write_filter(void)
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
        DENY(mount), DENY(umount2), DENY(pivot_root), DENY(chroot),
        DENY(fsopen), DENY(fsconfig), DENY(fsmount), DENY(move_mount),
        DENY(open_tree), DENY(mount_setattr), DENY(setns), DENY(unshare),
        DENY(open_by_handle_at), DENY(name_to_handle_at), DENY(fanotify_init),
        DENY(init_module), DENY(finit_module), DENY(delete_module),
        DENY(kexec_load), DENY(kexec_file_load), DENY(reboot),
        DENY(swapon), DENY(swapoff), DENY(iopl), DENY(ioperm),
        DENY(io_uring_setup), DENY(io_uring_enter), DENY(io_uring_register),
        DENY(pidfd_getfd),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
            CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID |
            CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 9),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 0, 5),
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
        perror("App Airlock syscall filter");
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
        perror("App Airlock descriptor isolation");
        return -1;
    }
#endif
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) || limit.rlim_max == RLIM_INFINITY ||
        limit.rlim_max > INT32_MAX) {
        fputs("App Airlock descriptor limits are unavailable\n", stderr);
        return -1;
    }
    for (rlim_t fd = 3; fd < limit.rlim_max; fd++)
        close((int)fd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "filter"))
        return write_filter();
    if (argc >= 4 && !strcmp(argv[1], "run") && !strcmp(argv[2], "--")) {
        const struct rlimit core = {0, 0};
        if (setrlimit(RLIMIT_CORE, &core) ||
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
            perror("App Airlock process isolation");
            return 1;
        }
        if (close_descriptors())
            return 1;
        execvp(argv[3], &argv[3]);
        perror("App Airlock command");
        return 1;
    }
    fputs("Usage: guard filter\n"
        "       guard run -- command [arguments...]\n", stderr);
    return 2;
}
