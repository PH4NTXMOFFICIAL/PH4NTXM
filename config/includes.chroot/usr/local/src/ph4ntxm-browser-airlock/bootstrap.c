#define _GNU_SOURCE
/* Copyright (C) PH4NTXM
 * Licensed under the GNU General Public License v3.0.
 */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef AIRLOCK_UID
#define AIRLOCK_UID 1000
#endif
#ifndef AIRLOCK_STATE
#define AIRLOCK_STATE "/run/ph4ntxm"
#endif
#ifndef AIRLOCK_BWRAP
#define AIRLOCK_BWRAP "/usr/local/libexec/ph4ntxm-browser-airlock/bwrap"
#endif

static volatile sig_atomic_t stopped;
static int diagnostic;

static int failure(const char *operation)
{
    int error = errno;
    if (diagnostic)
        dprintf(STDERR_FILENO, "Browser Airlock bootstrap: %s failed (errno %d).\n", operation, error);
    return 125;
}

static void stop(int number)
{
    if (number != SIGCHLD)
        stopped = number;
}

static int handlers(void)
{
    struct sigaction action = {.sa_handler = stop};
    sigemptyset(&action.sa_mask);
    return sigaction(SIGTERM, &action, NULL) ||
        sigaction(SIGINT, &action, NULL) ||
        sigaction(SIGHUP, &action, NULL) ||
        sigaction(SIGCHLD, &action, NULL);
}

static int drop(uid_t uid, gid_t gid)
{
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct caps[2] = {{0}};
    uid_t real, effective, saved;
    gid_t greal, geffective, gsaved;
    if (setgroups(0, NULL) || setresgid(gid, gid, gid) ||
        setresuid(uid, uid, uid) || syscall(SYS_capset, &header, caps) ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) ||
        getresuid(&real, &effective, &saved) ||
        getresgid(&greal, &geffective, &gsaved))
        return -1;
    return real != uid || effective != uid || saved != uid ||
        greal != gid || geffective != gid || gsaved != gid ? -1 : 0;
}

static int protected_file(int dir, const char *name, size_t maximum)
{
    errno = EINVAL;
    int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    if (fd < 0)
        return -1;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid ||
        (info.st_mode & 0022) || info.st_size <= 0 ||
        (uint64_t)info.st_size > maximum) {
        close(fd);
        return -1;
    }
    return fd;
}

static int identity(void)
{
    errno = EINVAL;
    struct stat info;
    int dir = open(AIRLOCK_STATE, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0)
        return -1;
    if (fstat(dir, &info) || info.st_uid || (info.st_mode & 0022)) {
        close(dir);
        return -1;
    }
    int mode = protected_file(dir, "mode", 16);
    char value[17] = {0};
    ssize_t length = mode < 0 ? -1 : read(mode, value, sizeof(value) - 1);
    if (mode >= 0)
        close(mode);
    int result = -1;
    if (length > 0) {
        if (value[length - 1] == '\n')
            value[--length] = 0;
        if ((size_t)length != strlen(value)) {
            close(dir);
            return -1;
        }
        if (!strcmp(value, "linux") || !strcmp(value, "windows"))
            result = protected_file(dir, "fake_cpuinfo", 1024 * 1024);
        else if (!strcmp(value, "lonewolf"))
            result = -2;
    }
    close(dir);
    return result;
}

static int filter_number(const char *value)
{
    char *end;
    errno = 0;
    long number = strtol(value, &end, 10);
    if (!*value || *end || errno || number < 3 || number > INT32_MAX) {
        errno = EINVAL;
        return -1;
    }
    errno = EINVAL;
    struct stat info;
    int fd = (int)number;
    int seals = fcntl(fd, F_GET_SEALS);
    int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) ||
        info.st_size <= 0 || info.st_size > 32768 || info.st_size % 8 ||
        seals < 0 || (seals & required) != required)
        return -1;
    return fd;
}

static int standard_descriptors(void)
{
    int fd = open("/dev/null", O_RDWR | O_NOFOLLOW);
    struct stat info;
    if (fd < 0 || fstat(fd, &info) || !S_ISCHR(info.st_mode) ||
        info.st_rdev != makedev(1, 3))
        return -1;
    for (int target = 0; target < 3; target++)
        if ((target != STDERR_FILENO || !diagnostic) && dup2(fd, target) < 0)
            return -1;
    if (fd > 2)
        close(fd);
    return 0;
}

static int close_except(int filter)
{
    if (filter > 3 && syscall(SYS_close_range, 3U, (unsigned int)filter - 1U, 0))
        return -1;
    return syscall(SYS_close_range, (unsigned int)filter + 1U, ~0U, 0) ? -1 : 0;
}

static int status_code(int status)
{
    return WIFEXITED(status) ? WEXITSTATUS(status) :
        WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 125;
}

static int supervise(pid_t child)
{
    int status;
    sigset_t blocked, previous;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGTERM);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGHUP);
    sigaddset(&blocked, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &blocked, &previous))
        return failure("signal mask");
    for (;;) {
        if (stopped) {
            kill(child, SIGKILL);
            while (waitpid(child, &status, 0) < 0 && errno == EINTR)
                ;
            return 128 + stopped;
        }
        pid_t result = waitpid(-1, &status, WNOHANG);
        if (result == child)
            return status_code(status);
        if (result > 0)
            continue;
        if (result < 0 && errno != EINTR)
            return failure("child wait");
        sigsuspend(&previous);
    }
}

int main(int argc, char **argv)
{
    struct stat error_info;
    int error_flags = fcntl(STDERR_FILENO, F_GETFL);
    diagnostic = error_flags >= 0 && (error_flags & O_ACCMODE) == O_WRONLY &&
        !fstat(STDERR_FILENO, &error_info) && S_ISFIFO(error_info.st_mode);
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (uid != AIRLOCK_UID || !uid || geteuid() || getegid() != gid || argc < 3) {
        errno = EPERM;
        return failure("caller validation");
    }
    int filter = filter_number(argv[1]);
    if (filter < 0 || close_except(filter) || standard_descriptors() || chdir("/"))
        return failure("descriptor isolation");
    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL))
        return failure("signal mask");
    if (handlers())
        return failure("signal handlers");
    if (unshare(CLONE_NEWNS))
        return failure("mount namespace");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
        return failure("private mount propagation");
    int cpu = identity();
    if (cpu == -1)
        return failure("protected identity");
    if (unshare(CLONE_NEWPID))
        return failure("PID namespace");
    pid_t parent = getpid();
    int parentfd = (int)syscall(SYS_pidfd_open, parent, 0);
    if (parentfd < 0)
        return failure("parent tracking");
    int ready[2];
    if (pipe2(ready, O_CLOEXEC))
        return failure("parent handshake");
    pid_t caller = getppid();
    pid_t child = fork();
    if (child < 0)
        return failure("PID namespace fork");
    if (child) {
        close(ready[0]);
        close(parentfd);
        close(filter);
        if (cpu >= 0)
            close(cpu);
        if (drop(uid, gid) || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != caller) {
            kill(child, SIGKILL);
            return failure("parent privilege drop");
        }
        if (write(ready[1], "R", 1) != 1) {
            kill(child, SIGKILL);
            return failure("parent readiness");
        }
        close(ready[1]);
        return supervise(child);
    }
    close(ready[1]);
    if (getpid() != 1 || mount("proc", "/proc", "proc",
        MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL))
        return failure("private proc mount");
    if (cpu >= 0) {
        char source[64];
        snprintf(source, sizeof(source), "/proc/self/fd/%d", cpu);
        if (mount(source, "/proc/cpuinfo", NULL, MS_BIND, NULL))
            return failure("protected CPU mount");
        if (mount(NULL, "/proc/cpuinfo", NULL,
            MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL))
            return failure("read-only CPU mount");
        close(cpu);
    }
    char byte;
    if (drop(uid, gid) || read(ready[0], &byte, 1) != 1 || byte != 'R')
        return failure("child privilege drop or parent readiness");
    close(ready[0]);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL))
        return failure("parent death signal");
    struct pollfd parent_state = {.fd = parentfd, .events = POLLIN};
    if (poll(&parent_state, 1, 0) != 0)
        return failure("parent liveness");
    close(parentfd);
    if (fcntl(filter, F_SETFD, 0))
        return failure("filter descriptor");
    child = fork();
    if (child < 0)
        return failure("sandbox fork");
    if (child) {
        close(filter);
        return supervise(child);
    }
    struct sigaction reset = {.sa_handler = SIG_DFL};
    sigemptyset(&reset.sa_mask);
    if (sigaction(SIGTERM, &reset, NULL) || sigaction(SIGINT, &reset, NULL) ||
        sigaction(SIGHUP, &reset, NULL) || prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != 1)
        return failure("sandbox parent tracking");
    char *environment[] = {"PATH=/usr/bin:/bin", "LANG=C.UTF-8", NULL};
    argv[1] = AIRLOCK_BWRAP;
    execve(AIRLOCK_BWRAP, &argv[1], environment);
    return failure("sandbox execution");
}
