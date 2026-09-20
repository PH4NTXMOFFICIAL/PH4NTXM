// Copyright (C) PH4NTXM
// Licensed under the GNU General Public License v3.0.

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <linux/securebits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__)
#define PH4_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define PH4_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error Unsupported syscall architecture
#endif

#define CPU_BYTES 1024
#define CPU_LIMIT (CPU_BYTES * CHAR_BIT)
#define VIEW_LIMIT 256
#define NOTIFY(number) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, number, 0, 1), \
                       BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF)

static char root[PATH_MAX];
static char anchor[PATH_MAX];
static unsigned int cpu_count;
static int physical[VIEW_LIMIT];
static unsigned long long ram;
static int listener = -1;
static struct {
    pid_t pid;
    unsigned long long started;
    char executable[PATH_MAX];
} ancestors[32];
static unsigned int ancestor_count;
static dev_t dynamic_device[3];
static ino_t dynamic_inode[3];
static const char *dynamic_paths[] = {"/proc/meminfo", "/proc/stat",
                                     "/sys/devices/system/node/node0/meminfo"};

static void fail(const char *operation)
{
    fprintf(stderr, "ph4ntxm-hardware-run: %s: %s\n", operation, strerror(errno));
    exit(125);
}

static unsigned long long number(const char *name, unsigned long long maximum)
{
    const char *value = getenv(name);
    char *end;
    if (!value || !*value || *value < '0' || *value > '9') {
        errno = EINVAL;
        fail(name);
    }
    errno = 0;
    unsigned long long result = strtoull(value, &end, 10);
    if (errno || *end || !result || result > maximum) {
        errno = EINVAL;
        fail(name);
    }
    return result;
}

static int put_file(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    size_t size = strlen(value);
    ssize_t written = write(fd, value, size);
    int saved = written == (ssize_t)size ? 0 : (written < 0 ? errno : EIO);
    close(fd);
    errno = saved;
    return saved ? -1 : 0;
}

static int process_identity(pid_t pid, pid_t *parent, unsigned long long *started)
{
    char path[64], buffer[8192];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *input = fopen(path, "re");
    if (!input)
        return -1;
    size_t length = fread(buffer, 1, sizeof(buffer) - 1, input);
    fclose(input);
    buffer[length] = 0;
    char *cursor = strrchr(buffer, ')');
    if (!cursor || cursor[1] != ' ')
        return -1;
    char *save;
    char *value = strtok_r(cursor + 2, " ", &save);
    for (int field = 3; value && field <= 22; field++) {
        if (field == 4)
            *parent = (pid_t)strtol(value, NULL, 10);
        if (field == 22) {
            *started = strtoull(value, NULL, 10);
            return 0;
        }
        value = strtok_r(NULL, " ", &save);
    }
    return -1;
}

static void capture_ancestors(void)
{
    pid_t pid = getppid();
    while (pid > 0 && ancestor_count < 32) {
        pid_t parent;
        unsigned long long started;
        if (process_identity(pid, &parent, &started) < 0)
            break;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/exe", pid);
        ssize_t length = readlink(path, ancestors[ancestor_count].executable, PATH_MAX - 1);
        if (length >= 0) {
            ancestors[ancestor_count].pid = pid;
            ancestors[ancestor_count].started = started;
            ancestors[ancestor_count].executable[length] = 0;
            ancestor_count++;
        }
        if (parent == pid)
            break;
        pid = parent;
    }
}

static void user_namespace(void)
{
    uid_t uid = getuid();
    gid_t gid = getgid();
    char map[96];
    if (unshare(CLONE_NEWUSER) < 0)
        fail("create user namespace");
    if (put_file("/proc/self/setgroups", "deny") < 0 && errno != ENOENT)
        fail("disable supplementary group changes");
    snprintf(map, sizeof(map), "%u %u 1\n", uid, uid);
    if (put_file("/proc/self/uid_map", map) < 0)
        fail("map user identity");
    snprintf(map, sizeof(map), "%u %u 1\n", gid, gid);
    if (put_file("/proc/self/gid_map", map) < 0)
        fail("map group identity");
}

static void complete_cpu_map(unsigned int found)
{
    if (found == cpu_count)
        return;
    FILE *input = fopen("/sys/devices/system/cpu/online", "re");
    if (!input)
        fail("read online CPUs");
    char *line = NULL;
    size_t capacity = 0;
    ssize_t size = getline(&line, &capacity, input);
    fclose(input);
    if (size < 0)
        fail("read online CPUs");
    char *cursor = line;
    while (*cursor && found < cpu_count) {
        char *end;
        unsigned long first = strtoul(cursor, &end, 10), last = first;
        if (end == cursor)
            break;
        if (*end == '-') {
            cursor = end + 1;
            last = strtoul(cursor, &end, 10);
            if (end == cursor)
                break;
        }
        if (last < first || last >= CPU_LIMIT)
            break;
        for (unsigned long cpu = first; cpu <= last && found < cpu_count; cpu++) {
            unsigned int i;
            for (i = 0; i < found && physical[i] != (int)cpu; i++) {}
            if (i == found)
                physical[found++] = (int)cpu;
        }
        cursor = *end == ',' ? end + 1 : end;
    }
    free(line);
    if (found != cpu_count) {
        errno = EINVAL;
        fail("session CPU count exceeds online CPUs");
    }
}

static void bind_view(const char *source, const char *target)
{
    if (mount(source, target, NULL, MS_BIND | MS_REC, NULL) < 0)
        fail(target);
    if (mount(NULL, target, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
              NULL) < 0)
        fail("protect hardware view");
}

static void mount_namespace(void)
{
    static const char *paths[] = {
        "/proc/cpuinfo", "/proc/meminfo", "/proc/stat", "/proc/kcore",
        "/sys/devices/system/cpu", "/sys/devices/system/memory",
        "/sys/devices/system/node", "/sys/bus/memory",
        "/sys/devices/virtual/dmi/id", "/sys/firmware", NULL};
    if (unshare(CLONE_NEWNS) < 0 || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        fail("create mount namespace");
    for (int i = 0; paths[i]; i++) {
        char source[PATH_MAX];
        if (snprintf(source, sizeof(source), "%s%s", root, paths[i]) >= (int)sizeof(source)) {
            errno = ENAMETOOLONG;
            fail("hardware view path");
        }
        bind_view(source, paths[i]);
    }
    bind_view(root, root);
    bind_view(root, anchor);
}

static int filter_install(void)
{
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PH4_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__)
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000U, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
#endif
        NOTIFY(SYS_sysinfo),
        NOTIFY(SYS_uname),
        NOTIFY(SYS_sched_getaffinity),
        NOTIFY(SYS_sched_setaffinity),
        NOTIFY(SYS_getcpu),
#ifdef SYS_open
        NOTIFY(SYS_open),
#endif
        NOTIFY(SYS_openat),
        NOTIFY(SYS_openat2),
        NOTIFY(SYS_lseek),
#ifdef SYS_readlink
        NOTIFY(SYS_readlink),
#endif
        NOTIFY(SYS_readlinkat),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len = sizeof(code) / sizeof(code[0]), .filter = code};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
}

static void pass_fd(int socket, int fd)
{
    char control[CMSG_SPACE(sizeof(int))] = {0};
    char value = 0;
    struct iovec vector = {.iov_base = &value, .iov_len = 1};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
                             .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    if (sendmsg(socket, &message, MSG_NOSIGNAL) != 1)
        fail("send syscall listener");
}

static int receive_fd(int socket)
{
    char control[CMSG_SPACE(sizeof(int))] = {0};
    char value;
    struct iovec vector = {.iov_base = &value, .iov_len = 1};
    struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1,
                             .msg_control = control, .msg_controllen = sizeof(control)};
    if (recvmsg(socket, &message, MSG_CMSG_CLOEXEC) != 1)
        return -1;
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len != CMSG_LEN(sizeof(int)) || message.msg_flags & MSG_CTRUNC) {
        errno = EPROTO;
        return -1;
    }
    int fd;
    memcpy(&fd, CMSG_DATA(header), sizeof(fd));
    return fd;
}

static int transfer(struct seccomp_notif *request, uint64_t address, void *buffer,
                    size_t size, int writing)
{
    if (!size)
        return 0;
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id) < 0)
        return -1;
    struct iovec local = {.iov_base = buffer, .iov_len = size};
    struct iovec remote = {.iov_base = (void *)(uintptr_t)address, .iov_len = size};
    ssize_t result = writing
        ? process_vm_writev((pid_t)request->pid, &local, 1, &remote, 1, 0)
        : process_vm_readv((pid_t)request->pid, &local, 1, &remote, 1, 0);
    if (result != (ssize_t)size) {
        if (result >= 0)
            errno = EFAULT;
        return -1;
    }
    return 0;
}

static int read_string(struct seccomp_notif *request, uint64_t address, char *buffer,
                       size_t size)
{
    size_t used = 0;
    while (used < size) {
        size_t amount = 4096 - (size_t)((address + used) & 4095);
        if (amount > size - used)
            amount = size - used;
        if (transfer(request, address + used, buffer + used, amount, 0) < 0)
            return -1;
        char *end = memchr(buffer + used, 0, amount);
        if (end)
            return 0;
        used += amount;
    }
    errno = ENAMETOOLONG;
    return -1;
}

static void respond(struct seccomp_notif *request, long value, int error, int flags)
{
    struct seccomp_notif_resp reply = {.id = request->id, .val = value,
                                       .error = -error, .flags = (unsigned int)flags};
    if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &reply) < 0 && errno != ENOENT)
        fail("reply to syscall");
}

static int same_namespace(pid_t target)
{
    struct stat ours, theirs;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/ns/user", target);
    return !stat("/proc/self/ns/user", &ours) && !stat(path, &theirs) &&
           ours.st_dev == theirs.st_dev && ours.st_ino == theirs.st_ino;
}

static void affinity(struct seccomp_notif *request, int setting)
{
    __u64 *args = request->data.args;
    pid_t target = (pid_t)args[0];
    if (!target)
        target = (pid_t)request->pid;
    unsigned char actual[CPU_BYTES] = {0};
    size_t bytes = (cpu_count + sizeof(unsigned long) * CHAR_BIT - 1) /
                   (sizeof(unsigned long) * CHAR_BIT) * sizeof(unsigned long);
    unsigned char visible[VIEW_LIMIT / CHAR_BIT] = {0};
    if (!setting) {
        long status = syscall(SYS_sched_getaffinity, target, sizeof(actual), actual);
        if (status < 0) {
            respond(request, 0, errno, 0);
            return;
        }
        if (args[1] < bytes || args[1] % sizeof(unsigned long)) {
            respond(request, 0, EINVAL, 0);
            return;
        }
        for (unsigned int i = 0; i < cpu_count; i++)
            if (actual[physical[i] / CHAR_BIT] & (1U << (physical[i] % CHAR_BIT)))
                visible[i / CHAR_BIT] |= 1U << (i % CHAR_BIT);
        if (transfer(request, args[2], visible, bytes, 1) < 0)
            respond(request, 0, errno, 0);
        else
            respond(request, (long)bytes, 0, 0);
    } else {
        if (!same_namespace(target)) {
            respond(request, 0, EPERM, 0);
            return;
        }
        size_t length = args[1] < bytes ? (size_t)args[1] : bytes;
        if (transfer(request, args[2], visible, length, 0) < 0) {
            respond(request, 0, errno, 0);
            return;
        }
        for (unsigned int i = 0; i < cpu_count; i++)
            if (visible[i / CHAR_BIT] & (1U << (i % CHAR_BIT)))
                actual[physical[i] / CHAR_BIT] |= 1U << (physical[i] % CHAR_BIT);
        long status = syscall(SYS_sched_setaffinity, target, sizeof(actual), actual);
        respond(request, status < 0 ? 0 : status, status < 0 ? errno : 0, 0);
    }
}

static unsigned int current_cpu(pid_t tid)
{
    char path[64], buffer[8192];
    snprintf(path, sizeof(path), "/proc/%d/stat", tid);
    FILE *stream = fopen(path, "re");
    if (!stream)
        return 0;
    size_t length = fread(buffer, 1, sizeof(buffer) - 1, stream);
    fclose(stream);
    buffer[length] = 0;
    char *cursor = strrchr(buffer, ')');
    if (!cursor || cursor[1] != ' ')
        return 0;
    cursor += 2;
    char *save;
    char *token = strtok_r(cursor, " ", &save);
    for (int field = 3; token && field < 39; field++)
        token = strtok_r(NULL, " ", &save);
    if (token) {
        int cpu = atoi(token);
        for (unsigned int i = 0; i < cpu_count; i++)
            if (physical[i] == cpu)
                return i;
    }
    return 0;
}

static int dynamic_kind(pid_t tid, int directory, const char *path)
{
    char resolved[PATH_MAX + 128];
    if (path[0] == '/')
        snprintf(resolved, sizeof(resolved), "/proc/%d/root%s", tid, path);
    else if (directory == AT_FDCWD)
        snprintf(resolved, sizeof(resolved), "/proc/%d/cwd/%s", tid, path);
    else
        snprintf(resolved, sizeof(resolved), "/proc/%d/fd/%d/%s", tid, directory, path);
    struct stat status;
    if (stat(resolved, &status) < 0)
        return -1;
    for (int i = 0; i < 3; i++)
        if (status.st_dev == dynamic_device[i] && status.st_ino == dynamic_inode[i])
            return i;
    return -1;
}

static int node_contents(int fd)
{
    DIR *nodes = opendir("/sys/devices/system/node");
    if (!nodes)
        return -1;
    char keys[128][80], units[128][8];
    unsigned long long values[128] = {0};
    unsigned int count = 0;
    struct dirent *entry;
    while ((entry = readdir(nodes))) {
        unsigned int index;
        char extra;
        if (sscanf(entry->d_name, "node%u%c", &index, &extra) != 1)
            continue;
        char path[128];
        snprintf(path, sizeof(path), "/sys/devices/system/node/node%u/meminfo", index);
        FILE *input = fopen(path, "re");
        if (!input) {
            closedir(nodes);
            return -1;
        }
        char line[256], key[80], unit[8];
        unsigned long long value;
        while (fgets(line, sizeof(line), input)) {
            unit[0] = 0;
            if (sscanf(line, "Node %*u %79[^:]: %llu %7s", key, &value, unit) < 2)
                continue;
            unsigned int i;
            for (i = 0; i < count && strcmp(keys[i], key); i++) {}
            if (i == count) {
                if (count == 128) {
                    fclose(input);
                    closedir(nodes);
                    errno = EOVERFLOW;
                    return -1;
                }
                strcpy(keys[i], key);
                strcpy(units[i], unit);
                count++;
            }
            values[i] += value;
        }
        fclose(input);
    }
    closedir(nodes);
    unsigned long long total = 0;
    for (unsigned int i = 0; i < count; i++)
        if (!strcmp(keys[i], "MemTotal"))
            total = values[i];
    if (!total) {
        errno = EIO;
        return -1;
    }
    char *result = NULL;
    size_t size = 0;
    FILE *output = open_memstream(&result, &size);
    if (!output)
        return -1;
    for (unsigned int i = 0; i < count; i++) {
        unsigned long long value = values[i];
        if (!strcmp(units[i], "kB") && strcmp(keys[i], "SwapCached"))
            value = (unsigned long long)((long double)value * (ram / 1024) / total);
        fprintf(output, "Node 0 %s: %8llu%s%s\n", keys[i], value,
                units[i][0] ? " " : "", units[i]);
    }
    int status = fclose(output);
    if (!status && (pwrite(fd, result, size, 0) != (ssize_t)size ||
                    ftruncate(fd, (off_t)size) < 0))
        status = -1;
    free(result);
    return status;
}

static int memory_contents(int fd)
{
    FILE *input = fopen("/proc/meminfo", "re");
    if (!input)
        return -1;
    char *result = NULL, *line = NULL;
    size_t size = 0, capacity = 0;
    FILE *output = open_memstream(&result, &size);
    if (!output) {
        fclose(input);
        return -1;
    }
    unsigned long long total = 0;
    while (getline(&line, &capacity, input) >= 0) {
        unsigned long long value;
        char key[80], unit[8];
        if (sscanf(line, "MemTotal: %llu", &value) == 1)
            total = value;
        if (sscanf(line, "%79[^:]: %llu %7s", key, &value, unit) == 3 &&
            !strcmp(unit, "kB") && total && strncmp(key, "Swap", 4) &&
            strcmp(key, "Hugepagesize")) {
            value = (unsigned long long)((long double)value * (ram / 1024) / total);
            fprintf(output, "%s: %8llu kB\n", key, value);
        } else {
            fputs(line, output);
        }
    }
    int status = ferror(input) ? -1 : 0;
    free(line);
    fclose(input);
    if (fclose(output) != 0)
        status = -1;
    if (!status && (pwrite(fd, result, size, 0) != (ssize_t)size ||
                    ftruncate(fd, (off_t)size) < 0))
        status = -1;
    free(result);
    return status;
}

static int stat_contents(int fd)
{
    FILE *input = fopen("/proc/stat", "re");
    if (!input)
        return -1;
    unsigned long long rows[VIEW_LIMIT][10] = {{0}}, totals[10] = {0};
    unsigned int count = 0;
    char *line = NULL, *tail = NULL, *result = NULL;
    size_t capacity = 0, tail_size = 0, size = 0;
    FILE *other = open_memstream(&tail, &tail_size);
    if (!other) {
        fclose(input);
        return -1;
    }
    while (getline(&line, &capacity, input) >= 0) {
        unsigned int index;
        if (line[3] >= '0' && line[3] <= '9' && sscanf(line, "cpu%u ", &index) == 1) {
            for (unsigned int i = 0; i < cpu_count; i++) {
                if ((unsigned int)physical[i] != index)
                    continue;
                unsigned long long *row = rows[i];
                sscanf(line, "%*s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                       &row[0], &row[1], &row[2], &row[3], &row[4], &row[5], &row[6],
                       &row[7], &row[8], &row[9]);
                count++;
            }
        } else if (strncmp(line, "cpu ", 4)) {
            fputs(line, other);
        }
    }
    int status = ferror(input) ? -1 : 0;
    free(line);
    fclose(input);
    if (fclose(other) != 0)
        status = -1;
    FILE *output = open_memstream(&result, &size);
    if (!output || !count)
        status = -1;
    if (output && count) {
        for (unsigned int i = 0; i < cpu_count; i++)
            for (int j = 0; j < 10; j++)
                totals[j] += rows[i][j];
        fputs("cpu", output);
        for (int j = 0; j < 10; j++)
            fprintf(output, " %llu", totals[j]);
        fputc('\n', output);
        for (unsigned int i = 0; i < cpu_count; i++) {
            fprintf(output, "cpu%u", i);
            for (int j = 0; j < 10; j++)
                fprintf(output, " %llu", rows[i][j]);
            fputc('\n', output);
        }
        fputs(tail, output);
    }
    if (output && fclose(output) != 0)
        status = -1;
    if (!status && (pwrite(fd, result, size, 0) != (ssize_t)size ||
                    ftruncate(fd, (off_t)size) < 0))
        status = -1;
    free(tail);
    free(result);
    return status;
}

static int fill_dynamic(int fd, int kind)
{
    return kind == 1 ? stat_contents(fd) : kind == 2 ? node_contents(fd) : memory_contents(fd);
}

static int dynamic_open(struct seccomp_notif *request)
{
    __u64 *args = request->data.args;
    int directory = AT_FDCWD;
    uint64_t address, flags;
#ifdef SYS_open
    if (request->data.nr == SYS_open) {
        address = args[0];
        flags = args[1];
    } else
#endif
    {
        directory = (int)args[0];
        address = args[1];
        flags = args[2];
    }
    if (request->data.nr == SYS_openat2) {
        struct open_how how;
        if (args[3] != sizeof(how) || transfer(request, args[2], &how, sizeof(how), 0) < 0)
            return 0;
        if (how.resolve || how.mode)
            return 0;
        flags = how.flags;
    }
    if (flags & ~(uint64_t)(O_CLOEXEC | O_NONBLOCK | O_NOCTTY | O_LARGEFILE))
        return 0;
    char path[PATH_MAX];
    if (read_string(request, address, path, sizeof(path)) < 0)
        return 0;
    int kind = dynamic_kind((pid_t)request->pid, directory, path);
    if (kind < 0)
        return 0;
    char name[48];
    snprintf(name, sizeof(name), "ph4ntxm-live-%d", kind);
    int fd = memfd_create(name, MFD_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fill_dynamic(fd, kind) < 0) {
        close(fd);
        errno = EIO;
        return -1;
    }
    char source[64];
    snprintf(source, sizeof(source), "/proc/self/fd/%d", fd);
    int readonly = open(source, O_RDONLY | O_CLOEXEC | ((int)flags & O_NONBLOCK));
    close(fd);
    if (readonly < 0)
        return -1;
    struct seccomp_notif_addfd add = {.id = request->id, .flags = SECCOMP_ADDFD_FLAG_SEND,
                                      .srcfd = (unsigned int)readonly,
                                      .newfd_flags = (unsigned int)flags & O_CLOEXEC};
    int status = ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &add);
    int saved = errno;
    close(readonly);
    errno = saved;
    return status < 0 ? -1 : 1;
}

static void dynamic_rewind(struct seccomp_notif *request)
{
    if (request->data.args[1] || request->data.args[2] != SEEK_SET)
        return;
    char path[64], name[128];
    snprintf(path, sizeof(path), "/proc/%u/fd/%d", request->pid, (int)request->data.args[0]);
    ssize_t size = readlink(path, name, sizeof(name) - 1);
    if (size < 0)
        return;
    name[size] = 0;
    for (int kind = 0; kind < 3; kind++) {
        char expected[64];
        snprintf(expected, sizeof(expected), "/memfd:ph4ntxm-live-%d (deleted)", kind);
        if (strcmp(name, expected))
            continue;
        int fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd >= 0) {
            fill_dynamic(fd, kind);
            close(fd);
        }
        break;
    }
}

static void executable_link(struct seccomp_notif *request)
{
    __u64 *args = request->data.args;
    int offset = request->data.nr == SYS_readlinkat ? 1 : 0;
    char path[PATH_MAX];
    if (read_string(request, args[offset], path, sizeof(path)) < 0)
        goto native;
    pid_t pid;
    int used = 0;
    if (sscanf(path, "/proc/%d/exe%n", &pid, &used) != 1 || !used || path[used])
        goto native;
    for (unsigned int i = 0; i < ancestor_count; i++) {
        pid_t parent;
        unsigned long long started;
        if (ancestors[i].pid != pid || process_identity(pid, &parent, &started) < 0 ||
            started != ancestors[i].started)
            continue;
        if ((int)args[offset + 2] <= 0) {
            respond(request, 0, EINVAL, 0);
            return;
        }
        size_t length = strlen(ancestors[i].executable);
        if (length > args[offset + 2])
            length = (size_t)args[offset + 2];
        if (transfer(request, args[offset + 1], ancestors[i].executable, length, 1) < 0)
            respond(request, 0, errno, 0);
        else
            respond(request, (long)length, 0, 0);
        return;
    }
native:
    respond(request, 0, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE);
}

static void dispatch(struct seccomp_notif *request)
{
    __u64 *args = request->data.args;
    if (request->data.nr == SYS_sysinfo) {
        struct sysinfo value;
        if (sysinfo(&value) < 0) {
            respond(request, 0, errno, 0);
            return;
        }
        if (value.totalram && value.mem_unit) {
            long double ratio = (long double)ram / ((long double)value.totalram * value.mem_unit);
            value.freeram *= ratio;
            value.sharedram *= ratio;
            value.bufferram *= ratio;
            value.totalhigh *= ratio;
            value.freehigh *= ratio;
            value.totalram = ram / value.mem_unit;
        }
        int result = transfer(request, args[0], &value, sizeof(value), 1);
        respond(request, 0, result < 0 ? errno : 0, 0);
    } else if (request->data.nr == SYS_uname) {
        struct utsname value;
        if (uname(&value) < 0) {
            respond(request, 0, errno, 0);
            return;
        }
        snprintf(value.machine, sizeof(value.machine), "%s", getenv("PH4_CPU_ARCHITECTURE"));
        int result = transfer(request, args[0], &value, sizeof(value), 1);
        respond(request, 0, result < 0 ? errno : 0, 0);
    } else if (request->data.nr == SYS_sched_getaffinity ||
               request->data.nr == SYS_sched_setaffinity) {
        affinity(request, request->data.nr == SYS_sched_setaffinity);
    } else if (request->data.nr == SYS_getcpu) {
        unsigned int cpu = current_cpu((pid_t)request->pid), node = 0;
        int result = args[0] ? transfer(request, args[0], &cpu, sizeof(cpu), 1) : 0;
        if (!result && args[1])
            result = transfer(request, args[1], &node, sizeof(node), 1);
        respond(request, 0, result < 0 ? errno : 0, 0);
    } else if (request->data.nr == SYS_readlinkat
#ifdef SYS_readlink
               || request->data.nr == SYS_readlink
#endif
    ) {
        executable_link(request);
    } else if (request->data.nr == SYS_lseek) {
        dynamic_rewind(request);
        respond(request, 0, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE);
    } else {
        int result = dynamic_open(request);
        if (!result)
            respond(request, 0, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE);
        else if (result < 0 && errno != ENOENT)
            respond(request, 0, errno, 0);
    }
}

static void drop_capabilities(void)
{
    if (prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
              SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED, 0, 0, 0) < 0)
        fail("lock namespace capabilities");
    for (int capability = 0; capability <= CAP_LAST_CAP; capability++)
        if (prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) < 0 && errno != EINVAL)
            fail("drop capability bounding set");
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0)
        fail("drop ambient capabilities");
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct data[2] = {{0}};
    if (syscall(SYS_capset, &header, data) < 0)
        fail("drop namespace capabilities");
    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0)
        fail("enable supervisor access");
}

static int remove_entry(const char *path, const struct stat *status, int type,
                        struct FTW *walk)
{
    (void)status;
    (void)walk;
    return type == FTW_DP ? rmdir(path) : unlink(path);
}

static void cleanup(void)
{
    const char *owned = getenv("PH4_INVENTORY_OWNED");
    const char *name = strrchr(root, '/');
    struct stat status;
    if (owned && !strcmp(owned, "1") && name &&
        !strncmp(name + 1, ".ph4ntxm-inventory-", 19) &&
        !lstat(root, &status) && S_ISDIR(status.st_mode) && status.st_uid == getuid() &&
        (status.st_mode & 0777) == 0700)
        nftw(root, remove_entry, 16, FTW_DEPTH | FTW_PHYS | FTW_MOUNT);
}

static void close_except(int fd)
{
    if ((fd > 3 && syscall(SYS_close_range, 3U, (unsigned int)fd - 1, 0) < 0) ||
        syscall(SYS_close_range, (unsigned int)fd + 1, ~0U, 0) < 0)
        fail("close inherited descriptors");
}

static void serve(int channel)
{
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
        fail("protect supervisor");
    close_except(channel);
    listener = receive_fd(channel);
    if (listener < 0)
        exit(125);
    struct seccomp_notif_sizes sizes;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0)
        fail("read notification ABI");
    struct seccomp_notif *request = calloc(1, sizes.seccomp_notif);
    if (!request)
        fail("allocate notification");
    if (send(channel, "R", 1, MSG_NOSIGNAL) != 1)
        exit(125);
    close(channel);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    struct pollfd descriptor = {.fd = listener, .events = POLLIN};
    for (;;) {
        if (poll(&descriptor, 1, -1) < 0) {
            if (errno == EINTR)
                continue;
            fail("wait for syscalls");
        }
        if (descriptor.revents & POLLHUP)
            break;
        if (descriptor.revents & (POLLERR | POLLNVAL)) {
            errno = EIO;
            fail("syscall listener");
        }
        if (descriptor.revents & POLLIN) {
            memset(request, 0, sizes.seccomp_notif);
            if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, request) == 0)
                dispatch(request);
            else if (errno != EINTR && errno != ENOENT)
                fail("receive syscall");
        }
    }
    free(request);
    close(listener);
    exit(0);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: ph4ntxm-hardware-run COMMAND [ARGUMENT...]\n");
        return 2;
    }
    if (getenv("LD_PRELOAD") || getenv("LD_AUDIT") || getenv("LD_LIBRARY_PATH")) {
        errno = EINVAL;
        fail("supervisor loader environment");
    }
    const char *snapshot = getenv("PH4_INVENTORY_ROOT");
    const char *architecture = getenv("PH4_CPU_ARCHITECTURE");
    struct utsname host;
    if (!snapshot || !realpath(snapshot, root)) {
        errno = EINVAL;
        fail("session hardware directory");
    }
    atexit(cleanup);
    if (uname(&host) < 0 || !architecture || strcmp(host.machine, architecture)) {
        errno = EINVAL;
        fail("session hardware profile");
    }
    ssize_t executable_size = readlink("/proc/self/exe", anchor, sizeof(anchor) - 6);
    if (executable_size < 0)
        fail("supervisor location");
    anchor[executable_size] = 0;
    char *separator = strrchr(anchor, '/');
    if (!separator) {
        errno = EINVAL;
        fail("supervisor location");
    }
    strcpy(separator, "/view");
    ram = number("PH4_INVENTORY_RAM_BYTES", 4096ULL * 1024 * 1024 * 1024);
    cpu_count = (unsigned int)number("PH4_REPORTED_CORES", VIEW_LIMIT);
    unsigned char allowed[CPU_BYTES] = {0};
    if (syscall(SYS_sched_getaffinity, 0, sizeof(allowed), allowed) < 0)
        fail("read CPU affinity");
    unsigned int found = 0;
    for (int cpu = 0; cpu < CPU_LIMIT && found < cpu_count; cpu++)
        if (allowed[cpu / CHAR_BIT] & (1U << (cpu % CHAR_BIT)))
            physical[found++] = cpu;
    complete_cpu_map(found);
    for (int i = 0; i < 3; i++) {
        char path[PATH_MAX];
        struct stat status;
        if (snprintf(path, sizeof(path), "%s%s", root, dynamic_paths[i]) >= (int)sizeof(path) ||
            stat(path, &status) < 0 || !S_ISREG(status.st_mode)) {
            errno = EINVAL;
            fail("session counter view");
        }
        dynamic_device[i] = status.st_dev;
        dynamic_inode[i] = status.st_ino;
    }
    capture_ancestors();
    user_namespace();
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) < 0)
        fail("create supervisor channel");
    pid_t worker = fork();
    if (worker < 0)
        fail("start supervisor");
    if (!worker) {
        close(pair[1]);
        if (setsid() < 0)
            _exit(125);
        pid_t detached = fork();
        if (detached < 0)
            _exit(125);
        if (detached)
            _exit(0);
        serve(pair[0]);
    }
    close(pair[0]);
    int status;
    while (waitpid(worker, &status, 0) < 0) {
        if (errno != EINTR)
            fail("start supervisor");
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        errno = ECHILD;
        fail("start supervisor");
    }
    mount_namespace();
    unsigned char selected[CPU_BYTES] = {0};
    for (unsigned int i = 0; i < cpu_count; i++)
        selected[physical[i] / CHAR_BIT] |= 1U << (physical[i] % CHAR_BIT);
    for (unsigned int i = 0; i < sizeof(allowed); i++)
        selected[i] &= allowed[i];
    if (syscall(SYS_sched_setaffinity, 0, sizeof(selected), selected) < 0)
        fail("set application CPU affinity");
    drop_capabilities();
    int fd = filter_install();
    if (fd < 0)
        fail("install syscall filter");
    pass_fd(pair[1], fd);
    close(fd);
    char ready;
    if (recv(pair[1], &ready, 1, 0) != 1 || ready != 'R') {
        errno = EIO;
        fail("start syscall supervision");
    }
    close(pair[1]);
    if (syscall(SYS_close_range, 3U, ~0U, 0) < 0)
        fail("close inherited descriptors");
    const char *variables[] = {"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", NULL};
    for (int i = 0; variables[i]; i++) {
        char key[80];
        snprintf(key, sizeof(key), "PH4_CHILD_%s", variables[i]);
        const char *value = getenv(key);
        if (value && setenv(variables[i], value, 1) < 0)
            fail("restore command environment");
        unsetenv(key);
    }
    setenv("PH4_INVENTORY_SYSCALLS", "1", 1);
    const char *name = getenv("PH4_INVENTORY_ARGV0");
    char *command = argv[1];
    if (name && *name)
        argv[1] = (char *)name;
    execvp(command, argv + 1);
    fail("execute command");
}
