/*
 * Copyright (C) PH4NTXM
 * Licensed under the GNU General Public License v3.0.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "guard.h"

#ifndef GUARD_OBJECT_PATH
#define GUARD_OBJECT_PATH "/usr/lib/ph4ntxm/net-guard.bpf.o"
#endif
#define RUNTIME "/run/ph4ntxm-net-guard"
#define PINROOT "/sys/fs/bpf/ph4ntxm-net-guard"
#define CONTROL_SOCKET RUNTIME "/control.sock"
#define COMMAND_MAX 512U
#define RESPONSE_MAX 524288U
#define TOKEN_LENGTH 32U
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct map_spec {
    const char *name;
    enum bpf_map_type type;
    __u32 key_size;
    __u32 value_size;
    __u32 capacity;
    int fd;
};

static struct map_spec maps[] = {
    {"control", BPF_MAP_TYPE_ARRAY, 4, sizeof(struct guard_control), 1, -1},
    {"executions", BPF_MAP_TYPE_HASH, 4, sizeof(struct execution_key), GUARD_MAX_EXECUTIONS, -1},
    {"approvals", BPF_MAP_TYPE_HASH, sizeof(struct execution_key), sizeof(struct approval_value), GUARD_MAX_EXECUTIONS, -1},
    {"pending", BPF_MAP_TYPE_HASH, sizeof(struct execution_key), sizeof(struct pending_request), GUARD_MAX_REQUESTS, -1},
    {"overflow", BPF_MAP_TYPE_ARRAY, 4, 8, 1, -1},
    {"sockets", BPF_MAP_TYPE_SK_STORAGE, 4, sizeof(struct socket_identity), 0, -1}
};

enum { CONTROL_MAP, EXECUTIONS_MAP, APPROVALS_MAP, PENDING_MAP, OVERFLOW_MAP, SOCKETS_MAP };
struct program_spec {
    const char *name;
    const char *pin;
    const char *program_pin;
    unsigned map_mask;
    enum bpf_prog_type type;
    enum bpf_attach_type attach;
};
static const struct program_spec programs[] = {
    {"guard_socket_create", "create", "program_create", 0x3b, BPF_PROG_TYPE_LSM, BPF_LSM_MAC},
    {"guard_socket_connect", "connect", "program_connect", 0x3f, BPF_PROG_TYPE_LSM, BPF_LSM_MAC},
    {"guard_socket_send", "send", "program_send", 0x3f, BPF_PROG_TYPE_LSM, BPF_LSM_MAC},
    {"guard_egress", "egress", "program_egress", 0x27, BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_EGRESS},
    {"guard_exec", "exec", "program_exec", 0x1f, BPF_PROG_TYPE_TRACING, BPF_TRACE_RAW_TP},
    {"guard_exit", "exit", "program_exit", 0x0e, BPF_PROG_TYPE_TRACING, BPF_TRACE_RAW_TP}
};

struct request_slot {
    bool occupied;
    bool seen;
    char token[TOKEN_LENGTH + 1];
    struct execution_key execution;
};

struct command {
    char action[16];
    char generation[TOKEN_LENGTH + 1];
    char request_id[TOKEN_LENGTH + 1];
};

struct metadata {
    char executable[4096];
    char app_name[256];
    int pidfd;
};

static struct guard_control control;
static struct request_slot requests[GUARD_MAX_REQUESTS];
static char generation[TOKEN_LENGTH + 1];
static volatile sig_atomic_t stopping;
static int cgroup_fd = -1;
static unsigned long cgroup_inode;

static uint64_t monotonic_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static bool same_execution(const struct execution_key *a, const struct execution_key *b)
{
    return a->tgid == b->tgid && a->started_ns == b->started_ns && a->exec_id == b->exec_id;
}

static int random_bytes(void *destination, size_t length)
{
    unsigned char *cursor = destination;
    while (length) {
        ssize_t count = getrandom(cursor, length, 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        cursor += count;
        length -= (size_t)count;
    }
    return 0;
}

static int new_token(char token[TOKEN_LENGTH + 1])
{
    unsigned char bytes[TOKEN_LENGTH / 2];
    static const char digits[] = "0123456789abcdef";
    if (random_bytes(bytes, sizeof(bytes)))
        return -1;
    for (size_t index = 0; index < sizeof(bytes); index++) {
        token[index * 2] = digits[bytes[index] >> 4];
        token[index * 2 + 1] = digits[bytes[index] & 15];
    }
    token[TOKEN_LENGTH] = 0;
    return 0;
}

static bool protected_path(const char *path, bool directory, mode_t mode)
{
    struct stat status;
    if (lstat(path, &status) || status.st_uid != 0 || S_ISLNK(status.st_mode))
        return false;
    if (directory ? !S_ISDIR(status.st_mode) : !S_ISREG(status.st_mode))
        return false;
    return (status.st_mode & 0777) == mode;
}

static int secure_directory(const char *path)
{
    if (mkdir(path, 0700) && errno != EEXIST)
        return -1;
    if (!protected_path(path, true, 0700)) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int pin_path(char *path, size_t size, const char *name)
{
    int count = snprintf(path, size, "%s/%s", PINROOT, name);
    return count >= 0 && (size_t)count < size ? 0 : -1;
}

static int validate_map(int descriptor, const struct map_spec *specification)
{
    struct bpf_map_info information = {};
    __u32 size = sizeof(information);
    if (bpf_obj_get_info_by_fd(descriptor, &information, &size))
        return -1;
    if (information.type != (__u32)specification->type ||
        information.key_size != specification->key_size ||
        information.value_size != specification->value_size ||
        information.max_entries != specification->capacity ||
        strncmp((const char *)information.name, specification->name, BPF_OBJ_NAME_LEN)) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static int write_control(void)
{
    __u32 zero = 0;
    return bpf_map_update_elem(maps[CONTROL_MAP].fd, &zero, &control, BPF_ANY);
}

static int renew_lease(void)
{
    uint64_t now = monotonic_ns();
    if (!now)
        return -1;
    control.lease_ns = now + GUARD_LEASE_NS;
    return write_control();
}

static int validate_links(void)
{
    __u32 expected_maps[ARRAY_SIZE(maps)];
    for (size_t index = 0; index < ARRAY_SIZE(maps); index++) {
        struct bpf_map_info information = {};
        __u32 size = sizeof(information);
        if (bpf_obj_get_info_by_fd(maps[index].fd, &information, &size))
            return -1;
        expected_maps[index] = information.id;
    }
    char path[256];
    for (size_t index = 0; index < ARRAY_SIZE(programs); index++) {
        if (pin_path(path, sizeof(path), programs[index].pin))
            return -1;
        int descriptor = bpf_obj_get(path);
        if (descriptor < 0)
            return -1;
        struct bpf_link_info information = {};
        __u32 size = sizeof(information);
        int result = bpf_obj_get_info_by_fd(descriptor, &information, &size);
        close(descriptor);
        if (result)
            return -1;
        if (programs[index].type == BPF_PROG_TYPE_CGROUP_SKB) {
            if (information.type != BPF_LINK_TYPE_CGROUP ||
                information.cgroup.attach_type != BPF_CGROUP_INET_EGRESS ||
                information.cgroup.cgroup_id != cgroup_inode) {
                errno = EPROTO;
                return -1;
            }
        } else if (programs[index].attach == BPF_TRACE_RAW_TP) {
            if (information.type != BPF_LINK_TYPE_RAW_TRACEPOINT) {
                errno = EPROTO;
                return -1;
            }
        } else if (information.type != BPF_LINK_TYPE_TRACING ||
                   information.tracing.attach_type != (__u32)programs[index].attach) {
            errno = EPROTO;
            return -1;
        }
        if (pin_path(path, sizeof(path), programs[index].program_pin))
            return -1;
        int program_fd = bpf_obj_get(path);
        if (program_fd < 0)
            return -1;
        __u32 actual_maps[ARRAY_SIZE(maps)] = {};
        struct bpf_prog_info program = {
            .nr_map_ids = ARRAY_SIZE(actual_maps),
            .map_ids = (__u64)(uintptr_t)actual_maps
        };
        size = sizeof(program);
        result = bpf_obj_get_info_by_fd(program_fd, &program, &size);
        close(program_fd);
        if (result || program.id != information.prog_id ||
            program.nr_map_ids > ARRAY_SIZE(actual_maps) ||
            program.type != (__u32)programs[index].type ||
            strncmp((const char *)program.name, programs[index].name, BPF_OBJ_NAME_LEN - 1)) {
            errno = EPROTO;
            return -1;
        }
        unsigned map_mask = 0;
        for (size_t actual = 0; actual < program.nr_map_ids; actual++) {
            bool recognized = false;
            for (size_t expected = 0; expected < ARRAY_SIZE(expected_maps); expected++) {
                if (actual_maps[actual] == expected_maps[expected]) {
                    map_mask |= 1U << expected;
                    recognized = true;
                    break;
                }
            }
            if (!recognized) {
                errno = EPROTO;
                return -1;
            }
        }
        if (map_mask != programs[index].map_mask) {
            errno = EPROTO;
            return -1;
        }
    }
    return 0;
}

static void remove_new_pins(void)
{
    char path[256];
    for (size_t index = 0; index < ARRAY_SIZE(programs); index++) {
        if (!pin_path(path, sizeof(path), programs[index].pin))
            unlink(path);
        if (!pin_path(path, sizeof(path), programs[index].program_pin))
            unlink(path);
    }
    for (size_t index = 0; index < ARRAY_SIZE(maps); index++)
        if (!pin_path(path, sizeof(path), maps[index].name))
            unlink(path);
}

static int load_new_objects(void)
{
    struct stat object_status;
    if (lstat(GUARD_OBJECT_PATH, &object_status) || !S_ISREG(object_status.st_mode) ||
        object_status.st_uid != 0 || (object_status.st_mode & 0022)) {
        errno = EPERM;
        return -1;
    }
    struct bpf_object *object = bpf_object__open_file(GUARD_OBJECT_PATH, NULL);
    long error = libbpf_get_error(object);
    if (error) {
        errno = (int)-error;
        return -1;
    }
    int result = -1;
    if (bpf_object__load(object))
        goto done;
    for (size_t index = 0; index < ARRAY_SIZE(maps); index++) {
        struct bpf_map *map = bpf_object__find_map_by_name(object, maps[index].name);
        if (!map || validate_map(bpf_map__fd(map), &maps[index]))
            goto done;
        maps[index].fd = fcntl(bpf_map__fd(map), F_DUPFD_CLOEXEC, 3);
        if (maps[index].fd < 0)
            goto done;
    }
    if (write_control())
        goto done;
    for (size_t index = 0; index < ARRAY_SIZE(maps); index++) {
        char path[256];
        if (pin_path(path, sizeof(path), maps[index].name) ||
            bpf_obj_pin(maps[index].fd, path) || chmod(path, 0600))
            goto cleanup;
    }
    for (size_t index = 0; index < ARRAY_SIZE(programs); index++) {
        struct bpf_program *program = bpf_object__find_program_by_name(object, programs[index].name);
        if (!program)
            goto cleanup;
        char path[256];
        if (pin_path(path, sizeof(path), programs[index].program_pin) ||
            bpf_obj_pin(bpf_program__fd(program), path) || chmod(path, 0600))
            goto cleanup;
        struct bpf_link *link = programs[index].type == BPF_PROG_TYPE_CGROUP_SKB
            ? bpf_program__attach_cgroup(program, cgroup_fd)
            : bpf_program__attach(program);
        if (libbpf_get_error(link))
            goto cleanup;
        if (pin_path(path, sizeof(path), programs[index].pin) || bpf_link__pin(link, path) ||
            chmod(path, 0600)) {
            bpf_link__destroy(link);
            goto cleanup;
        }
        bpf_link__disconnect(link);
        bpf_link__destroy(link);
    }
    result = validate_links();
    if (!result)
        goto done;
cleanup:
    remove_new_pins();
done:
    bpf_object__close(object);
    return result;
}

static int clear_map(int descriptor)
{
    struct execution_key key;
    for (size_t iteration = 0; iteration < GUARD_MAX_EXECUTIONS * 2U; iteration++) {
        if (bpf_map_get_next_key(descriptor, NULL, &key))
            return errno == ENOENT ? 0 : -1;
        if (bpf_map_delete_elem(descriptor, &key) && errno != ENOENT)
            return -1;
    }
    errno = EBUSY;
    return -1;
}

static int change_generation(void)
{
    if (new_token(generation) || random_bytes(&control.epoch, sizeof(control.epoch)))
        return -1;
    if (!control.epoch)
        control.epoch = 1;
    memset(requests, 0, sizeof(requests));
    if (clear_map(maps[APPROVALS_MAP].fd) || clear_map(maps[PENDING_MAP].fd))
        return -1;
    __u32 zero = 0;
    __u64 count = 0;
    return bpf_map_update_elem(maps[OVERFLOW_MAP].fd, &zero, &count, BPF_ANY);
}

static int initialize_objects(uid_t uid)
{
    struct statfs filesystem;
    struct stat root;
    if (statfs("/sys/fs/bpf", &filesystem) || (unsigned long)filesystem.f_type != BPF_FS_MAGIC) {
        fprintf(stderr, "Net Guard requires bpffs mounted at /sys/fs/bpf\n");
        return -1;
    }
    if (secure_directory(PINROOT))
        return -1;
    cgroup_fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (cgroup_fd < 0 || fstatfs(cgroup_fd, &filesystem) ||
        (unsigned long)filesystem.f_type != CGROUP2_SUPER_MAGIC || fstat(cgroup_fd, &root))
        return -1;
    cgroup_inode = root.st_ino;
    memset(&control, 0, sizeof(control));
    control.abi = GUARD_ABI;
    control.guarded_uid = uid;
    control.daemon_tgid = (__u32)getpid();
    if (random_bytes(&control.epoch, sizeof(control.epoch)))
        return -1;
    if (!control.epoch)
        control.epoch = 1;
    char path[256];
    if (pin_path(path, sizeof(path), maps[CONTROL_MAP].name))
        return -1;
    maps[CONTROL_MAP].fd = bpf_obj_get(path);
    bool resume = false;
    if (maps[CONTROL_MAP].fd >= 0) {
        __u32 zero = 0;
        struct guard_control previous;
        if (validate_map(maps[CONTROL_MAP].fd, &maps[CONTROL_MAP]) ||
            bpf_map_lookup_elem(maps[CONTROL_MAP].fd, &zero, &previous) ||
            previous.abi != GUARD_ABI || previous.guarded_uid != uid || previous.enabled > 2)
            return -1;
        resume = previous.enabled != 0;
        control = previous;
        control.enabled = resume ? 2 : 0;
        control.lease_ns = 0;
        control.daemon_tgid = (__u32)getpid();
        memset(&control.daemon, 0, sizeof(control.daemon));
        if (write_control())
            return -1;
        for (size_t index = 1; index < ARRAY_SIZE(maps); index++) {
            if (pin_path(path, sizeof(path), maps[index].name))
                return -1;
            maps[index].fd = bpf_obj_get(path);
            if (maps[index].fd < 0 || validate_map(maps[index].fd, &maps[index]))
                return -1;
        }
        if (validate_links())
            return -1;
    } else if (errno != ENOENT || load_new_objects()) {
        return -1;
    }
    int probe = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (probe < 0)
        return -1;
    close(probe);
    __u32 self = (__u32)getpid();
    if (bpf_map_lookup_elem(maps[EXECUTIONS_MAP].fd, &self, &control.daemon) ||
        control.daemon.tgid != self || !control.daemon.started_ns || change_generation())
        return -1;
    control.enabled = resume ? 1 : 0;
    return renew_lease();
}

static bool execution_live(const struct execution_key *key)
{
    struct execution_key actual;
    return !bpf_map_lookup_elem(maps[EXECUTIONS_MAP].fd, &key->tgid, &actual) &&
           same_execution(key, &actual);
}

static bool process_metadata(const struct execution_key *key, struct metadata *metadata)
{
    memset(metadata, 0, sizeof(*metadata));
    metadata->pidfd = -1;
    if (!execution_live(key))
        return false;
    int descriptor = (int)syscall(SYS_pidfd_open, key->tgid, 0);
    if (descriptor < 0)
        return false;
    metadata->pidfd = descriptor;
    struct pollfd status = {.fd = descriptor, .events = POLLIN};
    if (poll(&status, 1, 0) != 0)
        goto failed;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/stat", key->tgid);
    int stat_fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (stat_fd < 0)
        goto failed;
    char contents[8192];
    ssize_t length = read(stat_fd, contents, sizeof(contents) - 1);
    close(stat_fd);
    if (length <= 0 || (size_t)length >= sizeof(contents) - 1)
        goto failed;
    contents[length] = 0;
    char *cursor = strrchr(contents, ')');
    if (!cursor || cursor[1] != ' ')
        goto failed;
    cursor += 2;
    unsigned field = 3;
    while (field < 22 && *cursor) {
        while (*cursor && *cursor != ' ')
            cursor++;
        while (*cursor == ' ')
            cursor++;
        field++;
    }
    char *end;
    errno = 0;
    unsigned long long ticks = strtoull(cursor, &end, 10);
    long frequency = sysconf(_SC_CLK_TCK);
    if (errno || end == cursor || (*end != ' ' && *end != '\n') || frequency <= 0 ||
        ticks != key->started_ns / 1000000000ULL * (unsigned long long)frequency +
                 key->started_ns % 1000000000ULL * (unsigned long long)frequency / 1000000000ULL)
        goto failed;
    snprintf(path, sizeof(path), "/proc/%u/exe", key->tgid);
    length = readlink(path, metadata->executable, sizeof(metadata->executable) - 1);
    if (length <= 0 || (size_t)length >= sizeof(metadata->executable) - 1)
        goto failed;
    metadata->executable[length] = 0;
    const char *name = strrchr(metadata->executable, '/');
    name = name ? name + 1 : metadata->executable;
    snprintf(metadata->app_name, sizeof(metadata->app_name), "%.255s", name);
    if (poll(&status, 1, 0) != 0 || !execution_live(key))
        goto failed;
    return true;
failed:
    close(descriptor);
    metadata->pidfd = -1;
    return false;
}

static void json_string(FILE *stream, const char *value)
{
    fputc('"', stream);
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor; cursor++) {
        if (*cursor == '"' || *cursor == '\\')
            fprintf(stream, "\\%c", *cursor);
        else if (*cursor < 32 || *cursor >= 127)
            fprintf(stream, "\\u%04x", *cursor);
        else
            fputc(*cursor, stream);
    }
    fputc('"', stream);
}

static struct request_slot *slot_for(const struct execution_key *key)
{
    struct request_slot *empty = NULL;
    for (size_t index = 0; index < ARRAY_SIZE(requests); index++) {
        if (requests[index].occupied && same_execution(&requests[index].execution, key)) {
            return &requests[index];
        }
        if (!requests[index].occupied && !empty)
            empty = &requests[index];
    }
    if (!empty || new_token(empty->token))
        return NULL;
    empty->execution = *key;
    empty->occupied = true;
    return empty;
}

static bool granted(const struct execution_key *key)
{
    struct approval_value grant;
    return !bpf_map_lookup_elem(maps[APPROVALS_MAP].fd, key, &grant) && grant.epoch == control.epoch;
}

static const char *protocol_name(__u8 protocol, __u16 family)
{
    if (family == AF_PACKET || family == 44)
        return "raw";
    switch (protocol) {
    case IPPROTO_TCP: return "tcp";
    case IPPROTO_UDP: return "udp";
    case IPPROTO_ICMP: return "icmp";
    case IPPROTO_ICMPV6: return "icmpv6";
    default: return "unknown";
    }
}

static const char *request_reason(__u32 reason)
{
    switch (reason) {
    case GUARD_REASON_RECONNECT: return "This connection predates activation. Approve this process, then reconnect.";
    case GUARD_REASON_SHARED: return "The socket belongs to another execution. This process must open its own connection.";
    case GUARD_REASON_UNAVAILABLE: return "This network operation cannot be approved. Raw packet and XDP access remain blocked while Net Guard is on.";
    default: return "Network access is blocked until this execution is approved.";
    }
}

static bool healthy(void)
{
    __u32 zero = 0;
    struct guard_control actual;
    return !bpf_map_lookup_elem(maps[CONTROL_MAP].fd, &zero, &actual) &&
           !memcmp(&control, &actual, sizeof(control)) && control.enabled < 2 &&
           control.lease_ns > monotonic_ns() && execution_live(&control.daemon) &&
           !validate_links();
}

static char *snapshot(bool ok, const char *message, size_t *length)
{
    char *response = NULL;
    FILE *stream = open_memstream(&response, length);
    if (!stream)
        return NULL;
    bool active = control.enabled != 0;
    const char *state = healthy() ? (active ? "on" : "off") : "attention";
    __u32 zero = 0;
    __u64 count = 0;
    if (bpf_map_lookup_elem(maps[OVERFLOW_MAP].fd, &zero, &count))
        count = 1;
    fprintf(stream, "{\"ok\":%s,\"state\":\"%s\",\"enabled\":%s,\"generation\":\"%s\",\"message\":",
            ok ? "true" : "false", state, active ? "true" : "false", generation);
    json_string(stream, message);
    fputs(",\"requests\":[", stream);
    for (size_t index = 0; index < ARRAY_SIZE(requests); index++)
        requests[index].seen = false;
    struct execution_key key;
    struct execution_key previous;
    bool have_previous = false;
    bool comma = false;
    for (size_t iteration = 0; iteration < GUARD_MAX_REQUESTS * 2U; iteration++) {
        if (bpf_map_get_next_key(maps[PENDING_MAP].fd, have_previous ? &previous : NULL, &key))
            break;
        previous = key;
        have_previous = true;
        struct pending_request request;
        if (bpf_map_lookup_elem(maps[PENDING_MAP].fd, &key, &request))
            continue;
        if (!active || request.epoch != control.epoch || !execution_live(&key)) {
            bpf_map_delete_elem(maps[PENDING_MAP].fd, &key);
            bpf_map_delete_elem(maps[APPROVALS_MAP].fd, &key);
            have_previous = false;
            continue;
        }
        struct request_slot *slot = slot_for(&key);
        if (!slot || slot->seen)
            continue;
        slot->seen = true;
        long position = ftell(stream);
        if (position < 0 || (size_t)position > RESPONSE_MAX - 28672U) {
            count++;
            continue;
        }
        struct metadata metadata;
        bool identity_valid = process_metadata(&key, &metadata);
        bool approved = granted(&key);
        char destination[INET6_ADDRSTRLEN] = "";
        if (request.family == AF_INET || request.family == AF_INET6) {
            static const unsigned char zeros[16];
            size_t bytes = request.family == AF_INET ? 4 : 16;
            if (memcmp(request.destination, zeros, bytes))
                inet_ntop(request.family, request.destination, destination, sizeof(destination));
        }
        if (comma)
            fputc(',', stream);
        comma = true;
        fprintf(stream, "{\"request_id\":\"%s\",\"pid\":%u,\"app_name\":", slot->token, key.tgid);
        json_string(stream, identity_valid ? metadata.app_name : "Unavailable process");
        fputs(",\"executable\":", stream);
        json_string(stream, identity_valid ? metadata.executable : "");
        fputs(",\"destination\":", stream);
        json_string(stream, destination);
        fprintf(stream, ",\"port\":%u,\"protocol\":\"%s\",\"approved\":%s,\"approval_available\":%s,\"reason\":",
                request.port, protocol_name(request.protocol, request.family), approved ? "true" : "false",
                identity_valid && !approved && control.enabled == 1 &&
                request.reason != GUARD_REASON_UNAVAILABLE ? "true" : "false");
        json_string(stream, identity_valid ? request_reason(request.reason) : "The process identity could not be verified.");
        fputc('}', stream);
        if (metadata.pidfd >= 0)
            close(metadata.pidfd);
    }
    for (size_t index = 0; index < ARRAY_SIZE(requests); index++)
        if (requests[index].occupied && !requests[index].seen)
            memset(&requests[index], 0, sizeof(requests[index]));
    fprintf(stream, "],\"overflow\":%llu}\n", (unsigned long long)count);
    if (fclose(stream) || *length > RESPONSE_MAX) {
        free(response);
        return NULL;
    }
    return response;
}

static void skip_space(const char **cursor)
{
    while (**cursor == ' ' || **cursor == '\t' || **cursor == '\r' || **cursor == '\n')
        (*cursor)++;
}

static int parse_string(const char **cursor, char *output, size_t capacity)
{
    skip_space(cursor);
    if (*(*cursor)++ != '"')
        return -1;
    size_t length = 0;
    while (**cursor && **cursor != '"') {
        unsigned char byte = (unsigned char)*(*cursor)++;
        if (byte < 32 || byte >= 127 || byte == '\\' || length + 1 >= capacity)
            return -1;
        output[length++] = (char)byte;
    }
    if (*(*cursor)++ != '"')
        return -1;
    output[length] = 0;
    return 0;
}

static bool hex_token(const char *value)
{
    if (strlen(value) != TOKEN_LENGTH)
        return false;
    for (size_t index = 0; index < TOKEN_LENGTH; index++)
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f')))
            return false;
    return true;
}

static int parse_command(const char *input, struct command *command)
{
    memset(command, 0, sizeof(*command));
    const char *cursor = input;
    skip_space(&cursor);
    if (*cursor++ != '{')
        return -1;
    unsigned fields = 0;
    for (unsigned iteration = 0; iteration < 3; iteration++) {
        char name[16];
        char value[40];
        if (parse_string(&cursor, name, sizeof(name)))
            return -1;
        skip_space(&cursor);
        if (*cursor++ != ':' || parse_string(&cursor, value, sizeof(value)))
            return -1;
        unsigned flag;
        char *target;
        size_t size;
        if (!strcmp(name, "action")) { flag = 1; target = command->action; size = sizeof(command->action); }
        else if (!strcmp(name, "generation")) { flag = 2; target = command->generation; size = sizeof(command->generation); }
        else if (!strcmp(name, "request_id")) { flag = 4; target = command->request_id; size = sizeof(command->request_id); }
        else return -1;
        if ((fields & flag) || strlen(value) >= size)
            return -1;
        fields |= flag;
        memcpy(target, value, strlen(value) + 1);
        skip_space(&cursor);
        if (*cursor == '}') {
            cursor++;
            skip_space(&cursor);
            if (*cursor)
                return -1;
            if (!strcmp(command->action, "snapshot") || !strcmp(command->action, "enable") ||
                !strcmp(command->action, "disable"))
                return fields == 1 ? 0 : -1;
            if (!strcmp(command->action, "allow") && fields == 7 &&
                hex_token(command->generation) && hex_token(command->request_id))
                return 0;
            return -1;
        }
        if (*cursor++ != ',')
            return -1;
    }
    return -1;
}

static const char *apply_command(const struct command *command, bool *ok)
{
    *ok = false;
    if (!strcmp(command->action, "snapshot")) {
        *ok = true;
        return control.enabled ? "Each approval applies to one running execution. Existing connections must reconnect." : "Net Guard is off.";
    }
    if (!strcmp(command->action, "disable")) {
        if (new_token(generation))
            return "Could not reset the approval generation.";
        control.enabled = 0;
        if (write_control())
            return "Could not disable kernel enforcement.";
        if (change_generation() || renew_lease())
            return "Net Guard is off, but cleanup failed.";
        *ok = true;
        return "Net Guard is off. All approvals were cleared.";
    }
    if (!strcmp(command->action, "enable")) {
        if (validate_links())
            return "Required kernel enforcement links are unavailable.";
        if (control.enabled == 1) {
            *ok = true;
            return "Net Guard is already enabled.";
        }
        control.enabled = 2;
        if (write_control() || change_generation())
            return "Activation could not complete; network access remains blocked.";
        control.enabled = 1;
        if (renew_lease()) {
            control.enabled = 2;
            write_control();
            return "Activation could not complete; network access remains blocked.";
        }
        *ok = true;
        return "Net Guard is enabled. Approve each execution, then reconnect existing applications.";
    }
    if (control.enabled != 1 || strcmp(command->generation, generation) || !healthy())
        return "The approval generation changed or enforcement is unavailable. Refresh the requests.";
    struct request_slot *slot = NULL;
    for (size_t index = 0; index < ARRAY_SIZE(requests); index++)
        if (requests[index].occupied && !strcmp(requests[index].token, command->request_id))
            slot = &requests[index];
    if (!slot)
        return "The approval request has expired.";
    struct pending_request pending;
    struct metadata metadata;
    if (bpf_map_lookup_elem(maps[PENDING_MAP].fd, &slot->execution, &pending) ||
        pending.epoch != control.epoch || pending.reason == GUARD_REASON_UNAVAILABLE || !process_metadata(&slot->execution, &metadata))
        return "The process ended or changed execution. Refresh the requests.";
    struct approval_value value = {.epoch = control.epoch};
    int result = bpf_map_update_elem(maps[APPROVALS_MAP].fd, &slot->execution, &value, BPF_ANY);
    struct pollfd status = {.fd = metadata.pidfd, .events = POLLIN};
    bool alive = poll(&status, 1, 0) == 0 && execution_live(&slot->execution);
    close(metadata.pidfd);
    if (result || !alive) {
        bpf_map_delete_elem(maps[APPROVALS_MAP].fd, &slot->execution);
        return "The process could not be approved. Refresh the requests.";
    }
    *ok = true;
    return "This execution is approved. Retry the connection; sockets from earlier activations remain blocked.";
}

static bool root_peer(int descriptor)
{
    struct ucred credentials;
    socklen_t size = sizeof(credentials);
    return !getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &size) &&
           size == sizeof(credentials) && credentials.uid == 0;
}

static int read_line(int descriptor, char *buffer, size_t capacity, int timeout_ms)
{
    size_t length = 0;
    uint64_t until = monotonic_ns() + (uint64_t)timeout_ms * 1000000ULL;
    while (length + 1 < capacity) {
        uint64_t now = monotonic_ns();
        if (!now || now >= until)
            return -1;
        struct pollfd status = {.fd = descriptor, .events = POLLIN};
        int remaining = (int)((until - now) / 1000000ULL + 1);
        int ready = poll(&status, 1, remaining);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0)
            return -1;
        ssize_t count = read(descriptor, buffer + length, 1);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        if (!buffer[length])
            return -1;
        if (buffer[length++] == '\n') {
            buffer[length] = 0;
            return 0;
        }
    }
    return -1;
}

static int send_all(int descriptor, const char *buffer, size_t length)
{
    size_t sent = 0;
    while (sent < length) {
        ssize_t count = send(descriptor, buffer + sent, length - sent, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return -1;
        sent += (size_t)count;
    }
    return 0;
}

static int control_listener(void)
{
    int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (descriptor < 0)
        return -1;
    struct stat status;
    if (!lstat(CONTROL_SOCKET, &status)) {
        if (!S_ISSOCK(status.st_mode) || status.st_uid != 0 || unlink(CONTROL_SOCKET))
            goto failed;
    } else if (errno != ENOENT) {
        goto failed;
    }
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, CONTROL_SOCKET, sizeof(CONTROL_SOCKET));
    if (bind(descriptor, (struct sockaddr *)&address, sizeof(address)) ||
        chmod(CONTROL_SOCKET, 0600) || listen(descriptor, 4))
        goto failed;
    return descriptor;
failed:
    close(descriptor);
    return -1;
}

static void handle_client(int listener)
{
    int descriptor = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    if (descriptor < 0)
        return;
    struct timeval timeout = {.tv_sec = 1};
    if (!root_peer(descriptor) ||
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
        goto done;
    char input[COMMAND_MAX + 1];
    struct command command;
    bool ok = false;
    const char *message = "Invalid control request.";
    if (!read_line(descriptor, input, sizeof(input), 1000) && !parse_command(input, &command))
        message = apply_command(&command, &ok);
    if (renew_lease())
        goto done;
    size_t length = 0;
    char *response = snapshot(ok, message, &length);
    if (response) {
        send_all(descriptor, response, length);
        free(response);
    }
done:
    close(descriptor);
}

static void signal_stop(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static int daemon_main(void)
{
    umask(0077);
    if (secure_directory(RUNTIME))
        return 1;
    int lock = open(RUNTIME "/daemon.lock", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    struct stat lock_status;
    if (lock < 0 || fstat(lock, &lock_status) || !S_ISREG(lock_status.st_mode) ||
        lock_status.st_uid != 0 || (lock_status.st_mode & 0777) != 0600 ||
        flock(lock, LOCK_EX | LOCK_NB))
        return 1;
    struct passwd *user = getpwnam("ph4ntxm");
    if (!user || !user->pw_uid) {
        fprintf(stderr, "The ph4ntxm live account is unavailable\n");
        return 1;
    }
    if (initialize_objects(user->pw_uid)) {
        perror("Net Guard initialization");
        return 1;
    }
    int listener = control_listener();
    if (listener < 0) {
        perror("Net Guard control socket");
        return 1;
    }
    struct sigaction action = {.sa_handler = signal_stop};
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    uint64_t last_inspection = 0;
    int result = 0;
    while (!stopping) {
        uint64_t now = monotonic_ns();
        if (!now || renew_lease()) {
            result = 1;
            break;
        }
        if (now - last_inspection >= 1000000000ULL) {
            last_inspection = now;
            if (validate_links()) {
                control.enabled = control.enabled ? 2 : 0;
                control.lease_ns = 0;
                write_control();
                result = 1;
                break;
            }
        }
        struct pollfd status = {.fd = listener, .events = POLLIN};
        int ready = poll(&status, 1, 250);
        if (ready < 0 && errno != EINTR) {
            result = 1;
            break;
        }
        if (ready > 0 && (status.revents & POLLIN))
            handle_client(listener);
    }
    control.lease_ns = 0;
    write_control();
    close(listener);
    unlink(CONTROL_SOCKET);
    close(lock);
    return result;
}

static int client_main(void)
{
    if (!protected_path(RUNTIME, true, 0700))
        return 1;
    struct stat status;
    if (lstat(CONTROL_SOCKET, &status) || !S_ISSOCK(status.st_mode) || status.st_uid != 0 ||
        (status.st_mode & 0777) != 0600)
        return 1;
    char input[COMMAND_MAX + 1];
    struct command command;
    if (read_line(STDIN_FILENO, input, sizeof(input), 5000) || parse_command(input, &command))
        return 2;
    int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0)
        return 1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, CONTROL_SOCKET, sizeof(CONTROL_SOCKET));
    struct timeval timeout = {.tv_sec = 2};
    if (setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ||
        connect(descriptor, (struct sockaddr *)&address, sizeof(address)) || !root_peer(descriptor) ||
        send_all(descriptor, input, strlen(input))) {
        close(descriptor);
        return 1;
    }
    char *response = malloc(RESPONSE_MAX + 1);
    if (!response) {
        close(descriptor);
        return 1;
    }
    int result = read_line(descriptor, response, RESPONSE_MAX + 1, 5000);
    if (!result && fputs(response, stdout) < 0)
        result = -1;
    free(response);
    close(descriptor);
    return result ? 1 : 0;
}

static int self_test(void)
{
    struct command command;
    if (parse_command("{\"action\":\"snapshot\"}\n", &command) ||
        parse_command("{\"request_id\":\"0123456789abcdef0123456789abcdef\",\"action\":\"allow\",\"generation\":\"fedcba9876543210fedcba9876543210\"}", &command))
        return 1;
    const char *invalid[] = {
        "{}", "{\"action\":\"snapshot\",\"action\":\"enable\"}",
        "{\"action\":\"allow\"}", "{\"action\":\"enable\"} trailing",
        "{\"action\":\"unknown\"}", "{\"action\":\"snapshot\",\"extra\":\"x\"}",
        "{\"action\":\"snapshot\",}", "{\"action\":\"snapshot\\u0000\"}",
        "{\"action\":\"allow\",\"generation\":\"00000000000000000000000000000000\",\"request_id\":\"x\"}"
    };
    for (size_t index = 0; index < ARRAY_SIZE(invalid); index++)
        if (!parse_command(invalid[index], &command))
            return 1;
    if (new_token(generation) || !hex_token(generation))
        return 1;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--self-test"))
        return self_test();
    if (getuid() != 0 || geteuid() != 0 || argc != 2)
        return 2;
    if (!strcmp(argv[1], "daemon"))
        return daemon_main();
    if (!strcmp(argv[1], "client"))
        return client_main();
    return 2;
}
