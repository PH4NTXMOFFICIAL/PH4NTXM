#define _GNU_SOURCE

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "packet-transformation-engine-shared.h"

#ifndef PH4NTXM_PACKET_TRANSFORMATION_ENGINE_EBPF_OBJECT
#define PH4NTXM_PACKET_TRANSFORMATION_ENGINE_EBPF_OBJECT "/usr/lib/ph4ntxm/packet-transformation-engine.bpf.o"
#endif

#define PACKET_TRANSFORMATION_ENGINE_TC_HANDLE 1U
#define PACKET_TRANSFORMATION_ENGINE_TC_PRIORITY 1U

struct program_identity {
    __u32 id;
    __u8 tag[BPF_TAG_SIZE];
};

static int print_loaded_identity(int program_fd,
                                 const struct ph4ntxm_packet_transformation_engine_guard_config *config)
{
    struct bpf_prog_info program_info = {};
    __u32 program_info_length = sizeof(program_info);

    if (bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_length) != 0)
        return -1;
    if (program_info.id == 0 || program_info.type != BPF_PROG_TYPE_SCHED_CLS ||
        strncmp((const char *)program_info.name, "ph4ntxm_guard",
                sizeof(program_info.name)) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (printf("PROGRAM_ID=%u\nPROGRAM_TAG=", program_info.id) < 0)
        return -1;
    for (size_t index = 0; index < sizeof(program_info.tag); index++) {
        if (printf("%02x", program_info.tag[index]) < 0)
            return -1;
    }
    if (printf("\nIFINDEX=%u\nMODE=%u\nMAC=", config->ifindex,
               (unsigned int)config->mode) < 0)
        return -1;
    for (size_t index = 0; index < sizeof(config->mac); index++) {
        if (printf("%02x", config->mac[index]) < 0)
            return -1;
    }
    if (printf("\nHOSTNAME=%.*s\n", (int)config->hostname_length,
               (const char *)config->hostname) < 0 || fflush(stdout) != 0)
        return -1;
    return 0;
}

static int read_text(const char *path, char *output, size_t capacity)
{
    struct stat metadata;
    int flags = O_RDONLY | O_CLOEXEC;
    int descriptor;
    size_t length;

#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    descriptor = open(path, flags);
    if (descriptor < 0)
        return -1;
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid != 0 || (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(descriptor);
        errno = EPERM;
        return -1;
    }
    if (metadata.st_size <= 0 || (uintmax_t)metadata.st_size >= capacity) {
        close(descriptor);
        errno = EOVERFLOW;
        return -1;
    }
    length = 0;
    while (length < (size_t)metadata.st_size) {
        ssize_t result = read(descriptor, output + length,
                              (size_t)metadata.st_size - length);

        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0) {
            int saved_errno = result == 0 ? EIO : errno;

            close(descriptor);
            errno = saved_errno;
            return -1;
        }
        length += (size_t)result;
    }
    {
        char extra;
        ssize_t trailing;
        int saved_errno;

        do {
            trailing = read(descriptor, &extra, sizeof(extra));
        } while (trailing < 0 && errno == EINTR);
        saved_errno = errno;
        close(descriptor);
        if (trailing != 0) {
            errno = trailing < 0 ? saved_errno : EFBIG;
            return -1;
        }
    }
    if (memchr(output, '\0', length) != NULL) {
        errno = EINVAL;
        return -1;
    }
    if (length < 2 || output[length - 1] != '\n' ||
        memchr(output, '\n', length - 1) != NULL ||
        memchr(output, '\r', length - 1) != NULL) {
        errno = EINVAL;
        return -1;
    }
    output[length - 1] = '\0';
    return 0;
}

static int current_config(const char *interface, struct ph4ntxm_packet_transformation_engine_guard_config *config)
{
    struct ifreq request = {};
    char hostname[PH4NTXM_PACKET_TRANSFORMATION_ENGINE_HOSTNAME_MAX + 2];
    char mode[32];
    size_t hostname_length;
    unsigned int ifindex;
    int descriptor;

    ifindex = if_nametoindex(interface);
    if (ifindex == 0 || read_text("/run/ph4ntxm/mode", mode, sizeof(mode)) != 0 ||
        read_text("/etc/hostname", hostname, sizeof(hostname)) != 0)
        return -1;
    hostname_length = strlen(hostname);
    if (hostname_length == 0 || hostname_length > PH4NTXM_PACKET_TRANSFORMATION_ENGINE_HOSTNAME_MAX ||
        hostname[0] == '-' || hostname[hostname_length - 1] == '-') {
        errno = EINVAL;
        return -1;
    }
    for (size_t index = 0; index < hostname_length; index++) {
        char value = hostname[index];

        if (!((value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') ||
              value == '-')) {
            errno = EINVAL;
            return -1;
        }
    }
    memset(config, 0, sizeof(*config));
    config->magic = PH4NTXM_PACKET_TRANSFORMATION_ENGINE_CONFIG_MAGIC;
    config->ifindex = ifindex;
    if (strcmp(mode, "linux") == 0)
        config->mode = PH4NTXM_PACKET_TRANSFORMATION_ENGINE_MODE_LINUX;
    else if (strcmp(mode, "windows") == 0)
        config->mode = PH4NTXM_PACKET_TRANSFORMATION_ENGINE_MODE_WINDOWS;
    else {
        errno = EINVAL;
        return -1;
    }
    descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0)
        return -1;
    memcpy(request.ifr_name, interface, strlen(interface) + 1);
    if (ioctl(descriptor, SIOCGIFHWADDR, &request) != 0 ||
        request.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        int saved_errno = errno == 0 ? EPROTONOSUPPORT : errno;

        close(descriptor);
        errno = saved_errno;
        return -1;
    }
    memcpy(config->mac, request.ifr_hwaddr.sa_data, sizeof(config->mac));
    config->hostname_length = (__u8)hostname_length;
    memcpy(config->hostname, hostname, hostname_length);
    close(descriptor);
    return 0;
}

static struct bpf_map *find_rodata(struct bpf_object *object)
{
    struct bpf_map *map;

    bpf_object__for_each_map(map, object) {
        const char *name = bpf_map__name(map);

        if (name != NULL && strcmp(name, ".rodata.ph4ntxm") == 0)
            return map;
    }
    return NULL;
}

static int attach_program(const char *interface)
{
    struct ph4ntxm_packet_transformation_engine_guard_config config;
    struct bpf_object_open_opts open_options = {};
    struct bpf_tc_hook hook = {};
    struct bpf_tc_opts tc_options = {};
    struct bpf_object *object = NULL;
    struct bpf_program *program;
    struct bpf_map *rodata;
    const char *stage;
    int error = -1;
    int saved_errno;

    if (current_config(interface, &config) != 0) {
        fprintf(stderr, "ph4ntxm-packet-transformation-engine-loader: failed to read interface configuration\n");
        return -1;
    }
    open_options.sz = sizeof(open_options);
    stage = "open eBPF object";
    object = bpf_object__open_file(PH4NTXM_PACKET_TRANSFORMATION_ENGINE_EBPF_OBJECT, &open_options);
    error = libbpf_get_error(object);
    if (error != 0) {
        object = NULL;
        errno = -error;
        goto out;
    }
    rodata = find_rodata(object);
    program = bpf_object__find_program_by_name(object, "ph4ntxm_guard");
    stage = "initialize and load eBPF object";
    if (rodata == NULL || program == NULL ||
        bpf_map__set_initial_value(rodata, &config, sizeof(config)) != 0 ||
        bpf_object__load(object) != 0) {
        error = -1;
        errno = EINVAL;
        goto out;
    }
    hook.sz = sizeof(hook);
    hook.ifindex = (int)config.ifindex;
    hook.attach_point = BPF_TC_EGRESS;
    tc_options.sz = sizeof(tc_options);
    tc_options.handle = PACKET_TRANSFORMATION_ENGINE_TC_HANDLE;
    tc_options.priority = PACKET_TRANSFORMATION_ENGINE_TC_PRIORITY;
    tc_options.prog_fd = bpf_program__fd(program);
    stage = "attach Packet Transformation Engine filter";
    error = bpf_tc_attach(&hook, &tc_options);
    if (error == -EEXIST) {
        tc_options.flags = BPF_TC_F_REPLACE;
        stage = "replace Packet Transformation Engine filter";
        error = bpf_tc_attach(&hook, &tc_options);
    }
    if (error != 0) {
        errno = -error;
        goto out;
    }
    stage = "report attached program identity";
    if (print_loaded_identity(bpf_program__fd(program), &config) != 0) {
        error = -1;
        goto out;
    }
    error = 0;
out:
    saved_errno = errno;
    if (error != 0)
        fprintf(stderr, "ph4ntxm-packet-transformation-engine-loader: failed to %s\n", stage);
    bpf_object__close(object);
    errno = saved_errno;
    return error;
}

static int read_attached_config(__u32 program_id,
                                struct ph4ntxm_packet_transformation_engine_guard_config *attached,
                                struct program_identity *identity)
{
    struct bpf_prog_info program_info = {};
    __u32 program_info_length = sizeof(program_info);
    __u32 map_ids[8] = {};
    const char *stage = "open attached program";
    int program_fd = -1;
    int result = -1;
    int saved_errno;

    program_fd = bpf_prog_get_fd_by_id(program_id);
    if (program_fd < 0)
        goto out;
    stage = "read attached program metadata";
    program_info.nr_map_ids = sizeof(map_ids) / sizeof(map_ids[0]);
    program_info.map_ids = (__u64)(uintptr_t)map_ids;
    if (bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_length) != 0)
        goto out;
    stage = "validate attached program metadata";
    if (program_info.type != BPF_PROG_TYPE_SCHED_CLS ||
        strncmp((const char *)program_info.name, "ph4ntxm_guard",
                sizeof(program_info.name)) != 0 ||
        program_info.nr_map_ids == 0 || program_info.nr_map_ids > 8) {
        errno = EINVAL;
        goto out;
    }
    stage = "read attached immutable configuration";
    for (__u32 index = 0; index < program_info.nr_map_ids; index++) {
        struct bpf_map_info map_info = {};
        __u32 map_info_length = sizeof(map_info);
        __u32 key = 0;
        int map_fd = bpf_map_get_fd_by_id(map_ids[index]);

        if (map_fd < 0)
            continue;
        if (bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_length) == 0 &&
            map_info.type == BPF_MAP_TYPE_ARRAY && map_info.key_size == sizeof(key) &&
            map_info.value_size == sizeof(*attached) && map_info.max_entries == 1 &&
            (map_info.map_flags & BPF_F_RDONLY_PROG) != 0 &&
            bpf_map_lookup_elem(map_fd, &key, attached) == 0) {
            close(map_fd);
            result = 0;
            break;
        }
        close(map_fd);
    }
    if (result != 0)
        errno = EINVAL;
    else if (identity != NULL) {
        identity->id = program_info.id;
        memcpy(identity->tag, program_info.tag, sizeof(identity->tag));
    }
out:
    saved_errno = errno;
    if (result != 0)
        fprintf(stderr, "ph4ntxm-packet-transformation-engine-loader: failed to %s\n", stage);
    if (program_fd >= 0)
        close(program_fd);
    errno = saved_errno;
    return result;
}

static int read_verified_program(const char *interface, struct program_identity *identity)
{
    struct ph4ntxm_packet_transformation_engine_guard_config expected;
    struct ph4ntxm_packet_transformation_engine_guard_config attached = {};
    struct bpf_tc_hook hook = {};
    struct bpf_tc_opts tc_options = {};
    int error;

    if (current_config(interface, &expected) != 0)
        return -1;
    hook.sz = sizeof(hook);
    hook.ifindex = (int)expected.ifindex;
    hook.attach_point = BPF_TC_EGRESS;
    tc_options.sz = sizeof(tc_options);
    tc_options.handle = PACKET_TRANSFORMATION_ENGINE_TC_HANDLE;
    tc_options.priority = PACKET_TRANSFORMATION_ENGINE_TC_PRIORITY;
    error = bpf_tc_query(&hook, &tc_options);
    if (error != 0) {
        errno = -error;
        fprintf(stderr, "ph4ntxm-packet-transformation-engine-loader: failed to query Packet Transformation Engine filter\n");
        return -1;
    }
    if (tc_options.prog_id == 0 ||
        read_attached_config(tc_options.prog_id, &attached, identity) != 0) {
        if (errno == 0)
            errno = EINVAL;
        return -1;
    }
    if (memcmp(&attached, &expected, sizeof(expected)) != 0) {
        errno = EINVAL;
        fprintf(stderr, "ph4ntxm-packet-transformation-engine-loader: attached configuration mismatch\n");
        return -1;
    }
    return 0;
}

static int verify_program(const char *interface)
{
    return read_verified_program(interface, NULL);
}

static int print_program_identity(const char *interface)
{
    struct program_identity identity = {};

    if (read_verified_program(interface, &identity) != 0)
        return -1;
    printf("PROGRAM_ID=%u\nPROGRAM_TAG=", identity.id);
    for (size_t index = 0; index < sizeof(identity.tag); index++)
        printf("%02x", identity.tag[index]);
    putchar('\n');
    return 0;
}

static int print_drop_counters(const char *interface)
{
    static const char *const names[PACKET_TRANSFORMATION_ENGINE_DROP_REASON_COUNT] = {
        "configuration", "source_mac", "vlan", "marked_layout", "unexpected_mark",
        "arp_layout", "arp_header", "arp_source", "arp_target", "eapol", "raw_ip",
        "other_protocol", "dhcp_ipv4", "dhcp_udp", "dhcp_bootp", "dhcp_client",
        "dhcp_reserved", "dhcp_addresses", "dhcp_options", "dhcp_route", "dhcp_store",
        "dhcp_ipv4_layout", "dhcp_ipv4_checksum",
    };
    struct ph4ntxm_packet_transformation_engine_guard_config expected;
    struct bpf_prog_info program_info = {};
    __u32 program_info_length = sizeof(program_info);
    __u32 map_ids[8] = {};
    struct bpf_tc_hook hook = {};
    struct bpf_tc_opts tc_options = {};
    int program_fd = -1;
    int result = -1;
    int saved_errno;
    int error;

    if (current_config(interface, &expected) != 0)
        return -1;
    hook.sz = sizeof(hook);
    hook.ifindex = (int)expected.ifindex;
    hook.attach_point = BPF_TC_EGRESS;
    tc_options.sz = sizeof(tc_options);
    tc_options.handle = PACKET_TRANSFORMATION_ENGINE_TC_HANDLE;
    tc_options.priority = PACKET_TRANSFORMATION_ENGINE_TC_PRIORITY;
    error = bpf_tc_query(&hook, &tc_options);
    if (error != 0 || tc_options.prog_id == 0) {
        errno = error == 0 ? ENOENT : -error;
        return -1;
    }
    program_fd = bpf_prog_get_fd_by_id(tc_options.prog_id);
    if (program_fd < 0)
        return -1;
    program_info.nr_map_ids = sizeof(map_ids) / sizeof(map_ids[0]);
    program_info.map_ids = (__u64)(uintptr_t)map_ids;
    if (bpf_obj_get_info_by_fd(program_fd, &program_info, &program_info_length) != 0)
        goto out;
    for (__u32 map_index = 0; map_index < program_info.nr_map_ids; map_index++) {
        struct bpf_map_info map_info = {};
        __u32 map_info_length = sizeof(map_info);
        int map_fd = bpf_map_get_fd_by_id(map_ids[map_index]);

        if (map_fd < 0)
            continue;
        if (bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_length) == 0 &&
            map_info.type == BPF_MAP_TYPE_ARRAY && map_info.key_size == sizeof(__u32) &&
            map_info.value_size == sizeof(__u64) &&
            map_info.max_entries == PACKET_TRANSFORMATION_ENGINE_DROP_REASON_COUNT &&
            strncmp((const char *)map_info.name, "ph4ntxm_drops", sizeof(map_info.name)) == 0) {
            for (__u32 reason = 0; reason < PACKET_TRANSFORMATION_ENGINE_DROP_REASON_COUNT; reason++) {
                __u64 value;

                if (bpf_map_lookup_elem(map_fd, &reason, &value) != 0) {
                    close(map_fd);
                    goto out;
                }
                printf("%s=%llu\n", names[reason], (unsigned long long)value);
            }
            close(map_fd);
            result = 0;
            continue;
        }
        close(map_fd);
    }
    if (result != 0)
        errno = ENOENT;
out:
    saved_errno = errno;
    close(program_fd);
    errno = saved_errno;
    return result;
}

int main(int argc, char **argv)
{
    struct rlimit core_limit = {.rlim_cur = 0, .rlim_max = 0};

    if (argc == 2 && strcmp(argv[1], "--self-test") == 0)
        return sizeof(struct ph4ntxm_packet_transformation_engine_guard_config) == 48 ? EXIT_SUCCESS : EXIT_FAILURE;
    if (argc != 3 || (strcmp(argv[1], "attach") != 0 && strcmp(argv[1], "verify") != 0 &&
                      strcmp(argv[1], "identity") != 0 && strcmp(argv[1], "stats") != 0) ||
        strlen(argv[2]) == 0 || strlen(argv[2]) >= IFNAMSIZ || strchr(argv[2], '/') != NULL ||
        setrlimit(RLIMIT_CORE, &core_limit) != 0) {
        fprintf(stderr, "usage: %s {attach|verify|identity|stats} INTERFACE\n", argv[0]);
        return EXIT_FAILURE;
    }
    int result = strcmp(argv[1], "attach") == 0 ? attach_program(argv[2]) :
                 strcmp(argv[1], "verify") == 0 ? verify_program(argv[2]) :
                 strcmp(argv[1], "identity") == 0 ? print_program_identity(argv[2]) :
                 print_drop_counters(argv[2]);

    if (result != 0) {
        perror("ph4ntxm-packet-transformation-engine-loader");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
