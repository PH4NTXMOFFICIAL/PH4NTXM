#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define INBOUND_QUEUE 1U
#define OUTBOUND_QUEUE 2U
#define QUEUE_LENGTH 4096U
#define REQUESTED_COPY_RANGE 65535U
#define EFFECTIVE_COPY_RANGE 65531U
#define MAX_IP_PACKET_LENGTH 65535U
#define PROVENANCE_MARK 0x50544531U
#define RECEIVE_BUFFER_SIZE (1024U * 1024U)
#define ERROR_BUFFER_SIZE 192U
#define HEALTH_INTERVAL_SECONDS 5U
#define MAINTENANCE_INTERVAL_SECONDS 15U
#define ERROR_LOG_INTERVAL_SECONDS 30U

struct Engine;

extern struct Engine *ph4ntxm_packet_transformation_engine_new(uint8_t mode, const uint8_t *seed, size_t seed_length);
extern void ph4ntxm_packet_transformation_engine_free(struct Engine *engine);
extern int32_t ph4ntxm_packet_transformation_engine_process(struct Engine *engine, const uint8_t *input, size_t input_length,
                                  uint8_t outbound, uint32_t interface, uint8_t checksum_not_ready,
                                  uint8_t *output, size_t output_capacity, size_t *output_length,
                                  uint8_t *error, size_t error_capacity);
extern int32_t ph4ntxm_packet_transformation_engine_maintenance(struct Engine *engine);
extern int32_t ph4ntxm_packet_transformation_engine_self_test(void);

struct packet_metadata {
    bool valid;
    uint16_t queue_number;
    uint32_t packet_id;
    uint16_t hardware_protocol;
    uint8_t hook;
    uint32_t original_length;
    uint32_t captured_length;
    uint32_t skb_info;
};

struct runtime;

struct queue_context {
    struct runtime *runtime;
    uint16_t queue_number;
    bool outbound;
};

struct runtime {
    struct nfq_handle *handle;
    struct nfq_q_handle *inbound_handle;
    struct nfq_q_handle *outbound_handle;
    struct Engine *engine;
    struct queue_context inbound;
    struct queue_context outbound;
    struct packet_metadata current;
    uint8_t *receive_buffer;
    uint8_t *output_buffer;
    uint32_t netlink_port_id;
    uint64_t last_error_log;
};

static uint64_t monotonic_seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec;
}

static void log_drop(struct runtime *runtime, const char *message) {
    uint64_t now = monotonic_seconds();
    if (now >= runtime->last_error_log && now - runtime->last_error_log < ERROR_LOG_INTERVAL_SECONDS) {
        return;
    }
    runtime->last_error_log = now;
    fprintf(stderr, "ph4ntxm-packet-transformation-engine-native: packet dropped: %.160s\n", message);
}

static int secure_read_ascii(const char *path, char *output, size_t capacity) {
    int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int descriptor = open(path, flags);
    if (descriptor < 0) {
        return -1;
    }
    struct stat metadata;
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_uid != 0 ||
        (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(descriptor);
        errno = EPERM;
        return -1;
    }
    if (metadata.st_size <= 0 || (uintmax_t)metadata.st_size >= capacity) {
        close(descriptor);
        errno = EOVERFLOW;
        return -1;
    }
    size_t expected = (size_t)metadata.st_size;
    size_t length = 0;
    while (length < expected) {
        ssize_t result = read(descriptor, output + length, expected - length);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            int saved_errno = result == 0 ? EIO : errno;
            close(descriptor);
            errno = saved_errno;
            return -1;
        }
        length += (size_t)result;
    }
    char extra;
    ssize_t trailing;
    do {
        trailing = read(descriptor, &extra, sizeof(extra));
    } while (trailing < 0 && errno == EINTR);
    int saved_errno = errno;
    close(descriptor);
    if (trailing != 0) {
        errno = trailing < 0 ? saved_errno : EFBIG;
        return -1;
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

static int decode_seed(const char *encoded, uint8_t seed[32]) {
    if (strlen(encoded) != 64) {
        return -1;
    }
    for (size_t index = 0; index < 32; index++) {
        unsigned int high = (unsigned char)encoded[index * 2];
        unsigned int low = (unsigned char)encoded[index * 2 + 1];
        if (high >= '0' && high <= '9') {
            high -= '0';
        } else if (high >= 'a' && high <= 'f') {
            high = high - 'a' + 10;
        } else {
            return -1;
        }
        if (low >= '0' && low <= '9') {
            low -= '0';
        } else if (low >= 'a' && low <= 'f') {
            low = low - 'a' + 10;
        } else {
            return -1;
        }
        seed[index] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

static int send_drop(struct nfq_q_handle *queue, uint32_t packet_id) {
    return nfq_set_verdict(queue, packet_id, NF_DROP, 0, NULL);
}

static int packet_callback(struct nfq_q_handle *queue, struct nfgenmsg *message, struct nfq_data *data, void *opaque) {
    (void)message;
    struct queue_context *context = opaque;
    struct runtime *runtime = context->runtime;
    struct nfqnl_msg_packet_hdr *header = nfq_get_msg_packet_hdr(data);
    if (header == NULL) {
        fprintf(stderr, "ph4ntxm-packet-transformation-engine-native: missing NFQUEUE packet header\n");
        return -1;
    }
    uint32_t packet_id = ntohl(header->packet_id);
    struct packet_metadata *metadata = &runtime->current;
    if (!metadata->valid || metadata->queue_number != context->queue_number || metadata->packet_id != packet_id ||
        metadata->hardware_protocol != ntohs(header->hw_protocol) || metadata->hook != header->hook) {
        fprintf(stderr,
                "ph4ntxm-packet-transformation-engine-native: NFQUEUE callback metadata mismatch "
                "valid=%u queue=%u/%u id=%u/%u protocol=%u/%u hook=%u/%u\n",
                metadata->valid ? 1U : 0U, metadata->queue_number, context->queue_number,
                metadata->packet_id, packet_id, metadata->hardware_protocol,
                ntohs(header->hw_protocol), metadata->hook, header->hook);
        (void)send_drop(queue, packet_id);
        return -1;
    }
    unsigned char *payload = NULL;
    int payload_length = nfq_get_payload(data, &payload);
    const char *drop_reason = NULL;
    bool fatal = false;
    if (payload_length <= 0 || payload == NULL || (uint32_t)payload_length != metadata->captured_length) {
        drop_reason = "invalid NFQUEUE payload";
        fatal = true;
    } else if (metadata->original_length != metadata->captured_length) {
        drop_reason = "truncated NFQUEUE payload";
    } else if ((metadata->skb_info & NFQA_SKB_GSO) != 0) {
        drop_reason = "unexpected GSO super-packet";
    } else if ((metadata->skb_info & ~(NFQA_SKB_CSUMNOTREADY | NFQA_SKB_GSO | NFQA_SKB_CSUM_NOTVERIFIED)) != 0) {
        drop_reason = "unknown NFQUEUE skb metadata";
    } else {
        uint8_t version = payload[0] >> 4;
        uint16_t expected_protocol = version == 4 ? ETH_P_IP : version == 6 ? ETH_P_IPV6 : 0;
        uint8_t expected_hook = context->outbound ? NF_INET_LOCAL_OUT : NF_INET_PRE_ROUTING;
        if (expected_protocol == 0 || metadata->hardware_protocol != expected_protocol) {
            drop_reason = "NFQUEUE protocol mismatch";
        } else if (metadata->hook != expected_hook) {
            drop_reason = "unexpected NFQUEUE hook";
        }
    }
    size_t output_length = 0;
    uint8_t error[ERROR_BUFFER_SIZE] = {0};
    if (drop_reason == NULL) {
        uint32_t interface = context->outbound ? nfq_get_outdev(data) : nfq_get_indev(data);
        int32_t result = ph4ntxm_packet_transformation_engine_process(
            runtime->engine, payload, (size_t)payload_length, context->outbound ? 1 : 0, interface,
            (metadata->skb_info & NFQA_SKB_CSUMNOTREADY) != 0 ? 1 : 0, runtime->output_buffer,
            MAX_IP_PACKET_LENGTH,
            &output_length, error, sizeof(error));
        if (result == 1) {
            if (output_length == 0 || output_length > MAX_IP_PACKET_LENGTH ||
                nfq_set_verdict2(queue, packet_id, NF_ACCEPT, PROVENANCE_MARK,
                                 (uint32_t)output_length, runtime->output_buffer) < 0) {
                (void)send_drop(queue, packet_id);
                return -1;
            }
            return 0;
        }
        drop_reason = error[0] == 0 ? "native core rejected packet" : (const char *)error;
        fatal = result < 0;
    }
    if (send_drop(queue, packet_id) < 0) {
        return -1;
    }
    log_drop(runtime, drop_reason);
    return fatal ? -1 : 0;
}

static int extract_metadata(const struct nlmsghdr *netlink_header, struct packet_metadata *metadata) {
    memset(metadata, 0, sizeof(*metadata));
    if (netlink_header->nlmsg_type != ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET)) {
        fprintf(stderr,
                "ph4ntxm-packet-transformation-engine-native: unexpected netlink message "
                "type=%u flags=%u length=%u\n",
                netlink_header->nlmsg_type, netlink_header->nlmsg_flags,
                netlink_header->nlmsg_len);
        errno = EPROTO;
        return -1;
    }
    struct nlattr *attributes[NFQA_MAX + 1] = {0};
    if (nfq_nlmsg_parse(netlink_header, attributes) < 0 || attributes[NFQA_PACKET_HDR] == NULL ||
        attributes[NFQA_PAYLOAD] == NULL) {
        fprintf(stderr,
                "ph4ntxm-packet-transformation-engine-native: incomplete NFQUEUE packet "
                "attributes header=%u payload=%u\n",
                attributes[NFQA_PACKET_HDR] != NULL ? 1U : 0U,
                attributes[NFQA_PAYLOAD] != NULL ? 1U : 0U);
        errno = EPROTO;
        return -1;
    }
    const struct nfgenmsg *nfgen = mnl_nlmsg_get_payload(netlink_header);
    const struct nfqnl_msg_packet_hdr *packet_header = mnl_attr_get_payload(attributes[NFQA_PACKET_HDR]);
    uint32_t captured_length = mnl_attr_get_payload_len(attributes[NFQA_PAYLOAD]);
    uint32_t original_length = attributes[NFQA_CAP_LEN] == NULL
                                   ? captured_length
                                   : ntohl(mnl_attr_get_u32(attributes[NFQA_CAP_LEN]));
    metadata->valid = true;
    metadata->queue_number = ntohs(nfgen->res_id);
    metadata->packet_id = ntohl(packet_header->packet_id);
    metadata->hardware_protocol = ntohs(packet_header->hw_protocol);
    metadata->hook = packet_header->hook;
    metadata->original_length = original_length;
    metadata->captured_length = captured_length;
    metadata->skb_info = attributes[NFQA_SKB_INFO] == NULL
                             ? 0
                             : ntohl(mnl_attr_get_u32(attributes[NFQA_SKB_INFO]));
    return 0;
}

static int configure_queue(struct nfq_q_handle *queue) {
    uint32_t mask = NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO;
    if (nfq_set_queue_flags(queue, mask, 0) < 0 ||
        nfq_set_mode(queue, NFQNL_COPY_PACKET, REQUESTED_COPY_RANGE) < 0 ||
        nfq_set_queue_maxlen(queue, QUEUE_LENGTH) < 0) {
        return -1;
    }
    return 0;
}

static int verify_queue_bindings(uint32_t expected_port_id) {
    FILE *status = fopen("/proc/net/netfilter/nfnetlink_queue", "re");
    if (status == NULL) {
        return -1;
    }
    bool inbound = false;
    bool outbound = false;
    char line[512];
    while (fgets(line, sizeof(line), status) != NULL) {
        unsigned int queue_number = 0;
        unsigned int port_id = 0;
        unsigned int queued = 0;
        unsigned int copy_mode = 0;
        unsigned int copy_range = 0;
        unsigned long long queue_dropped = 0;
        unsigned long long userspace_dropped = 0;
        unsigned long long sequence = 0;
        unsigned int format_sentinel = 0;
        int fields = sscanf(line, "%u %u %u %u %u %llu %llu %llu %u", &queue_number, &port_id, &queued,
                            &copy_mode, &copy_range, &queue_dropped, &userspace_dropped, &sequence,
                            &format_sentinel);
        (void)queued;
        (void)sequence;
        if (fields < 9) {
            fclose(status);
            errno = EPROTO;
            return -1;
        }
        if (queue_number == INBOUND_QUEUE || queue_number == OUTBOUND_QUEUE) {
            if (port_id != expected_port_id || copy_mode != NFQNL_COPY_PACKET ||
                copy_range < EFFECTIVE_COPY_RANGE ||
                queue_dropped != 0 || userspace_dropped != 0 || format_sentinel != 1) {
                fprintf(stderr,
                        "ph4ntxm-packet-transformation-engine-native: unsafe NFQUEUE %u status "
                        "owner=%u expected-owner=%u mode=%u range=%u kernel-drops=%llu userspace-drops=%llu "
                        "format-sentinel=%u\n",
                        queue_number, port_id, expected_port_id, copy_mode, copy_range, queue_dropped,
                        userspace_dropped, format_sentinel);
                fclose(status);
                errno = EIO;
                return -1;
            }
            if (queue_number == INBOUND_QUEUE) {
                if (inbound) {
                    fclose(status);
                    errno = EEXIST;
                    return -1;
                }
                inbound = true;
            } else {
                if (outbound) {
                    fclose(status);
                    errno = EEXIST;
                    return -1;
                }
                outbound = true;
            }
        }
    }
    if (ferror(status) != 0) {
        fclose(status);
        return -1;
    }
    fclose(status);
    if (!inbound || !outbound) {
        errno = ENOENT;
        return -1;
    }
    return 0;
}

static int notify_systemd(const char *message) {
    const char *address = getenv("NOTIFY_SOCKET");
    if (address == NULL || message == NULL || (address[0] != '/' && address[0] != '@')) {
        errno = ENOENT;
        return -1;
    }
    struct sockaddr_un destination;
    memset(&destination, 0, sizeof(destination));
    destination.sun_family = AF_UNIX;
    size_t length = strlen(address);
    if (length >= sizeof(destination.sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if (address[0] == '@') {
        destination.sun_path[0] = '\0';
        memcpy(destination.sun_path + 1, address + 1, length - 1);
    } else {
        memcpy(destination.sun_path, address, length + 1);
    }
    int descriptor = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        return -1;
    }
    socklen_t destination_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + length +
                                               (address[0] == '@' ? 0 : 1));
    int result = sendto(descriptor, message, strlen(message), MSG_NOSIGNAL,
                        (const struct sockaddr *)&destination, destination_length) < 0
                     ? -1
                     : 0;
    int saved_errno = errno;
    close(descriptor);
    errno = saved_errno;
    return result;
}

static int notify_ready(void) {
    return notify_systemd("READY=1\nSTATUS=Native NFQUEUE packet transformation active");
}

static void destroy_runtime(struct runtime *runtime) {
    if (runtime->inbound_handle != NULL) {
        nfq_destroy_queue(runtime->inbound_handle);
    }
    if (runtime->outbound_handle != NULL) {
        nfq_destroy_queue(runtime->outbound_handle);
    }
    if (runtime->handle != NULL) {
        nfq_close(runtime->handle);
    }
    ph4ntxm_packet_transformation_engine_free(runtime->engine);
    free(runtime->receive_buffer);
    free(runtime->output_buffer);
    memset(runtime, 0, sizeof(*runtime));
}

static int initialize_runtime(struct runtime *runtime, uint8_t mode, const uint8_t seed[32]) {
    memset(runtime, 0, sizeof(*runtime));
    runtime->receive_buffer = malloc(RECEIVE_BUFFER_SIZE);
    runtime->output_buffer = malloc(MAX_IP_PACKET_LENGTH);
    runtime->engine = ph4ntxm_packet_transformation_engine_new(mode, seed, 32);
    runtime->handle = nfq_open();
    if (runtime->receive_buffer == NULL || runtime->output_buffer == NULL || runtime->engine == NULL ||
        runtime->handle == NULL) {
        return -1;
    }
    runtime->inbound = (struct queue_context){.runtime = runtime, .queue_number = INBOUND_QUEUE, .outbound = false};
    runtime->outbound = (struct queue_context){.runtime = runtime, .queue_number = OUTBOUND_QUEUE, .outbound = true};
    runtime->inbound_handle = nfq_create_queue(runtime->handle, INBOUND_QUEUE, packet_callback, &runtime->inbound);
    runtime->outbound_handle = nfq_create_queue(runtime->handle, OUTBOUND_QUEUE, packet_callback, &runtime->outbound);
    if (runtime->inbound_handle == NULL || runtime->outbound_handle == NULL ||
        configure_queue(runtime->inbound_handle) != 0 || configure_queue(runtime->outbound_handle) != 0) {
        return -1;
    }
    int descriptor = nfq_fd(runtime->handle);
    if (descriptor < 0) {
        return -1;
    }
    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    socklen_t local_length = sizeof(local);
    if (getsockname(descriptor, (struct sockaddr *)&local, &local_length) != 0 || local.nl_family != AF_NETLINK ||
        local.nl_pid == 0) {
        return -1;
    }
    runtime->netlink_port_id = local.nl_pid;
    int socket_buffer = 8 * 1024 * 1024;
#ifdef SO_RCVBUFFORCE
    if (setsockopt(descriptor, SOL_SOCKET, SO_RCVBUFFORCE, &socket_buffer, sizeof(socket_buffer)) != 0) {
        return -1;
    }
#else
    if (setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &socket_buffer, sizeof(socket_buffer)) != 0) {
        return -1;
    }
#endif
    return verify_queue_bindings(runtime->netlink_port_id);
}

static int event_loop(struct runtime *runtime) {
    int descriptor = nfq_fd(runtime->handle);
    uint64_t last_health = monotonic_seconds();
    uint64_t last_maintenance = last_health;
    for (;;) {
        struct pollfd event = {.fd = descriptor, .events = POLLIN, .revents = 0};
        int ready = poll(&event, 1, 1000);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if ((event.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            errno = EIO;
            return -1;
        }
        if (ready > 0 && (event.revents & POLLIN) != 0) {
            struct iovec vector = {.iov_base = runtime->receive_buffer, .iov_len = RECEIVE_BUFFER_SIZE};
            struct msghdr message = {.msg_iov = &vector, .msg_iovlen = 1};
            ssize_t length = recvmsg(descriptor, &message, 0);
            if (length < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            if (length == 0 || (message.msg_flags & MSG_TRUNC) != 0) {
                errno = EMSGSIZE;
                return -1;
            }
            size_t remaining = (size_t)length;
            uint8_t *cursor = runtime->receive_buffer;
            while (remaining != 0) {
                if (remaining < sizeof(struct nlmsghdr)) {
                    fprintf(stderr,
                            "ph4ntxm-packet-transformation-engine-native: trailing netlink data "
                            "bytes=%zu\n",
                            remaining);
                    errno = EPROTO;
                    return -1;
                }
                struct nlmsghdr *header = (struct nlmsghdr *)cursor;
                size_t message_length = header->nlmsg_len;
                if (message_length < sizeof(struct nlmsghdr) || message_length > remaining) {
                    fprintf(stderr,
                            "ph4ntxm-packet-transformation-engine-native: invalid netlink length "
                            "message=%zu remaining=%zu\n",
                            message_length, remaining);
                    errno = EPROTO;
                    return -1;
                }
                if (extract_metadata(header, &runtime->current) != 0) {
                    return -1;
                }
                if (nfq_handle_packet(runtime->handle, (char *)header, (int)header->nlmsg_len) < 0) {
                    runtime->current.valid = false;
                    return -1;
                }
                runtime->current.valid = false;
                size_t aligned_length = NLMSG_ALIGN(message_length);
                size_t consumed = aligned_length <= remaining ? aligned_length : message_length;
                cursor += consumed;
                remaining -= consumed;
            }
        }
        uint64_t now = monotonic_seconds();
        if (now < last_health || now - last_health >= HEALTH_INTERVAL_SECONDS) {
            if (verify_queue_bindings(runtime->netlink_port_id) != 0 ||
                notify_systemd("WATCHDOG=1") != 0) {
                return -1;
            }
            last_health = now;
        }
        if (now < last_maintenance || now - last_maintenance >= MAINTENANCE_INTERVAL_SECONDS) {
            if (ph4ntxm_packet_transformation_engine_maintenance(runtime->engine) != 0) {
                errno = EFAULT;
                return -1;
            }
            last_maintenance = now;
        }
    }
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        return ph4ntxm_packet_transformation_engine_self_test() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--self-test]\n", argv[0]);
        return EXIT_FAILURE;
    }
    struct rlimit core_limit = {.rlim_cur = 0, .rlim_max = 0};
    if (setrlimit(RLIMIT_CORE, &core_limit) != 0 || prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||
        ph4ntxm_packet_transformation_engine_self_test() != 0) {
        perror("native Packet Transformation Engine hardening/self-test");
        return EXIT_FAILURE;
    }
    char mode_text[32];
    char seed_text[80];
    uint8_t seed[32];
    if (secure_read_ascii("/run/ph4ntxm/mode", mode_text, sizeof(mode_text)) != 0 ||
        secure_read_ascii("/run/ph4ntxm/persona_seed", seed_text, sizeof(seed_text)) != 0 ||
        decode_seed(seed_text, seed) != 0) {
        fprintf(stderr, "ph4ntxm-packet-transformation-engine-native: invalid required state\n");
        explicit_bzero(seed, sizeof(seed));
        explicit_bzero(seed_text, sizeof(seed_text));
        return EXIT_FAILURE;
    }
    uint8_t mode;
    if (strcmp(mode_text, "linux") == 0) {
        mode = 0;
    } else if (strcmp(mode_text, "windows") == 0) {
        mode = 1;
    } else {
        fprintf(stderr, "ph4ntxm-packet-transformation-engine-native: invalid mode\n");
        explicit_bzero(seed, sizeof(seed));
        explicit_bzero(seed_text, sizeof(seed_text));
        return EXIT_FAILURE;
    }
    struct runtime runtime;
    if (initialize_runtime(&runtime, mode, seed) != 0) {
        perror("ph4ntxm-packet-transformation-engine-native: initialization failed");
        explicit_bzero(seed, sizeof(seed));
        explicit_bzero(seed_text, sizeof(seed_text));
        destroy_runtime(&runtime);
        return EXIT_FAILURE;
    }
    explicit_bzero(seed, sizeof(seed));
    explicit_bzero(seed_text, sizeof(seed_text));
    if (notify_ready() != 0) {
        perror("ph4ntxm-packet-transformation-engine-native: readiness notification failed");
        destroy_runtime(&runtime);
        return EXIT_FAILURE;
    }
    int result = event_loop(&runtime);
    int saved_errno = errno;
    destroy_runtime(&runtime);
    errno = saved_errno;
    if (result != 0) {
        perror("ph4ntxm-packet-transformation-engine-native: fatal runtime failure");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
