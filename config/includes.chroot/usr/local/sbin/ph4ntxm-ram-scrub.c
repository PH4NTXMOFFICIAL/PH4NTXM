#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <unistd.h>

#define MIB ((size_t)1024 * 1024)
#define CHUNK_SIZE (8 * MIB)

struct block {
    void *address;
    size_t length;
};

static unsigned long long meminfo_kib(const char *name)
{
    FILE *stream = fopen("/proc/meminfo", "re");
    char key[64];
    unsigned long long value;
    char unit[16];

    if (stream == NULL)
        return 0;

    while (fscanf(stream, "%63s %llu %15s", key, &value, unit) == 3) {
        size_t length = strlen(key);
        if (length > 0 && key[length - 1] == ':')
            key[length - 1] = '\0';
        if (strcmp(key, name) == 0) {
            fclose(stream);
            return value;
        }
    }

    fclose(stream);
    return 0;
}

static void overwrite_block(void *address, size_t length, uint64_t seed)
{
    volatile uint64_t *words = address;
    size_t count = length / sizeof(*words);

    for (size_t index = 0; index < count; ++index) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        words[index] = seed;
    }

    explicit_bzero(address, length);
}

static int scrub_available_memory(void)
{
    unsigned long long available_kib = meminfo_kib("MemAvailable");
    unsigned long long reserve_kib = 128 * 1024;
    struct sysinfo information;
    size_t target;
    size_t count = 0;
    size_t allocated = 0;
    size_t capacity;
    struct block *blocks;

    if (available_kib == 0 && sysinfo(&information) == 0) {
        available_kib = ((unsigned long long)information.freeram *
                         (unsigned long long)information.mem_unit) / 1024;
    }

    if (available_kib <= reserve_kib)
        return 1;

    target = (size_t)(available_kib - reserve_kib) * 1024;
    capacity = target / CHUNK_SIZE + 2;
    blocks = calloc(capacity, sizeof(*blocks));
    if (blocks == NULL)
        return 1;

    (void)setpriority(PRIO_PROCESS, 0, 19);
    sync();

    while (allocated < target && count < capacity) {
        size_t length = target - allocated;
        if (length > CHUNK_SIZE)
            length = CHUNK_SIZE;

        void *address = mmap(NULL, length, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (address == MAP_FAILED)
            break;

        (void)madvise(address, length, MADV_DONTDUMP);
        overwrite_block(address, length,
                        (uint64_t)getpid() ^ (uint64_t)allocated ^
                        UINT64_C(0x9e3779b97f4a7c15));
        blocks[count].address = address;
        blocks[count].length = length;
        ++count;
        allocated += length;
    }

    for (size_t index = 0; index < count; ++index) {
        explicit_bzero(blocks[index].address, blocks[index].length);
        (void)munmap(blocks[index].address, blocks[index].length);
    }

    explicit_bzero(blocks, capacity * sizeof(*blocks));
    free(blocks);
    sync();
    return allocated < target ? 1 : 0;
}

static int trigger_crashkernel(void)
{
    char loaded = '0';
    int descriptor = open("/sys/kernel/kexec_crash_loaded", O_RDONLY | O_CLOEXEC);

    if (descriptor >= 0) {
        if (read(descriptor, &loaded, 1) != 1)
            loaded = '0';
        close(descriptor);
    }
    if (loaded != '1')
        return 1;

    descriptor = open("/proc/sys/kernel/sysrq", O_WRONLY | O_CLOEXEC);
    if (descriptor >= 0) {
        if (write(descriptor, "1\n", 2) != 2) {
            close(descriptor);
            return 1;
        }
        close(descriptor);
    }

    sync();
    descriptor = open("/proc/sysrq-trigger", O_WRONLY | O_CLOEXEC);
    if (descriptor < 0)
        return 1;
    if (write(descriptor, "c\n", 2) != 2) {
        close(descriptor);
        return 1;
    }
    close(descriptor);

    for (;;)
        pause();
}

int main(int argc, char **argv)
{
    if (argc > 1 &&
        (strcmp(argv[1], "poweroff") == 0 ||
         strcmp(argv[1], "reboot") == 0 ||
         strcmp(argv[1], "halt") == 0 ||
         strcmp(argv[1], "kexec") == 0)) {
        if (trigger_crashkernel() == 0)
            return 0;
        (void)scrub_available_memory();
        return 1;
    }

    return scrub_available_memory();
}
