// Copyright (C) PH4NTXM
// Licensed under the GNU General Public License v3.0.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <unistd.h>

static __thread char mapped[PATH_MAX];

static const char *translate(int fd, const char *path)
{
    static const char *roots[] = {"/proc/cpuinfo",
                                  "/proc/meminfo",
                                  "/proc/stat",
                                  "/proc/kcore",
                                  "/sys/devices/system/memory",
                                  "/sys/bus/memory",
                                  "/sys/devices/system/cpu",
                                  "/sys/devices/system/node",
                                  "/sys/devices/virtual/dmi/id",
                                  "/sys/class/dmi/id",
                                  "/sys/firmware/dmi",
                                  "/sys/firmware/efi",
                                  "/sys/firmware/acpi/tables/UEFI",
                                  NULL};
    const char *base = getenv("PH4_INVENTORY_ROOT");
    char absolute[PATH_MAX];
    if (!base || !*base || !path)
        return path;
    if (path[0] != '/') {
        char directory[PATH_MAX];
        if (fd == AT_FDCWD) {
            if (!getcwd(directory, sizeof(directory)))
                return path;
        } else {
            char link[64];
            ssize_t (*original)(const char *, char *, size_t) = dlsym(RTLD_NEXT, "readlink");
            snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
            ssize_t size = original(link, directory, sizeof(directory) - 1);
            if (size < 0)
                return path;
            directory[size] = '\0';
        }
        if (snprintf(absolute, sizeof(absolute), "%s/%s", directory, path) >= (int)sizeof(absolute))
            return path;
    } else {
        if (strlen(path) >= sizeof(absolute))
            return path;
        strcpy(absolute, path);
    }
    for (int i = 0; roots[i]; i++) {
        size_t length = strlen(roots[i]);
        if (!strncmp(absolute, roots[i], length) &&
            (absolute[length] == '/' || absolute[length] == '\0' ||
             !strcmp(roots[i], "/sys/firmware/acpi/tables/UEFI"))) {
            if (snprintf(mapped, sizeof(mapped), "%s%s", base, absolute) >= (int)sizeof(mapped)) {
                errno = ENAMETOOLONG;
                return path;
            }
            return mapped;
        }
    }
    return path;
}

static int firmware_tables(int fd, const char *path)
{
    const char *base = getenv("PH4_INVENTORY_ROOT");
    if (!base || !*base)
        return 0;
    int saved = errno, result = 0;
    char absolute[PATH_MAX], directory[PATH_MAX];
    if (path && path[0] == '/') {
        if (snprintf(absolute, sizeof(absolute), "%s", path) >= (int)sizeof(absolute))
            goto finish;
    } else {
        if (fd == AT_FDCWD) {
            if (!getcwd(directory, sizeof(directory)))
                goto finish;
        } else {
            char link[64];
            ssize_t (*original)(const char *, char *, size_t) = dlsym(RTLD_NEXT, "readlink");
            snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
            ssize_t size = original(link, directory, sizeof(directory) - 1);
            if (size < 0 || size >= (ssize_t)sizeof(directory) - 1)
                goto finish;
            directory[size] = '\0';
        }
        if (snprintf(absolute, sizeof(absolute), "%s%s%s", directory, path ? "/" : "",
                     path ? path : "") >= (int)sizeof(absolute))
            goto finish;
    }
    size_t length = strlen(absolute);
    while (length > 1 && absolute[length - 1] == '/')
        absolute[--length] = '\0';
    result = !strcmp(absolute, "/sys/firmware/acpi/tables");
finish:
    errno = saved;
    return result;
}

static int memory_fd(int kind)
{
    const char *ram = getenv("PH4_INVENTORY_RAM_BYTES");
    if (!ram)
        return -1;
    return memfd_create(kind == 2 ? "ph4ntxm-stat" : "ph4ntxm-meminfo", MFD_CLOEXEC);
}

static int is_memory_fd(int fd)
{
    ssize_t (*original)(const char *, char *, size_t) = dlsym(RTLD_NEXT, "readlink");
    char path[64], target[128];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    ssize_t size = original(path, target, sizeof(target) - 1);
    if (size < 0)
        return 0;
    target[size] = 0;
    if (!strcmp(target, "/memfd:ph4ntxm-stat (deleted)"))
        return 2;
    return !strcmp(target, "/memfd:ph4ntxm-meminfo (deleted)");
}

static void refresh_memory(int fd)
{
    FILE *(*real_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    FILE *source = real_fopen("/proc/meminfo", "r");
    if (!source)
        return;
    char input[16384], output[16384];
    size_t length = fread(input, 1, sizeof(input) - 1, source);
    fclose(source);
    input[length] = 0;
    unsigned long long total = 0,
                       ram = strtoull(getenv("PH4_INVENTORY_RAM_BYTES"), NULL, 10) / 1024;
    if (sscanf(input, "MemTotal: %llu", &total) != 1 || !total)
        return;
    char *cursor, *line = strtok_r(input, "\n", &cursor);
    size_t used = 0;
    while (line && used < sizeof(output) - 1) {
        char key[80], unit[8];
        unsigned long long amount;
        int size;
        if (sscanf(line, "%79[^:]: %llu %7s", key, &amount, unit) == 3 && !strcmp(unit, "kB") &&
            strncmp(key, "Swap", 4) && strcmp(key, "Hugepagesize")) {
            amount = (unsigned long long)((long double)amount * ram / total);
            size = snprintf(output + used, sizeof(output) - used, "%s: %8llu kB\n", key, amount);
        } else {
            size = snprintf(output + used, sizeof(output) - used, "%s\n", line);
        }
        if (size < 0 || (size_t)size >= sizeof(output) - used)
            return;
        used += (size_t)size;
        line = strtok_r(NULL, "\n", &cursor);
    }
    if (pwrite(fd, output, used, 0) == (ssize_t)used)
        (void)ftruncate(fd, (off_t)used);
}

static void refresh_stat(int fd)
{
    FILE *(*real_fopen)(const char *, const char *) = dlsym(RTLD_NEXT, "fopen");
    FILE *source = real_fopen("/proc/stat", "r");
    if (!source)
        return;
    unsigned long count = strtoul(getenv("PH4_REPORTED_CORES"), NULL, 10);
    unsigned long long rows[256][10] = {{0}}, totals[10] = {0};
    char *line = NULL, *tail = NULL, *result = NULL;
    size_t length = 0, tail_size = 0, result_size = 0, real_count = 0;
    FILE *other = open_memstream(&tail, &tail_size);
    if (!other || count < 1 || count > 256) {
        if (other)
            fclose(other);
        free(tail);
        fclose(source);
        return;
    }
    while (getline(&line, &length, source) >= 0) {
        unsigned int index;
        if (line[3] >= '0' && line[3] <= '9' && sscanf(line, "cpu%u ", &index) == 1) {
            if (real_count < 256) {
                unsigned long long *row = rows[real_count++];
                (void)sscanf(line, "%*s %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu", &row[0],
                             &row[1], &row[2], &row[3], &row[4], &row[5], &row[6], &row[7], &row[8],
                             &row[9]);
            }
        } else if (strncmp(line, "cpu ", 4)) {
            fputs(line, other);
        }
    }
    free(line);
    fclose(source);
    fclose(other);
    FILE *output = open_memstream(&result, &result_size);
    if (output && real_count) {
        for (unsigned long i = 0; i < count; i++)
            for (int j = 0; j < 10; j++)
                totals[j] += rows[i % real_count][j];
        fputs("cpu", output);
        for (int j = 0; j < 10; j++)
            fprintf(output, " %llu", totals[j]);
        fputc('\n', output);
        for (unsigned long i = 0; i < count; i++) {
            fprintf(output, "cpu%lu", i);
            for (int j = 0; j < 10; j++)
                fprintf(output, " %llu", rows[i % real_count][j]);
            fputc('\n', output);
        }
        fwrite(tail, 1, tail_size, output);
    }
    if (output)
        fclose(output);
    if (result_size && pwrite(fd, result, result_size, 0) == (ssize_t)result_size)
        (void)ftruncate(fd, (off_t)result_size);
    free(tail);
    free(result);
}

static void refresh_snapshot(int fd)
{
    if (is_memory_fd(fd) == 2)
        refresh_stat(fd);
    else
        refresh_memory(fd);
}

static int memory_path(const char *path)
{
    const char *root = getenv("PH4_INVENTORY_ROOT");
    if (!root || !path)
        return 0;
    if (!strncmp(path, root, strlen(root)))
        path += strlen(root);
    if (!strcmp(path, "/proc/meminfo"))
        return 1;
    return !strcmp(path, "/proc/stat") ? 2 : 0;
}

static int open_memory(int kind)
{
    int fd = memory_fd(kind);
    if (fd >= 0)
        refresh_snapshot(fd);
    return fd;
}

off_t lseek(int fd, off_t offset, int whence)
{
    off_t (*original)(int, off_t, int) = dlsym(RTLD_NEXT, "lseek");
    if (!offset && whence == SEEK_SET && is_memory_fd(fd))
        refresh_snapshot(fd);
    return original(fd, offset, whence);
}

off64_t lseek64(int fd, off64_t offset, int whence)
{
    off64_t (*original)(int, off64_t, int) = dlsym(RTLD_NEXT, "lseek64");
    if (!offset && whence == SEEK_SET && is_memory_fd(fd))
        refresh_snapshot(fd);
    return original(fd, offset, whence);
}

void rewind(FILE *stream)
{
    void (*original)(FILE *) = dlsym(RTLD_NEXT, "rewind");
    if (is_memory_fd(fileno(stream)))
        refresh_snapshot(fileno(stream));
    original(stream);
}

#define OPEN_FUNCTION(name) \
    int name(const char *path, int flags, ...) \
    { \
        mode_t mode = 0; \
        if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) { \
            va_list args; \
            va_start(args, flags); \
            mode = va_arg(args, int); \
            va_end(args); \
        } \
        int (*original)(const char *, int, ...) = dlsym(RTLD_NEXT, #name); \
        const char *target = translate(AT_FDCWD, path); \
        if ((flags & O_ACCMODE) == O_RDONLY && memory_path(target)) \
            return open_memory(memory_path(target)); \
        return original(target, flags, mode); \
    }
OPEN_FUNCTION(open)
OPEN_FUNCTION(open64)

#define OPENAT_FUNCTION(name) \
    int name(int fd, const char *path, int flags, ...) \
    { \
        mode_t mode = 0; \
        if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) { \
            va_list args; \
            va_start(args, flags); \
            mode = va_arg(args, int); \
            va_end(args); \
        } \
        int (*original)(int, const char *, int, ...) = dlsym(RTLD_NEXT, #name); \
        const char *target = translate(fd, path); \
        if ((flags & O_ACCMODE) == O_RDONLY && memory_path(target)) \
            return open_memory(memory_path(target)); \
        return original(fd, target, flags, mode); \
    }
OPENAT_FUNCTION(openat)
OPENAT_FUNCTION(openat64)

#define OPEN_CHECKED(name) \
    int name(const char *path, int flags) \
    { \
        int (*original)(const char *, int) = dlsym(RTLD_NEXT, #name); \
        if ((flags & O_ACCMODE) == O_RDONLY && memory_path(translate(AT_FDCWD, path))) \
            return open_memory(memory_path(translate(AT_FDCWD, path))); \
        return original(translate(AT_FDCWD, path), flags); \
    }
OPEN_CHECKED(__open_2)
OPEN_CHECKED(__open64_2)

#define OPENAT_CHECKED(name) \
    int name(int fd, const char *path, int flags) \
    { \
        int (*original)(int, const char *, int) = dlsym(RTLD_NEXT, #name); \
        if ((flags & O_ACCMODE) == O_RDONLY && memory_path(translate(fd, path))) \
            return open_memory(memory_path(translate(fd, path))); \
        return original(fd, translate(fd, path), flags); \
    }
OPENAT_CHECKED(__openat_2)
OPENAT_CHECKED(__openat64_2)

int statx(int fd, const char *path, int flags, unsigned int mask, struct statx *buf)
{
    int (*original)(int, const char *, int, unsigned int, struct statx *) =
        dlsym(RTLD_NEXT, "statx");
    return original(fd, translate(fd, path), flags, mask, buf);
}

int fstatat64(int fd, const char *path, struct stat64 *buf, int flags)
{
    int (*original)(int, const char *, struct stat64 *, int) = dlsym(RTLD_NEXT, "fstatat64");
    return original(fd, translate(fd, path), buf, flags);
}

#define FOPEN_FUNCTION(name) \
    FILE *name(const char *path, const char *mode) \
    { \
        FILE *(*original)(const char *, const char *) = dlsym(RTLD_NEXT, #name); \
        const char *target = translate(AT_FDCWD, path); \
        if (mode[0] == 'r' && !strchr(mode, '+') && memory_path(target)) { \
            int fd = open_memory(memory_path(target)); \
            if (fd < 0) \
                return NULL; \
            FILE *stream = fdopen(fd, mode); \
            if (!stream) \
                close(fd); \
            return stream; \
        } \
        return original(target, mode); \
    }
FOPEN_FUNCTION(fopen)
FOPEN_FUNCTION(fopen64)

DIR *opendir(const char *path)
{
    DIR *(*original)(const char *) = dlsym(RTLD_NEXT, "opendir");
    return original(translate(AT_FDCWD, path));
}

#define READDIR_FUNCTION(name, type) \
    struct type *name(DIR *stream) \
    { \
        struct type *(*original)(DIR *) = dlsym(RTLD_NEXT, #name); \
        struct type *entry; \
        while ((entry = original(stream))) { \
            if (strncmp(entry->d_name, "UEFI", 4)) \
                break; \
            int saved = errno; \
            int filtered = firmware_tables(dirfd(stream), NULL); \
            errno = saved; \
            if (!filtered) \
                break; \
        } \
        return entry; \
    }
READDIR_FUNCTION(readdir, dirent)
READDIR_FUNCTION(readdir64, dirent64)

#define FILTER_FIRMWARE_ENTRIES(fd, path, list, count) \
    do { \
        if (count > 0 && firmware_tables(fd, path)) { \
            int kept = 0; \
            for (int i = 0; i < count; i++) { \
                if (!strncmp((*list)[i]->d_name, "UEFI", 4)) \
                    free((*list)[i]); \
                else \
                    (*list)[kept++] = (*list)[i]; \
            } \
            count = kept; \
        } \
    } while (0)

#define SCANDIR_FUNCTION(name, type) \
    int name(const char *path, struct type ***list, int (*filter)(const struct type *), \
             int (*compare)(const struct type **, const struct type **)) \
    { \
        int (*original)(const char *, struct type ***, int (*)(const struct type *), \
                        int (*)(const struct type **, const struct type **)) = \
            dlsym(RTLD_NEXT, #name); \
        int count = original(translate(AT_FDCWD, path), list, filter, compare); \
        FILTER_FIRMWARE_ENTRIES(AT_FDCWD, path, list, count); \
        return count; \
    }
SCANDIR_FUNCTION(scandir, dirent)
SCANDIR_FUNCTION(scandir64, dirent64)

#define SCANDIRAT_FUNCTION(name, type) \
    int name(int fd, const char *path, struct type ***list, int (*filter)(const struct type *), \
             int (*compare)(const struct type **, const struct type **)) \
    { \
        int (*original)(int, const char *, struct type ***, int (*)(const struct type *), \
                        int (*)(const struct type **, const struct type **)) = \
            dlsym(RTLD_NEXT, #name); \
        int count = original(fd, translate(fd, path), list, filter, compare); \
        FILTER_FIRMWARE_ENTRIES(fd, path, list, count); \
        return count; \
    }
SCANDIRAT_FUNCTION(scandirat, dirent)
SCANDIRAT_FUNCTION(scandirat64, dirent64)

#define STAT_FUNCTION(name, type) \
    int name(const char *path, struct type *buf) \
    { \
        int (*original)(const char *, struct type *) = dlsym(RTLD_NEXT, #name); \
        return original(translate(AT_FDCWD, path), buf); \
    }
STAT_FUNCTION(stat, stat)
STAT_FUNCTION(lstat, stat)
STAT_FUNCTION(stat64, stat64)
STAT_FUNCTION(lstat64, stat64)

#define XSTAT_FUNCTION(name, type) \
    int name(int version, const char *path, struct type *buf) \
    { \
        int (*original)(int, const char *, struct type *) = dlsym(RTLD_NEXT, #name); \
        return original(version, translate(AT_FDCWD, path), buf); \
    }
XSTAT_FUNCTION(__xstat, stat)
XSTAT_FUNCTION(__lxstat, stat)
XSTAT_FUNCTION(__xstat64, stat64)
XSTAT_FUNCTION(__lxstat64, stat64)

int fstatat(int fd, const char *path, struct stat *buf, int flags)
{
    int (*original)(int, const char *, struct stat *, int) = dlsym(RTLD_NEXT, "fstatat");
    return original(fd, translate(fd, path), buf, flags);
}

int access(const char *path, int mode)
{
    int (*original)(const char *, int) = dlsym(RTLD_NEXT, "access");
    return original(translate(AT_FDCWD, path), mode);
}

int faccessat(int fd, const char *path, int mode, int flags)
{
    int (*original)(int, const char *, int, int) = dlsym(RTLD_NEXT, "faccessat");
    return original(fd, translate(fd, path), mode, flags);
}

static unsigned long value(const char *name)
{
    const char *text = getenv(name);
    return text ? strtoul(text, NULL, 10) : 0;
}

int get_nprocs(void)
{
    int (*original)(void) = dlsym(RTLD_NEXT, "get_nprocs");
    unsigned long count = value("PH4_REPORTED_CORES");
    return count ? (int)count : original();
}

int get_nprocs_conf(void)
{
    int (*original)(void) = dlsym(RTLD_NEXT, "get_nprocs_conf");
    unsigned long count = value("PH4_REPORTED_CORES");
    return count ? (int)count : original();
}

long sysconf(int name)
{
    long (*original)(int) = dlsym(RTLD_NEXT, "sysconf");
    unsigned long count = value("PH4_REPORTED_CORES");
    unsigned long ram = value("PH4_INVENTORY_RAM_BYTES");
    const int cache_names[4][3] = {
        {_SC_LEVEL1_DCACHE_SIZE, _SC_LEVEL1_DCACHE_ASSOC, _SC_LEVEL1_DCACHE_LINESIZE},
        {_SC_LEVEL1_ICACHE_SIZE, _SC_LEVEL1_ICACHE_ASSOC, _SC_LEVEL1_ICACHE_LINESIZE},
        {_SC_LEVEL2_CACHE_SIZE, _SC_LEVEL2_CACHE_ASSOC, _SC_LEVEL2_CACHE_LINESIZE},
        {_SC_LEVEL3_CACHE_SIZE, _SC_LEVEL3_CACHE_ASSOC, _SC_LEVEL3_CACHE_LINESIZE}};
    const char *cache_keys[] = {"PH4_CACHE_L1D", "PH4_CACHE_L1I", "PH4_CACHE_L2", "PH4_CACHE_L3"};
    for (int i = 0; i < 4; i++) {
        const char *size = getenv(cache_keys[i]);
        if (!size)
            continue;
        if (name == cache_names[i][0])
            return (long)strtoul(size, NULL, 10);
        if (name == cache_names[i][2])
            return strtoul(size, NULL, 10) ? 64 : 0;
        if (name == cache_names[i][1]) {
            char key[32];
            snprintf(key, sizeof(key), "%s_WAYS", cache_keys[i]);
            return (long)value(key);
        }
    }
    if (count && (name == _SC_LEVEL4_CACHE_SIZE || name == _SC_LEVEL4_CACHE_ASSOC ||
                  name == _SC_LEVEL4_CACHE_LINESIZE))
        return 0;
    if (count && (name == _SC_NPROCESSORS_CONF || name == _SC_NPROCESSORS_ONLN))
        return (long)count;
    if (ram && name == _SC_PHYS_PAGES)
        return (long)(ram / (unsigned long)original(_SC_PAGESIZE));
    if (ram && name == _SC_AVPHYS_PAGES) {
        long total = original(_SC_PHYS_PAGES);
        long available = original(_SC_AVPHYS_PAGES);
        if (total > 0 && available >= 0)
            return (long)((long double)available * ram / total / original(_SC_PAGESIZE));
    }
    return original(name);
}

int sysinfo(struct sysinfo *info)
{
    int (*original)(struct sysinfo *) = dlsym(RTLD_NEXT, "sysinfo");
    int result = original(info);
    unsigned long ram = value("PH4_INVENTORY_RAM_BYTES");
    if (!result && ram && info->totalram && info->mem_unit) {
        long double ratio = (long double)ram / ((long double)info->totalram * info->mem_unit);
        info->freeram = (unsigned long)(info->freeram * ratio);
        info->sharedram = (unsigned long)(info->sharedram * ratio);
        info->bufferram = (unsigned long)(info->bufferram * ratio);
        info->totalhigh = (unsigned long)(info->totalhigh * ratio);
        info->freehigh = (unsigned long)(info->freehigh * ratio);
        info->totalram = ram / info->mem_unit;
    }
    return result;
}

int uname(struct utsname *buf)
{
    int (*original)(struct utsname *) = dlsym(RTLD_NEXT, "uname");
    int result = original(buf);
    const char *arch = getenv("PH4_CPU_ARCHITECTURE");
    if (!result && arch && (!strcmp(arch, "x86_64") || !strcmp(arch, "aarch64")))
        snprintf(buf->machine, sizeof(buf->machine), "%s", arch);
    return result;
}

int sched_getaffinity(pid_t pid, size_t size, cpu_set_t *mask)
{
    int (*original)(pid_t, size_t, cpu_set_t *) = dlsym(RTLD_NEXT, "sched_getaffinity");
    int result = original(pid, size, mask);
    unsigned long count = value("PH4_REPORTED_CORES");
    if (!result && count && (pid == 0 || pid == getpid())) {
        if (size * CHAR_BIT < count) {
            errno = EINVAL;
            return -1;
        }
        CPU_ZERO_S(size, mask);
        for (unsigned long cpu = 0; cpu < count; cpu++)
            CPU_SET_S(cpu, size, mask);
    }
    return result;
}
