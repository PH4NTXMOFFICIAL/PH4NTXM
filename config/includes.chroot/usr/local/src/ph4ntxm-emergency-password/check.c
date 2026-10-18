/* Copyright (C) PH4NTXM
 * Licensed under the GNU General Public License v3.0.
 */
#define _GNU_SOURCE
#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "protocol.h"

#ifdef PH4_TEST
#include "test_config.h"
#else
#define PH4_STATE_PARENT "/run"
#define PH4_STATE_NAME "ph4ntxm-session-auth"
#define PH4_DISPATCH_PATH "/usr/bin/systemctl"
#define PH4_OWNER 0
#endif

static int directory_ok(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) &&
           st.st_uid == PH4_OWNER && !(st.st_mode & 0022);
}

static int read_record(char record[160])
{
    int parent = -1, dir = -1, fd = -1, result = -1;
    struct stat st;
    ssize_t n;
    parent = open(PH4_STATE_PARENT, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0 || !directory_ok(parent))
        goto done;
    dir = openat(parent, PH4_STATE_NAME, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0 || !directory_ok(dir))
        goto done;
    fd = openat(dir, "emergency", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != PH4_OWNER || (st.st_mode & 07777) != 0600 ||
        st.st_nlink != 1 || st.st_size < 1 || st.st_size > 159)
        goto done;
    n = read(fd, record, 159);
    if (n < 1 || n != st.st_size)
        goto done;
    record[n] = '\0';
    if (memchr(record, '\0', (size_t)n) || record[n - 1] != '\n')
        goto done;
    {
        char extra;
        if (read(fd, &extra, 1) != 0)
            goto done;
    }
    record[n - 1] = '\0';
    result = 0;
done:
    if (fd >= 0)
        close(fd);
    if (dir >= 0)
        close(dir);
    if (parent >= 0)
        close(parent);
    return result;
}

static int alphabet(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '/';
}

static int hash_valid(const char *hash)
{
    static const char prefix[] = "$6$rounds=100000$";
    const size_t p = sizeof(prefix) - 1;
    if (strlen(hash) != p + 16 + 1 + 86 || strncmp(hash, prefix, p))
        return 0;
    for (size_t i = p; i < p + 16; i++)
        if (!alphabet((unsigned char)hash[i]))
            return 0;
    if (hash[p + 16] != '$')
        return 0;
    for (size_t i = p + 17; i < p + 17 + 86; i++)
        if (!alphabet((unsigned char)hash[i]))
            return 0;
    return 1;
}

static int read_exact(int fd, void *buffer, size_t length)
{
    unsigned char *p = buffer;
    while (length) {
        ssize_t n = read(fd, p, length);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        length -= (size_t)n;
    }
    return 0;
}

static int read_token(unsigned char token[PH4_MAX_TOKEN + 1])
{
    unsigned char frame[4], extra;
    size_t n;
    if (read_exact(STDIN_FILENO, frame, sizeof(frame)))
        return -1;
    n = ((size_t)frame[0] << 24) | ((size_t)frame[1] << 16) |
        ((size_t)frame[2] << 8) | (size_t)frame[3];
    if (!n || n > PH4_MAX_TOKEN || read_exact(STDIN_FILENO, token, n) ||
        read(STDIN_FILENO, &extra, 1) != 0 || !ph4_token_valid(token, n))
        return -1;
    token[n] = '\0';
    return 0;
}

static int caller_ok(void)
{
#ifdef PH4_TEST
    return getuid() == PH4_OWNER && geteuid() == PH4_OWNER;
#else
    struct passwd account, *found = NULL;
    char buffer[16384];
    uid_t caller = getuid();
    if (geteuid() != 0)
        return 0;
    if (caller == 0)
        return 1;
    return getpwnam_r("ph4ntxm", &account, buffer, sizeof(buffer), &found) == 0 &&
           found && found->pw_uid != 0 && caller == found->pw_uid;
#endif
}

static void dispatch(void)
{
    int nullfd;
    char *const argv[] = {PH4_DISPATCH_PATH, "start", "--no-block", "ph4ntxm-panic.service", NULL};
    char *const env[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", NULL};
    alarm(3);
#ifndef PH4_TEST
    if (setgroups(0, NULL) || setresgid(0, 0, 0) || setresuid(0, 0, 0))
        _exit(PH4_MATCH);
#endif
    nullfd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (nullfd < 0)
        _exit(PH4_MATCH);
    for (int fd = 0; fd < 3; fd++)
        if (dup2(nullfd, fd) < 0)
            _exit(PH4_MATCH);
    close_range(3, ~0U, 0);
    execve(PH4_DISPATCH_PATH, argv, env);
    _exit(PH4_MATCH);
}

int main(int argc, char **argv)
{
    unsigned char token[PH4_MAX_TOKEN + 1] = {0};
    char record[160] = {0};
    struct crypt_data data = {0};
    struct rlimit core = {0, 0};
    int result = PH4_ERROR;
    char *computed;
    sigset_t signals;
    struct sigaction action = {.sa_handler = SIG_DFL};
    (void)argv;
    clearenv();
    sigemptyset(&signals);
    sigprocmask(SIG_SETMASK, &signals, NULL);
    sigemptyset(&action.sa_mask);
    sigaction(SIGALRM, &action, NULL);
    setrlimit(RLIMIT_CORE, &core);
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    umask(077);
    close_range(3, ~0U, 0);
    alarm(5);
    if (argc != 1 || !caller_ok() || read_token(token) || read_record(record))
        goto done;
    if (!strcmp(record, "disabled")) {
        result = PH4_DISABLED;
        goto done;
    }
    if (!hash_valid(record))
        goto done;
    computed = crypt_r((const char *)token, record, &data);
    if (!computed || strlen(computed) != strlen(record))
        goto done;
    {
        unsigned int difference = 0;
        for (size_t i = 0; record[i]; i++)
            difference |= (unsigned char)record[i] ^ (unsigned char)computed[i];
        result = difference ? PH4_NONMATCH : PH4_MATCH;
    }
done:
    explicit_bzero(token, sizeof(token));
    explicit_bzero(record, sizeof(record));
    explicit_bzero(&data, sizeof(data));
    if (result == PH4_MATCH) {
        pid_t child = fork();
        if (child == 0)
            dispatch();
        if (child > 0) {
            int status;
            while (waitpid(child, &status, 0) < 0 && errno == EINTR)
                ;
        }
    }
    return result;
}
