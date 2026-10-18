/* Copyright (C) PH4NTXM
 * Licensed under the GNU General Public License v3.0.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <security/pam_modules.h>
#include "protocol.h"

#ifdef PH4_TEST
#include "test_config.h"
#else
#define PH4_HELPER_PATH "/usr/local/libexec/ph4ntxm-emergency-check"
#endif

static int check_token(const unsigned char *token, size_t length)
{
    int pair[2], status = 0, result = PAM_AUTH_ERR;
    int spawned = 0, actions_ready = 0;
    pid_t pid = -1;
    unsigned char packet[PH4_MAX_TOKEN + 4];
    posix_spawn_file_actions_t actions;
    char *const argv[] = {PH4_HELPER_PATH, NULL};
    char *const env[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", NULL};
    packet[0] = (unsigned char)(length >> 24);
    packet[1] = (unsigned char)(length >> 16);
    packet[2] = (unsigned char)(length >> 8);
    packet[3] = (unsigned char)length;
    memcpy(packet + 4, token, length);
    if (pipe2(pair, O_CLOEXEC))
        goto clear;
    {
        size_t offset = 0;
        while (offset < length + 4) {
            ssize_t n = write(pair[1], packet + offset, length + 4 - offset);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                goto done;
            offset += (size_t)n;
        }
    }
    if (posix_spawn_file_actions_init(&actions))
        goto done;
    actions_ready = 1;
    if (posix_spawn_file_actions_adddup2(&actions, pair[0], STDIN_FILENO) ||
        posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) ||
        posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) ||
        posix_spawn_file_actions_addclosefrom_np(&actions, 3) ||
        posix_spawn(&pid, PH4_HELPER_PATH, &actions, NULL, argv, env))
        goto done;
    spawned = 1;
    close(pair[0]);
    pair[0] = -1;
    close(pair[1]);
    pair[1] = -1;
    {
        struct timespec start, now, delay = {.tv_sec = 0, .tv_nsec = 10000000};
        if (clock_gettime(CLOCK_MONOTONIC, &start))
            goto done;
        for (;;) {
            pid_t completed = waitpid(pid, &status, WNOHANG);
            if (completed == pid)
                break;
            if (completed < 0 && errno != EINTR)
                goto done;
            if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec - start.tv_sec > 6)
                goto done;
            nanosleep(&delay, NULL);
        }
    }
    spawned = 0;
    if (WIFEXITED(status) && (WEXITSTATUS(status) == PH4_NONMATCH || WEXITSTATUS(status) == PH4_DISABLED))
        result = PAM_IGNORE;
done:
    if (spawned) {
        kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
            ;
    }
    if (actions_ready)
        posix_spawn_file_actions_destroy(&actions);
    if (pair[0] >= 0)
        close(pair[0]);
    if (pair[1] >= 0)
        close(pair[1]);
clear:
    explicit_bzero(packet, sizeof(packet));
    return result;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const void *service = NULL, *user = NULL, *token = NULL;
    size_t length;
    (void)flags;
    (void)argv;
    if (argc != 0 || pam_get_item(pamh, PAM_SERVICE, &service) != PAM_SUCCESS ||
        !service || strcmp(service, "xfce4-screensaver") ||
        pam_get_item(pamh, PAM_USER, &user) != PAM_SUCCESS ||
        !user || strcmp(user, "ph4ntxm"))
        return PAM_AUTH_ERR;
    if (pam_get_item(pamh, PAM_AUTHTOK, &token) != PAM_SUCCESS || !token)
        return PAM_AUTH_ERR;
    length = strnlen(token, PH4_MAX_TOKEN + 1);
    if (!ph4_token_valid(token, length))
        return PAM_AUTH_ERR;
    return check_token(token, length);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}
