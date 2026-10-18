/* Copyright (C) PH4NTXM
 * Licensed under the GNU General Public License v3.0.
 */
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct handle {
    const char *service;
    const char *user;
    const char *token;
    int failed_item;
};

int pam_get_item(const pam_handle_t *pamh, int item, const void **value)
{
    const struct handle *h = (const void *)pamh;
    if (item == h->failed_item)
        return PAM_SYSTEM_ERR;
    if (item == PAM_SERVICE)
        *value = h->service;
    else if (item == PAM_USER)
        *value = h->user;
    else if (item == PAM_AUTHTOK)
        *value = h->token;
    else
        return PAM_BAD_ITEM;
    return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
    char token[2048] = {0};
    struct handle h = {.service = "xfce4-screensaver", .user = "ph4ntxm"};
    size_t n = fread(token, 1, sizeof(token) - 1, stdin);
    int result;
    if (argc != 2 || ferror(stdin) || n == sizeof(token) - 1)
        return 99;
    h.token = token;
    if (!strcmp(argv[1], "service"))
        h.service = "sudo";
    else if (!strcmp(argv[1], "user"))
        h.user = "root";
    else if (!strcmp(argv[1], "missing"))
        h.token = NULL;
    else if (!strcmp(argv[1], "item-error"))
        h.failed_item = PAM_AUTHTOK;
    else if (!strcmp(argv[1], "null-service"))
        h.service = NULL;
    else if (!strcmp(argv[1], "null-user"))
        h.user = NULL;
    if (!strcmp(argv[1], "setcred"))
        result = pam_sm_setcred((pam_handle_t *)&h, 0, 0, NULL);
    else
        result = pam_sm_authenticate((pam_handle_t *)&h, 0, !strcmp(argv[1], "arguments"), NULL);
    explicit_bzero(token, sizeof(token));
    printf("%d\n", result);
    return 0;
}
