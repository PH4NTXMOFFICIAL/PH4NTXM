/* Copyright (C) PH4NTXM
 * Licensed under the GNU General Public License v3.0.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct answers {
    const char *token;
    int prompts;
};

int audit_open(void)
{
    errno = EAFNOSUPPORT;
    return -1;
}

static int converse(int count, const struct pam_message **messages, struct pam_response **response, void *data)
{
    struct answers *answers = data;
    struct pam_response *reply = calloc((size_t)count, sizeof(*reply));
    if (!reply)
        return PAM_BUF_ERR;
    for (int i = 0; i < count; i++) {
        if (messages[i]->msg_style != PAM_PROMPT_ECHO_OFF) {
            for (int j = 0; j < i; j++)
                free(reply[j].resp);
            free(reply);
            return PAM_CONV_ERR;
        }
        answers->prompts++;
        reply[i].resp = strdup(answers->token);
        if (!reply[i].resp) {
            for (int j = 0; j < i; j++)
                free(reply[j].resp);
            free(reply);
            return PAM_BUF_ERR;
        }
    }
    *response = reply;
    return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
    char token[2048] = {0};
    struct answers answers = {.token = token};
    struct pam_conv conversation = {.conv = converse, .appdata_ptr = &answers};
    pam_handle_t *pamh = NULL;
    int status;
    size_t n = fread(token, 1, sizeof(token) - 1, stdin);
    if (argc != 2 || ferror(stdin) || n == sizeof(token) - 1)
        return 99;
    status = pam_start_confdir("xfce4-screensaver", "ph4ntxm", &conversation, argv[1], &pamh);
    if (status == PAM_SUCCESS)
        status = pam_authenticate(pamh, 0);
    if (pamh)
        pam_end(pamh, status);
    explicit_bzero(token, sizeof(token));
    printf("%d %d\n", status, answers.prompts);
    return 0;
}
