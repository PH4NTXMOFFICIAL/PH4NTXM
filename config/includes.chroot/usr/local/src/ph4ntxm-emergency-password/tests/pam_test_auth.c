/* Copyright (C) PH4NTXM
 * Licensed under the GNU General Public License v3.0.
 */
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
#ifdef PH4_TEST_DENY
    (void)pamh;
    (void)argc;
    (void)argv;
    return PAM_AUTH_ERR;
#else
    const char *token = NULL;
    if (pam_get_authtok(pamh, PAM_AUTHTOK, &token, NULL) != PAM_SUCCESS || !token)
        return PAM_AUTH_ERR;
    if ((argc == 1 && !strcmp(argv[0], "accept-any")) || !strcmp(token, "Synthetic-Normal-Password"))
        return PAM_SUCCESS;
    return PAM_AUTH_ERR;
#endif
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
