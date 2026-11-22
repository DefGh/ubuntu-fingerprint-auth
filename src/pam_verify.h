/* SPDX-License-Identifier: MIT */
#pragma once

#include <string.h>

#include <security/pam_appl.h>

#ifndef LOCAL_PAM_CONFIG
#define LOCAL_PAM_CONFIG "/etc/pam.d"
#endif

static inline int check_with_pam_in(const char *config_dir, const char *service,
                                    const char *user, const char *remote_host,
                                    const struct pam_conv *conversation, int flags)
{
    pam_handle_t *check = NULL;
    int result = pam_start_confdir(service, user, conversation, config_dir, &check);
    if (result != PAM_SUCCESS)
        return result;

    result = pam_set_item(check, PAM_RHOST, remote_host);
    if (result == PAM_SUCCESS)
        result = pam_authenticate(check, flags);
    if (result == PAM_SUCCESS) {
        const void *authenticated = NULL;
        if (pam_get_item(check, PAM_USER, &authenticated) != PAM_SUCCESS ||
            authenticated == NULL || strcmp(user, authenticated) != 0)
            result = PAM_AUTH_ERR;
    }
    pam_end(check, result);
    return result;
}

static inline int check_with_pam(const char *service, const char *user, const char *remote_host,
                                 const struct pam_conv *conversation, int flags)
{
    return check_with_pam_in(LOCAL_PAM_CONFIG, service, user, remote_host, conversation, flags);
}
