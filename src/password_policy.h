/* SPDX-License-Identifier: MIT */
#pragma once

#include <stdbool.h>
#include <security/pam_appl.h>

bool password_policy_allows_parallel(void);
int check_password(const char *user, const char *remote_host,
                   const struct pam_conv *conversation, int flags);
