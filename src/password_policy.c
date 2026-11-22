/* SPDX-License-Identifier: MIT */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "pam_verify.h"
#include "password_policy.h"

bool password_policy_allows_parallel(void)
{
    FILE *config = fopen(LOCAL_PAM_CONFIG "/common-auth", "re");
    if (config == NULL)
        return false;

    /* Do not substitute a single biometric factor for a custom mandatory
     * rule. These are the controls used by Ubuntu's alternative primary
     * verifiers and the generated end of the primary stack. */
    const char *pattern = "^-?auth[[:blank:]]+("
                          "(\\[success=[1-9][0-9]*[[:blank:]]+default=ignore\\]|sufficient|optional)"
                          "[[:blank:]]+[^[:space:]]+|"
                          "required[[:blank:]]+([^[:space:]]*/)?pam_permit\\.so|"
                          "requisite[[:blank:]]+([^[:space:]]*/)?pam_deny\\.so)([[:space:]]|$)";
    regex_t standard;
    if (regcomp(&standard, pattern, REG_EXTENDED | REG_NOSUB) != 0) {
        fclose(config);
        return false;
    }

    char *line = NULL;
    size_t capacity = 0;
    bool allowed = true;
    while (getline(&line, &capacity, config) >= 0) {
        const char *rule = line + strspn(line, " \t\r\n");
        if (*rule != '\0' && *rule != '#' && regexec(&standard, rule, 0, NULL, 0) != 0) {
            allowed = false;
            break;
        }
    }
    allowed = allowed && feof(config);
    free(line);
    regfree(&standard);
    fclose(config);
    return allowed;
}

/* pam-auth-update makes fprintd an alternative primary verifier. Preserve
 * the rule and its jump offsets, while giving that rule an ignored failure
 * in the password transaction. Explicit multifactor rules remain intact. */
static int password_rules(char **policy)
{
    FILE *original = fopen(LOCAL_PAM_CONFIG "/common-auth", "re");
    if (original == NULL)
        return errno == ENOENT ? 0 : -1;

    regex_t alternate;
    const char *pattern = "^[[:blank:]]*-?auth[[:blank:]]+"
                          "(\\[success=[1-9][0-9]*[[:blank:]]+default=ignore\\]|sufficient)"
                          "[[:blank:]]+([^[:blank:]]*/)?pam_fprintd\\.so([[:blank:]]|$)";
    if (regcomp(&alternate, pattern, REG_EXTENDED | REG_NEWLINE) != 0) {
        fclose(original);
        return -1;
    }

    size_t size = 0, capacity = 0;
    char *line = NULL;
    FILE *filtered = open_memstream(policy, &size);
    int result = -1;
    if (filtered != NULL) {
        bool changed = false;
        int written = 0;
        while (getline(&line, &capacity, original) >= 0) {
            regmatch_t matches[2];
            if (regexec(&alternate, line, 2, matches, 0) == 0) {
                written = fprintf(filtered, "%.*s\tpam_deny.so\n", (int)matches[1].rm_eo, line);
                changed = true;
            } else {
                written = fputs(line, filtered);
            }
            if (written < 0)
                break;
        }
        if (written >= 0 && feof(original))
            result = changed ? 1 : 0;
        if (fclose(filtered) != 0)
            result = -1;
    }

    free(line);
    regfree(&alternate);
    fclose(original);
    return result;
}

static bool populate_view(const char *directory, const char *policy)
{
    DIR *system = opendir(LOCAL_PAM_CONFIG);
    int view = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    bool okay = system != NULL && view >= 0;
    if (okay) {
        for (;;) {
            errno = 0;
            struct dirent *entry = readdir(system);
            if (entry == NULL) {
                okay = errno == 0;
                break;
            }
            if (entry->d_name[0] == '.' || strcmp(entry->d_name, "common-auth") == 0)
                continue;
            char target[PATH_MAX];
            int length = snprintf(target, sizeof target, "%s/%s", LOCAL_PAM_CONFIG, entry->d_name);
            if (length < 0 || (size_t)length >= sizeof target || symlinkat(target, view, entry->d_name) != 0) {
                okay = false;
                break;
            }
        }
    }
    if (okay) {
        int fd = openat(view, "common-auth", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        FILE *file = fd >= 0 ? fdopen(fd, "w") : NULL;
        if (file == NULL) {
            if (fd >= 0)
                close(fd);
            okay = false;
        } else {
            okay = fputs(policy, file) >= 0;
            if (fclose(file) != 0)
                okay = false;
        }
    }
    if (view >= 0)
        close(view);
    if (system != NULL)
        closedir(system);
    return okay;
}

static void remove_view(const char *directory)
{
    DIR *view = opendir(directory);
    if (view != NULL) {
        struct dirent *entry;
        while ((entry = readdir(view)) != NULL) {
            if (entry->d_name[0] != '.')
                unlinkat(dirfd(view), entry->d_name, 0);
        }
        closedir(view);
    }
    rmdir(directory);
}

int check_password(const char *user, const char *remote_host,
                   const struct pam_conv *conversation, int flags)
{
    static const char service[] = "fingerprint-parallel-password";
    char *policy = NULL;
    int rules = password_rules(&policy);
    if (rules <= 0) {
        free(policy);
        return rules == 0 ? check_with_pam(service, user, remote_host, conversation, flags) : PAM_SYSTEM_ERR;
    }

    char directory[] = "/tmp/fingerprint-pam-XXXXXX";
    int result = PAM_SYSTEM_ERR;
    if (mkdtemp(directory) != NULL) {
        if (populate_view(directory, policy))
            result = check_with_pam_in(directory, service, user, remote_host, conversation, flags);
        remove_view(directory);
    }
    free(policy);
    return result;
}
