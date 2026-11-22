#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)flags;
    if (argc == 1 && strcmp(argv[0], "simulated-finger") == 0) {
        usleep(300000);
        return PAM_SUCCESS;
    }
    if (argc == 2 && strcmp(argv[0], "record-finger") == 0) {
        FILE *trace = fopen(argv[1], "w");
        if (trace != NULL) {
            fputs("unexpected fingerprint invocation\n", trace);
            fclose(trace);
        }
        return PAM_AUTH_ERR;
    }

    char *response = NULL;
    int status = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &response, "Password:");
    if (status == PAM_SUCCESS && response != NULL)
        status = strcmp(response, "test-password-35") == 0 ? PAM_SUCCESS : PAM_AUTH_ERR;
    else
        status = PAM_AUTH_ERR;
    if (response != NULL) {
        explicit_bzero(response, strlen(response));
        free(response);
    }
    return status;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}
