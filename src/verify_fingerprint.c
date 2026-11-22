/* SPDX-License-Identifier: MIT */
#include <signal.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "pam_verify.h"

static int no_password(int count, const struct pam_message **messages,
                       struct pam_response **responses, void *argument)
{
    (void)argument;
    for (int i = 0; i < count; i++) {
        if (messages[i]->msg_style != PAM_TEXT_INFO && messages[i]->msg_style != PAM_ERROR_MSG)
            return PAM_CONV_ERR;
    }
    *responses = calloc((size_t)count, sizeof **responses);
    return *responses != NULL ? PAM_SUCCESS : PAM_BUF_ERR;
}

int main(int argc, char **argv)
{
    if (argc != 5 || prctl(PR_SET_PDEATHSIG, SIGINT) != 0 || getppid() != (pid_t)atoi(argv[1]))
        return EXIT_FAILURE;
    sigset_t pending;
    if (sigpending(&pending) == 0 && sigismember(&pending, SIGINT))
        return EXIT_FAILURE;

    const struct pam_conv conversation = { no_password, NULL };
    int result = check_with_pam("fingerprint-parallel-reader", argv[2], argv[3], &conversation, atoi(argv[4]));
    return result == PAM_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}
