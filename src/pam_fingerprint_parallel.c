/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/pidfd.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <security/pam_modules.h>
#include "password_policy.h"

#ifndef FINGERPRINT_HELPER
#define FINGERPRINT_HELPER "/usr/lib/fingerprint-auth-choice/verify-fingerprint"
#endif

struct password_input {
    const struct pam_conv *parent;
    const char *password;
    bool supplied;
};

static int password_conversation(int count, const struct pam_message **messages,
                                 struct pam_response **responses, void *argument)
{
    struct password_input *input = argument;
    struct pam_response *reply = calloc((size_t)count, sizeof *reply);
    if (reply == NULL)
        return PAM_BUF_ERR;

    int status = PAM_SUCCESS;
    for (int i = 0; i < count; i++) {
        if (!input->supplied && messages[i]->msg_style == PAM_PROMPT_ECHO_OFF) {
            reply[i].resp = strdup(input->password);
            if (reply[i].resp == NULL) {
                status = PAM_BUF_ERR;
                break;
            }
            input->supplied = true;
        } else {
            struct pam_response *forwarded = NULL;
            status = input->parent->conv(1, &messages[i], &forwarded, input->parent->appdata_ptr);
            if (status != PAM_SUCCESS)
                break;
            if (forwarded != NULL) {
                reply[i] = *forwarded;
                free(forwarded);
            }
        }
    }
    if (status == PAM_SUCCESS) {
        *responses = reply;
    } else {
        for (int i = 0; i < count; i++) {
            if (reply[i].resp != NULL) {
                explicit_bzero(reply[i].resp, strlen(reply[i].resp));
                free(reply[i].resp);
            }
        }
        free(reply);
    }
    return status;
}

static pid_t start_fingerprint(const char *user, const char *remote_host, int flags)
{
    char parent_arg[32], flags_arg[32];
    snprintf(parent_arg, sizeof parent_arg, "%ld", (long)getpid());
    snprintf(flags_arg, sizeof flags_arg, "%d", flags);
    char *const argv[] = { FINGERPRINT_HELPER, parent_arg, (char *)user,
                           (char *)(remote_host != NULL ? remote_host : ""), flags_arg, NULL };
    char *const environment[] = { "PATH=/usr/bin:/usr/sbin", NULL };
    posix_spawn_file_actions_t file_actions;
    if (posix_spawn_file_actions_init(&file_actions) != 0)
        return -1;

    pid_t worker = -1;
    if (posix_spawn_file_actions_addopen(&file_actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0 &&
        posix_spawn_file_actions_addopen(&file_actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) == 0 &&
        posix_spawn_file_actions_addopen(&file_actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0 &&
        posix_spawn_file_actions_addclosefrom_np(&file_actions, 3) == 0 &&
        posix_spawn(&worker, FINGERPRINT_HELPER, &file_actions, NULL, argv, environment) != 0)
        worker = -1;
    posix_spawn_file_actions_destroy(&file_actions);
    return worker;
}

/* Ordinary sudo invocations can use the controlling terminal directly. Leave
 * explicit stdin, askpass and noninteractive modes to sudo's conversation. */
static bool uses_interactive_sudo(void)
{
#ifdef FINGERPRINT_TEST
    return true;
#else
    struct stat invoked, sudo_binary;
    if (stat("/proc/self/exe", &invoked) != 0 || stat("/usr/lib/cargo/bin/sudo", &sudo_binary) != 0 ||
        invoked.st_dev != sudo_binary.st_dev || invoked.st_ino != sudo_binary.st_ino)
        return false;

    char command[8192];
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    ssize_t length = read(fd, command, sizeof command);
    close(fd);
    if (length <= 0 || (size_t)length == sizeof command || command[length - 1] != '\0')
        return false;

    const char *end = command + length;
    for (const char *arg = command + strlen(command) + 1; arg < end; arg += strlen(arg) + 1) {
        if (arg[0] != '-') {
            if (strchr(arg, '=') != NULL)
                continue;
            break;
        }
        if (arg[1] == '\0' || strcmp(arg, "--") == 0)
            break;
        if (arg[1] == '-') {
            if (strcmp(arg, "--askpass") == 0 || strcmp(arg, "--stdin") == 0 ||
                strcmp(arg, "--non-interactive") == 0 || strcmp(arg, "--bell") == 0 ||
                strcmp(arg, "--prompt") == 0 || strncmp(arg, "--prompt=", 9) == 0)
                return false;
            if (strcmp(arg, "--chdir") == 0 || strcmp(arg, "--group") == 0 ||
                strcmp(arg, "--host") == 0 || strcmp(arg, "--chroot") == 0 ||
                strcmp(arg, "--other-user") == 0 || strcmp(arg, "--user") == 0 ||
                strcmp(arg, "--close-from") == 0 ||
                strcmp(arg, "--command-timeout") == 0) {
                arg += strlen(arg) + 1;
                if (arg >= end)
                    return false;
            }
            continue;
        }
        for (const char *option = arg + 1; *option != '\0'; option++) {
            if (strchr("ABSpn", *option) != NULL)
                return false;
            if (strchr("CDghRTUu", *option) != NULL) {
                if (option[1] == '\0') {
                    arg += strlen(arg) + 1;
                    if (arg >= end)
                        return false;
                }
                break;
            }
        }
    }
    return true;
#endif
}

static bool uses_polkit_socket(void)
{
    struct stat input, output;
    int domain;
    socklen_t length = sizeof domain;
    return fstat(STDIN_FILENO, &input) == 0 && fstat(STDOUT_FILENO, &output) == 0 &&
           S_ISSOCK(input.st_mode) && input.st_ino == output.st_ino && input.st_dev == output.st_dev &&
           getsockopt(STDIN_FILENO, SOL_SOCKET, SO_DOMAIN, &domain, &length) == 0 && domain == AF_UNIX;
}

static bool wait_for_fingerprint(pid_t worker)
{
    int status;
    pid_t result;
    do {
        result = waitpid(worker, &status, 0);
    } while (result < 0 && errno == EINTR);
    return result == worker && WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS;
}

static int read_authentication(int fd, int signal_fd, bool dialog, pid_t worker, int worker_fd,
                               char *password, size_t capacity)
{
    struct pollfd fds[] = {
        { .fd = fd, .events = POLLIN | POLLRDHUP },
        { .fd = worker_fd, .events = POLLIN },
        { .fd = signal_fd, .events = POLLIN },
    };
    size_t length = 0;
    int result = PAM_ABORT;
    for (;;) {
        int ready = poll(fds, 3, -1);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready < 0 || fds[2].revents || (fds[0].revents & (POLLERR | POLLHUP | POLLRDHUP | POLLNVAL)))
            break;

        if (fds[1].revents & (POLLIN | POLLHUP)) {
            bool matched = wait_for_fingerprint(worker);
            worker = -1;
            fds[1].fd = -1;
            if (matched) {
                result = PAM_SUCCESS;
                break;
            }
        }

        if (fds[0].revents & POLLIN) {
            char byte;
            ssize_t count = dialog ? recv(fd, &byte, 1, MSG_DONTWAIT) : read(fd, &byte, 1);
            if (count < 0 && (errno == EINTR || errno == EAGAIN))
                continue;
            if (count <= 0 || byte == '\0')
                break;
            if (byte == '\n') {
                password[length] = '\0';
                result = PAM_INCOMPLETE; /* A complete password is ready for PAM. */
                break;
            }
            if (length + 1 >= capacity) {
                result = PAM_AUTH_ERR;
                break;
            }
            password[length++] = byte;
        }
    }
    if (worker > 0) {
        kill(worker, SIGINT);
        wait_for_fingerprint(worker);
    }
    return result;
}

static int wait_for_either(bool dialog, const char *user, const char *remote_host, int flags,
                           char *password, size_t capacity)
{
    static const char gui_prompt[] = "PAM_PROMPT_ECHO_OFF Password or fingerprint:\n";
    static const char tty_prompt[] = "[sudo] Password or fingerprint: ";
    int fd = dialog ? STDIN_FILENO : open("/dev/tty", O_RDWR | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
    if (fd < 0)
        return PAM_IGNORE;

    struct termios original;
    bool tty_changed = false;
    sigset_t blocked, old_mask;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGQUIT);
    sigaddset(&blocked, SIGTERM);
    sigaddset(&blocked, SIGHUP);
    sigaddset(&blocked, SIGTSTP);
    sigaddset(&blocked, SIGTTIN);
    sigaddset(&blocked, SIGTTOU);
    if (sigprocmask(SIG_BLOCK, &blocked, &old_mask) != 0) {
        if (!dialog)
            close(fd);
        return PAM_IGNORE;
    }

    int result = PAM_IGNORE;
    int signal_fd = signalfd(-1, &blocked, SFD_CLOEXEC | SFD_NONBLOCK);
    if (signal_fd >= 0) {
        bool ready = dialog;
        if (!dialog && tcgetpgrp(fd) == getpgrp() && tcgetattr(fd, &original) == 0) {
            struct termios hidden = original;
            hidden.c_lflag |= ICANON | ISIG;
            hidden.c_lflag &= ~(ECHO | ECHONL);
            hidden.c_iflag |= ICRNL;
            hidden.c_iflag &= ~(IGNCR | INLCR);
            ready = tty_changed = tcsetattr(fd, TCSAFLUSH, &hidden) == 0;
        }
        if (ready) {
            pid_t worker = start_fingerprint(user, remote_host, flags);
            int worker_fd = worker > 0 ? pidfd_open(worker, 0) : -1;
            if (worker > 0 && worker_fd < 0) {
                kill(worker, SIGINT);
                wait_for_fingerprint(worker);
                worker = -1;
            }
            const char *prompt = dialog ? gui_prompt : tty_prompt;
            ssize_t shown = dialog ? send(STDOUT_FILENO, prompt, strlen(prompt), MSG_NOSIGNAL)
                                   : write(fd, prompt, strlen(prompt));
            if (shown == (ssize_t)strlen(prompt)) {
                result = read_authentication(fd, signal_fd, dialog, worker, worker_fd, password, capacity);
            } else {
                if (worker > 0) {
                    kill(worker, SIGINT);
                    wait_for_fingerprint(worker);
                }
                result = PAM_ABORT;
            }
            if (worker_fd >= 0)
                close(worker_fd);
        }
    }

    if (tty_changed) {
        tcsetattr(fd, TCSAFLUSH, &original);
        (void)!write(fd, "\n", 1);
    }
    if (!dialog)
        close(fd);
    if (signal_fd >= 0) {
        struct signalfd_siginfo discarded;
        while (read(signal_fd, &discarded, sizeof discarded) == sizeof discarded)
            ;
        close(signal_fd);
    }
    sigprocmask(SIG_SETMASK, &old_mask, NULL);
    return result;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)argc;
    (void)argv;
    const void *service = NULL, *conversation = NULL, *remote_host = NULL;
    const char *user = NULL;
    if (pam_get_item(pamh, PAM_SERVICE, &service) != PAM_SUCCESS || service == NULL ||
        pam_get_item(pamh, PAM_CONV, &conversation) != PAM_SUCCESS || conversation == NULL ||
        pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL ||
        pam_get_item(pamh, PAM_RHOST, &remote_host) != PAM_SUCCESS)
        return PAM_IGNORE;
    if (remote_host != NULL && *(const char *)remote_host != '\0' && strcmp(remote_host, "localhost") != 0)
        return PAM_IGNORE;

    bool dialog = strcmp(service, "polkit-1") == 0;
    bool sudo = strcmp(service, "sudo") == 0 || strcmp(service, "sudo-i") == 0;
    if (dialog ? !uses_polkit_socket() : !sudo || !uses_interactive_sudo())
        return PAM_IGNORE;
    if (!password_policy_allows_parallel())
        return PAM_IGNORE;

    char password[PAM_MAX_RESP_SIZE];
    int result = wait_for_either(dialog, user, remote_host, flags, password, sizeof password);
    if (result == PAM_INCOMPLETE) {
        struct password_input input = { .parent = conversation, .password = password };
        const struct pam_conv supplied = { password_conversation, &input };
        result = check_password(user, remote_host, &supplied, flags);
        if (result == PAM_SYSTEM_ERR)
            result = PAM_IGNORE;
        else if (result == PAM_IGNORE || result == PAM_INCOMPLETE)
            result = PAM_AUTH_ERR;
    } else if (result == PAM_SUCCESS && !password_policy_allows_parallel()) {
        result = PAM_IGNORE;
    }
    explicit_bzero(password, sizeof password);
    return result;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_IGNORE;
}
