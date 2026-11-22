# Changelog

## 3.0 — 2026-11-22

- Build Ubuntu 26.04 packages for `amd64` and `arm64` without a fixed user account.
- Keep the password prompt available while `fprintd` waits for a fingerprint in `sudo-rs` and GNOME PolicyKit.
- Remove the prompt timeout for both methods.
- Accept the system password when Ubuntu's global alternative fingerprint profile is enabled, while preserving the original PAM policy for other services.
- Upgrade earlier `fingerprint-auth-choice` installations in place and restore their previous PAM configuration on removal.
