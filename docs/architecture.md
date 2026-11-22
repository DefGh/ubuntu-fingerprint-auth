# Architecture

The Debian package installs a PAM module for the `sudo`, `sudo-i` and `polkit-1` services. It runs before the service's `common-auth` include. The normal account and session stacks still run after authentication. The package also installs a sudoers drop-in with `passwd_timeout=0`.

## Authentication paths

1. The module presents a password prompt immediately and starts a separate fingerprint verifier process. Interactive `sudo-rs` uses the controlling terminal. The GNOME PolicyKit agent receives the prompt over the stock helper's Unix socket.
2. The verifier runs stock `pam_fprintd` for the same PAM user, with `timeout=-1` and `max-tries=3`. It returns success only after stock PAM reports a match. The module watches the verifier and password input together.
3. A submitted password is checked by a separate PAM transaction against `common-auth`. A standard alternative `pam_fprintd` rule already enabled through `pam-auth-update` is skipped in a private copy of that policy. The copy preserves rule ordering and numeric jumps, contains policy text only, and is removed when verification ends.
4. A matching fingerprint completes the request without a password. Submitting a password, pressing `Ctrl+C` in the terminal, or closing the graphical dialog cancels the pending fingerprint verification and releases the reader. Terminal settings are restored before returning.

An unavailable or unconfigured reader leaves password entry available. Explicit stdin, askpass and noninteractive `sudo` modes use the native conversation. A custom mandatory rule in `common-auth` is left to the standard PAM path.

## Package lifecycle

`src/configure.py` stores the original service files in `/var/lib/fingerprint-auth-choice/originals.json`. Installation replaces earlier rules from this project and is repeatable. Removal restores the originals if the service files still match the installed versions. For a locally edited service file, it removes the project's rule and preserves the other edits.

The package ID is `fingerprint-auth-choice` so existing installations upgrade in place. Each binary package also contains its own buildable `source.tar.gz` under `/usr/share/doc/fingerprint-auth-choice/`.
