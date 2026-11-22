# Ubuntu Fingerprint Auth

[Русский README](README.md)

Ubuntu Fingerprint Auth gives interactive `sudo-rs` and GNOME PolicyKit one **Password or fingerprint** prompt on Ubuntu 26.04. You can type your password immediately while `fprintd` listens for your finger. Prompt waiting has no time limit. After three unsuccessful scans, password entry is still available.

## Install and verify

Use Ubuntu 26.04 on `amd64` or `arm64` and a reader that already works with `fprintd`. Enroll a finger with `fprintd-enroll` and verify it with `fprintd-verify`. Pick the build for the architecture printed by `dpkg --print-architecture`.

```bash
sudo apt install ./fingerprint-auth-choice_3.0-1+ubuntu26.04_amd64.deb
sudo -k && sudo -v
pkexec /usr/bin/true
```

The example uses the `amd64` package. Use the `_arm64.deb` build on ARM. Run the two checks separately so each can use the reader.

## Build from source

On Ubuntu 26.04, run from the repository root:

```bash
sudo apt install gcc binutils dpkg-dev libpam0g-dev libpam-modules python3
sh src/build.sh dist
sh test/run.sh
python3 -B test/test_configure.py
```

The build writes a `.deb` to `dist/`. For native and cross builds, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Uninstall

Run `sudo apt remove fingerprint-auth-choice` to restore the previous PAM configuration. If a service was edited after installation, removal keeps the local edits and removes the project's rule. See [architecture](docs/architecture.md) for the managed services and rules.

[Changelog](CHANGELOG.md) · [Security](SECURITY.md) · [MIT license](LICENSE)
