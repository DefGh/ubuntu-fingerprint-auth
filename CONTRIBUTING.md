# Contributing

Run these commands from the repository root on Ubuntu 26.04.

```bash
sudo apt install gcc binutils dpkg-dev libpam0g-dev libpam-modules python3
sh test/run.sh
python3 -B test/test_configure.py
sh src/build.sh dist
```

The synthetic tests check immediate password entry, wrong password rejection, fingerprint success, interaction with the Ubuntu fingerprint profile, and preservation of a mandatory PAM rule. The packaging tests exercise installation, migration, and rollback against temporary configuration files.

Set `FPRINT_TEST_LIVE=1` for the hardware checks. Run them as the user with the enrolled fingerprint and keep other fingerprint authentication prompts closed while the checks run.

```bash
FPRINT_TEST_LIVE=1 sh test/run.sh
```

## ARM64 cross-build

Use an Ubuntu 26.04 build environment with `gcc-aarch64-linux-gnu`, `binutils-aarch64-linux-gnu`, `dpkg-dev`, the ARM64 libc development files, and `libpam0g-dev:arm64`. The ARM64 PAM library must be available under `/usr/lib/aarch64-linux-gnu`.

```bash
TARGET_ARCH=arm64 CC=aarch64-linux-gnu-gcc STRIP=aarch64-linux-gnu-strip \
  sh src/build.sh dist /path/to/libpam/headers
```

The last argument is the directory containing `security/pam_appl.h`. In a build environment where `libpam0g-dev:arm64` installs the headers under `/usr/include`, omit that argument.

## CI and versions

The workflow builds each architecture in an Ubuntu 26.04 container and uploads the `.deb` with a SHA-256 checksum. To prepare a new local version, update the Debian version in `src/build.sh` and record changes in [CHANGELOG.md](CHANGELOG.md). Check the resulting package with `dpkg-deb -I` before tagging it.
