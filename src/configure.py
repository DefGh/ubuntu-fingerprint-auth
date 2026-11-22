#!/usr/bin/python3
# SPDX-License-Identifier: MIT
import json
import os
import stat
import sys
import tempfile
from pathlib import Path


PAM = Path("/etc/pam.d")
VENDOR_POLKIT = Path("/usr/lib/pam.d/polkit-1")
STATE = Path("/var/lib/fingerprint-auth-choice/originals.json")
LEGACY_RULE = "auth [success=done abort=die conv_err=die default=ignore] pam_fingerprint_choice.so\n"
RULE = "auth [success=done ignore=ignore open_err=ignore symbol_err=ignore default=die] pam_fingerprint_parallel.so\n"
SERVICES = ("sudo", "sudo-i", "polkit-1")


def configured(text):
    lines = text.splitlines(keepends=True)
    if RULE in lines:
        return text
    if LEGACY_RULE in lines:
        lines.remove(LEGACY_RULE)
    include = [line for line in lines if line.split() == ["@include", "common-auth"]]
    if len(include) != 1:
        raise ValueError("Expected one @include common-auth in the PAM configuration")
    for line in lines[:]:
        fields = line.split()
        if len(fields) >= 3 and fields[0] == "auth" and fields[2] == "pam_fprintd.so":
            if fields[1] != "sufficient":
                raise ValueError("Found a custom pam_fprintd policy")
            lines.remove(line)
    index = lines.index(include[0])
    for line in lines[index + 1:]:
        fields = line.split()
        if fields and fields[0] in {"auth", "-auth"}:
            raise ValueError("Unexpected auth rule after common-auth")
    lines.insert(index, RULE)
    return "".join(lines)


def read_config(path):
    if path.is_symlink():
        raise ValueError(f"Unexpected symbolic link {path}")
    if not path.exists():
        return None
    return {"text": path.read_text(), "mode": stat.S_IMODE(path.stat().st_mode)}


def replace(path, text, mode):
    replacement = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", delete=False) as staged:
            replacement = Path(staged.name)
            os.fchmod(staged.fileno(), mode)
            staged.write(text)
        replacement.replace(path)
    finally:
        if replacement is not None:
            replacement.unlink(missing_ok=True)


def install():
    saved = json.loads(STATE.read_text()) if STATE.exists() else {}
    updates = {}
    for service in SERVICES:
        path = PAM / service
        original = read_config(path)
        base = original
        if base is None and service == "polkit-1":
            base = read_config(VENDOR_POLKIT)
        if base is None:
            raise ValueError(f"Configuration not found for {service}")
        text = configured(base["text"])
        if service not in saved:
            saved[service] = {"original": original, "installed": text}
        elif original is not None and original["text"] == saved[service]["installed"]:
            saved[service]["installed"] = text
        if original is None or text != original["text"]:
            updates[path] = (text, base["mode"])

    STATE.parent.mkdir(mode=0o700, exist_ok=True)
    replace(STATE, json.dumps(saved), 0o600)
    for path, (text, mode) in updates.items():
        replace(path, text, mode)


def uninstall():
    if not STATE.exists():
        return
    saved = json.loads(STATE.read_text())
    for service in SERVICES:
        path = PAM / service
        current = read_config(path)
        entry = saved[service]
        if current is None or RULE not in current["text"]:
            continue
        original = entry["original"]
        if current["text"] != entry["installed"]:
            replace(path, current["text"].replace(RULE, ""), current["mode"])
        elif original is None:
            path.unlink()
        else:
            replace(path, original["text"], original["mode"])
    STATE.unlink()
    STATE.parent.rmdir()


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("Administrator privileges are required")
    try:
        if sys.argv[1:] == ["install"]:
            install()
        elif sys.argv[1:] == ["remove"]:
            uninstall()
        else:
            sys.exit("Usage: configure.py install|remove")
    except (OSError, ValueError) as error:
        sys.exit(str(error))
