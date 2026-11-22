import os
import pwd
import pty
import select
import shlex
import socket
import subprocess
import sys
import time
from pathlib import Path


root = Path(__file__).resolve().parent
runner = root / "pam_run.py"
module = root / "pam_fingerprint_parallel.so"
fixture = root / "pam_fixture.so"
reader = root / "fingerprint-parallel-reader"
reader_stock = "auth required pam_fprintd.so timeout=-1 max-tries=3\n"
rule = f"auth [success=done ignore=ignore open_err=ignore symbol_err=ignore default=die] {module}\n"
secret = b"test-password-35"
common = root / "common-auth"
password_rules = f"auth [success=1 default=ignore] {fixture}\nauth requisite pam_deny.so\nauth required pam_permit.so\n"
common.write_text(password_rules)

for service in ("sudo", "sudo-i", "polkit-1"):
    (root / service).write_text(rule + "auth required pam_deny.so\n")
(root / "fingerprint-parallel-password").write_text("@include common-auth\n")


def receive(fd, needle, max_wait=5):
    until = time.monotonic() + max_wait
    data = b""
    while needle not in data:
        ready, _, _ = select.select([fd], [], [], max(0, until - time.monotonic()))
        if not ready:
            raise AssertionError((needle, data))
        chunk = os.read(fd, 8192)
        if not chunk:
            raise AssertionError((needle, data, "EOF"))
        data += chunk
    assert secret not in data, "Password echoed"
    return data


def terminal(service, response, expected, delay=0):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(sys.executable, [sys.executable, str(runner), service])
    try:
        receive(fd, b"Password or fingerprint:")
        if delay:
            assert not select.select([fd], [], [], delay)[0], "Prompt ended during idle wait"
            assert_reader_busy()
        if response is not None:
            os.write(fd, response + b"\n" if response != b"\x03" else response)
        receive(fd, f"STATUS={expected}".encode())
        _, status = os.waitpid(pid, 0)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, status
    finally:
        os.close(fd)


def dialog(response, expected, delay=0, disconnect=False):
    agent, helper = socket.socketpair()
    args = [sys.executable, str(runner), "polkit-1"]
    if disconnect:
        args.append("closed")
    proc = subprocess.Popen(args, stdin=helper, stdout=helper,
                            stderr=subprocess.PIPE)
    helper.close()
    try:
        receive(agent.fileno(), b"PAM_PROMPT_ECHO_OFF Password or fingerprint:\n")
        if delay:
            assert not select.select([agent], [], [], delay)[0], "Dialog ended during idle wait"
            assert_reader_busy()
        if response is not None:
            for part in (response[:3], response[3:] + b"\n"):
                agent.sendall(part)
        if disconnect:
            agent.close()
        else:
            receive(agent.fileno(), f"STATUS={expected}".encode())
        errors = proc.communicate(timeout=5)[1]
        assert errors == (f"STATUS={expected}\n".encode() if disconnect else b""), errors
        assert proc.returncode == 0, proc.returncode
    finally:
        agent.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def assert_reader_busy():
    device = shlex.split(subprocess.check_output([
        "busctl", "--timeout=2s", "call", "net.reactivated.Fprint", "/net/reactivated/Fprint/Manager",
        "net.reactivated.Fprint.Manager", "GetDefaultDevice",
    ], text=True))[1]
    claim = subprocess.run([
        "busctl", "--timeout=2s", "call", "net.reactivated.Fprint", device,
        "net.reactivated.Fprint.Device", "Claim", "s", pwd.getpwuid(os.getuid()).pw_name,
    ], capture_output=True, text=True)
    assert claim.returncode != 0 and "claimed" in claim.stderr.lower(), claim.stderr


reader.write_text("auth required pam_deny.so\n")
terminal("sudo", secret, 0)
terminal("sudo-i", b"incorrect", 7)
dialog(secret, 0)
dialog(b"incorrect", 7)

mock_reader = root / "pam_fprintd.so"
mock_reader.unlink(missing_ok=True)
mock_reader.symlink_to(fixture)
trace = root / "fingerprint-called"
trace.unlink(missing_ok=True)
global_rules = f"auth [success=2 default=ignore] {mock_reader} record-finger {trace}\n" + password_rules
common.write_text(global_rules)
terminal("sudo", secret, 0)
dialog(secret, 0)
dialog(b"incorrect", 7)
assert not trace.exists() and common.read_text() == global_rules
print("Password works in both interfaces with the global fingerprint profile enabled", flush=True)

common.write_text(f"auth required {mock_reader} record-finger {trace}\n" + password_rules)
native = subprocess.check_output([sys.executable, str(runner), "sudo"], text=True)
assert native == "STATUS=7\n" and not trace.exists(), native
common.write_text(password_rules)
print("Custom mandatory common-auth rules use the original PAM policy", flush=True)

if os.getenv("FPRINT_TEST_LIVE") == "1":
    reader.write_text(reader_stock)
    dialog(None, 26, delay=12, disconnect=True)
    terminal("sudo", b"\x03", 26, delay=12)
    terminal("sudo", secret, 0)
    print("Real scanner keeps waiting in both interfaces and is released after cancellation", flush=True)

reader.write_text(f"auth required {fixture} simulated-finger\n")
terminal("sudo", None, 0)
dialog(None, 0)
reader.write_text(reader_stock)
print("Fingerprint success completed both interfaces without reading a password", flush=True)
