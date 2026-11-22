import ctypes as C
import os
import pwd
import sys
import termios
from pathlib import Path


class Conv(C.Structure):
    _fields_ = [("callback", C.c_void_p), ("data", C.c_void_p)]


callback = C.CFUNCTYPE(C.c_int, C.c_int, C.c_void_p, C.c_void_p, C.c_void_p)(lambda *_: 19)
conv = Conv(C.cast(callback, C.c_void_p), None)
pam = C.CDLL("libpam.so.0")
pam.pam_start_confdir.argtypes = [C.c_char_p, C.c_char_p, C.POINTER(Conv), C.c_char_p, C.POINTER(C.c_void_p)]
pam.pam_authenticate.argtypes = [C.c_void_p, C.c_int]
pam.pam_end.argtypes = [C.c_void_p, C.c_int]
root = Path(__file__).resolve().parent
handle = C.c_void_p()
original_tty = termios.tcgetattr(0) if os.isatty(0) else None
assert pam.pam_start_confdir(sys.argv[1].encode(), pwd.getpwuid(os.getuid()).pw_name.encode(),
                             C.byref(conv), os.fsencode(root), C.byref(handle)) == 0
status = pam.pam_authenticate(handle, 0)
pam.pam_end(handle, status)
if original_tty is not None:
    assert termios.tcgetattr(0) == original_tty, "Terminal settings must be restored"
print(f"STATUS={status}", file=sys.stderr if sys.argv[2:] == ["closed"] else sys.stdout, flush=True)
