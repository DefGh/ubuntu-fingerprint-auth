#!/bin/sh
set -eu

tests=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
source_dir=${FPRINT_SOURCE_DIR:-$(dirname "$tests")/src}
headers=${PAM_HEADERS:-/usr/include}
scratch=$(mktemp -d /tmp/fprint-parallel-test-XXXXXX)
trap 'rm -rf "$scratch"' EXIT

cp "$tests/pam_run.py" "$tests/verify_parallel.py" "$scratch/"
gcc -D_GNU_SOURCE -std=c17 -O2 -Wall -Wextra -Werror -fPIC -shared -I"$headers" \
    -o "$scratch/pam_fixture.so" "$tests/pam_fixture.c" -l:libpam.so.0
gcc -D_GNU_SOURCE -std=c17 -O2 -Wall -Wextra -Werror -I"$headers" \
    -DLOCAL_PAM_CONFIG=\""$scratch"\" -o "$scratch/verify-fingerprint" \
    "$source_dir/verify_fingerprint.c" -l:libpam.so.0
gcc -D_GNU_SOURCE -DFINGERPRINT_TEST -std=c17 -O2 -Wall -Wextra -Werror -fPIC -shared \
    -I"$headers" -DLOCAL_PAM_CONFIG=\""$scratch"\" \
    -DFINGERPRINT_HELPER=\""$scratch/verify-fingerprint"\" \
    -o "$scratch/pam_fingerprint_parallel.so" "$source_dir/pam_fingerprint_parallel.c" \
    "$source_dir/password_policy.c" -l:libpam.so.0
python3 "$scratch/verify_parallel.py"
