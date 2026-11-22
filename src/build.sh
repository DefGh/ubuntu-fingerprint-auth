#!/bin/sh
set -eu
umask 022

source_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
output_dir=${1:-"$PWD"}
headers=${2:-/usr/include}
arch=${TARGET_ARCH:-$(dpkg-architecture -qDEB_HOST_ARCH)}
multiarch=$(dpkg-architecture -a "$arch" -qDEB_HOST_MULTIARCH)
compiler=${CC:-gcc}
strip_tool=${STRIP:-strip}
case "$arch" in
  amd64) branch_protection=-fcf-protection ;;
  arm64) branch_protection=-mbranch-protection=standard ;;
  *) printf '%s\n' "Unsupported architecture: $arch" >&2; exit 2 ;;
esac
mkdir -p "$output_dir"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
chmod 0755 "$stage"

name=fingerprint-auth-choice
version=3.0-1+ubuntu26.04
module_dir="$stage/usr/lib/$multiarch/security"
support="$stage/usr/lib/$name"
docs="$stage/usr/share/doc/$name"

mkdir -p "$module_dir" "$support" "$stage/DEBIAN" "$docs"
"$compiler" -D_GNU_SOURCE -D_FORTIFY_SOURCE=3 -std=c17 -O2 -Wall -Wextra -Werror \
  -fPIC -shared -fstack-protector-strong -fstack-clash-protection "$branch_protection" \
  -I"$headers" -L"/usr/lib/$multiarch" -Wl,-z,defs,-z,relro,-z,now \
  -o "$module_dir/pam_fingerprint_parallel.so" "$source_dir/pam_fingerprint_parallel.c" \
  "$source_dir/password_policy.c" -l:libpam.so.0
"$compiler" -D_GNU_SOURCE -D_FORTIFY_SOURCE=3 -std=c17 -O2 -Wall -Wextra -Werror \
  -fPIE -pie -fstack-protector-strong -fstack-clash-protection "$branch_protection" \
  -I"$headers" -L"/usr/lib/$multiarch" -Wl,-z,defs,-z,relro,-z,now \
  -o "$support/verify-fingerprint" "$source_dir/verify_fingerprint.c" -l:libpam.so.0
"$strip_tool" --strip-unneeded "$module_dir/pam_fingerprint_parallel.so" "$support/verify-fingerprint"

cat > "$stage/DEBIAN/control" <<EOF
Package: $name
Version: $version
Architecture: $arch
Maintainer: Local build
Section: admin
Priority: optional
Depends: libc6 (>= 2.36), libpam0g (>= 1.4), libpam-fprintd, python3, polkitd (>= 127), sudo-rs
Description: Concurrent password and fingerprint for sudo and PolicyKit
 Starts fingerprint verification while the password prompt is open.
 Both methods use the platform PAM verifiers, with no prompt timeout.
EOF
install -m755 "$source_dir/postinst" "$source_dir/prerm" "$stage/DEBIAN/"
install -Dm644 "$source_dir/configure.py" "$stage/usr/lib/$name/configure.py"
install -Dm644 "$source_dir/fingerprint-parallel-reader" "$stage/etc/pam.d/fingerprint-parallel-reader"
install -m644 "$source_dir/fingerprint-parallel-password" "$stage/etc/pam.d/fingerprint-parallel-password"
mkdir -p "$stage/etc/sudoers.d"
printf '%s\n' 'Defaults passwd_timeout=0' > "$stage/etc/sudoers.d/90-fingerprint-auth-choice"
chmod 0440 "$stage/etc/sudoers.d/90-fingerprint-auth-choice"
printf '%s\n' /etc/pam.d/fingerprint-parallel-reader /etc/pam.d/fingerprint-parallel-password > "$stage/DEBIAN/conffiles"
install -m644 "$source_dir/README" "$source_dir/LICENSE" "$docs/"
tar -czf "$docs/source.tar.gz" -C "$source_dir" README LICENSE build.sh configure.py \
  fingerprint-parallel-reader fingerprint-parallel-password pam_fingerprint_parallel.c pam_verify.h \
  password_policy.c password_policy.h verify_fingerprint.c postinst prerm
dpkg-deb --root-owner-group --build "$stage" "$output_dir/${name}_${version}_${arch}.deb"
