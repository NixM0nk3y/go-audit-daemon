#!/bin/sh

# depends on `fpm`, install via `gem`

VERSION="0.1.0"
BUILD="openenterprise1"
CONTACT="Nick Gregory <github@PLZREMOVEMEopenenterprise.co.uk>"
PACKAGE_NAME="go-audit-daemon"

DIRNAME="$(cd "$(dirname "$0")" && pwd)"
OLDESTPWD="$PWD"

case $(uname -m) in
arm*)
  ARCH="armhf"
  ;;
*)
  ARCH="amd64"
  ;;
esac

go build
rm -f "$PWD/rootfs"
mkdir -p "$PWD/rootfs/usr/local/bin"
mv "$PWD/go-audit-daemon" "$PWD/rootfs/usr/local/bin/"

fakeroot fpm -C "$PWD/rootfs" \
    --license "MIT" \
    --url "https://github.com/NixM0nk3y/go-audit-daemon" \
    --vendor "" \
    --description "go-audit-daemon is an alternative to the auditd daemon that ships with many distros." \
    -d "auditd" \
    -m "${CONTACT}" \
    -n "${PACKAGE_NAME}" -v "$VERSION-$BUILD" \
    -p "$OLDESTPWD/${PACKAGE_NAME}_${VERSION}-${BUILD}_${ARCH}.deb" \
    -s "dir" -t "deb" \
    "usr"
