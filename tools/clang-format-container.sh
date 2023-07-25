#!/bin/bash

set -e

die() {
    echo "$@" >&2
    exit 1
}

DIR="$(realpath "$(dirname "$0")/../")"
cd "$DIR"

# The correct clang-format version is the one from the Fedora version used in our
# github action pipeline. Parse it from ".github/workflows/ci.yml".
FEDORA_VERSION="$(sed -n 's/^      image: fedora:\([0-9]\+\)$/\1/p' .github/workflows/ci.yml)"

test -n "$FEDORA_VERSION" || die "Could not detect the Fedora version in .github/workflows/ci.yml"

PODNAME="libnl-code-format-f$FEDORA_VERSION"

RENEW=0
for a; do
    case "$a" in
        -f)
            RENEW=1
            ;;
        *)
            die "invalid argument \"$a\""
            ;;
    esac
done

set -x

if [ "$RENEW" == 1 ]; then
    if podman container exists "$PODNAME" ; then
        podman rm "$PODNAME"
    fi
fi

if ! podman container exists "$PODNAME" ; then
    podman run \
        --name="$PODNAME" \
        -v "$DIR:/tmp/libnl3:Z" \
        -w /tmp/libnl3 \
        "fedora:$FEDORA_VERSION" \
        /bin/bash -c 'dnf upgrade -y && dnf install -y git /usr/bin/clang-format && tools/clang-format.sh -i'
    exit 0
fi

podman start -a "$PODNAME"
