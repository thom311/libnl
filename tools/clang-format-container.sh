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

IMAGENAME="libnl-code-format-f$FEDORA_VERSION"

ARGS=( "$@" )

if ! podman image exists "$IMAGENAME" ; then
    echo "Building image \"$IMAGENAME\"..."
    podman build \
        --squash-all \
        --tag "$IMAGENAME" \
        -f <(cat <<EOF
FROM fedora:$FEDORA_VERSION
RUN dnf upgrade -y
RUN dnf install -y git /usr/bin/clang-format
EOF
)
fi

CMD=( ./tools/clang-format.sh "${ARGS[@]}" )

podman run \
    --rm \
    --name "libnm-code-format-f$FEDORA_VERSION" \
    -v "$DIR:/tmp/NetworkManager:Z" \
    -w /tmp/NetworkManager \
    -e "_LIBNL_CODE_FORMAT_CONTAINER=$IMAGENAME" \
    -ti \
    "$IMAGENAME" \
    "${CMD[@]}"
