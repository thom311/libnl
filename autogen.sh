#!/bin/bash

set -e

die() {
    echo "$@" >&2
    exit 1
}

BASEDIR="$(dirname "$0")"

cd "$BASEDIR" || die "Could not change into base directory $BASEDIR"

autoreconf -fi || die "Error during autoreconf"
rm -rf autom4te.cache

doc/autogen.sh || die "Error during doc/autogen.sh"
