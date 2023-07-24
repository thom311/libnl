#!/bin/bash

set -e

BASEDIR="$(dirname "$0")"

cd "$BASEDIR" || die "Could not change into base directory $BASEDIR"

autoreconf -fi
rm -rf autom4te.cache
