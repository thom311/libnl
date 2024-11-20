#!/usr/bin/env bash

set -e

print_and_exit() {
	local err="$1"
	shift
	printf '%s\n' "$*"
	exit "$err"
}

die() {
	print_and_exit 1 "$@"
}

command -v meson &>/dev/null || print_and_exit 0 "$0: skip: meson not available"
command -v ninja &>/dev/null || print_and_exit 0 "$0: skip: ninja not available"

BUILDDIR="$PWD"
SRCDIR="$(dirname "$0")/.."

_BUILDDIR="$BUILDDIR/build-c-list"
_SRCDIR="$SRCDIR/third_party/c-list"

if [ ! -d "$_BUILDDIR" ] ; then
    meson setup "$_BUILDDIR" "$_SRCDIR" || die "meson failed"
    ninja -C "$_BUILDDIR" || die "failed build"
fi

ninja -C "$_BUILDDIR" test || die "c-list tests failed"
