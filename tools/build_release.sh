#!/bin/bash

# script to create libnl release.
# Steps:
# - create new commit, bumping version number
# - run this script
# - check all is good
# - tag the commit (signed)
#     git tag -m 'libnl-3.2.26-rc1' -s libnl3_2_26rc1 HEAD
# - publish the tarballs
# - push the commit to github
# - publish the tag on github
# - publish the tarballs on github
# - send ANN email


die() {
    printf '%s\n' "$@"
    exit 1
}

set -x
set -e

cd "$(dirname "$0")/.."
git_dir="$(readlink -f "$(git rev-parse --show-toplevel)")"
test -f "$git_dir/tools/build_release.sh"

Build() {
    test "$(git status --porcelain)" = "" || die "there are uncommited changes"
    git clean -fdx
    ./autogen.sh
    ./configure
    pushd ./doc/
        ./autogen.sh
        ./configure --enable-doc
    popd
    make -j 5
    make -C doc
    make -C doc gendoc
    make -j 5 distcheck
    make -C doc dist
    echo "Build: success"
}

Copy() {
    local V="$(ls -1 ./libnl-*.tar.gz | sed -n 's/^\.\/libnl-\(3\.[0-9]\+\.[0-9]\+\(-rc[0-9]\)\?\).tar.gz$/\1/p')"
    test -n "$V"
    local REL="libnl-$V"
    rm -rf "./$REL"
    mkdir "./$REL"
    ln "./libnl-$V.tar.gz" "./$REL/"
    ln "./doc/libnl-doc-$V.tar.gz" "./$REL/"
    (
        cd "./$REL/"
        for F in "libnl-$V.tar.gz" "libnl-doc-$V.tar.gz"; do
            md5sum "./$F" > "./$F.md5sum"
            sha256sum "./$F" > "./$F.sha256sum"
            gpg ${GPG_USER--u thaller@redhat.com} --armor --verbose -o "./$F.sig" --detach-sign "./$F"
        done
    )
    tar -cvf "./$REL.tar" "./$REL/"
    echo "Copy: success"
}

BuildAll() {
     Build || return
     Copy || return
     echo "BuildAll: success"
}

case "$1" in
    Build)
        Build
        ;;
    Copy)
        Copy
        ;;
    BuildAll)
        BuildAll
        ;;
    *)
        echo "SYNOPSIS: $0 Build|Copy|BuildAll"
        echo "WARNING: does a git-clean first!!"
        ;;
esac
