#!/bin/bash

set -e

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

EXCLUDE_PATHS_TOPLEVEL=(
    "include/linux-private"
)

# The following files are currently not formatted with clang.
# Exclude them too.
EXCLUDE_PATHS_TOPLEVEL+=(
    "include/netlink/addr.h"
    "include/netlink/attr.h"
    "include/netlink/cache-api.h"
    "include/netlink/cache.h"
    "include/netlink/cli/addr.h"
    "include/netlink/cli/cls.h"
    "include/netlink/cli/link.h"
    "include/netlink/cli/mdb.h"
    "include/netlink/cli/neigh.h"
    "include/netlink/cli/qdisc.h"
    "include/netlink/cli/route.h"
    "include/netlink/cli/tc.h"
    "include/netlink/cli/utils.h"
    "include/netlink/data.h"
    "include/netlink/errno.h"
    "include/netlink/fib_lookup/lookup.h"
    "include/netlink/fib_lookup/request.h"
    "include/netlink/genl/ctrl.h"
    "include/netlink/genl/family.h"
    "include/netlink/genl/genl.h"
    "include/netlink/genl/mngt.h"
    "include/netlink/handlers.h"
    "include/netlink/hash.h"
    "include/netlink/hashtable.h"
    "include/netlink/idiag/idiagnl.h"
    "include/netlink/idiag/meminfo.h"
    "include/netlink/idiag/msg.h"
    "include/netlink/idiag/req.h"
    "include/netlink/idiag/vegasinfo.h"
    "include/netlink/list.h"
    "include/netlink/msg.h"
    "include/netlink/netfilter/ct.h"
    "include/netlink/netfilter/exp.h"
    "include/netlink/netfilter/log.h"
    "include/netlink/netfilter/log_msg.h"
    "include/netlink/netfilter/netfilter.h"
    "include/netlink/netfilter/nfnl.h"
    "include/netlink/netfilter/queue.h"
    "include/netlink/netfilter/queue_msg.h"
    "include/netlink/netlink-compat.h"
    "include/netlink/netlink-kernel.h"
    "include/netlink/netlink.h"
    "include/netlink/object.h"
    "include/netlink/route/act/skbedit.h"
    "include/netlink/route/action.h"
    "include/netlink/route/addr.h"
    "include/netlink/route/class.h"
    "include/netlink/route/classifier.h"
    "include/netlink/route/cls/basic.h"
    "include/netlink/route/cls/cgroup.h"
    "include/netlink/route/cls/ematch.h"
    "include/netlink/route/cls/ematch/cmp.h"
    "include/netlink/route/cls/ematch/meta.h"
    "include/netlink/route/cls/ematch/nbyte.h"
    "include/netlink/route/cls/ematch/text.h"
    "include/netlink/route/cls/flower.h"
    "include/netlink/route/cls/fw.h"
    "include/netlink/route/cls/matchall.h"
    "include/netlink/route/cls/police.h"
    "include/netlink/route/cls/u32.h"
    "include/netlink/route/link.h"
    "include/netlink/route/link/api.h"
    "include/netlink/route/link/bonding.h"
    "include/netlink/route/link/bridge.h"
    "include/netlink/route/link/can.h"
    "include/netlink/route/link/geneve.h"
    "include/netlink/route/link/inet.h"
    "include/netlink/route/link/inet6.h"
    "include/netlink/route/link/info-api.h"
    "include/netlink/route/link/ip6gre.h"
    "include/netlink/route/link/ip6tnl.h"
    "include/netlink/route/link/ip6vti.h"
    "include/netlink/route/link/ipgre.h"
    "include/netlink/route/link/ipip.h"
    "include/netlink/route/link/ipvlan.h"
    "include/netlink/route/link/ipvti.h"
    "include/netlink/route/link/macsec.h"
    "include/netlink/route/link/macvlan.h"
    "include/netlink/route/link/macvtap.h"
    "include/netlink/route/link/ppp.h"
    "include/netlink/route/link/sit.h"
    "include/netlink/route/link/sriov.h"
    "include/netlink/route/link/team.h"
    "include/netlink/route/link/vlan.h"
    "include/netlink/route/link/vxlan.h"
    "include/netlink/route/link/xfrmi.h"
    "include/netlink/route/mdb.h"
    "include/netlink/route/neighbour.h"
    "include/netlink/route/neightbl.h"
    "include/netlink/route/netconf.h"
    "include/netlink/route/nexthop.h"
    "include/netlink/route/pktloc.h"
    "include/netlink/route/qdisc.h"
    "include/netlink/route/qdisc/cbq.h"
    "include/netlink/route/qdisc/dsmark.h"
    "include/netlink/route/qdisc/fifo.h"
    "include/netlink/route/qdisc/fq_codel.h"
    "include/netlink/route/qdisc/hfsc.h"
    "include/netlink/route/qdisc/htb.h"
    "include/netlink/route/qdisc/mqprio.h"
    "include/netlink/route/qdisc/netem.h"
    "include/netlink/route/qdisc/plug.h"
    "include/netlink/route/qdisc/prio.h"
    "include/netlink/route/qdisc/red.h"
    "include/netlink/route/qdisc/sfq.h"
    "include/netlink/route/route.h"
    "include/netlink/route/rtnl.h"
    "include/netlink/route/rule.h"
    "include/netlink/route/tc-api.h"
    "include/netlink/route/tc.h"
    "include/netlink/socket.h"
    "include/netlink/types.h"
    "include/netlink/utils.h"
    "include/netlink/xfrm/ae.h"
    "include/netlink/xfrm/lifetime.h"
    "include/netlink/xfrm/sa.h"
    "include/netlink/xfrm/selector.h"
    "include/netlink/xfrm/sp.h"
    "include/netlink/xfrm/template.h"
    "include/nl-priv-dynamic-core/cache-api.h"
    "include/nl-priv-dynamic-core/object-api.h"
    "lib/addr.c"
    "lib/attr.c"
    "lib/cache.c"
    "lib/cache_mngr.c"
    "lib/cache_mngt.c"
    "lib/cli/cls/basic.c"
    "lib/cli/cls/cgroup.c"
    "lib/cli/qdisc/bfifo.c"
    "lib/cli/qdisc/blackhole.c"
    "lib/cli/qdisc/fq_codel.c"
    "lib/cli/qdisc/hfsc.c"
    "lib/cli/qdisc/htb.c"
    "lib/cli/qdisc/ingress.c"
    "lib/cli/qdisc/pfifo.c"
    "lib/cli/qdisc/plug.c"
    "lib/data.c"
    "lib/error.c"
    "lib/fib_lookup/lookup.c"
    "lib/fib_lookup/request.c"
    "lib/genl/ctrl.c"
    "lib/genl/family.c"
    "lib/genl/genl.c"
    "lib/genl/mngt.c"
    "lib/genl/nl-genl.h"
    "lib/handlers.c"
    "lib/hash.c"
    "lib/hashtable.c"
    "lib/idiag/idiag.c"
    "lib/idiag/idiag_meminfo_obj.c"
    "lib/idiag/idiag_msg_obj.c"
    "lib/idiag/idiag_req_obj.c"
    "lib/idiag/idiag_vegasinfo_obj.c"
    "lib/mpls.c"
    "lib/mpls.h"
    "lib/msg.c"
    "lib/netfilter/ct.c"
    "lib/netfilter/ct_obj.c"
    "lib/netfilter/exp.c"
    "lib/netfilter/exp_obj.c"
    "lib/netfilter/log.c"
    "lib/netfilter/log_msg.c"
    "lib/netfilter/log_msg_obj.c"
    "lib/netfilter/log_obj.c"
    "lib/netfilter/netfilter.c"
    "lib/netfilter/nfnl.c"
    "lib/netfilter/queue.c"
    "lib/netfilter/queue_msg.c"
    "lib/netfilter/queue_msg_obj.c"
    "lib/netfilter/queue_obj.c"
    "lib/nl-core.h"
    "lib/nl.c"
    "lib/object.c"
    "lib/route/act.c"
    "lib/route/act/gact.c"
    "lib/route/act/mirred.c"
    "lib/route/act/skbedit.c"
    "lib/route/act/vlan.c"
    "lib/route/addr.c"
    "lib/route/class.c"
    "lib/route/classid.c"
    "lib/route/cls.c"
    "lib/route/cls/basic.c"
    "lib/route/cls/cgroup.c"
    "lib/route/cls/ematch.c"
    "lib/route/cls/ematch/cmp.c"
    "lib/route/cls/ematch/container.c"
    "lib/route/cls/ematch/meta.c"
    "lib/route/cls/ematch/nbyte.c"
    "lib/route/cls/ematch/text.c"
    "lib/route/cls/flower.c"
    "lib/route/cls/fw.c"
    "lib/route/cls/mall.c"
    "lib/route/cls/police.c"
    "lib/route/cls/u32.c"
    "lib/route/link-sriov.h"
    "lib/route/link.c"
    "lib/route/link/api.c"
    "lib/route/link/bonding.c"
    "lib/route/link/bridge.c"
    "lib/route/link/can.c"
    "lib/route/link/dummy.c"
    "lib/route/link/geneve.c"
    "lib/route/link/ifb.c"
    "lib/route/link/inet.c"
    "lib/route/link/inet6.c"
    "lib/route/link/ip6gre.c"
    "lib/route/link/ip6tnl.c"
    "lib/route/link/ip6vti.c"
    "lib/route/link/ipgre.c"
    "lib/route/link/ipip.c"
    "lib/route/link/ipvlan.c"
    "lib/route/link/ipvti.c"
    "lib/route/link/link-api.h"
    "lib/route/link/macsec.c"
    "lib/route/link/macvlan.c"
    "lib/route/link/ppp.c"
    "lib/route/link/sit.c"
    "lib/route/link/sriov.c"
    "lib/route/link/team.c"
    "lib/route/link/veth.c"
    "lib/route/link/vlan.c"
    "lib/route/link/vrf.c"
    "lib/route/link/vxlan.c"
    "lib/route/link/xfrmi.c"
    "lib/route/mdb.c"
    "lib/route/neigh.c"
    "lib/route/netconf.c"
    "lib/route/nexthop-encap.h"
    "lib/route/nexthop.c"
    "lib/route/nexthop_encap.c"
    "lib/route/nh_encap_mpls.c"
    "lib/route/pktloc.c"
    "lib/route/qdisc.c"
    "lib/route/qdisc/blackhole.c"
    "lib/route/qdisc/cbq.c"
    "lib/route/qdisc/dsmark.c"
    "lib/route/qdisc/fifo.c"
    "lib/route/qdisc/fq_codel.c"
    "lib/route/qdisc/hfsc.c"
    "lib/route/qdisc/htb.c"
    "lib/route/qdisc/ingress.c"
    "lib/route/qdisc/mqprio.c"
    "lib/route/qdisc/netem.c"
    "lib/route/qdisc/plug.c"
    "lib/route/qdisc/prio.c"
    "lib/route/qdisc/red.c"
    "lib/route/qdisc/sfq.c"
    "lib/route/qdisc/tbf.c"
    "lib/route/route.c"
    "lib/route/route_obj.c"
    "lib/route/route_utils.c"
    "lib/route/rtnl.c"
    "lib/route/rule.c"
    "lib/route/tc-api.h"
    "lib/route/tc.c"
    "lib/socket.c"
    "lib/utils.c"
    "lib/version.c"
    "lib/xfrm/ae.c"
    "lib/xfrm/lifetime.c"
    "lib/xfrm/sa.c"
    "lib/xfrm/selector.c"
    "lib/xfrm/sp.c"
    "lib/xfrm/template.c"
    "python/netlink/utils.h"
    "src/genl-ctrl-list.c"
    "src/idiag-socket-details.c"
    "src/lib/addr.c"
    "src/lib/cls.c"
    "src/lib/ct.c"
    "src/lib/exp.c"
    "src/lib/link.c"
    "src/lib/neigh.c"
    "src/lib/route.c"
    "src/lib/tc.c"
    "src/lib/utils.c"
    "src/nf-ct-add.c"
    "src/nf-ct-events.c"
    "src/nf-ct-list.c"
    "src/nf-exp-add.c"
    "src/nf-exp-delete.c"
    "src/nf-exp-list.c"
    "src/nf-log.c"
    "src/nf-monitor.c"
    "src/nf-queue.c"
    "src/nl-addr-add.c"
    "src/nl-addr-delete.c"
    "src/nl-addr-list.c"
    "src/nl-class-add.c"
    "src/nl-class-delete.c"
    "src/nl-class-list.c"
    "src/nl-classid-lookup.c"
    "src/nl-cls-add.c"
    "src/nl-cls-delete.c"
    "src/nl-cls-list.c"
    "src/nl-fib-lookup.c"
    "src/nl-link-enslave.c"
    "src/nl-link-list.c"
    "src/nl-link-release.c"
    "src/nl-link-set.c"
    "src/nl-link-stats.c"
    "src/nl-list-caches.c"
    "src/nl-list-sockets.c"
    "src/nl-monitor.c"
    "src/nl-neigh-add.c"
    "src/nl-neigh-delete.c"
    "src/nl-neigh-list.c"
    "src/nl-neightbl-list.c"
    "src/nl-pktloc-lookup.c"
    "src/nl-qdisc-add.c"
    "src/nl-qdisc-delete.c"
    "src/nl-qdisc-list.c"
    "src/nl-route-add.c"
    "src/nl-route-delete.c"
    "src/nl-route-get.c"
    "src/nl-route-list.c"
    "src/nl-rule-list.c"
    "src/nl-tctree-list.c"
    "src/nl-util-addr.c"
    "tests/test-cache-mngr.c"
    "tests/test-complex-HTB-with-hash-filters.c"
    "tests/test-create-bridge.c"
    "tests/test-create-geneve.c"
    "tests/test-create-ip6tnl.c"
    "tests/test-create-ipgre.c"
    "tests/test-create-ipgretap.c"
    "tests/test-create-ipip.c"
    "tests/test-create-ipvti.c"
    "tests/test-create-macsec.c"
    "tests/test-create-macvlan.c"
    "tests/test-create-macvtap.c"
    "tests/test-create-sit.c"
    "tests/test-create-veth.c"
    "tests/test-create-xfrmi.c"
    "tests/test-genl.c"
    "tests/test-nf-cache-mngr.c"
    "tests/test-socket-creation.c"
    "tests/test-u32-filter-with-actions.c"
)

DIR_ROOT="$(git rev-parse --show-toplevel)" || die "not inside a git repository"
DIR_PREFIX="$(git rev-parse --show-prefix)" || die "not inside a git repository"

if [ ! -f "$DIR_ROOT/.clang-format" ]; then
    die "Error: the clang-format file in \"$DIR_ROOT\" does not exist"
fi

if ! command -v clang-format &> /dev/null; then
    die "Error: clang-format is not installed. On RHEL/Fedora/CentOS run 'dnf install clang-tools-extra'"
fi

if test -n "$DIR_PREFIX"; then
    EXCLUDE_PATHS=()
    for e in "${EXCLUDE_PATHS_TOPLEVEL[@]}"; do
        REGEX="^$DIR_PREFIX([^/].*)$"
        if [[ "$e" =~ $REGEX ]]; then
            EXCLUDE_PATHS+=("${BASH_REMATCH[1]}")
        fi
    done
else
    EXCLUDE_PATHS=("${EXCLUDE_PATHS_TOPLEVEL[@]}")
fi

FILES=()
HAS_EXPLICIT_FILES=0
SHOW_FILENAMES=0
TEST_ONLY=0
CHECK_UPSTREAM=

usage() {
    printf "Usage: %s [OPTION]... [FILE]...\n" "$(basename "$0")"
    printf "Reformat source files using clang-format.\n\n"
    printf "If no file is given the script runs on the whole codebase.\n"
    printf "OPTIONS:\n"
    printf "    -h                    Print this help message.\n"
    printf "    -i                    Reformat files (the default).\n"
    printf "    -n|--dry-run          Only check the files (contrary to \"-i\").\n"
    printf "    -a|--all              Check all files (the default).\n"
    printf "    -u|--upstream COMMIT  Check only files from \`git diff --name-only COMMIT\` (contrary to \"-a\").\n"
    printf "                          This also affects directories given in the [FILE] list, but not files.\n"
    printf "                          If this is the last parameter and COMMIT is unspecified/empty, it defaults to \"main\".\n"
    printf "    -F|--fast             Same as \`-u HEAD^\`.\n"
    printf "    -l|--show-filenames   Only print the filenames that would be checked/formatted\n"
    printf "    --                    Separate options from filenames/directories\n"
    if [ -n "${_LIBNL_CODE_FORMAT_CONTAINER+x}" ] ; then
        printf "\n"
        printf "Command runs inside container image \"$_LIBNL_CODE_FORMAT_CONTAINER\".\n"
        printf "Delete/renew image with \`podman rmi \"$_LIBNL_CODE_FORMAT_CONTAINER\"\`.\n"
    fi
}

ls_files_exist() {
    local OLD_IFS="$IFS"
    local f

    IFS=$'\n'
    for f in $(cat) ; do
        test -f "$f" && printf '%s\n' "$f"
    done
    IFS="$OLD_IFS"
}

ls_files_filter() {
    local OLD_IFS="$IFS"
    local f

    IFS=$'\n'
    for f in $(cat) ; do
        local found=1
        local p
        for p; do
            [[ "$f" = "$p/"* ]] && found=
            [[ "$f" = "$p" ]] && found=
        done
        test -n "$found" && printf '%s\n' "$f"
    done
    IFS="$OLD_IFS"
}

g_ls_files() {
    local pattern="$1"
    shift

    if [ -z "$CHECK_UPSTREAM" ]; then
        git ls-files -- "$pattern"
    else
        git diff --no-renames --name-only "$CHECK_UPSTREAM" -- "$pattern" \
            | ls_files_exist
    fi | ls_files_filter "$@"
}

HAD_DASHDASH=0
while (( $# )); do
    if [ "$HAD_DASHDASH" = 0 ]; then
        case "$1" in
            -h)
                usage
                exit 0
                ;;
            -l|--show-filenames)
                SHOW_FILENAMES=1
                shift
                continue
                ;;
            -a|--all)
                CHECK_UPSTREAM=
                shift
                continue
                ;;
            -u|--upstream)
                shift
                CHECK_UPSTREAM="$1"
                test -n "$CHECK_UPSTREAM" || CHECK_UPSTREAM=main
                shift || :
                continue
                ;;
            -F|--fast)
                CHECK_UPSTREAM='HEAD^'
                shift
                continue
                ;;
            -n|--dry-run)
                TEST_ONLY=1
                shift
                continue
                ;;
            -i)
                TEST_ONLY=0
                shift
                continue
                ;;
            --)
                HAD_DASHDASH=1
                shift
                continue
                ;;
        esac
    fi
    if [ -d "$1" ]; then
        while IFS='' read -r line;
            do FILES+=("$line")
        done < <(CHECK_UPSTREAM="$CHECK_UPSTREAM" g_ls_files "${1}/*.[hc]" "${EXCLUDE_PATHS[@]}")
    elif [ -f "$1" ]; then
        FILES+=("$1")
    else
        usage >&2
        echo >&2
        die "Unknown argument \"$1\" which also is neither a file nor a directory."
    fi
    shift
    HAS_EXPLICIT_FILES=1
done

if [ $HAS_EXPLICIT_FILES = 0 ]; then
    while IFS='' read -r line; do
        FILES+=("$line")
    done < <(CHECK_UPSTREAM="$CHECK_UPSTREAM" g_ls_files '*.[ch]' "${EXCLUDE_PATHS[@]}")
fi

if [ $SHOW_FILENAMES = 1 ]; then
    for f in "${FILES[@]}" ; do
        printf '%s\n' "$f"
    done
    exit 0
fi

if [ "${#FILES[@]}" = 0 ]; then
    if [ -z "$CHECK_UPSTREAM" ]; then
        die "Error: no files to check"
    fi
    exit 0
fi

FLAGS_TEST=( --Werror -n --ferror-limit=1 )

if [ $TEST_ONLY = 1 ]; then
    # We assume that all formatting is correct. In that mode, passing
    # all filenames to clang-format is significantly faster.
    #
    # Only in case of an error, we iterate over the files one by one
    # until we find the first invalid file.
    for f in "${FILES[@]}"; do
        [ -f "$f" ] || die "Error: file \"$f\" does not exist (or is not a regular file)"
    done
    clang-format "${FLAGS_TEST[@]}" "${FILES[@]}" &>/dev/null && exit 0
    for f in "${FILES[@]}"; do
        [ -f "$f" ] || die "Error: file \"$f\" does not exist (or is not a regular file)"
        if ! clang-format "${FLAGS_TEST[@]}" "$f" &>/dev/null; then
            FF="$(mktemp)"
            trap 'rm -f "$FF"' EXIT
            clang-format "$f" 2>/dev/null > "$FF"
            git --no-pager diff "$f" "$FF" || :
            FEDORA_VERSION="$(sed -n 's/^      image: fedora:\([0-9]\+\)$/\1/p' .github/workflows/ci.yml)"
            die "Error: file \"$f\" has style issues."$'\n'"Fix it by running \`\"$0\"\` using $(clang-format --version)
Alternatively, run \`./tools/clang-format-container.sh\` to use a podman container named \"libnl-code-format-f$FEDORA_VERSION\"."
        fi
    done
    die "an unknown error happened."
fi

clang-format -i "${FILES[@]}"
