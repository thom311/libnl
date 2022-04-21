/* SPDX-License-Identifier: LGPL-2.1-only */

#include "nl-test-util.h"

#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>

#include "netlink-private/utils.h"
#include "netlink/netlink.h"
#include "netlink/route/link.h"
#include "netlink/socket.h"

/*****************************************************************************/

#define _CANARY 539339

struct nltst_netns {
	int canary;
};

/*****************************************************************************/

#define _assert_nltst_netns(nsdata)                                            \
	do {                                                                   \
		const struct nltst_netns *_nsdata = (nsdata);                  \
                                                                               \
		ck_assert_ptr_nonnull(_nsdata);                                \
		ck_assert_int_eq(_nsdata->canary, _CANARY);                    \
	} while (0)

static struct {
	struct nltst_netns *nsdata;
} _netns_fixture_global;

void nltst_netns_fixture_setup(void)
{
	ck_assert(!_netns_fixture_global.nsdata);

	_netns_fixture_global.nsdata = nltst_netns_enter();
	_assert_nltst_netns(_netns_fixture_global.nsdata);
}

void nltst_netns_fixture_teardown(void)
{
	_assert_nltst_netns(_netns_fixture_global.nsdata);
	_nl_clear_pointer(&_netns_fixture_global.nsdata, nltst_netns_leave);
}

/*****************************************************************************/

static void unshare_user(void)
{
	const uid_t uid = geteuid();
	const gid_t gid = getegid();
	FILE *f;
	int r;

	/* Become a root in new user NS. */
	r = unshare(CLONE_NEWUSER);
	_nltst_assert_errno(r == 0);

	/* Since Linux 3.19 we have to disable setgroups() in order to map users.
	 * Just proceed if the file is not there. */
	f = fopen("/proc/self/setgroups", "we");
	if (f) {
		r = fprintf(f, "deny");
		_nltst_assert_errno(r > 0);
		_nltst_fclose(f);
	}

	/* Map current UID to root in NS to be created. */
	f = fopen("/proc/self/uid_map", "we");
	_nltst_assert_errno(f);
	r = fprintf(f, "0 %d 1", uid);
	_nltst_assert_errno(r > 0);
	_nltst_fclose(f);

	/* Map current GID to root in NS to be created. */
	f = fopen("/proc/self/gid_map", "we");
	_nltst_assert_errno(f);
	r = fprintf(f, "0 %d 1", gid);
	_nltst_assert_errno(r > 0);
	_nltst_fclose(f);
}

struct nltst_netns *nltst_netns_enter(void)
{
	struct nltst_netns *nsdata;
	int r;

	nsdata = calloc(1, sizeof(struct nltst_netns));
	ck_assert(nsdata);

	nsdata->canary = _CANARY;

	unshare_user();

	r = unshare(CLONE_NEWNET | CLONE_NEWNS);
	_nltst_assert_errno(r == 0);

	/* We need a read-only /sys so that the platform knows there's no udev. */
	mount(NULL, "/sys", "sysfs", MS_SLAVE, NULL);
	r = mount("sys", "/sys", "sysfs", MS_RDONLY, NULL);
	_nltst_assert_errno(r == 0);

	return nsdata;
}

void nltst_netns_leave(struct nltst_netns *nsdata)
{
	ck_assert(nsdata);
	ck_assert_int_eq(nsdata->canary, _CANARY);

	/* nltst_netns_leave() was supposed to enter the original namespaces again
	 * and undo enter.
	 *
	 * However, I could get it to work (setns() always fails with EPERM)
	 * and valgrind on current Ubuntu seems not to support setns() call.
	 *
	 * So, do nothing. It's not really a problem, because the next test
	 * either should unshare yet another namespace, or not care about
	 * such things. */

	free(nsdata);
}

/*****************************************************************************/

void _nltst_object_identical(const void *a, const void *b)
{
	struct nl_object *o_a = (void *)a;
	struct nl_object *o_b = (void *)b;

	ck_assert(a);
	ck_assert(b);

	ck_assert_int_eq(nl_object_identical(o_a, o_b), 1);
	ck_assert_int_eq(nl_object_identical(o_b, o_a), 1);
	ck_assert_int_eq(nl_object_diff64(o_b, o_a), 0);
	ck_assert_int_eq(nl_object_diff64(o_a, o_b), 0);
	ck_assert_int_eq(nl_object_diff(o_a, o_b), 0);
	ck_assert_int_eq(nl_object_diff(o_b, o_a), 0);
}

/*****************************************************************************/

struct cache_get_all_data {
	struct nl_object **arr;
	size_t len;
	size_t idx;
};

static void _cache_get_all_fcn(struct nl_object *obj, void *user_data)
{
	struct cache_get_all_data *data = user_data;
	size_t i;

	ck_assert(obj);
	ck_assert_int_lt(data->idx, data->len);

	for (i = 0; i < data->idx; i++)
		ck_assert_ptr_ne(data->arr[i], obj);

	data->arr[data->idx++] = obj;
}

struct nl_object **_nltst_cache_get_all(struct nl_cache *cache, size_t *out_len)
{
	int nitems;
	struct cache_get_all_data data = {
		.idx = 0,
		.len = 0,
	};

	ck_assert(cache);

	nitems = nl_cache_nitems(cache);
	ck_assert_int_ge(nitems, 0);

	data.len = nitems;
	data.arr = malloc(sizeof(struct nl_object *) * (data.len + 1));
	ck_assert_ptr_nonnull(data.arr);

	nl_cache_foreach(cache, _cache_get_all_fcn, &data);

	ck_assert_int_eq(data.idx, data.len);

	data.arr[data.len] = NULL;
	if (out_len)
		*out_len = data.len;
	return data.arr;
}

/*****************************************************************************/

struct nl_sock *_nltst_socket(int protocol)
{
	struct nl_sock *sk;
	int r;

	sk = nl_socket_alloc();
	ck_assert(sk);

	r = nl_connect(sk, protocol);
	ck_assert_int_eq(r, 0);

	return sk;
}

void _nltst_add_link(struct nl_sock *sk, const char *ifname, const char *kind)
{
	_nl_auto_nl_socket struct nl_sock *sk_free = NULL;
	_nl_auto_rtnl_link struct rtnl_link *link = NULL;
	int r;

	ck_assert(ifname);
	ck_assert(kind);

	if (!sk) {
		sk = _nltst_socket(NETLINK_ROUTE);
		sk_free = sk;
	}

	link = rtnl_link_alloc();
	ck_assert(link);

	r = rtnl_link_set_type(link, kind);
	ck_assert_int_eq(r, 0);

	rtnl_link_set_name(link, ifname);

	r = rtnl_link_add(sk, link, NLM_F_CREATE);
	ck_assert_int_eq(r, 0);
}
