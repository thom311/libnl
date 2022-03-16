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

/*****************************************************************************/

#define _CANARY 539339

struct nltst_netns {
	int canary;
};

/*****************************************************************************/

static struct {
	struct nltst_netns *nsdata;
} _netns_fixture_global;

void nltst_netns_fixture_setup(void)
{
	ck_assert(!_netns_fixture_global.nsdata);

	_netns_fixture_global.nsdata = nltst_netns_enter();
	ck_assert(_netns_fixture_global.nsdata);
}

void nltst_netns_fixture_teardown(void)
{
	ck_assert(_netns_fixture_global.nsdata);
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
		fprintf(f, "deny");
		fclose(f);
	}

	/* Map current UID to root in NS to be created. */
	f = fopen("/proc/self/uid_map", "we");
	ck_assert(f);
	fprintf(f, "0 %d 1", uid);
	fclose(f);

	/* Map current GID to root in NS to be created. */
	f = fopen("/proc/self/gid_map", "we");
	ck_assert(f);
	fprintf(f, "0 %d 1", gid);
	fclose(f);
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
