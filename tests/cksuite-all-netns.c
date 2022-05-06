/* SPDX-License-Identifier: LGPL-2.1-only */

#include <stdlib.h>
#include <stdbool.h>
#include <linux/netlink.h>

#include "netlink-private/utils.h"
#include "netlink/route/link.h"

#include "cksuite-all.h"

START_TEST(cache_and_clone)
{
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_nl_cache struct nl_cache *link_cache = NULL;
	_nl_auto_free struct nl_object **links_all = NULL;
	static const struct {
		const char *ifname;
		const char *kind;
		bool add;
	} links[] = {
		{
			.ifname = "xbr0",
			.kind = "bridge",
			.add = true,
		},
		{
			.ifname = "xdummy0",
			.kind = "dummy",
			.add = true,
		},
		{
			.ifname = "xbond0",
			.kind = "bond",
			.add = true,
		},
		{
			.ifname = "lo",
			.kind = NULL,
			.add = false,
		},
	};
	int i;
	int r;

	for (i = 0; i < _NL_N_ELEMENTS(links); i++) {
		if (links[i].add)
			_nltst_add_link(NULL, links[i].ifname, links[i].kind,
					NULL);
	}

	sk = _nltst_socket(NETLINK_ROUTE);

	r = rtnl_link_alloc_cache(sk, AF_UNSPEC, &link_cache);
	ck_assert_int_eq(r, 0);

	r = nl_cache_refill(sk, link_cache);
	ck_assert_int_eq(r, 0);

	for (i = 0; i < _NL_N_ELEMENTS(links); i++) {
		_nl_auto_rtnl_link struct rtnl_link *link_clone = NULL;
		struct rtnl_link *link;

		link = _nltst_cache_get_link(link_cache, links[i].ifname);
		ck_assert_ptr_nonnull(link);

		ck_assert_str_eq(rtnl_link_get_name(link), links[i].ifname);

		if (_nl_streq(links[i].ifname, "lo"))
			ck_assert_int_eq(rtnl_link_get_ifindex(link), 1);
		else
			ck_assert_int_gt(rtnl_link_get_ifindex(link), 1);

		link_clone = (struct rtnl_link *)nl_object_clone(
			(struct nl_object *)link);
		ck_assert(link_clone);

		_nltst_object_identical(link, link_clone);
	}

	links_all = _nltst_cache_get_all(link_cache, NULL);
	for (i = 0; links_all[i]; i++) {
		struct rtnl_link *link = (struct rtnl_link *)links_all[i];
		_nl_auto_rtnl_link struct rtnl_link *link_clone = NULL;

		link_clone = (struct rtnl_link *)nl_object_clone(
			(struct nl_object *)link);
		ck_assert(link_clone);

		_nltst_object_identical(link, link_clone);
	}
}
END_TEST

Suite *make_nl_netns_suite(void)
{
	Suite *suite = suite_create("netns");
	TCase *tc = tcase_create("Core");

	tcase_add_checked_fixture(tc, nltst_netns_fixture_setup,
				  nltst_netns_fixture_teardown);
	tcase_add_test(tc, cache_and_clone);
	suite_add_tcase(suite, tc);

	return suite;
}
