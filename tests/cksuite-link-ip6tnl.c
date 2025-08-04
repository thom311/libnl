/* SPDX-License-Identifier: LGPL-2.1-only */

/*
 * Tests for rtnl_link_ip6_tnl_set/get_collect_metadata().
 *
 * We cover two aspects:
 *   1. Pure userspace logic – flag manipulation on an allocated link object.
 *   2. Kernel round-trip  – create a real ip6tnl interface inside a private
 *      network namespace with the flag enabled, query it back from the kernel
 *      and verify that the flag round-trips correctly.
 */

#include "nl-default.h"

#include <netlink/route/link/ip6tnl.h>

#include "cksuite-all.h"

/*****************************************************************************/

#define TTL 42
#define ENCAPLIMIT 3
#define TOS 0x1a
/* 0x7f means all IP6_TNL_F_ are set */
#define FLAGS 0x7f
/* The kernel will OR the flags with 0x30000 (IP6_TNL_F_CAP_XMIT | IP6_TNL_F_CAP_RCV) */
#define FLAGS_KERNEL (0x30000 | FLAGS)
#define FLOWINFO 0xbeefdead
#define PROTO 41 /* IPPROTO_IPV6 in decimal */
#define FWMARK 0xdead

/* Kernel round-trip all attributes */

START_TEST(test_kernel_roundtrip_all)
{
	const char *IFNAME = "xit6tnl1";
	const char *IFNAME_DUMMY = "xit6tnl-under";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_nl_cache struct nl_cache *cache = NULL;
	_nl_auto_rtnl_link struct rtnl_link *link = NULL;
	struct in6_addr addr_local, addr_remote, addr_tmp;
	struct rtnl_link *link_kernel;
	int ifindex_dummy;
	uint32_t u32tmp;
	int enabled;
	int r;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	link = rtnl_link_ip6_tnl_alloc();
	ck_assert_ptr_nonnull(link);

	auto_del_dummy = IFNAME_DUMMY;

	rtnl_link_set_name(link, IFNAME);

	_nltst_add_link(sk, IFNAME_DUMMY, "dummy", &ifindex_dummy);
	r = rtnl_link_ip6_tnl_set_link(link, ifindex_dummy);
	ck_assert_int_eq(r, 0);

	addr_local = _nltst_inet6("2001:db8::10");
	addr_remote = _nltst_inet6("2001:db8::20");

	r = rtnl_link_ip6_tnl_set_local(link, &addr_local);
	ck_assert_int_eq(r, 0);
	r = rtnl_link_ip6_tnl_set_remote(link, &addr_remote);
	ck_assert_int_eq(r, 0);

	r = rtnl_link_ip6_tnl_set_ttl(link, TTL);
	ck_assert_int_eq(r, 0);
	r = rtnl_link_ip6_tnl_set_encaplimit(link, ENCAPLIMIT);
	ck_assert_int_eq(r, 0);

	r = rtnl_link_ip6_tnl_set_tos(link, TOS);
	ck_assert_int_eq(r, 0);

	r = rtnl_link_ip6_tnl_set_flags(link, FLAGS);
	ck_assert_int_eq(r, 0);

	r = rtnl_link_ip6_tnl_set_flowinfo(link, FLOWINFO);
	ck_assert_int_eq(r, 0);

	r = rtnl_link_ip6_tnl_set_proto(link, PROTO);
	ck_assert_int_eq(r, 0);

	r = rtnl_link_ip6_tnl_set_fwmark(link, FWMARK);
	ck_assert_int_eq(r, 0);

	r = rtnl_link_ip6_tnl_set_collect_metadata(link, 1);
	ck_assert_int_eq(r, 0);

	/* Add the link to the kernel.
	 * This tests the netlink-message construction.
	 */
	r = rtnl_link_add(sk, link, NLM_F_CREATE);
	ck_assert_int_eq(r, 0);

	/* Now, query it and check whether all the attributes passed.
	 * This checks the netlink-message parsing.
	 */
	cache = _nltst_rtnl_link_alloc_cache(sk, AF_UNSPEC, 0);
	link_kernel = _nltst_cache_get_link(cache, IFNAME);
	ck_assert_ptr_nonnull(link_kernel);

	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_link(link_kernel),
			  (uint32_t)ifindex_dummy);

	ck_assert_int_eq(rtnl_link_is_ip6_tnl(link_kernel), 1);

	r = rtnl_link_ip6_tnl_get_local(link_kernel, &addr_tmp);
	ck_assert_int_eq(r, 0);
	ck_assert_int_eq(memcmp(&addr_tmp, &addr_local, sizeof(addr_local)), 0);
	r = rtnl_link_ip6_tnl_get_remote(link_kernel, &addr_tmp);
	ck_assert_int_eq(r, 0);
	ck_assert_int_eq(memcmp(&addr_tmp, &addr_remote, sizeof(addr_remote)),
			 0);

	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_ttl(link_kernel), TTL);
	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_encaplimit(link_kernel),
			  ENCAPLIMIT);

	/* Note: IP_TOS is actually not set'able for ip6-tnl. One can set the
	 * traffic-class through the flowinfo.
	 *
	 * But, the API exists in libnl, so let's test for it.
	 */
	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_tos(link_kernel), 0);

	u32tmp = 0;
	r = rtnl_link_ip6_tnl_get_fwmark(link_kernel, &u32tmp);
	ck_assert_int_eq(r, 0);
	ck_assert_uint_eq(u32tmp, FWMARK);

	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_flags(link_kernel),
			  FLAGS_KERNEL);

	/* Flowinfo and proto should be preserved by kernel */
	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_flowinfo(link_kernel),
			  FLOWINFO);
	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_proto(link_kernel), PROTO);

	enabled = 0;
	r = rtnl_link_ip6_tnl_get_collect_metadata(link_kernel, &enabled);
	ck_assert_int_eq(r, 0);
	ck_assert_int_eq(enabled, 1);

	rtnl_link_delete(sk, link);
}
END_TEST

/*****************************************************************************/
/* Userspace comprehensive test covering all API calls */

START_TEST(test_api_set_get_all)
{
	struct rtnl_link *link;
	struct in6_addr addr_local, addr_remote, tmp_addr;
	int r;
	uint32_t u32tmp;
	int enabled;

	link = rtnl_link_ip6_tnl_alloc();
	ck_assert_ptr_nonnull(link);
	ck_assert_int_eq(rtnl_link_is_ip6_tnl(link), 1);

	r = rtnl_link_ip6_tnl_set_link(link, 123);
	ck_assert_int_eq(r, 0);
	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_link(link), 123);

	/* Local / Remote addresses */
	addr_local = _nltst_inet6("2001:db8::1");
	addr_remote = _nltst_inet6("2001:db8::2");
	r = rtnl_link_ip6_tnl_set_local(link, &addr_local);
	ck_assert_int_eq(r, 0);
	r = rtnl_link_ip6_tnl_set_remote(link, &addr_remote);
	ck_assert_int_eq(r, 0);

	r = rtnl_link_ip6_tnl_get_local(link, &tmp_addr);
	ck_assert_int_eq(r, 0);
	ck_assert_int_eq(memcmp(&tmp_addr, &addr_local, sizeof(addr_local)), 0);

	r = rtnl_link_ip6_tnl_get_remote(link, &tmp_addr);
	ck_assert_int_eq(r, 0);
	ck_assert_int_eq(memcmp(&tmp_addr, &addr_remote, sizeof(addr_remote)),
			 0);

	r = rtnl_link_ip6_tnl_set_ttl(link, TTL);
	ck_assert_int_eq(r, 0);
	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_ttl(link), TTL);

	r = rtnl_link_ip6_tnl_set_tos(link, TOS);
	ck_assert_int_eq(r, 0);
	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_tos(link), TOS);

	r = rtnl_link_ip6_tnl_set_encaplimit(link, ENCAPLIMIT);
	ck_assert_int_eq(r, 0);
	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_encaplimit(link), ENCAPLIMIT);

	r = rtnl_link_ip6_tnl_set_flags(link, FLAGS);
	ck_assert_int_eq(r, 0);
	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_flags(link), FLAGS);

	r = rtnl_link_ip6_tnl_set_flowinfo(link, FLOWINFO);
	ck_assert_int_eq(r, 0);
	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_flowinfo(link), FLOWINFO);

	r = rtnl_link_ip6_tnl_set_proto(link, PROTO);
	ck_assert_int_eq(r, 0);
	ck_assert_uint_eq(rtnl_link_ip6_tnl_get_proto(link), PROTO);

	r = rtnl_link_ip6_tnl_set_fwmark(link, FWMARK);
	ck_assert_int_eq(r, 0);
	u32tmp = 0;
	r = rtnl_link_ip6_tnl_get_fwmark(link, &u32tmp);
	ck_assert_int_eq(r, 0);
	ck_assert_uint_eq(u32tmp, FWMARK);

	r = rtnl_link_ip6_tnl_set_collect_metadata(link, 1);
	ck_assert_int_eq(r, 0);
	enabled = 0;
	r = rtnl_link_ip6_tnl_get_collect_metadata(link, &enabled);
	ck_assert_int_eq(r, 0);
	ck_assert_int_eq(enabled, 1);

	r = rtnl_link_ip6_tnl_set_collect_metadata(link, 0);
	ck_assert_int_eq(r, 0);
	enabled = 1;
	r = rtnl_link_ip6_tnl_get_collect_metadata(link, &enabled);
	ck_assert_int_eq(r, 0);
	ck_assert_int_eq(enabled, 0);

	rtnl_link_put(link);
}
END_TEST

Suite *make_nl_ip6_tnl_suite(void)
{
	Suite *suite = suite_create("ip6tnl");
	TCase *tc_api = tcase_create("Userspace-API");
	TCase *tc_kernel = tcase_create("Kernel");

	/* Comprehensive API setter/getter test (userspace only) */
	tcase_add_test(tc_api, test_api_set_get_all);
	suite_add_tcase(suite, tc_api);

	/* Kernel round-trip – needs private netns */
	tcase_add_checked_fixture(tc_kernel, nltst_netns_fixture_setup,
				  nltst_netns_fixture_teardown);
	tcase_add_test(tc_kernel, test_kernel_roundtrip_all);
	suite_add_tcase(suite, tc_kernel);

	return suite;
}
