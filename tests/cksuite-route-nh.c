/* SPDX-License-Identifier: LGPL-2.1-only */

/*
 * Tests for include/netlink/route/nh.h getters and setters.
 *
 * We cover two aspects:
 *   1. Pure userspace logic – manipulating an allocated rtnl_nh object and
 *      validating all getters, including negative/error conditions.
 *   2. Kernel round-trip – create a real nexthop in a private network
 *      namespace, query it back via the cache and verify attributes round-trip.
 */

#include "nl-default.h"

#include <linux/nexthop.h>
#include <linux/if.h>

#include <netlink/route/nh.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/nexthop.h>

#include "cksuite-all.h"

/*****************************************************************************/
/* Kernel round-trip tests exercising rtnl_nh_add() and message parsing */

START_TEST(test_kernel_roundtrip_basic_v4)
{
	const char *IFNAME_DUMMY = "nh-dummy0";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_nl_cache struct nl_cache *cache = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;
	struct rtnl_nh *nh_kernel;
	_nl_auto_nl_addr struct nl_addr *gw4 = NULL;
	int ifindex_dummy;
	int r;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	/* Create dummy underlay */
	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_link(sk, IFNAME_DUMMY, "dummy", &ifindex_dummy);

	/* Bring up and add an IPv4 address via libnl */
	_nltst_link_up(sk, IFNAME_DUMMY);
	_nltst_addr4_add(sk, ifindex_dummy, "192.0.2.2", 24);

	/* Build nexthop: v4 gateway over dummy OIF with explicit id */
	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);
	ck_assert_int_eq(rtnl_nh_set_family(nh, AF_INET), 0);
	ck_assert_int_eq(rtnl_nh_set_id(nh, 1001), 0);
	ck_assert_int_eq(rtnl_nh_set_oif(nh, (uint32_t)ifindex_dummy), 0);
	ck_assert_int_eq(nl_addr_parse("192.0.2.1", AF_INET, &gw4), 0);
	ck_assert_int_eq(rtnl_nh_set_gateway(nh, gw4), 0);

	r = rtnl_nh_add(sk, nh, NLM_F_CREATE);
	ck_assert_int_eq(r, 0);

	/* Query and verify attributes */
	ck_assert_int_eq(rtnl_nh_alloc_cache(sk, AF_UNSPEC, &cache), 0);
	nh_kernel = rtnl_nh_get(cache, 1001);
	ck_assert_ptr_nonnull(nh_kernel);

	ck_assert_int_eq(rtnl_nh_get_id(nh_kernel), 1001);
	ck_assert_int_eq(rtnl_nh_get_family(nh_kernel), AF_INET);
	ck_assert_int_eq(rtnl_nh_get_oif(nh_kernel), ifindex_dummy);
	ck_assert_ptr_nonnull(rtnl_nh_get_gateway(nh_kernel));
	ck_assert_int_eq(nl_addr_get_family(rtnl_nh_get_gateway(nh_kernel)),
			 AF_INET);
}
END_TEST

/* Kernel round-trip tests for MPLS encap on rtnl_nh */

START_TEST(test_kernel_roundtrip_encap_mpls)
{
	const char *IFNAME_DUMMY = "nh-dummy-encap0";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_nl_cache struct nl_cache *cache = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;
	struct rtnl_nh *knh;
	struct rtnl_nh_encap *kencap;
	_nl_auto_nl_addr struct nl_addr *gw4 = NULL;
	_nl_auto_nl_addr struct nl_addr *labels = NULL;
	struct rtnl_nh_encap *encap = NULL;
	int ifindex_dummy;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	/* Create underlay */
	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_link(sk, IFNAME_DUMMY, "dummy", &ifindex_dummy);
	_nltst_link_up(sk, IFNAME_DUMMY);
	_nltst_addr4_add(sk, ifindex_dummy, "192.0.2.2", 24);

	/* Build nexthop: v4 gw over dummy with MPLS encap */
	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);
	ck_assert_int_eq(rtnl_nh_set_id(nh, 3101), 0);

	/* Surprisingly the kernel accepts a nexthop with encap and a gw */
	ck_assert_int_eq(nl_addr_parse("192.0.2.1", AF_INET, &gw4), 0);
	ck_assert_int_eq(rtnl_nh_set_gateway(nh, gw4), 0);

	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);
	ck_assert_int_eq(nl_addr_parse("100", AF_MPLS, &labels), 0);
	ck_assert_int_eq(rtnl_nh_encap_mpls(encap, labels, 64), 0);
	ck_assert_int_eq(rtnl_nh_set_encap(nh, encap), 0);

	/* Fails - we need a family & oif*/
	ck_assert_int_eq(rtnl_nh_add(sk, nh, NLM_F_CREATE), -NLE_INVAL);

	/* Fails, we need a family */
	ck_assert_int_eq(rtnl_nh_set_oif(nh, (uint32_t)ifindex_dummy), 0);
	ck_assert_int_eq(rtnl_nh_add(sk, nh, NLM_F_CREATE), -NLE_INVAL);

	ck_assert_int_eq(rtnl_nh_set_family(nh, AF_INET), 0);
	ck_assert_int_eq(rtnl_nh_add(sk, nh, NLM_F_CREATE), 0);

	/* Query and verify */
	ck_assert_int_eq(rtnl_nh_alloc_cache(sk, AF_UNSPEC, &cache), 0);
	knh = rtnl_nh_get(cache, 3101);
	ck_assert_ptr_nonnull(knh);
	ck_assert_int_eq(rtnl_nh_get_id(knh), 3101);
	ck_assert_int_eq(rtnl_nh_get_oif(knh), ifindex_dummy);

	kencap = rtnl_nh_get_encap(knh);
	ck_assert_ptr_nonnull(kencap);
	ck_assert_ptr_nonnull(rtnl_nh_get_encap_mpls_dst(kencap));
	ck_assert_uint_eq(rtnl_nh_get_encap_mpls_ttl(kencap), 64);
}
END_TEST

START_TEST(test_kernel_negative_mismatched_gw_family)
{
	const char *IFNAME_DUMMY = "nh-dummy-neg0";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;
	_nl_auto_nl_addr struct nl_addr *gw4 = NULL;
	int ifindex_dummy;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_link(sk, IFNAME_DUMMY, "dummy", &ifindex_dummy);
	_nltst_link_up(sk, IFNAME_DUMMY);

	/* Build nexthop with AF_INET6 but an IPv4 gateway -> invalid */
	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);
	ck_assert_int_eq(rtnl_nh_set_family(nh, AF_INET6), 0);
	ck_assert_int_eq(rtnl_nh_set_id(nh, 3001), 0);
	ck_assert_int_eq(rtnl_nh_set_oif(nh, (uint32_t)ifindex_dummy), 0);
	ck_assert_int_eq(nl_addr_parse("192.0.2.1", AF_INET, &gw4), 0);
	ck_assert_int_eq(rtnl_nh_set_gateway(nh, gw4), 0);

	ck_assert_int_eq(rtnl_nh_add(sk, nh, NLM_F_CREATE), -NLE_INVAL);
}
END_TEST

START_TEST(test_kernel_negative_group_without_entries)
{
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	/* Build a group nexthop with a type set but without any entries */
	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);
	ck_assert_int_eq(rtnl_nh_set_family(nh, AF_INET), 0);
	ck_assert_int_eq(rtnl_nh_set_id(nh, 3002), 0);
	ck_assert_int_eq(rtnl_nh_set_group_type(nh, NEXTHOP_GRP_TYPE_MPATH), 0);

	ck_assert_int_eq(rtnl_nh_add(sk, nh, NLM_F_CREATE), -NLE_INVAL);
}
END_TEST

START_TEST(test_kernel_negative_gateway_without_oif)
{
	const char *IFNAME_DUMMY = "nh-dummy-neg1";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;
	_nl_auto_nl_addr struct nl_addr *gw4 = NULL;
	int ifindex_dummy;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	/* Create a dummy device to avoid dependency on system state */
	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_link(sk, IFNAME_DUMMY, "dummy", &ifindex_dummy);
	_nltst_link_up(sk, IFNAME_DUMMY);

	/* Build nexthop with IPv4 gateway but no OIF -> invalid */
	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);
	ck_assert_int_eq(rtnl_nh_set_family(nh, AF_INET), 0);
	ck_assert_int_eq(rtnl_nh_set_id(nh, 3003), 0);
	ck_assert_int_eq(nl_addr_parse("192.0.2.1", AF_INET, &gw4), 0);
	ck_assert_int_eq(rtnl_nh_set_gateway(nh, gw4), 0);

	ck_assert_int_eq(rtnl_nh_add(sk, nh, NLM_F_CREATE), -NLE_INVAL);
}
END_TEST

START_TEST(test_kernel_roundtrip_oif_only)
{
	const char *IFNAME_DUMMY = "nh-dummy1";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_nl_cache struct nl_cache *cache = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;
	struct rtnl_nh *nh_kernel;
	int ifindex_dummy;
	int r;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_link(sk, IFNAME_DUMMY, "dummy", &ifindex_dummy);

	/* Bring interface up via libnl */
	_nltst_link_up(sk, IFNAME_DUMMY);

	/* Build nexthop: OIF only, unspecified family */
	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);
	ck_assert_int_eq(rtnl_nh_set_family(nh, AF_UNSPEC), 0);
	ck_assert_int_eq(rtnl_nh_set_id(nh, 1002), 0);
	ck_assert_int_eq(rtnl_nh_set_oif(nh, (uint32_t)ifindex_dummy), 0);

	r = rtnl_nh_add(sk, nh, NLM_F_CREATE);
	ck_assert_int_eq(r, -NLE_INVAL); /* Because family was AF_UNSPEC */

	/* Fix the family and now rtnl_nh_add should succeed */
	ck_assert_int_eq(rtnl_nh_set_family(nh, AF_INET6), 0);
	r = rtnl_nh_add(sk, nh, NLM_F_CREATE);
	ck_assert_int_eq(r, 0);

	ck_assert_int_eq(rtnl_nh_alloc_cache(sk, AF_UNSPEC, &cache), 0);
	nh_kernel = rtnl_nh_get(cache, 1002);
	ck_assert_ptr_nonnull(nh_kernel);

	ck_assert_int_eq(rtnl_nh_get_id(nh_kernel), 1002);
	ck_assert_int_eq(rtnl_nh_get_oif(nh_kernel), ifindex_dummy);
	ck_assert_ptr_null(rtnl_nh_get_gateway(nh_kernel));
}
END_TEST

START_TEST(test_kernel_roundtrip_group_mpath)
{
	const char *IFNAME_DUMMY = "nh-dummy2";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_nl_cache struct nl_cache *cache = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *nh1 = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *nh2 = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *grp = NULL;
	struct rtnl_nh *grp_kernel;
	nl_nh_group_info_t entries[2];
	int ifindex_dummy;
	int r;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_link(sk, IFNAME_DUMMY, "dummy", &ifindex_dummy);

	/* Bring interface up via libnl */
	_nltst_link_up(sk, IFNAME_DUMMY);

	/* Two basic nexthops to reference in the group */
	nh1 = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh1);
	ck_assert_int_eq(rtnl_nh_set_id(nh1, 1003), 0);
	ck_assert_int_eq(rtnl_nh_set_family(nh1, AF_INET6), 0);
	ck_assert_int_eq(rtnl_nh_set_oif(nh1, (uint32_t)ifindex_dummy), 0);
	r = rtnl_nh_add(sk, nh1, NLM_F_CREATE);
	ck_assert_int_eq(r, 0);

	nh2 = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh2);
	ck_assert_int_eq(rtnl_nh_set_id(nh2, 1004), 0);
	ck_assert_int_eq(rtnl_nh_set_family(nh2, AF_INET6), 0);
	ck_assert_int_eq(rtnl_nh_set_oif(nh2, (uint32_t)ifindex_dummy), 0);
	r = rtnl_nh_add(sk, nh2, NLM_F_CREATE);
	ck_assert_int_eq(r, 0);

	/* Group nexthop referencing the above two, with weights */
	grp = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(grp);
	ck_assert_int_eq(rtnl_nh_set_id(grp, 2000), 0);
	entries[0].nh_id = 666; /* Does not exist */
	entries[0].weight = 1;
	entries[1].nh_id = 1004;
	entries[1].weight = 2;
	ck_assert_int_eq(rtnl_nh_set_group(grp, entries, 2), 0);
	ck_assert_int_eq(rtnl_nh_set_group_type(grp, NEXTHOP_GRP_TYPE_MPATH),
			 0);

	r = rtnl_nh_add(sk, grp, NLM_F_CREATE);
	ck_assert_int_eq(r, -NLE_INVAL); /* One of the nh_ids did not exist */

	/* Fix entries[0].nh_id - now rtnl_nh_add will pass */
	entries[0].nh_id = 1003;
	ck_assert_int_eq(rtnl_nh_set_group(grp, entries, 2), 0);

	r = rtnl_nh_add(sk, grp, NLM_F_CREATE);
	ck_assert_int_eq(r, 0);

	ck_assert_int_eq(rtnl_nh_alloc_cache(sk, AF_UNSPEC, &cache), 0);
	grp_kernel = rtnl_nh_get(cache, 2000);
	ck_assert_ptr_nonnull(grp_kernel);

	ck_assert_int_eq(rtnl_nh_get_group_type(grp_kernel),
			 NEXTHOP_GRP_TYPE_MPATH);
	ck_assert_int_eq(rtnl_nh_get_group_size(grp_kernel), 2);
	ck_assert_int_eq(rtnl_nh_get_group_entry(grp_kernel, 0), 1003);
	ck_assert_int_eq(rtnl_nh_get_group_entry(grp_kernel, 1), 1004);
}
END_TEST

START_TEST(test_kernel_roundtrip_group_resilient)
{
	const char *IFNAME_DUMMY = "nh-dummy3";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_nl_cache struct nl_cache *cache = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *nh1 = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *nh2 = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *grp = NULL;
	struct rtnl_nh *grp_kernel;
	nl_nh_group_info_t entries[2];
	int ifindex_dummy;
	uint32_t tmp32;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_link(sk, IFNAME_DUMMY, "dummy", &ifindex_dummy);
	/* Bring interface up via libnl */
	_nltst_link_up(sk, IFNAME_DUMMY);

	/* Two basic nexthops to reference in the group */
	nh1 = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh1);
	ck_assert_int_eq(rtnl_nh_set_id(nh1, 1005), 0);
	ck_assert_int_eq(rtnl_nh_set_family(nh1, AF_INET6), 0);
	ck_assert_int_eq(rtnl_nh_set_oif(nh1, (uint32_t)ifindex_dummy), 0);
	ck_assert_int_eq(rtnl_nh_add(sk, nh1, NLM_F_CREATE), 0);

	nh2 = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh2);
	ck_assert_int_eq(rtnl_nh_set_id(nh2, 1006), 0);
	ck_assert_int_eq(rtnl_nh_set_family(nh2, AF_INET6), 0);
	ck_assert_int_eq(rtnl_nh_set_oif(nh2, (uint32_t)ifindex_dummy), 0);
	ck_assert_int_eq(rtnl_nh_add(sk, nh2, NLM_F_CREATE), 0);

	/* Resilient group with parameters */
	grp = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(grp);
	ck_assert_int_eq(rtnl_nh_set_id(grp, 2001), 0);
	entries[0].nh_id = 1005;
	entries[0].weight = 1;
	entries[1].nh_id = 1006;
	entries[1].weight = 1;
	ck_assert_int_eq(rtnl_nh_set_group(grp, entries, 2), 0);
	ck_assert_int_eq(rtnl_nh_set_group_type(grp, NEXTHOP_GRP_TYPE_RES), 0);
	ck_assert_int_eq(rtnl_nh_set_res_group_bucket_size(grp, 128), 0);
	ck_assert_int_eq(rtnl_nh_set_res_group_idle_timer(grp, 15), 0);
	ck_assert_int_eq(rtnl_nh_set_res_group_unbalanced_timer(grp, 25), 0);

	ck_assert_int_eq(rtnl_nh_add(sk, grp, NLM_F_CREATE), 0);

	ck_assert_int_eq(rtnl_nh_alloc_cache(sk, AF_UNSPEC, &cache), 0);
	grp_kernel = rtnl_nh_get(cache, 2001);
	ck_assert_ptr_nonnull(grp_kernel);

	ck_assert_int_eq(rtnl_nh_get_group_type(grp_kernel),
			 NEXTHOP_GRP_TYPE_RES);
	ck_assert_int_eq(rtnl_nh_get_group_size(grp_kernel), 2);
	ck_assert_int_eq(rtnl_nh_get_group_entry(grp_kernel, 0), 1005);
	ck_assert_int_eq(rtnl_nh_get_group_entry(grp_kernel, 1), 1006);

	ck_assert_int_eq(rtnl_nh_get_res_group_bucket_size(grp_kernel), 128);
	tmp32 = 0;
	ck_assert_int_eq(rtnl_nh_get_res_group_idle_timer(grp_kernel, &tmp32),
			 0);
	ck_assert_uint_ge(tmp32, 12U);
	ck_assert_uint_le(tmp32, 15U);
	tmp32 = 0;
	ck_assert_int_eq(
		rtnl_nh_get_res_group_unbalanced_timer(grp_kernel, &tmp32), 0);
	ck_assert_uint_ge(tmp32, 24U);
	ck_assert_uint_le(tmp32, 25U);
}
END_TEST

/* Userspace comprehensive test covering all API calls */

START_TEST(test_api_set_get_all)
{
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;
	_nl_auto_nl_addr struct nl_addr *gw4 = NULL;
	_nl_auto_nl_addr struct nl_addr *gw6 = NULL;
	nl_nh_group_info_t entries[2];
	uint32_t tmp32;

	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);

	/* Family set/get + negative on NULL */
	ck_assert_int_eq(rtnl_nh_get_family(nh), AF_UNSPEC);
	ck_assert_int_eq(rtnl_nh_set_family(nh, AF_INET6), 0);
	ck_assert_int_eq(rtnl_nh_get_family(nh), AF_INET6);
	ck_assert_int_eq(rtnl_nh_set_family(NULL, AF_INET), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_family(NULL), -NLE_INVAL);

	/* ID get before set -> -NLE_INVAL; set/get/clear */
	ck_assert_int_eq(rtnl_nh_get_id(nh), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_id(nh, 1001), 0);
	ck_assert_int_eq(rtnl_nh_get_id(nh), 1001);
	ck_assert_int_eq(rtnl_nh_set_id(nh, 0), 0);
	ck_assert_int_eq(rtnl_nh_get_id(nh), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_id(NULL, 1), -NLE_INVAL);

	/* OIF get before set is 0; set/get; clear; negative on NULL */
	ck_assert_int_eq(rtnl_nh_get_oif(nh), 0);
	ck_assert_int_eq(rtnl_nh_set_oif(nh, 1234), 0);
	ck_assert_int_eq(rtnl_nh_get_oif(nh), 1234);
	ck_assert_int_eq(rtnl_nh_set_oif(nh, 0), 0);
	ck_assert_int_eq(rtnl_nh_get_oif(nh), 0);
	ck_assert_int_eq(rtnl_nh_set_oif(NULL, 1), -NLE_INVAL);

	/* Gateway get/set; start NULL, set v4 then replace with v6 */
	ck_assert_ptr_eq(rtnl_nh_get_gateway(nh), NULL);
	ck_assert_int_eq(nl_addr_parse("192.0.2.1", AF_INET, &gw4), 0);
	ck_assert_int_eq(rtnl_nh_set_gateway(NULL, gw4), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_gateway(nh, NULL), 0);
	ck_assert_int_eq(rtnl_nh_set_gateway(nh, gw4), 0);

	ck_assert_ptr_nonnull(rtnl_nh_get_gateway(nh));
	ck_assert_int_eq(nl_addr_parse("2001:db8::1", AF_INET6, &gw6), 0);

	ck_assert_int_eq(rtnl_nh_set_gateway(nh, gw6), 0);

	/* Previous set_gateway replaced the old one. It should no more be shared now */
	ck_assert_int_eq(nl_addr_shared(gw4), 0);

	ck_assert_int_eq(nl_addr_get_family(rtnl_nh_get_gateway(nh)), AF_INET6);

	ck_assert_int_eq(rtnl_nh_set_gateway(nh, NULL), 0);
	ck_assert_ptr_eq(rtnl_nh_get_gateway(nh), NULL);

	/* FDB flag set/clear */
	ck_assert_int_eq(rtnl_nh_get_fdb(nh), 0);
	ck_assert_int_eq(rtnl_nh_set_fdb(nh, 1), 0);
	ck_assert_int_ne(rtnl_nh_get_fdb(nh), 1);
	ck_assert_int_eq(rtnl_nh_set_fdb(nh, 0), 0);
	ck_assert_int_eq(rtnl_nh_get_fdb(nh), 0);

	/* Group getters before set -> missing */
	ck_assert_int_eq(rtnl_nh_get_group_size(nh), -NLE_MISSING_ATTR);
	ck_assert_int_eq(rtnl_nh_get_group_entry(nh, 0), -NLE_MISSING_ATTR);

	/* Group setter - negative tests */
	ck_assert_int_eq(rtnl_nh_set_group(NULL, entries, 1), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_group(nh, NULL, 1), -NLE_INVAL);

	/* Group set/get and indexing */
	entries[0].nh_id = 10;
	entries[0].weight = 1;
	entries[1].nh_id = 20;
	entries[1].weight = 2;
	ck_assert_int_eq(rtnl_nh_set_group(nh, entries, 2), 0);
	ck_assert_int_eq(rtnl_nh_get_group_size(nh), 2);
	/* Unset the group with size == 0 */
	ck_assert_int_eq(rtnl_nh_set_group(nh, entries, 0), 0);
	ck_assert_int_eq(rtnl_nh_get_group_size(nh), -NLE_MISSING_ATTR);
	ck_assert_int_eq(rtnl_nh_set_group(nh, entries, 2), 0);
	ck_assert_int_eq(rtnl_nh_get_group_entry(nh, -1), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_group_entry(nh, 2), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_group_entry(nh, 0), 10);
	ck_assert_int_eq(rtnl_nh_get_group_entry(nh, 1), 20);

	/* Replace group with a different size */
	ck_assert_int_eq(rtnl_nh_set_group(nh, entries, 1), 0);
	ck_assert_int_eq(rtnl_nh_get_group_size(nh), 1);
	ck_assert_int_eq(rtnl_nh_get_group_entry(nh, 0), 10);
	ck_assert_int_eq(rtnl_nh_get_group_entry(nh, 1), -NLE_INVAL);

	/* Remove group */
	ck_assert_int_eq(rtnl_nh_set_group(nh, NULL, 0), 0);
	ck_assert_int_eq(rtnl_nh_get_group_size(nh), -NLE_MISSING_ATTR);

	/* Group type get negative before set, set/get after */
	ck_assert_int_eq(rtnl_nh_get_group_type(NULL), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_group_type(nh), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_group_type(NULL, NEXTHOP_GRP_TYPE_MPATH),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_group_type(nh, NEXTHOP_GRP_TYPE_MPATH), 0);
	ck_assert_int_eq(rtnl_nh_get_group_type(nh), NEXTHOP_GRP_TYPE_MPATH);
	ck_assert_int_eq(rtnl_nh_set_group_type(NULL, NEXTHOP_GRP_TYPE_RES),
			 -NLE_INVAL);

	/* Resilient group setters/getters negative when type != RES */
	ck_assert_int_eq(rtnl_nh_set_res_group_bucket_size(nh, 64), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_res_group_bucket_size(nh), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_res_group_idle_timer(nh, 10), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_res_group_idle_timer(nh, &tmp32),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_res_group_idle_timer(nh, NULL),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_res_group_unbalanced_timer(nh, 20),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_res_group_unbalanced_timer(nh, &tmp32),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_res_group_unbalanced_timer(nh, NULL),
			 -NLE_INVAL);

	/* Switch to resilient type and test getters/setters */
	ck_assert_int_eq(rtnl_nh_set_group_type(nh, NEXTHOP_GRP_TYPE_RES), 0);

	/* Bucket size: missing before set, then set/get, then clear */
	ck_assert_int_eq(rtnl_nh_get_res_group_bucket_size(nh),
			 -NLE_MISSING_ATTR);
	ck_assert_int_eq(rtnl_nh_set_res_group_bucket_size(nh, 128), 0);
	ck_assert_int_eq(rtnl_nh_get_res_group_bucket_size(nh), 128);
	ck_assert_int_eq(rtnl_nh_set_res_group_bucket_size(nh, 0), 0);
	ck_assert_int_eq(rtnl_nh_get_res_group_bucket_size(nh),
			 -NLE_MISSING_ATTR);

	/* Idle timer: missing before set, then set/get; out NULL negative */
	tmp32 = 0;
	ck_assert_int_eq(rtnl_nh_get_res_group_idle_timer(nh, &tmp32),
			 -NLE_MISSING_ATTR);
	ck_assert_int_eq(rtnl_nh_set_res_group_idle_timer(nh, 15), 0);
	tmp32 = 0;
	ck_assert_int_eq(rtnl_nh_get_res_group_idle_timer(nh, &tmp32), 0);
	ck_assert_int_eq(tmp32, 15U);
	ck_assert_int_eq(rtnl_nh_get_res_group_idle_timer(nh, NULL),
			 -NLE_INVAL);

	/* Unbalanced timer: missing before set, then set/get; out NULL negative */
	tmp32 = 0;
	ck_assert_int_eq(rtnl_nh_get_res_group_unbalanced_timer(nh, &tmp32),
			 -NLE_MISSING_ATTR);
	ck_assert_int_eq(rtnl_nh_set_res_group_unbalanced_timer(nh, 25), 0);
	tmp32 = 0;
	ck_assert_int_eq(rtnl_nh_get_res_group_unbalanced_timer(nh, &tmp32), 0);
	ck_assert_int_eq(tmp32, 25U);
	ck_assert_int_eq(rtnl_nh_get_res_group_unbalanced_timer(nh, NULL),
			 -NLE_INVAL);
}
END_TEST

/* Userspace tests for MPLS encap on rtnl_nh */

START_TEST(test_api_encap_mpls_set_get)
{
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;
	struct rtnl_nh_encap *encap = NULL;
	struct rtnl_nh_encap *got = NULL;
	_nl_auto_nl_addr struct nl_addr *labels = NULL;

	/* Allocate nh and an encap container */
	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);

	/* Negative: NULL nh */
	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);
	/* This will free encap */
	ck_assert_int_eq(rtnl_nh_set_encap(NULL, encap), -NLE_INVAL);

	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);

	/* "empty" encap (no type set) cannot be assigned. */
	ck_assert_int_eq(rtnl_nh_set_encap(nh, encap), -NLE_INVAL);
	ck_assert_ptr_eq(rtnl_nh_get_encap_mpls_dst(rtnl_nh_get_encap(nh)),
			 NULL);
	ck_assert_uint_eq(rtnl_nh_get_encap_mpls_ttl(rtnl_nh_get_encap(nh)),
			  -NLE_INVAL);

	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);
	/* Now build a valid MPLS encap: push label 100 with TTL 64 */
	ck_assert_int_eq(nl_addr_parse("100", AF_MPLS, &labels), 0);
	ck_assert_int_eq(rtnl_nh_encap_mpls(encap, labels, 64), 0);

	/* Attach and retrieve */
	ck_assert_int_eq(rtnl_nh_set_encap(nh, encap), 0);
	got = rtnl_nh_get_encap(nh);
	ck_assert_ptr_nonnull(got);

	/* Access MPLS-specific getters */
	ck_assert_ptr_nonnull(rtnl_nh_get_encap_mpls_dst(got));
	ck_assert_uint_eq(rtnl_nh_get_encap_mpls_ttl(got), 64);

	/* Clear encap */
	ck_assert_int_eq(rtnl_nh_set_encap(nh, NULL), 0);
	ck_assert_ptr_eq(rtnl_nh_get_encap(nh), NULL);
}
END_TEST

Suite *make_nl_route_nh_suite(void)
{
	Suite *suite = suite_create("route-nh");
	TCase *tc_api = tcase_create("Userspace-API");
	TCase *tc_kernel = tcase_create("Kernel");

	/* Comprehensive API setter/getter test (userspace only) */
	tcase_add_test(tc_api, test_api_set_get_all);
	/* Userspace encap tests */
	tcase_add_test(tc_api, test_api_encap_mpls_set_get);
	suite_add_tcase(suite, tc_api);

	/* Kernel round-trip – needs private netns */
	tcase_add_checked_fixture(tc_kernel, nltst_netns_fixture_setup,
				  nltst_netns_fixture_teardown);
	/* Exercise add+parse for all possible APIs: basic v4 gw, oif-only,
	 * multipath groups, resilient groups with parameters.
	 */
	tcase_add_test(tc_kernel, test_kernel_roundtrip_basic_v4);
	tcase_add_test(tc_kernel, test_kernel_roundtrip_oif_only);
	tcase_add_test(tc_kernel, test_kernel_roundtrip_group_mpath);
	tcase_add_test(tc_kernel, test_kernel_roundtrip_group_resilient);
	/* Encap (MPLS) on rtnl_nh */
	tcase_add_test(tc_kernel, test_kernel_roundtrip_encap_mpls);
	/* Negative tests: kernel should reject invalid nexthops */
	tcase_add_test(tc_kernel, test_kernel_negative_mismatched_gw_family);
	tcase_add_test(tc_kernel, test_kernel_negative_group_without_entries);
	tcase_add_test(tc_kernel, test_kernel_negative_gateway_without_oif);
	suite_add_tcase(suite, tc_kernel);

	return suite;
}
