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

#include <linux/if.h>
#include <linux/ila.h>
#include <linux/lwtunnel.h>
#include <linux/nexthop.h>
#include <linux-private/linux/if_tunnel.h>

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

	/* Create dummy underlay, bring up and add an IPv4 address */
	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_dummy_v4_with_addr(sk, IFNAME_DUMMY, &ifindex_dummy,
				      "192.0.2.2", 24);

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

	/* Create underlay with IPv4 address */
	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_dummy_v4_with_addr(sk, IFNAME_DUMMY, &ifindex_dummy,
				      "192.0.2.2", 24);

	/* Build nexthop: v4 gw over dummy with MPLS encap */
	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);
	ck_assert_int_eq(rtnl_nh_set_id(nh, 3101), 0);

	/* Surprisingly the kernel accepts a nexthop with encap and a gw */
	ck_assert_int_eq(nl_addr_parse("192.0.2.1", AF_INET, &gw4), 0);
	ck_assert_int_eq(rtnl_nh_set_gateway(nh, gw4), 0);

	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);
	ck_assert_ptr_null(rtnl_nh_get_encap_mpls_dst(encap));
	ck_assert_int_eq(rtnl_nh_get_encap_mpls_ttl(encap), -NLE_INVAL);
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
	ck_assert_int_eq(rtnl_nh_encap_get_type(kencap), LWTUNNEL_ENCAP_MPLS);
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
	_nltst_add_dummy_and_up(sk, IFNAME_DUMMY, &ifindex_dummy);

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
	_nltst_add_dummy_and_up(sk, IFNAME_DUMMY, &ifindex_dummy);

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
	_nltst_add_dummy_and_up(sk, IFNAME_DUMMY, &ifindex_dummy);

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
	_nltst_add_dummy_and_up(sk, IFNAME_DUMMY, &ifindex_dummy);

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
	_nltst_add_dummy_and_up(sk, IFNAME_DUMMY, &ifindex_dummy);

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
	/* Type getter negatives */
	ck_assert_int_eq(rtnl_nh_encap_get_type(NULL), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_encap_get_type(rtnl_nh_get_encap(nh)),
			 -NLE_INVAL);

	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);
	/* Now build a valid MPLS encap: push label 100 with TTL 64 */
	ck_assert_ptr_null(rtnl_nh_get_encap_mpls_dst(encap));
	ck_assert_int_eq(rtnl_nh_get_encap_mpls_ttl(encap), -NLE_INVAL);
	ck_assert_int_eq(nl_addr_parse("100", AF_MPLS, &labels), 0);
	ck_assert_int_eq(rtnl_nh_encap_mpls(encap, labels, 64), 0);

	/* Attach and retrieve */
	ck_assert_int_eq(rtnl_nh_set_encap(nh, encap), 0);
	got = rtnl_nh_get_encap(nh);
	ck_assert_ptr_nonnull(got);
	ck_assert_int_eq(rtnl_nh_encap_get_type(got), LWTUNNEL_ENCAP_MPLS);

	/* Access MPLS-specific getters */
	ck_assert_ptr_nonnull(rtnl_nh_get_encap_mpls_dst(got));
	ck_assert_uint_eq(rtnl_nh_get_encap_mpls_ttl(got), 64);

	/* Clear encap */
	ck_assert_int_eq(rtnl_nh_set_encap(nh, NULL), 0);
	ck_assert_ptr_eq(rtnl_nh_get_encap(nh), NULL);
}
END_TEST

/* Userspace tests for IPv6 encap on rtnl_nh (set/get + wrong-type negatives) */

START_TEST(test_api_encap_ip6)
{
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;
	_nl_auto_rtnl_nh_encap struct rtnl_nh_encap *encap = NULL;
	struct rtnl_nh_encap *got = NULL;
	struct nl_addr *got_dst = NULL;
	struct nl_addr *got_src = NULL;
	_nl_auto_nl_addr struct nl_addr *dst6 = NULL;
	_nl_auto_nl_addr struct nl_addr *src6 = NULL;
	_nl_auto_rtnl_nh_encap struct rtnl_nh_encap *encap_mpls = NULL;
	_nl_auto_nl_addr struct nl_addr *label = NULL;
	uint64_t id_val;
	uint16_t flags;

	/* Allocate nh and an encap container */
	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);

	/* Negative: NULL nh */
	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);

	/* This will free encap */
	ck_assert_int_eq(rtnl_nh_set_encap(NULL, _nl_steal_pointer(&encap)),
			 -NLE_INVAL);

	/* Allocate a fresh encap after negative test freed the previous one */
	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);

	/* Now build a valid IPv6 encap */
	ck_assert_int_eq(nl_addr_parse("2001:db8:1::1", AF_INET6, &dst6), 0);
	ck_assert_int_eq(rtnl_nh_encap_ip6(encap, dst6), 0);
	ck_assert_int_eq(nl_addr_parse("2001:db8:1::2", AF_INET6, &src6), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_src(encap, src6), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_hoplimit(encap, 32), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_tc(encap, 0x2e), 0);
	flags = TUNNEL_KEY | TUNNEL_CSUM | TUNNEL_SEQ;
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_flags(encap, flags), 0);

	ck_assert_uint_eq(rtnl_nh_get_encap_ip6_id(encap), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_id(encap, 0x1122334455667788ULL),
			 0);
	ck_assert_uint_eq(rtnl_nh_get_encap_ip6_id(encap),
			  0x1122334455667788ULL);

	/* Attach and retrieve */
	ck_assert_int_eq(rtnl_nh_set_encap(nh, _nl_steal_pointer(&encap)), 0);
	got = rtnl_nh_get_encap(nh);
	ck_assert_ptr_nonnull(got);
	ck_assert_int_eq(rtnl_nh_encap_get_type(got), LWTUNNEL_ENCAP_IP6);

	/* Access IPv6-specific getters */
	got_dst = rtnl_nh_get_encap_ip6_dst(got);
	ck_assert_ptr_nonnull(got_dst);
	ck_assert_int_eq(nl_addr_cmp(got_dst, dst6), 0);
	got_src = rtnl_nh_get_encap_ip6_src(got);
	ck_assert_ptr_nonnull(got_src);
	ck_assert_int_eq(nl_addr_cmp(got_src, src6), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ip6_hoplimit(got), 32);
	ck_assert_int_eq(rtnl_nh_get_encap_ip6_tc(got), 0x2e);
	ck_assert_int_eq(rtnl_nh_get_encap_ip6_flags(got), flags);
	ck_assert_uint_eq(rtnl_nh_get_encap_ip6_id(NULL), 0);
	ck_assert_uint_eq(rtnl_nh_get_encap_ip6_id(got), 0x1122334455667788ULL);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_id(got, 0x8877665544332211ULL),
			 0);
	id_val = rtnl_nh_get_encap_ip6_id(got);
	ck_assert(id_val == 0x8877665544332211ULL);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_id(got, 0), 0);
	ck_assert_uint_eq(rtnl_nh_get_encap_ip6_id(got), 0);

	/* Clear/zero optional fields and verify getters */
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_hoplimit(got, 0), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_tc(got, 0), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ip6_hoplimit(got), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ip6_tc(got), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_flags(got, 0), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ip6_flags(got), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_src(got, NULL), 0);
	ck_assert_ptr_eq(rtnl_nh_get_encap_ip6_src(got), NULL);

	/* Clear encap */
	ck_assert_int_eq(rtnl_nh_set_encap(nh, NULL), 0);
	ck_assert_ptr_eq(rtnl_nh_get_encap(nh), NULL);
	/* Type getter negative on NULL */
	ck_assert_int_eq(rtnl_nh_encap_get_type(NULL), -NLE_INVAL);

	/* Negative tests for IPv6 setters on a non-IPv6 encap (wrong type) */
	encap_mpls = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap_mpls);
	ck_assert_int_eq(nl_addr_parse("100", AF_MPLS, &label), 0);
	ck_assert_int_eq(rtnl_nh_encap_mpls(encap_mpls, label, 64), 0);

	/* Now try IPv6-specific setters/getters on MPLS encap */
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_hoplimit(encap_mpls, 16),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_tc(encap_mpls, 1), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_src(encap_mpls, NULL),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_flags(encap_mpls, 1),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_id(encap_mpls, 1), -NLE_INVAL);
	ck_assert_uint_eq(rtnl_nh_get_encap_ip6_id(encap_mpls), 0);
	/* And verify its type is MPLS */
	ck_assert_int_eq(rtnl_nh_encap_get_type(encap_mpls),
			 LWTUNNEL_ENCAP_MPLS);
	ck_assert_ptr_eq(rtnl_nh_get_encap_ip6_dst(encap_mpls), NULL);
	ck_assert_ptr_eq(rtnl_nh_get_encap_ip6_src(encap_mpls), NULL);
	ck_assert_int_eq(rtnl_nh_get_encap_ip6_hoplimit(encap_mpls),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_encap_ip6_tc(encap_mpls), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_encap_ip6_flags(encap_mpls), -NLE_INVAL);
	ck_assert_uint_eq(rtnl_nh_get_encap_ip6_id(encap_mpls), 0);
}
END_TEST

START_TEST(test_api_encap_ila)
{
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;
	_nl_auto_rtnl_nh_encap struct rtnl_nh_encap *encap = NULL;
	_nl_auto_rtnl_nh_encap struct rtnl_nh_encap *encap_mpls = NULL;
	struct rtnl_nh_encap *got = NULL;
	_nl_auto_nl_addr struct nl_addr *label = NULL;
	uint64_t locator = 0;

	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);

	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);
	ck_assert_int_eq(rtnl_nh_encap_ila(encap, 0x1122334455667788ULL), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ila_csum_mode(encap,
							 ILA_CSUM_NEUTRAL_MAP),
			 0);
	ck_assert_int_eq(
		rtnl_nh_set_encap_ila_ident_type(encap, ILA_ATYPE_LUID), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ila_hook_type(encap,
							 ILA_HOOK_ROUTE_OUTPUT),
			 0);

	ck_assert_int_eq(rtnl_nh_set_encap(nh, _nl_steal_pointer(&encap)), 0);
	got = rtnl_nh_get_encap(nh);
	ck_assert_ptr_nonnull(got);
	ck_assert_int_eq(rtnl_nh_encap_get_type(got), LWTUNNEL_ENCAP_ILA);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_locator(got, &locator), 0);
	ck_assert_uint_eq(locator, 0x1122334455667788ULL);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_locator(got, NULL), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_csum_mode(got),
			 ILA_CSUM_NEUTRAL_MAP);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_ident_type(got), ILA_ATYPE_LUID);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_hook_type(got),
			 ILA_HOOK_ROUTE_OUTPUT);

	ck_assert_int_eq(rtnl_nh_set_encap_ila_csum_mode(got, 0), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_csum_mode(got), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ila_ident_type(got, 0), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_ident_type(got), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ila_hook_type(got, 0), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_hook_type(got), 0);

	ck_assert_int_eq(rtnl_nh_set_encap(nh, NULL), 0);
	ck_assert_ptr_eq(rtnl_nh_get_encap(nh), NULL);

	encap_mpls = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap_mpls);
	ck_assert_int_eq(nl_addr_parse("100", AF_MPLS, &label), 0);
	ck_assert_int_eq(rtnl_nh_encap_mpls(encap_mpls, label, 64), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ila_csum_mode(encap_mpls, 1),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_locator(encap_mpls, &locator),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_csum_mode(encap_mpls),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_ident_type(encap_mpls),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_hook_type(encap_mpls),
			 -NLE_INVAL);
}
END_TEST

/* Userspace tests for IPv4 encap on rtnl_nh (set/get + wrong-type negatives) */

START_TEST(test_api_encap_ip)
{
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;
	_nl_auto_rtnl_nh_encap struct rtnl_nh_encap *encap = NULL;
	struct rtnl_nh_encap *got = NULL;
	struct nl_addr *got_dst = NULL;
	struct nl_addr *got_src = NULL;
	_nl_auto_nl_addr struct nl_addr *dst6 = NULL;
	_nl_auto_nl_addr struct nl_addr *src6 = NULL;
	_nl_auto_nl_addr struct nl_addr *dst4 = NULL;
	_nl_auto_nl_addr struct nl_addr *src4 = NULL;
	_nl_auto_rtnl_nh_encap struct rtnl_nh_encap *encap_mpls = NULL;
	_nl_auto_nl_addr struct nl_addr *label = NULL;
	uint64_t id = 0;

	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);

	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);
	/* This will free encap */
	ck_assert_int_eq(rtnl_nh_set_encap(NULL, _nl_steal_pointer(&encap)),
			 -NLE_INVAL);

	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);

	/* Family mismatch should be rejected */
	ck_assert_int_eq(nl_addr_parse("2001:db8::1", AF_INET6, &dst6), 0);
	ck_assert_int_eq(rtnl_nh_encap_ip(encap, dst6), -NLE_INVAL);

	/* Build a valid IPv4 encap */
	ck_assert_int_eq(nl_addr_parse("198.51.100.1", AF_INET, &dst4), 0);
	ck_assert_int_eq(rtnl_nh_encap_ip(encap, dst4), 0);
	ck_assert_int_eq(nl_addr_parse("2001:db8::2", AF_INET6, &src6), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_src(encap, src6), -NLE_INVAL);
	ck_assert_int_eq(nl_addr_parse("198.51.100.2", AF_INET, &src4), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_src(encap, src4), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_id(encap, 0x123456789ULL), 0);
	ck_assert_uint_eq(rtnl_nh_get_encap_ip_id(encap), 0x123456789ULL);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_ttl(encap, 32), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_tos(encap, 0x2e), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_flags(encap, 0x3), 0);

	/* Attach and retrieve */
	ck_assert_int_eq(rtnl_nh_set_encap(nh, _nl_steal_pointer(&encap)), 0);
	got = rtnl_nh_get_encap(nh);
	ck_assert_ptr_nonnull(got);
	ck_assert_int_eq(rtnl_nh_encap_get_type(got), LWTUNNEL_ENCAP_IP);

	/* Access IPv4-specific getters */
	got_dst = rtnl_nh_get_encap_ip_dst(got);
	ck_assert_ptr_nonnull(got_dst);
	ck_assert_int_eq(nl_addr_cmp(got_dst, dst4), 0);
	got_src = rtnl_nh_get_encap_ip_src(got);
	ck_assert_ptr_nonnull(got_src);
	ck_assert_int_eq(nl_addr_cmp(got_src, src4), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ip_ttl(got), 32);
	ck_assert_int_eq(rtnl_nh_get_encap_ip_tos(got), 0x2e);
	ck_assert_uint_eq(rtnl_nh_get_encap_ip_id(NULL), 0);
	ck_assert_uint_eq(rtnl_nh_get_encap_ip_id(got), 0x123456789ULL);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_id(got, 0x987654321ULL), 0);
	id = rtnl_nh_get_encap_ip_id(got);
	ck_assert(id == 0x987654321ULL);
	ck_assert_int_eq(rtnl_nh_get_encap_ip_flags(got), 0x3);

	/* Clear/zero optional fields and verify getters */
	ck_assert_int_eq(rtnl_nh_set_encap_ip_ttl(got, 0), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_tos(got, 0), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_id(got, 0), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_flags(got, 0), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ip_ttl(got), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ip_tos(got), 0);
	ck_assert_uint_eq(rtnl_nh_get_encap_ip_id(got), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ip_flags(got), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_src(got, NULL), 0);
	ck_assert_ptr_eq(rtnl_nh_get_encap_ip_src(got), NULL);

	/* Clear encap */
	ck_assert_int_eq(rtnl_nh_set_encap(nh, NULL), 0);
	ck_assert_ptr_eq(rtnl_nh_get_encap(nh), NULL);
	/* Type getter negative on NULL */
	ck_assert_int_eq(rtnl_nh_encap_get_type(NULL), -NLE_INVAL);

	/* Negative tests for IPv4 setters on a non-IPv4 encap (wrong type) */
	encap_mpls = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap_mpls);
	ck_assert_int_eq(nl_addr_parse("100", AF_MPLS, &label), 0);
	ck_assert_int_eq(rtnl_nh_encap_mpls(encap_mpls, label, 64), 0);

	ck_assert_int_eq(rtnl_nh_set_encap_ip_ttl(encap_mpls, 16), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_tos(encap_mpls, 1), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_id(encap_mpls, 1), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_flags(encap_mpls, 1), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_src(encap_mpls, NULL),
			 -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_encap_get_type(encap_mpls),
			 LWTUNNEL_ENCAP_MPLS);
	ck_assert_ptr_eq(rtnl_nh_get_encap_ip_dst(encap_mpls), NULL);
	ck_assert_ptr_eq(rtnl_nh_get_encap_ip_src(encap_mpls), NULL);
	ck_assert_int_eq(rtnl_nh_get_encap_ip_ttl(encap_mpls), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_encap_ip_tos(encap_mpls), -NLE_INVAL);
	ck_assert_uint_eq(rtnl_nh_get_encap_ip_id(encap_mpls), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ip_flags(encap_mpls), -NLE_INVAL);
}
END_TEST

/* Kernel round-trip tests for IPv6 encap on rtnl_nh */

START_TEST(test_kernel_roundtrip_encap_ip6)
{
	const char *IFNAME_DUMMY = "nh-dummy-encap6";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_nl_cache struct nl_cache *cache = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;
	struct rtnl_nh *knh;
	struct rtnl_nh_encap *kencap;
	struct nl_addr *kdst = NULL;
	struct nl_addr *ksrc = NULL;
	_nl_auto_nl_addr struct nl_addr *gw6 = NULL;
	_nl_auto_nl_addr struct nl_addr *dst6 = NULL;
	_nl_auto_nl_addr struct nl_addr *src6 = NULL;
	_nl_auto_rtnl_nh_encap struct rtnl_nh_encap *encap = NULL;
	uint16_t flags;
	int ifindex_dummy;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	/* Create underlay, bring it up and assign an IPv6 address */
	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_dummy_v6_with_addr(sk, IFNAME_DUMMY, &ifindex_dummy,
				      "2001:db8::2", 64);

	/* Build nexthop: IPv6 encap with dst/src/hoplimit/tc/flags and IPv6 gw */
	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);
	ck_assert_int_eq(rtnl_nh_set_id(nh, 3201), 0);

	ck_assert_int_eq(nl_addr_parse("2001:db8::1", AF_INET6, &gw6), 0);
	ck_assert_int_eq(rtnl_nh_set_gateway(nh, gw6), 0);

	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);
	ck_assert_int_eq(nl_addr_parse("2001:db8:1::1", AF_INET6, &dst6), 0);
	ck_assert_int_eq(rtnl_nh_encap_ip6(encap, dst6), 0);
	ck_assert_int_eq(nl_addr_parse("2001:db8:1::2", AF_INET6, &src6), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_src(encap, src6), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_hoplimit(encap, 32), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_tc(encap, 0x2e), 0);
	flags = TUNNEL_KEY | TUNNEL_CSUM | TUNNEL_SEQ;
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_flags(encap, flags), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip6_id(encap, 0x1122334455667788ULL),
			 0);
	ck_assert_int_eq(rtnl_nh_set_encap(nh, _nl_steal_pointer(&encap)), 0);

	/* Set required attributes and add */
	ck_assert_int_eq(rtnl_nh_set_oif(nh, (uint32_t)ifindex_dummy), 0);
	ck_assert_int_eq(rtnl_nh_set_family(nh, AF_INET6), 0);
	ck_assert_int_eq(rtnl_nh_add(sk, nh, NLM_F_CREATE), 0);

	/* Query and verify */
	ck_assert_int_eq(rtnl_nh_alloc_cache(sk, AF_UNSPEC, &cache), 0);
	knh = rtnl_nh_get(cache, 3201);
	ck_assert_ptr_nonnull(knh);
	ck_assert_int_eq(rtnl_nh_get_id(knh), 3201);
	ck_assert_int_eq(rtnl_nh_get_oif(knh), ifindex_dummy);

	kencap = rtnl_nh_get_encap(knh);
	ck_assert_ptr_nonnull(kencap);
	ck_assert_int_eq(rtnl_nh_encap_get_type(kencap), LWTUNNEL_ENCAP_IP6);
	kdst = rtnl_nh_get_encap_ip6_dst(kencap);
	ck_assert_ptr_nonnull(kdst);
	ck_assert_int_eq(nl_addr_cmp(kdst, dst6), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ip6_hoplimit(kencap), 32);
	ck_assert_int_eq(rtnl_nh_get_encap_ip6_tc(kencap), 0x2e);
	ksrc = rtnl_nh_get_encap_ip6_src(kencap);
	ck_assert_ptr_nonnull(ksrc);
	ck_assert_int_eq(nl_addr_cmp(ksrc, src6), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ip6_flags(kencap), flags);
	ck_assert_uint_eq(rtnl_nh_get_encap_ip6_id(kencap),
			  0x1122334455667788ULL);
}
END_TEST

START_TEST(test_kernel_roundtrip_encap_ila)
{
	const char *IFNAME_DUMMY = "encap-ila";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_nl_cache struct nl_cache *cache = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;
	_nl_auto_nl_addr struct nl_addr *gw6 = NULL;
	struct rtnl_nh *knh;
	struct rtnl_nh_encap *kencap;
	_nl_auto_rtnl_nh_encap struct rtnl_nh_encap *encap = NULL;
	uint64_t locator = 0;
	int ifindex_dummy;
	int ret;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	/* Create underlay, bring it up and assign an IPv6 address */
	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_dummy_v6_with_addr(sk, IFNAME_DUMMY, &ifindex_dummy,
				      "2001:db8:2::2", 64);

	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);
	ck_assert_int_eq(rtnl_nh_set_id(nh, 3401), 0);

	ck_assert_int_eq(nl_addr_parse("2001:db8:2::1", AF_INET6, &gw6), 0);
	ck_assert_int_eq(rtnl_nh_set_gateway(nh, gw6), 0);

	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);
	ck_assert_int_eq(rtnl_nh_encap_ila(encap, 0x1122334455667788ULL), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ila_csum_mode(encap,
							 ILA_CSUM_NEUTRAL_MAP),
			 0);
	ck_assert_int_eq(
		rtnl_nh_set_encap_ila_ident_type(encap, ILA_ATYPE_LUID), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ila_hook_type(encap,
							 ILA_HOOK_ROUTE_OUTPUT),
			 0);
	ck_assert_int_eq(rtnl_nh_set_encap(nh, _nl_steal_pointer(&encap)), 0);

	ck_assert_int_eq(rtnl_nh_set_oif(nh, (uint32_t)ifindex_dummy), 0);
	ck_assert_int_eq(rtnl_nh_set_family(nh, AF_INET6), 0);
	ret = rtnl_nh_add(sk, nh, NLM_F_CREATE);
	if (ret == -NLE_OPNOTSUPP) {
		/* ila module is not loaded - skipping */
		return;
	}
	ck_assert_int_eq(ret, 0);

	ck_assert_int_eq(rtnl_nh_alloc_cache(sk, AF_UNSPEC, &cache), 0);
	knh = rtnl_nh_get(cache, 3401);
	ck_assert_ptr_nonnull(knh);
	ck_assert_int_eq(rtnl_nh_get_id(knh), 3401);
	ck_assert_int_eq(rtnl_nh_get_oif(knh), ifindex_dummy);

	kencap = rtnl_nh_get_encap(knh);
	ck_assert_ptr_nonnull(kencap);
	ck_assert_int_eq(rtnl_nh_encap_get_type(kencap), LWTUNNEL_ENCAP_ILA);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_locator(kencap, &locator), 0);
	ck_assert_uint_eq(locator, 0x1122334455667788ULL);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_csum_mode(kencap),
			 ILA_CSUM_NEUTRAL_MAP);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_ident_type(kencap),
			 ILA_ATYPE_LUID);
	ck_assert_int_eq(rtnl_nh_get_encap_ila_hook_type(kencap),
			 ILA_HOOK_ROUTE_OUTPUT);
}
END_TEST

/* Kernel round-trip tests for IPv4 encap on rtnl_nh */

START_TEST(test_kernel_roundtrip_encap_ip)
{
	const char *IFNAME_DUMMY = "nh-dummy-encap4";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_nl_cache struct nl_cache *cache = NULL;
	_nl_auto_rtnl_nh struct rtnl_nh *nh = NULL;
	struct rtnl_nh *knh;
	struct rtnl_nh_encap *kencap;
	struct nl_addr *kdst = NULL;
	struct nl_addr *ksrc = NULL;
	_nl_auto_nl_addr struct nl_addr *gw4 = NULL;
	_nl_auto_nl_addr struct nl_addr *dst4 = NULL;
	_nl_auto_nl_addr struct nl_addr *src4 = NULL;
	_nl_auto_rtnl_nh_encap struct rtnl_nh_encap *encap = NULL;
	int ifindex_dummy;
	uint64_t id = 0;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	/* Create underlay and assign an IPv4 address */
	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_dummy_v4_with_addr(sk, IFNAME_DUMMY, &ifindex_dummy,
				      "192.0.2.2", 24);

	/* Build nexthop: IPv4 encap with dst/src/ttl/tos and IPv4 gw */
	nh = rtnl_nh_alloc();
	ck_assert_ptr_nonnull(nh);
	ck_assert_int_eq(rtnl_nh_set_id(nh, 3301), 0);

	ck_assert_int_eq(nl_addr_parse("192.0.2.1", AF_INET, &gw4), 0);
	ck_assert_int_eq(rtnl_nh_set_gateway(nh, gw4), 0);

	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);
	ck_assert_int_eq(nl_addr_parse("198.51.100.1", AF_INET, &dst4), 0);
	ck_assert_int_eq(rtnl_nh_encap_ip(encap, dst4), 0);
	ck_assert_int_eq(nl_addr_parse("198.51.100.2", AF_INET, &src4), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_src(encap, src4), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_id(encap, 0xABCDEFULL), 0);
	ck_assert_uint_eq(rtnl_nh_get_encap_ip_id(encap), 0xABCDEFULL);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_ttl(encap, 32), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_tos(encap, 0x2e), 0);
	ck_assert_int_eq(rtnl_nh_set_encap_ip_flags(encap, 0x5), 0);
	ck_assert_int_eq(rtnl_nh_set_encap(nh, _nl_steal_pointer(&encap)), 0);

	/* Set required attributes and add */
	ck_assert_int_eq(rtnl_nh_set_oif(nh, (uint32_t)ifindex_dummy), 0);
	ck_assert_int_eq(rtnl_nh_set_family(nh, AF_INET), 0);
	ck_assert_int_eq(rtnl_nh_add(sk, nh, NLM_F_CREATE), 0);

	/* Query and verify */
	ck_assert_int_eq(rtnl_nh_alloc_cache(sk, AF_UNSPEC, &cache), 0);
	knh = rtnl_nh_get(cache, 3301);
	ck_assert_ptr_nonnull(knh);
	ck_assert_int_eq(rtnl_nh_get_id(knh), 3301);
	ck_assert_int_eq(rtnl_nh_get_oif(knh), ifindex_dummy);

	kencap = rtnl_nh_get_encap(knh);
	ck_assert_ptr_nonnull(kencap);
	ck_assert_int_eq(rtnl_nh_encap_get_type(kencap), LWTUNNEL_ENCAP_IP);
	kdst = rtnl_nh_get_encap_ip_dst(kencap);
	ck_assert_ptr_nonnull(kdst);
	ck_assert_int_eq(nl_addr_cmp(kdst, dst4), 0);
	ck_assert_int_eq(rtnl_nh_get_encap_ip_ttl(kencap), 32);
	ck_assert_int_eq(rtnl_nh_get_encap_ip_tos(kencap), 0x2e);
	id = rtnl_nh_get_encap_ip_id(kencap);
	ck_assert(id == 0xABCDEFULL);
	ck_assert_int_eq(rtnl_nh_get_encap_ip_flags(kencap), 0x5);
	ksrc = rtnl_nh_get_encap_ip_src(kencap);
	ck_assert_ptr_nonnull(ksrc);
	ck_assert_int_eq(nl_addr_cmp(ksrc, src4), 0);
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
	/* Userspace IPv6 encap tests */
	tcase_add_test(tc_api, test_api_encap_ip6);
	/* Userspace ILA encap tests */
	tcase_add_test(tc_api, test_api_encap_ila);
	/* Userspace IPv4 encap tests */
	tcase_add_test(tc_api, test_api_encap_ip);
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
	/* Encap (IPv6) on rtnl_nh */
	tcase_add_test(tc_kernel, test_kernel_roundtrip_encap_ip6);
	/* Encap (ILA) on rtnl_nh */
	tcase_add_test(tc_kernel, test_kernel_roundtrip_encap_ila);
	/* Encap (IPv4) on rtnl_nh */
	tcase_add_test(tc_kernel, test_kernel_roundtrip_encap_ip);
	/* Negative tests: kernel should reject invalid nexthops */
	tcase_add_test(tc_kernel, test_kernel_negative_mismatched_gw_family);
	tcase_add_test(tc_kernel, test_kernel_negative_group_without_entries);
	tcase_add_test(tc_kernel, test_kernel_negative_gateway_without_oif);
	suite_add_tcase(suite, tc_kernel);

	return suite;
}
