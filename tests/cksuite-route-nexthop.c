/* SPDX-License-Identifier: LGPL-2.1-only */

/*
 * Tests for include/netlink/route/nexthop.h getters and setters.
 *
 * We cover two aspects:
 *   1. Pure userspace logic – manipulating an allocated rtnl_nexthop object
 *      and validating all getters, including negative/error conditions.
 *   2. Kernel round-trips – create real routes with nexthops in a private
 *      network namespace, query them back and verify attributes round-trip.
 */

#include "nl-default.h"

#include <linux/rtnetlink.h>
#include <linux/if.h>

#include <netlink/addr.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>

#include "cksuite-all.h"
#include "nl-priv-dynamic-route/nl-priv-dynamic-route.h"

/*****************************************************************************/
/* Userspace API tests */

START_TEST(test_route_nexthop_api_set_get_all)
{
	_nl_auto_rtnl_nexthop struct rtnl_nexthop *nh = NULL;
	_nl_auto_nl_addr struct nl_addr *gw4 = NULL;
	_nl_auto_nl_addr struct nl_addr *gw6 = NULL;
	_nl_auto_nl_addr struct nl_addr *newdst4 = NULL;
	_nl_auto_nl_addr struct nl_addr *via6 = NULL;
	_nl_auto_nl_addr struct nl_addr *mpls = NULL;
	_nl_auto_rtnl_nexthop struct rtnl_nexthop *clone = NULL;
	_nl_auto_rtnl_nexthop struct rtnl_nexthop *clone_with_encap = NULL;
	struct rtnl_nh_encap *encap = NULL;
	struct rtnl_nh_encap *got = NULL;
	struct rtnl_nh_encap *encap_clone = NULL;
	uint32_t realms = 0xAABBCCDDu;
	char flags_buf[64];
	int flags_parsed;

	nh = rtnl_route_nh_alloc();
	ck_assert_ptr_nonnull(nh);

	/* Ifindex set/get */
	ck_assert_int_eq(rtnl_route_nh_get_ifindex(nh), 0);
	rtnl_route_nh_set_ifindex(nh, 123);
	ck_assert_int_eq(rtnl_route_nh_get_ifindex(nh), 123);

	/* Weight set/get */
	ck_assert_uint_eq(rtnl_route_nh_get_weight(nh), 0);
	rtnl_route_nh_set_weight(nh, 7);
	ck_assert_uint_eq(rtnl_route_nh_get_weight(nh), 7);

	/* Flags set/unset/get and string conversion */
	ck_assert_uint_eq(rtnl_route_nh_get_flags(nh), 0U);
	rtnl_route_nh_set_flags(nh, RTNH_F_ONLINK);
	ck_assert_int_eq((int)(rtnl_route_nh_get_flags(nh) & RTNH_F_ONLINK),
			 (int)RTNH_F_ONLINK);
	ck_assert_ptr_nonnull(rtnl_route_nh_flags2str(RTNH_F_ONLINK, flags_buf,
						      sizeof(flags_buf)));
	flags_parsed = rtnl_route_nh_str2flags("onlink");
	ck_assert_int_eq(flags_parsed, RTNH_F_ONLINK);
	rtnl_route_nh_unset_flags(nh, RTNH_F_ONLINK);
	ck_assert_int_eq((int)(rtnl_route_nh_get_flags(nh) & RTNH_F_ONLINK), 0);

	/* Realms set/get */
	ck_assert_uint_eq(rtnl_route_nh_get_realms(nh), 0U);
	rtnl_route_nh_set_realms(nh, realms);
	ck_assert_uint_eq(rtnl_route_nh_get_realms(nh), realms);

	/* Gateway get/set; start NULL, set v4 then replace with v6 */
	ck_assert_ptr_eq(rtnl_route_nh_get_gateway(nh), NULL);
	ck_assert_int_eq(nl_addr_parse("192.0.2.1", AF_INET, &gw4), 0);
	rtnl_route_nh_set_gateway(nh, gw4);
	ck_assert_ptr_nonnull(rtnl_route_nh_get_gateway(nh));
	ck_assert_int_eq(nl_addr_get_family(rtnl_route_nh_get_gateway(nh)),
			 AF_INET);
	ck_assert_int_eq(nl_addr_parse("2001:db8::1", AF_INET6, &gw6), 0);
	rtnl_route_nh_set_gateway(nh, gw6);
	ck_assert_int_eq(nl_addr_shared(gw4), 0);
	ck_assert_int_eq(nl_addr_get_family(rtnl_route_nh_get_gateway(nh)),
			 AF_INET6);
	rtnl_route_nh_set_gateway(nh, NULL);
	ck_assert_ptr_eq(rtnl_route_nh_get_gateway(nh), NULL);

	/* newdst set/get */
	ck_assert_ptr_eq(rtnl_route_nh_get_newdst(nh), NULL);
	ck_assert_int_eq(nl_addr_parse("198.51.100.7", AF_INET, &newdst4), 0);
	ck_assert_int_eq(rtnl_route_nh_set_newdst(nh, newdst4), 0);
	ck_assert_ptr_nonnull(rtnl_route_nh_get_newdst(nh));
	ck_assert_int_eq(nl_addr_get_family(rtnl_route_nh_get_newdst(nh)),
			 AF_INET);
	ck_assert_int_eq(rtnl_route_nh_set_newdst(nh, NULL), 0);
	ck_assert_ptr_eq(rtnl_route_nh_get_newdst(nh), NULL);

	/* via set/get */
	ck_assert_ptr_eq(rtnl_route_nh_get_via(nh), NULL);
	ck_assert_int_eq(nl_addr_parse("2001:db8::2", AF_INET6, &via6), 0);
	ck_assert_int_eq(rtnl_route_nh_set_via(nh, via6), 0);
	ck_assert_ptr_nonnull(rtnl_route_nh_get_via(nh));
	ck_assert_int_eq(nl_addr_get_family(rtnl_route_nh_get_via(nh)),
			 AF_INET6);
	ck_assert_int_eq(rtnl_route_nh_set_via(nh, NULL), 0);
	ck_assert_ptr_eq(rtnl_route_nh_get_via(nh), NULL);

	/* clone, compare, identical */
	clone = rtnl_route_nh_clone(nh);
	ck_assert_ptr_nonnull(clone);
	ck_assert_int_eq(rtnl_route_nh_compare(nh, clone, 0xFFFFFFFFu, 0), 0);

	/* Only differ in flags/weight -> identical() should still be true */
	rtnl_route_nh_set_weight(clone, 9);
	rtnl_route_nh_set_flags(clone, RTNH_F_ONLINK);
	ck_assert_int_ne(rtnl_route_nh_compare(nh, clone, 0xFFFFFFFFu, 0), 0);
	ck_assert_int_ne(rtnl_route_nh_identical(nh, clone), 0);

	/* MPLS encapsulation */
	encap = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap);

	ck_assert_int_eq(rtnl_nh_get_encap_mpls_ttl(NULL), -NLE_INVAL);
	ck_assert_int_eq(rtnl_nh_get_encap_mpls_ttl(encap), -NLE_INVAL);

	/* Invalid: missing destination labels */
	ck_assert_int_eq(rtnl_nh_encap_mpls(encap, NULL, 0), -NLE_INVAL);

	/* Valid MPLS encap: push label 100 with TTL 64 */
	ck_assert_int_eq(nl_addr_parse("100", AF_MPLS, &mpls), 0);
	ck_assert_int_eq(rtnl_nh_encap_mpls(encap, mpls, 64), 0);

	/* Attach encap to nexthop and retrieve it back */
	ck_assert_int_eq(rtnl_route_nh_set_encap(nh, encap), 0);
	got = rtnl_route_nh_get_encap(nh);
	ck_assert_ptr_eq(got, encap);

	/* Access MPLS encap details through the new getters */
	ck_assert_ptr_nonnull(rtnl_nh_get_encap_mpls_dst(got));
	ck_assert_int_eq(rtnl_nh_get_encap_mpls_ttl(got), 64);

	/* Exercise rtnl_nh_encap_clone() directly */
	encap_clone = rtnl_nh_encap_clone(encap);
	ck_assert_ptr_nonnull(encap_clone);
	ck_assert_ptr_nonnull(rtnl_nh_get_encap_mpls_dst(encap_clone));
	ck_assert_int_eq(
		nl_addr_cmp(rtnl_nh_get_encap_mpls_dst(encap_clone), mpls), 0);
	ck_assert_uint_eq(rtnl_nh_get_encap_mpls_ttl(encap_clone), 64);
	/* Free the cloned encap explicitly */
	rtnl_nh_encap_free(encap_clone);
	encap_clone = NULL;

	/* Exercise nexthop clone with encap: encap should be deep-cloned */
	clone_with_encap = rtnl_route_nh_clone(nh);
	ck_assert_ptr_nonnull(clone_with_encap);
	encap_clone = rtnl_route_nh_get_encap(clone_with_encap);
	ck_assert_ptr_nonnull(encap_clone);
	/* The encap on the clone must not be the same pointer */
	ck_assert_ptr_ne(encap_clone, encap);
	ck_assert_int_eq(
		nl_addr_cmp(rtnl_nh_get_encap_mpls_dst(encap_clone), mpls), 0);
	ck_assert_uint_eq(rtnl_nh_get_encap_mpls_ttl(encap_clone), 64);

	/* Clear encap and verify it is removed */
	ck_assert_int_eq(rtnl_route_nh_set_encap(nh, NULL), 0);
	ck_assert_ptr_eq(rtnl_route_nh_get_encap(nh), NULL);
}
END_TEST

/*****************************************************************************/
/* Kernel round-trip tests */

/*
 * Helper: retrieve a configured route object by its prefix (exact match).
 * This searches the kernel's route tables for a route whose destination
 * prefix matches the nl_addr 'dst' (including prefix length), and returns
 * it via 'out'.
 */
static int nltst_route_get_by_dst(struct nl_sock *sk, struct nl_addr *dst,
				  struct rtnl_route **out)
{
	_nl_auto_nl_cache struct nl_cache *cache = NULL;
	_nl_auto_rtnl_route struct rtnl_route *filter = NULL;
	struct nl_object *obj;
	int err;

	if (!dst || !out)
		return -NLE_INVAL;

	err = rtnl_route_alloc_cache(sk, nl_addr_get_family(dst), 0, &cache);
	if (err < 0)
		return err;

	filter = rtnl_route_alloc();
	if (!filter)
		return -NLE_NOMEM;

	err = rtnl_route_set_dst(filter, dst);
	if (err < 0)
		return err;

	obj = nl_cache_find(cache, (struct nl_object *)filter);
	if (!obj)
		return -NLE_OBJ_NOTFOUND;

	*out = (struct rtnl_route *)obj;
	return 0;
}

START_TEST(test_kernel_route_roundtrip_single_v4)
{
	const char *IFNAME_DUMMY = "rnh-dummy0";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_rtnl_route struct rtnl_route *route = NULL;
	_nl_auto_rtnl_route struct rtnl_route *got = NULL;
	_nl_auto_nl_addr struct nl_addr *dst = NULL;
	_nl_auto_nl_addr struct nl_addr *gw = NULL;
	struct rtnl_nexthop *nh, *knh;
	struct nl_addr *kgw;
	int ifindex_dummy;
	int r;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_dummy_v4_with_addr(sk, IFNAME_DUMMY, &ifindex_dummy,
				      "192.0.2.2", 24);

	/* Build a simple IPv4 route via gateway on dummy */
	route = rtnl_route_alloc();
	ck_assert_ptr_nonnull(route);
	ck_assert_int_eq(nl_addr_parse("198.51.100.0/24", AF_INET, &dst), 0);
	ck_assert_int_eq(rtnl_route_set_family(route, AF_INET), 0);
	ck_assert_int_eq(rtnl_route_set_dst(route, dst), 0);

	nh = rtnl_route_nh_alloc();
	ck_assert_ptr_nonnull(nh);
	rtnl_route_nh_set_ifindex(nh, ifindex_dummy);
	ck_assert_int_eq(nl_addr_parse("192.0.2.1", AF_INET, &gw), 0);
	rtnl_route_nh_set_realms(nh, 0xdeadbeef);
	rtnl_route_nh_set_gateway(nh, gw);
	rtnl_route_nh_set_weight(nh, 1);
	rtnl_route_add_nexthop(route, nh);

	r = rtnl_route_add(sk, route, NLM_F_CREATE);
	ck_assert_int_eq(r, 0);

	/* Retrieve the route back by its prefix and validate nexthop attributes */
	ck_assert_int_eq(nltst_route_get_by_dst(sk, dst, &got), 0);
	ck_assert_ptr_nonnull(got);
	ck_assert_int_eq(nl_addr_cmp(rtnl_route_get_dst(got), dst), 0);
	ck_assert_int_eq(rtnl_route_get_nnexthops(got), 1);

	knh = rtnl_route_nexthop_n(got, 0);
	kgw = rtnl_route_nh_get_gateway(knh);
	ck_assert_int_eq(rtnl_route_nh_get_ifindex(knh), ifindex_dummy);
	ck_assert_ptr_nonnull(kgw);
	ck_assert_int_eq(nl_addr_get_family(kgw), AF_INET);
	ck_assert_int_eq(nl_addr_cmp(kgw, gw), 0);

	/* Single-nexthop route weight is not propagated to kernel - thus check for 0 */
	ck_assert_uint_eq(rtnl_route_nh_get_weight(knh), 0);
	ck_assert_uint_eq(rtnl_route_nh_get_flags(knh), 0U);
	ck_assert_uint_eq(rtnl_route_nh_get_realms(knh), 0xdeadbeef);
	ck_assert_ptr_eq(rtnl_route_nh_get_newdst(knh), NULL);
	ck_assert_ptr_eq(rtnl_route_nh_get_via(knh), NULL);
	/* No encap present */
	ck_assert_ptr_eq(rtnl_route_nh_get_encap(knh), NULL);
}
END_TEST

static void nltst_assert_multipath_v4(struct rtnl_route *route,
				      int ifindex_dummy, struct nl_addr *gw1,
				      unsigned int w1, struct nl_addr *gw2,
				      unsigned int w2, uint32_t realms)
{
	int seen_gw1 = 0, seen_gw2 = 0;
	struct nl_list_head *list = rtnl_route_get_nexthops(route);
	struct rtnl_nexthop *knh;
	size_t cnt = 0;

	nl_list_for_each_entry(knh, list, rtnh_list) {
		struct nl_addr *kgw = rtnl_route_nh_get_gateway(knh);

		ck_assert_int_eq(rtnl_route_nh_get_ifindex(knh), ifindex_dummy);
		ck_assert_ptr_nonnull(kgw);
		ck_assert_int_eq(nl_addr_get_family(kgw), AF_INET);

		if (nl_addr_cmp(kgw, gw1) == 0) {
			seen_gw1 = 1;
			ck_assert_uint_eq(rtnl_route_nh_get_weight(knh), w1);
		}
		if (nl_addr_cmp(kgw, gw2) == 0) {
			seen_gw2 = 1;
			ck_assert_uint_eq(rtnl_route_nh_get_weight(knh), w2);
		}

		ck_assert_uint_eq(rtnl_route_nh_get_flags(knh), 0U);
		ck_assert_uint_eq(rtnl_route_nh_get_realms(knh), realms);
		ck_assert_ptr_eq(rtnl_route_nh_get_newdst(knh), NULL);
		ck_assert_ptr_eq(rtnl_route_nh_get_via(knh), NULL);
		/* No encap present */
		ck_assert_ptr_eq(rtnl_route_nh_get_encap(knh), NULL);

		cnt++;
	}

	ck_assert_uint_eq(cnt, 2);
	ck_assert_int_ne(seen_gw1, 0);
	ck_assert_int_ne(seen_gw2, 0);
}

START_TEST(test_kernel_route_roundtrip_multipath_v4)
{
	const char *IFNAME_DUMMY = "rnh-dummy1";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_rtnl_route struct rtnl_route *route = NULL;
	_nl_auto_rtnl_route struct rtnl_route *got = NULL;
	_nl_auto_nl_addr struct nl_addr *dst = NULL;
	_nl_auto_nl_addr struct nl_addr *gw1 = NULL;
	_nl_auto_nl_addr struct nl_addr *gw2 = NULL;
	struct rtnl_nexthop *nh1 = NULL;
	struct rtnl_nexthop *nh2 = NULL;
	int ifindex_dummy;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_dummy_v4_with_addr(sk, IFNAME_DUMMY, &ifindex_dummy,
				      "192.0.2.2", 24);

	/* Build IPv4 ECMP route with 2 nexthops differing by gateway */
	route = rtnl_route_alloc();
	ck_assert_ptr_nonnull(route);
	ck_assert_int_eq(nl_addr_parse("198.51.101.0/24", AF_INET, &dst), 0);
	ck_assert_int_eq(rtnl_route_set_family(route, AF_INET), 0);
	ck_assert_int_eq(rtnl_route_set_dst(route, dst), 0);

	nh1 = rtnl_route_nh_alloc();
	ck_assert_ptr_nonnull(nh1);
	rtnl_route_nh_set_ifindex(nh1, ifindex_dummy);
	ck_assert_int_eq(nl_addr_parse("192.0.2.1", AF_INET, &gw1), 0);
	rtnl_route_nh_set_gateway(nh1, gw1);
	rtnl_route_nh_set_weight(nh1, 1);
	rtnl_route_nh_set_realms(nh1, 0xdeadbeef);
	rtnl_route_add_nexthop(route, nh1);

	nh2 = rtnl_route_nh_alloc();
	ck_assert_ptr_nonnull(nh2);
	rtnl_route_nh_set_ifindex(nh2, ifindex_dummy);
	ck_assert_int_eq(nl_addr_parse("192.0.2.3", AF_INET, &gw2), 0);
	rtnl_route_nh_set_gateway(nh2, gw2);
	rtnl_route_nh_set_weight(nh2, 2);
	rtnl_route_nh_set_realms(nh2, 0xdeadbeef);
	rtnl_route_add_nexthop(route, nh2);

	ck_assert_int_eq(rtnl_route_add(sk, route, NLM_F_CREATE), 0);

	/* Retrieve the route back by its prefix and validate multipath nexthops */
	ck_assert_int_eq(nltst_route_get_by_dst(sk, dst, &got), 0);
	ck_assert_ptr_nonnull(got);
	ck_assert_int_eq(nl_addr_cmp(rtnl_route_get_dst(got), dst), 0);
	ck_assert_int_eq(rtnl_route_get_nnexthops(got), 2);

	nltst_assert_multipath_v4(got, ifindex_dummy, gw1, 1, gw2, 2,
				  0xdeadbeef);
}
END_TEST

static void nltst_assert_single_v4_mpls(struct rtnl_route *route,
					int ifindex_dummy, struct nl_addr *gw,
					struct nl_addr *labels,
					unsigned int ttl)
{
	struct rtnl_nexthop *knh = rtnl_route_nexthop_n(route, 0);
	struct nl_addr *kgw = rtnl_route_nh_get_gateway(knh);
	struct rtnl_nh_encap *encap = rtnl_route_nh_get_encap(knh);
	struct nl_addr *klabels;

	ck_assert_ptr_nonnull(encap);
	ck_assert_int_eq(rtnl_route_nh_get_ifindex(knh), ifindex_dummy);
	ck_assert_ptr_nonnull(kgw);
	ck_assert_int_eq(nl_addr_get_family(kgw), AF_INET);
	ck_assert_int_eq(nl_addr_cmp(kgw, gw), 0);

	klabels = rtnl_nh_get_encap_mpls_dst(encap);
	ck_assert_ptr_nonnull(klabels);
	ck_assert_int_eq(nl_addr_get_family(klabels), AF_MPLS);
	ck_assert_int_eq(nl_addr_cmp(klabels, labels), 0);

	ck_assert_int_eq(rtnl_nh_get_encap_mpls_ttl(encap), ttl);
}

START_TEST(test_kernel_route_roundtrip_nh_mpls_encap_v4)
{
	const char *IFNAME_DUMMY = "rnh-dummy2";
	_nltst_auto_delete_link const char *auto_del_dummy = NULL;
	_nl_auto_nl_socket struct nl_sock *sk = NULL;
	_nl_auto_rtnl_route struct rtnl_route *route = NULL;
	_nl_auto_rtnl_route struct rtnl_route *got = NULL;
	_nl_auto_nl_addr struct nl_addr *dst = NULL;
	_nl_auto_nl_addr struct nl_addr *gw = NULL;
	_nl_auto_nl_addr struct nl_addr *labels = NULL;
	struct rtnl_nh_encap *encap2;
	struct rtnl_nexthop *nh = NULL;
	int ifindex_dummy;

	if (_nltst_skip_no_netns())
		return;

	sk = _nltst_socket(NETLINK_ROUTE);

	auto_del_dummy = IFNAME_DUMMY;
	_nltst_add_dummy_v4_with_addr(sk, IFNAME_DUMMY, &ifindex_dummy,
				      "192.0.2.2", 24);

	/* Build a simple IPv4 route via gateway on dummy with MPLS encap */
	route = rtnl_route_alloc();
	ck_assert_ptr_nonnull(route);
	ck_assert_int_eq(nl_addr_parse("198.51.102.0/24", AF_INET, &dst), 0);
	ck_assert_int_eq(rtnl_route_set_family(route, AF_INET), 0);
	ck_assert_int_eq(rtnl_route_set_dst(route, dst), 0);

	nh = rtnl_route_nh_alloc();
	ck_assert_ptr_nonnull(nh);
	rtnl_route_nh_set_ifindex(nh, ifindex_dummy);
	ck_assert_int_eq(nl_addr_parse("192.0.2.1", AF_INET, &gw), 0);
	rtnl_route_nh_set_gateway(nh, gw);

	/* Push label 100 with TTL 64 */
	encap2 = rtnl_nh_encap_alloc();
	ck_assert_ptr_nonnull(encap2);
	ck_assert_int_eq(nl_addr_parse("100", AF_MPLS, &labels), 0);
	ck_assert_int_eq(rtnl_nh_encap_mpls(encap2, labels, 64), 0);
	ck_assert_int_eq(rtnl_route_nh_set_encap(nh, encap2), 0);
	rtnl_route_add_nexthop(route, nh);

	ck_assert_int_eq(rtnl_route_add(sk, route, NLM_F_CREATE), 0);

	/* Retrieve the route back by its prefix and validate MPLS encap on nexthop */
	ck_assert_int_eq(nltst_route_get_by_dst(sk, dst, &got), 0);
	ck_assert_ptr_nonnull(got);
	ck_assert_int_eq(nl_addr_cmp(rtnl_route_get_dst(got), dst), 0);
	ck_assert_int_eq(rtnl_route_get_nnexthops(got), 1);
	nltst_assert_single_v4_mpls(got, ifindex_dummy, gw, labels, 64u);
}
END_TEST

Suite *make_nl_route_nexthop_suite(void)
{
	Suite *suite = suite_create("route-nexthop");
	TCase *tc_api = tcase_create("Userspace-API");
	TCase *tc_kernel = tcase_create("Kernel");

	/* Userspace only tests */
	tcase_add_test(tc_api, test_route_nexthop_api_set_get_all);
	suite_add_tcase(suite, tc_api);

	/* Kernel round-trip – needs private netns */
	tcase_add_checked_fixture(tc_kernel, nltst_netns_fixture_setup,
				  nltst_netns_fixture_teardown);
	tcase_add_test(tc_kernel, test_kernel_route_roundtrip_single_v4);
	tcase_add_test(tc_kernel, test_kernel_route_roundtrip_multipath_v4);
	/* Nexthop encapsulation roundtrip tests */
	tcase_add_test(tc_kernel, test_kernel_route_roundtrip_nh_mpls_encap_v4);
	suite_add_tcase(suite, tc_kernel);

	return suite;
}
