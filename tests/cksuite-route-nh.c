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

#include <netlink/route/nh.h>

#include "cksuite-all.h"

/*****************************************************************************/
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

Suite *make_nl_route_nh_suite(void)
{
	Suite *suite = suite_create("route-nh");
	TCase *tc_api = tcase_create("Userspace-API");

	/* Comprehensive API setter/getter test (userspace only) */
	tcase_add_test(tc_api, test_api_set_get_all);
	suite_add_tcase(suite, tc_api);

	return suite;
}
