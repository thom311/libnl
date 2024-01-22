/* SPDX-License-Identifier: LGPL-2.1-only */

#include "nl-default.h"

#include <check.h>

#include <linux/snmp.h>
#include <linux/if_bridge.h>

#include <netlink/route/link.h>
#include <netlink/route/link/bridge.h>

#include "nl-priv-static-route/nl-priv-static-route.h"
#include "nl-aux-core/nl-core.h"

#define CASES 5
#define MAX_ATTR 7

START_TEST(static_checks)
{
	int i, j;
	char strbuf[100];

	_NL_STATIC_ASSERT(RTNL_LINK_RX_PACKETS == 0);
	assert(_nltst_map_stat_id_from_IPSTATS_MIB_v2[0] ==
	       RTNL_LINK_RX_PACKETS);
	for (i = 1; i < __IPSTATS_MIB_MAX; i++) {
		assert(_nltst_map_stat_id_from_IPSTATS_MIB_v2[i] > 0);
		assert(_nltst_map_stat_id_from_IPSTATS_MIB_v2[i] <
		       __RTNL_LINK_STATS_MAX);
		for (j = 1; j < i; j++)
			assert(_nltst_map_stat_id_from_IPSTATS_MIB_v2[i] !=
			       _nltst_map_stat_id_from_IPSTATS_MIB_v2[j]);
	}

	for (i = 0; i <= RTNL_LINK_STATS_MAX + 1; i++) {
		const char *s;

		s = rtnl_link_stat2str(i, strbuf, sizeof(strbuf));
		assert(s);
		assert(s == strbuf);
		assert(strlen(s) < sizeof(strbuf));
		if (strncmp(s, "0x", 2) == 0) {
			assert(i == RTNL_LINK_STATS_MAX + 1);
			ck_assert_int_eq(strtoll(&s[2], NULL, 16), i);
		} else
			ck_assert_int_le(i, RTNL_LINK_STATS_MAX);
		ck_assert_int_eq(i, rtnl_link_str2stat(s));
	}

	ck_assert_int_eq(nl_str2ip_proto(""), -NLE_OBJ_NOTFOUND);
	ck_assert_int_eq(nl_str2ip_proto("5"), 5);
	ck_assert_int_eq(nl_str2ip_proto("  13 "), -NLE_OBJ_NOTFOUND);
	ck_assert_int_eq(nl_str2ip_proto("13"), 13);
	ck_assert_int_eq(nl_str2ip_proto("0x13"), 0x13);
	ck_assert_int_eq(nl_str2ip_proto("0342"), 0342);
	ck_assert_int_eq(nl_str2ip_proto("2147483647"), 2147483647);
	ck_assert_int_eq(nl_str2ip_proto("2147483648"), -NLE_OBJ_NOTFOUND);
}
END_TEST

static void set_bitmap_range(u_int32_t start, u_int32_t end,
			     struct rtnl_link_bridge_vlan *vlan_info,
			     int untagged)
{
	for (u_int32_t i = start; i <= end; i++) {
		vlan_info->vlan_bitmap[i / 32] |= (((uint32_t)1) << (i % 32));
		if (untagged) {
			vlan_info->untagged_bitmap[i / 32] |=
				(((uint32_t)1) << (i % 32));
		}
	}
}

START_TEST(vlan_attribute_check)
{
	struct nlmsghdr *nlh;
	struct nlattr *a;
	int attr_count, rem;
	struct bridge_vlan_info *vlan_attr;
	struct rtnl_link_bridge_vlan vlan_info[CASES];
	struct bridge_vlan_info expected_attr[CASES][MAX_ATTR];

	for (int i = 0; i < CASES; i++) {
		memset(&vlan_info[i], 0, sizeof(struct rtnl_link_bridge_vlan));
		memset(&expected_attr[i], 0,
		       sizeof(struct bridge_vlan_info) * MAX_ATTR);
	}

	// Case 1 setting pvid untagged.
	vlan_info[0].pvid = 1;
	set_bitmap_range(1, 1, &vlan_info[0], 1);
	expected_attr[0][0].vid = 1;
	expected_attr[0][0].flags = BRIDGE_VLAN_INFO_PVID |
				    BRIDGE_VLAN_INFO_UNTAGGED;

	// Case 2 setting vid range.
	vlan_info[1].pvid = 0;
	set_bitmap_range(1, 4094, &vlan_info[1], 0);
	expected_attr[1][0].vid = 1;
	expected_attr[1][0].flags = BRIDGE_VLAN_INFO_RANGE_BEGIN;
	expected_attr[1][1].vid = 4094;
	expected_attr[1][1].flags = BRIDGE_VLAN_INFO_RANGE_END;

	// Case 3 interweaving pvid with vid range.
	vlan_info[2].pvid = 7;
	set_bitmap_range(1, 27, &vlan_info[2], 0);
	set_bitmap_range(7, 7, &vlan_info[2], 1);
	expected_attr[2][0].vid = 1;
	expected_attr[2][0].flags = BRIDGE_VLAN_INFO_RANGE_BEGIN;
	expected_attr[2][1].vid = 6;
	expected_attr[2][1].flags = BRIDGE_VLAN_INFO_RANGE_END;
	expected_attr[2][2].vid = 8;
	expected_attr[2][2].flags = BRIDGE_VLAN_INFO_RANGE_BEGIN;
	expected_attr[2][3].vid = 27;
	expected_attr[2][3].flags = BRIDGE_VLAN_INFO_RANGE_END;
	expected_attr[2][4].vid = 7;
	expected_attr[2][4].flags = BRIDGE_VLAN_INFO_PVID |
				    BRIDGE_VLAN_INFO_UNTAGGED;

	// Case 4 interweaving untagged and tagged vid ranges.
	vlan_info[3].pvid = 1;
	set_bitmap_range(1, 1, &vlan_info[3], 1);
	set_bitmap_range(1, 25, &vlan_info[3], 0);
	set_bitmap_range(26, 50, &vlan_info[3], 1);
	set_bitmap_range(51, 75, &vlan_info[3], 0);
	expected_attr[3][0].vid = 2;
	expected_attr[3][0].flags = BRIDGE_VLAN_INFO_RANGE_BEGIN;
	expected_attr[3][1].vid = 25;
	expected_attr[3][1].flags = BRIDGE_VLAN_INFO_RANGE_END;
	expected_attr[3][2].vid = 26;
	expected_attr[3][2].flags = BRIDGE_VLAN_INFO_RANGE_BEGIN |
				    BRIDGE_VLAN_INFO_UNTAGGED;
	expected_attr[3][3].vid = 50;
	expected_attr[3][3].flags = BRIDGE_VLAN_INFO_RANGE_END |
				    BRIDGE_VLAN_INFO_UNTAGGED;
	expected_attr[3][4].vid = 51;
	expected_attr[3][4].flags = BRIDGE_VLAN_INFO_RANGE_BEGIN;
	expected_attr[3][5].vid = 75;
	expected_attr[3][5].flags = BRIDGE_VLAN_INFO_RANGE_END;
	expected_attr[3][6].vid = 1;
	expected_attr[3][6].flags = BRIDGE_VLAN_INFO_PVID |
				    BRIDGE_VLAN_INFO_UNTAGGED;

	// Case 5 individual vid.
	vlan_info[4].pvid = 0;
	set_bitmap_range(5, 5, &vlan_info[4], 0);
	set_bitmap_range(3067, 3067, &vlan_info[4], 1);
	expected_attr[4][0].vid = 5;
	expected_attr[4][0].flags = 0;
	expected_attr[4][1].vid = 3067;
	expected_attr[4][1].flags = BRIDGE_VLAN_INFO_UNTAGGED;

	for (int i = 0; i < CASES; i++) {
		_nl_auto_nl_msg struct nl_msg *msg = nlmsg_alloc();
		attr_count = 0;
		ck_assert_msg(msg, "Unable to allocate netlink message");
		ck_assert_int_eq(0,
				 _nl_bridge_fill_vlan_info(msg, &vlan_info[i]));

		nlh = nlmsg_hdr(msg);

		nlmsg_for_each_attr(a, nlh, 0, rem) {
			ck_assert_msg(expected_attr[i][attr_count].vid != 0,
				      "Attribute number %d unexpected",
				      attr_count);
			ck_assert_msg(
				nla_type(a) == IFLA_BRIDGE_VLAN_INFO,
				"Expected attribute IFLA_BRIDGE_VLAN_INFO %d",
				IFLA_BRIDGE_VLAN_INFO);
			vlan_attr = (struct bridge_vlan_info *)nla_data(a);
			ck_assert_int_eq(vlan_attr->vid,
					 expected_attr[i][attr_count].vid);
			ck_assert_int_eq(vlan_attr->flags,
					 expected_attr[i][attr_count].flags);
			attr_count++;
		}
	}
}
END_TEST

static Suite *make_suite(void)
{
	Suite *suite = suite_create("Direct");
	TCase *tc = tcase_create("Core");

	tcase_add_test(tc, static_checks);
	tcase_add_test(tc, vlan_attribute_check);
	suite_add_tcase(suite, tc);
	return suite;
}

int main(int argc, char *argv[])
{
	SRunner *runner;
	int nfailed;

	runner = srunner_create(suite_create("main"));

	srunner_add_suite(runner, make_suite());

	srunner_run_all(runner, CK_ENV);

	nfailed = srunner_ntests_failed(runner);
	srunner_free(runner);
	return nfailed != 0;
}
