/* SPDX-License-Identifier: LGPL-2.1-only */

#include "cksuite-all.h"

START_TEST(dummy)
{
}
END_TEST

Suite *make_nl_netns_suite(void)
{
	Suite *suite = suite_create("netns");
	TCase *tc = tcase_create("Core");

	tcase_add_checked_fixture(tc, nltst_netns_fixture_setup,
				  nltst_netns_fixture_teardown);
	tcase_add_test(tc, dummy);
	suite_add_tcase(suite, tc);

	return suite;
}
