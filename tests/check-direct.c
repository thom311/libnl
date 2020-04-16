/* SPDX-License-Identifier: LGPL-2.1-only */

#include <check.h>

START_TEST(static_checks)
{
}
END_TEST

static Suite *make_suite(void)
{
	Suite *suite = suite_create("Direct");

	TCase *nl_attr = tcase_create("Core");
	tcase_add_test(nl_attr, static_checks);
	suite_add_tcase(suite, nl_attr);
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
