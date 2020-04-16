/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2013 Thomas Graf <tgraf@suug.ch>
 */

#include <check.h>

#include "util.h"

static Suite *main_suite(void)
{
	Suite *suite = suite_create("main");

	return suite;
}

int main(int argc, char *argv[])
{
	SRunner *runner;
	int nfailed;
	
	runner = srunner_create(main_suite());

	/* Add testsuites below */

	srunner_add_suite(runner, make_nl_addr_suite());
	srunner_add_suite(runner, make_nl_attr_suite());
	srunner_add_suite(runner, make_nl_ematch_tree_clone_suite());

	/* Do not add testsuites below this line */

	srunner_run_all(runner, CK_ENV);

	nfailed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return nfailed != 0;
}
