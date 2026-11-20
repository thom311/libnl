/* SPDX-License-Identifier: LGPL-2.1-only */

#include "nl-default.h"

#include <stdio.h>
#include <stdlib.h>

#include <check.h>

#include <netlink/route/cls/ematch.h>

#include "cksuite-all.h"

START_TEST(test_parse_long_quoted_string)
{
	char expr[4096];
	char *err = NULL;
	struct rtnl_ematch_tree *tree = NULL;
	size_t pos = 0;
	int rc;
	unsigned int i;

	pos += snprintf(expr + pos, sizeof(expr) - pos, "text(x \"");
	for (i = 0; i < 1000; i++)
		expr[pos++] = 'A';
	expr[pos++] = '"';
	expr[pos++] = ')';
	expr[pos] = '\0';

	rc = rtnl_ematch_parse_expr(expr, &err, &tree);
	ck_assert_int_eq(rc, 0);
	ck_assert(tree != NULL);

	free(err);
	rtnl_ematch_tree_free(tree);
}
END_TEST

Suite *make_nl_ematch_parse_suite(void)
{
	Suite *suite = suite_create("ematch-parse");
	TCase *tc = tcase_create("quoted");

	tcase_add_test(tc, test_parse_long_quoted_string);
	suite_add_tcase(suite, tc);

	return suite;
}
