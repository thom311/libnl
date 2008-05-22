/*
 * src/rule-utils.c     Routing Rule Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#include "rule-utils.h"

struct rtnl_rule *nlt_alloc_rule(void)
{
	struct rtnl_rule *rule;

	rule = rtnl_rule_alloc();
	if (!rule)
		fatal(ENOMEM, "Unable to allocate rule object");

	return rule;
}

void parse_family(struct rtnl_rule *rule, char *arg)
{
	int family;

	if ((family = nl_str2af(arg)) != AF_UNSPEC)
		rtnl_rule_set_family(rule, family);
}
