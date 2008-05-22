/*
 * src/rule-utils.h     Routing Rule Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __RULE_UTILS_H_
#define __RULE_UTILS_H_

#include "utils.h"

extern struct rtnl_rule *nlt_alloc_rule(void);
extern void parse_family(struct rtnl_rule *, char *);

#endif
