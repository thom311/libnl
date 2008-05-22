/*
 * src/qdisc-utils.h     QDisc Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __QDISC_UTILS_H_
#define __QDISC_UTILS_H_

#include "utils.h"

extern struct rtnl_qdisc *nlt_alloc_qdisc(void);
extern void parse_dev(struct rtnl_qdisc *, struct nl_cache *, char *);
extern void parse_parent(struct rtnl_qdisc *, char *);
extern void parse_handle(struct rtnl_qdisc *, char *);
extern void parse_kind(struct rtnl_qdisc *, char *);

#endif
