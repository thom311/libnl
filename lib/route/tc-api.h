/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2011-2013 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_TC_API_H_
#define NETLINK_TC_API_H_

#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/route/tc.h>

#include "nl-hidden-route/nl-hidden-route.h"

struct rtnl_tc_type_ops
{
	enum rtnl_tc_type tt_type;

	char *tt_dump_prefix;

	/**
	 * Dump callbacks
	 */
	void (*tt_dump[NL_DUMP_MAX+1])(struct rtnl_tc *,
				        struct nl_dump_params *);
};

void *rtnl_tc_data_peek(struct rtnl_tc *tc);

/*****************************************************************************/

/* WARNING: the following symbols are wrongly exported in libnl-route-3
 * library. They are private API, but leaked. */
extern int			rtnl_tc_msg_parse(struct nlmsghdr *,
						  struct rtnl_tc *);
extern int			rtnl_tc_msg_build(struct rtnl_tc *, int,
						  int, struct nl_msg **);

extern void			rtnl_tc_free_data(struct nl_object *);
extern int			rtnl_tc_clone(struct nl_object *,
					      struct nl_object *);
extern void			rtnl_tc_dump_line(struct nl_object *,
						  struct nl_dump_params *);
extern void			rtnl_tc_dump_details(struct nl_object *,
						     struct nl_dump_params *);
extern void			rtnl_tc_dump_stats(struct nl_object *,
						   struct nl_dump_params *);
extern uint64_t			rtnl_tc_compare(struct nl_object *,
						struct nl_object *,
						uint64_t, int);

extern void *			rtnl_tc_data(struct rtnl_tc *);
extern void *			rtnl_tc_data_check(struct rtnl_tc *,
						   struct rtnl_tc_ops *, int *);

extern int 			rtnl_tc_register(struct rtnl_tc_ops *);
extern void 			rtnl_tc_unregister(struct rtnl_tc_ops *);

extern void			rtnl_tc_type_register(struct rtnl_tc_type_ops *);
extern void			rtnl_tc_type_unregister(struct rtnl_tc_type_ops *);


extern int rtnl_tc_build_rate_table(struct rtnl_tc *tc, struct rtnl_ratespec *,
				    uint32_t *);

/*****************************************************************************/

#endif
