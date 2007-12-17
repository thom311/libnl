/*
 * lib/route/class.c            Queueing Classes
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup tc
 * @defgroup class Queueing Classes
 * @{
 */

#include <netlink-local.h>
#include <netlink-tc.h>
#include <netlink/netlink.h>
#include <netlink/route/tc.h>
#include <netlink/route/class.h>
#include <netlink/route/class-modules.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/classifier.h>
#include <netlink/utils.h>

static struct nl_cache_ops rtnl_class_ops;

static int class_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			    struct nlmsghdr *n, struct nl_parser_param *pp)
{
	int err;
	struct rtnl_class *class;
	struct rtnl_class_ops *cops;

	class = rtnl_class_alloc();
	if (!class) {
		err = nl_errno(ENOMEM);
		goto errout;
	}
	class->ce_msgtype = n->nlmsg_type;

	err = tca_msg_parser(n, (struct rtnl_tca *) class);
	if (err < 0)
		goto errout_free;

	cops = rtnl_class_lookup_ops(class);
	if (cops && cops->co_msg_parser) {
		err = cops->co_msg_parser(class);
		if (err < 0)
			goto errout_free;
	}

	err = pp->pp_cb((struct nl_object *) class, pp);
	if (err < 0)
		goto errout_free;

	err = P_ACCEPT;

errout_free:
	rtnl_class_put(class);
errout:
	return err;
}

static int class_request_update(struct nl_cache *cache,
				struct nl_handle *handle)
{
	struct tcmsg tchdr = {
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = cache->c_iarg1,
	};

	return nl_send_simple(handle, RTM_GETTCLASS, NLM_F_DUMP, &tchdr,
			      sizeof(tchdr));
}

/**
 * @name Addition/Modification
 * @{
 */

static struct nl_msg *class_build(struct rtnl_class *class, int type, int flags)
{
	struct rtnl_class_ops *cops;
	struct nl_msg *msg;
	int err;

	msg = tca_build_msg((struct rtnl_tca *) class, type, flags);
	if (!msg)
		goto errout;

	cops = rtnl_class_lookup_ops(class);
	if (cops && cops->co_get_opts) {
		struct nl_msg *opts;
		
		opts = cops->co_get_opts(class);
		if (opts) {
			err = nla_put_nested(msg, TCA_OPTIONS, opts);
			nlmsg_free(opts);
			if (err < 0)
				goto errout;
		}
	}

	return msg;
errout:
	nlmsg_free(msg);
	return NULL;
}

/**
 * Build a netlink message to add a new class
 * @arg class		class to add 
 * @arg flags		additional netlink message flags
 *
 * Builds a new netlink message requesting an addition of a class.
 * The netlink message header isn't fully equipped with all relevant
 * fields and must be sent out via nl_send_auto_complete() or
 * supplemented as needed. 
 *
 * Common message flags
 *   - NLM_F_REPLACE - replace possibly existing classes
 *
 * @return New netlink message
 */
struct nl_msg *rtnl_class_build_add_request(struct rtnl_class *class, int flags)
{
	return class_build(class, RTM_NEWTCLASS, NLM_F_CREATE | flags);
}

/**
 * Add a new class
 * @arg handle		netlink handle
 * @arg class		class to delete
 * @arg flags		additional netlink message flags
 *
 * Builds a netlink message by calling rtnl_qdisc_build_add_request(),
 * sends the request to the kernel and waits for the next ACK to be
 * received and thus blocks until the request has been processed.
 *
 * Common message flags
 *   - NLM_F_REPLACE - replace possibly existing classes
 *
 * @return 0 on success or a negative error code
 */
int rtnl_class_add(struct nl_handle *handle, struct rtnl_class *class,
		   int flags)
{
	struct nl_msg *msg;
	int err;

	msg = rtnl_class_build_add_request(class, flags);
	if (!msg)
		return nl_errno(ENOMEM);

	err = nl_send_auto_complete(handle, msg);
	if (err < 0)
		return err;

	nlmsg_free(msg);
	return nl_wait_for_ack(handle);
}

/** @} */

/**
 * @name Cache Management
 * @{
 */

/**
 * Build a class cache including all classes attached to the specified interface
 * @arg handle		netlink handle
 * @arg ifindex		interface index of the link the classes are
 *                      attached to.
 *
 * Allocates a new cache, initializes it properly and updates it to
 * include all classes attached to the specified interface.
 *
 * @return The cache or NULL if an error has occured.
 */
struct nl_cache * rtnl_class_alloc_cache(struct nl_handle *handle, int ifindex)
{
	struct nl_cache * cache;
	
	cache = nl_cache_alloc(&rtnl_class_ops);
	if (!cache)
		return NULL;

	cache->c_iarg1 = ifindex;
	
	if (handle && nl_cache_refill(handle, cache) < 0) {
		nl_cache_free(cache);
		return NULL;
	}

	return cache;
}

/** @} */

static struct nl_cache_ops rtnl_class_ops = {
	.co_name		= "route/class",
	.co_hdrsize		= sizeof(struct tcmsg),
	.co_msgtypes		= {
					{ RTM_NEWTCLASS, NL_ACT_NEW, "new" },
					{ RTM_DELTCLASS, NL_ACT_DEL, "del" },
					{ RTM_GETTCLASS, NL_ACT_GET, "get" },
					END_OF_MSGTYPES_LIST,
				  },
	.co_protocol		= NETLINK_ROUTE,
	.co_request_update	= &class_request_update,
	.co_msg_parser		= &class_msg_parser,
	.co_obj_ops		= &class_obj_ops,
};

static void __init class_init(void)
{
	nl_cache_mngt_register(&rtnl_class_ops);
}

static void __exit class_exit(void)
{
	nl_cache_mngt_unregister(&rtnl_class_ops);
}

/** @} */
