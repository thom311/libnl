/*
 * lib/route/classifier.c       Classifier
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
 * @defgroup cls Classifiers
 *
 * @par Classifier Identification
 * - protocol
 * - priority
 * - parent
 * - interface
 * - kind
 * - handle
 * 
 * @{
 */

#include <netlink-local.h>
#include <netlink-tc.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/tc.h>
#include <netlink/route/classifier.h>
#include <netlink/route/classifier-modules.h>
#include <netlink/route/link.h>

static struct nl_cache_ops rtnl_cls_ops;

static int cls_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			  struct nlmsghdr *nlh, struct nl_parser_param *pp)
{
	int err;
	struct rtnl_cls *cls;
	struct rtnl_cls_ops *cops;

	cls = rtnl_cls_alloc();
	if (!cls) {
		err = nl_errno(ENOMEM);
		goto errout;
	}
	cls->ce_msgtype = nlh->nlmsg_type;

	err = tca_msg_parser(nlh, (struct rtnl_tca *) cls);
	if (err < 0)
		goto errout_free;

	cls->c_prio = TC_H_MAJ(cls->c_info) >> 16;
	cls->c_protocol = ntohs(TC_H_MIN(cls->c_info));

	cops = rtnl_cls_lookup_ops(cls);
	if (cops && cops->co_msg_parser) {
		err = cops->co_msg_parser(cls);
		if (err < 0)
			goto errout_free;
	}

	err = pp->pp_cb((struct nl_object *) cls, pp);
	if (err < 0)
		goto errout_free;

	err = P_ACCEPT;

errout_free:
	rtnl_cls_put(cls);
errout:
	return err;
}

static int cls_request_update(struct nl_cache *cache, struct nl_handle *handle)
{
	struct tcmsg tchdr = {
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = cache->c_iarg1,
		.tcm_parent = cache->c_iarg2,
	};

	return nl_send_simple(handle, RTM_GETTFILTER, NLM_F_DUMP, &tchdr,
			      sizeof(tchdr));
}


static struct nl_msg *cls_build(struct rtnl_cls *cls, int type, int flags)
{
	struct nl_msg *msg;
	struct rtnl_cls_ops *cops;
	int err, prio, proto;
	struct tcmsg *tchdr;

	msg = tca_build_msg((struct rtnl_tca *) cls, type, flags);
	if (!msg)
		goto errout;

	tchdr = nlmsg_data(nlmsg_hdr(msg));
	prio = rtnl_cls_get_prio(cls);
	proto = rtnl_cls_get_protocol(cls);
	tchdr->tcm_info = TC_H_MAKE(prio << 16, htons(proto)),

	cops = rtnl_cls_lookup_ops(cls);
	if (cops && cops->co_get_opts) {
		struct nl_msg *opts;
		
		opts = cops->co_get_opts(cls);
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
 * @name Classifier Addition/Modification/Deletion
 * @{
 */

/**
 * Build a netlink message to add a new classifier
 * @arg cls		classifier to add
 * @arg flags		additional netlink message flags
 *
 * Builds a new netlink message requesting an addition of a classifier
 * The netlink message header isn't fully equipped with all relevant
 * fields and must be sent out via nl_send_auto_complete() or
 * supplemented as needed. \a classifier must contain the attributes of
 * the new classifier set via \c rtnl_cls_set_* functions. \a opts
 * may point to the clsasifier specific options.
 *
 * @return New netlink message
 */
struct nl_msg * rtnl_cls_build_add_request(struct rtnl_cls *cls, int flags)
{
	return cls_build(cls, RTM_NEWTFILTER, NLM_F_CREATE | flags);
}

/**
 * Add a new classifier
 * @arg handle		netlink handle
 * @arg cls 		classifier to add
 * @arg flags		additional netlink message flags
 *
 * Builds a netlink message by calling rtnl_cls_build_add_request(),
 * sends the request to the kernel and waits for the next ACK to be
 * received and thus blocks until the request has been processed.
 *
 * @return 0 on sucess or a negative error if an error occured.
 */
int rtnl_cls_add(struct nl_handle *handle, struct rtnl_cls *cls, int flags)
{
	int err;
	struct nl_msg *msg;
	
	msg = rtnl_cls_build_add_request(cls, flags);
	if (!msg)
		return nl_errno(ENOMEM);
	
	err = nl_send_auto_complete(handle, msg);
	if (err < 0)
		return err;

	nlmsg_free(msg);
	return nl_wait_for_ack(handle);
}

/**
 * Build a netlink message to change classifier attributes
 * @arg cls		classifier to change
 * @arg flags		additional netlink message flags
 *
 * Builds a new netlink message requesting a change of a neigh
 * attributes. The netlink message header isn't fully equipped with
 * all relevant fields and must thus be sent out via nl_send_auto_complete()
 * or supplemented as needed.
 *
 * @return The netlink message
 */
struct nl_msg *rtnl_cls_build_change_request(struct rtnl_cls *cls, int flags)
{
	return cls_build(cls, RTM_NEWTFILTER, NLM_F_REPLACE | flags);
}

/**
 * Change a classifier
 * @arg handle		netlink handle
 * @arg cls		classifier to change
 * @arg flags		additional netlink message flags
 *
 * Builds a netlink message by calling rtnl_cls_build_change_request(),
 * sends the request to the kernel and waits for the next ACK to be
 * received and thus blocks until the request has been processed.
 *
 * @return 0 on sucess or a negative error if an error occured.
 */
int rtnl_cls_change(struct nl_handle *handle, struct rtnl_cls *cls,
		    int flags)
{
	int err;
	struct nl_msg *msg;
	
	msg = rtnl_cls_build_change_request(cls, flags);
	if (!msg)
		return nl_errno(ENOMEM);
	
	err = nl_send_auto_complete(handle, msg);
	if (err < 0)
		return err;

	nlmsg_free(msg);
	return nl_wait_for_ack(handle);
}

/**
 * Build a netlink request message to delete a classifier
 * @arg cls		classifier to delete
 * @arg flags		additional netlink message flags
 *
 * Builds a new netlink message requesting a deletion of a classifier.
 * The netlink message header isn't fully equipped with all relevant
 * fields and must thus be sent out via nl_send_auto_complete()
 * or supplemented as needed.
 *
 * @return New netlink message
 */
struct nl_msg *rtnl_cls_build_delete_request(struct rtnl_cls *cls, int flags)
{
	return cls_build(cls, RTM_DELTFILTER, flags);
}


/**
 * Delete a classifier
 * @arg handle		netlink handle
 * @arg cls		classifier to delete
 * @arg flags		additional netlink message flags
 *
 * Builds a netlink message by calling rtnl_cls_build_delete_request(),
 * sends the request to the kernel and waits for the next ACK to be
 * received and thus blocks until the request has been processed.
 *
 * @return 0 on sucess or a negative error if an error occured.
 */
int rtnl_cls_delete(struct nl_handle *handle, struct rtnl_cls *cls, int flags)
{
	int err;
	struct nl_msg *msg;
	
	msg = rtnl_cls_build_delete_request(cls, flags);
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
 * Build a classifier cache including all classifiers attached to the
 * specified class/qdisc on eht specified interface.
 * @arg handle		netlink handle
 * @arg ifindex		interface index of the link the classes are
 *                      attached to.
 * @arg parent          parent qdisc/class
 *
 * Allocates a new cache, initializes it properly and updates it to
 * include all classes attached to the specified interface.
 *
 * @note The caller is responsible for destroying and freeing the
 *       cache after using it.
 * @return The cache or NULL if an error has occured.
 */
struct nl_cache *rtnl_cls_alloc_cache(struct nl_handle *handle,
				      int ifindex, uint32_t parent)
{
	struct nl_cache * cache;
	
	cache = nl_cache_alloc(&rtnl_cls_ops);
	if (cache == NULL)
		return NULL;

	cache->c_iarg1 = ifindex;
	cache->c_iarg2 = parent;
	
	if (handle && nl_cache_refill(handle, cache) < 0) {
		nl_cache_free(cache);
		return NULL;
	}

	return cache;
}

/** @} */

static struct nl_cache_ops rtnl_cls_ops = {
	.co_name		= "route/cls",
	.co_hdrsize		= sizeof(struct tcmsg),
	.co_msgtypes		= {
					{ RTM_NEWTFILTER, NL_ACT_NEW, "new" },
					{ RTM_DELTFILTER, NL_ACT_DEL, "del" },
					{ RTM_GETTFILTER, NL_ACT_GET, "get" },
					END_OF_MSGTYPES_LIST,
				  },
	.co_protocol		= NETLINK_ROUTE,
	.co_request_update	= cls_request_update,
	.co_msg_parser		= cls_msg_parser,
	.co_obj_ops		= &cls_obj_ops,
};

static void __init cls_init(void)
{
	nl_cache_mngt_register(&rtnl_cls_ops);
}

static void __exit cls_exit(void)
{
	nl_cache_mngt_unregister(&rtnl_cls_ops);
}

/** @} */
