/*
 * lib/route/cls_api.c       Classifier Object
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup cls
 * @defgroup cls_obj Classifier Object
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

/** @cond SKIP */
#define CLS_ATTR_PRIO		(TCA_ATTR_MAX << 1)
#define CLS_ATTR_PROTOCOL	(TCA_ATTR_MAX << 2)
/** @endcond */

static void cls_free_data(struct nl_object *obj)
{
	struct rtnl_cls *cls = (struct rtnl_cls *) obj;
	struct rtnl_cls_ops *cops;
	
	tca_free_data((struct rtnl_tca *) cls);

	cops = rtnl_cls_lookup_ops(cls);
	if (cops && cops->co_free_data)
		cops->co_free_data(cls);
}

static int cls_clone(struct nl_object *_dst, struct nl_object *_src)
{
	struct rtnl_cls *dst = nl_object_priv(_dst);
	struct rtnl_cls *src = nl_object_priv(_src);
	struct rtnl_cls_ops *cops;
	int err;
	
	err = tca_clone((struct rtnl_tca *) dst, (struct rtnl_tca *) src);
	if (err < 0)
		goto errout;

	cops = rtnl_cls_lookup_ops(src);
	if (cops && cops->co_clone)
		err = cops->co_clone(dst, src);
errout:
	return err;
}

static void cls_dump_line(struct nl_object *obj, struct nl_dump_params *p)
{
	char buf[32];
	struct rtnl_cls *cls = (struct rtnl_cls *) obj;
	struct rtnl_cls_ops *cops;

	tca_dump_line((struct rtnl_tca *) cls, "cls", p);

	nl_dump(p, " prio %u protocol %s", cls->c_prio,
		nl_ether_proto2str(cls->c_protocol, buf, sizeof(buf)));

	cops = rtnl_cls_lookup_ops(cls);
	if (cops && cops->co_dump[NL_DUMP_LINE])
		cops->co_dump[NL_DUMP_LINE](cls, p);
	nl_dump(p, "\n");
}

static void cls_dump_details(struct nl_object *obj, struct nl_dump_params *p)
{
	struct rtnl_cls *cls = (struct rtnl_cls *) obj;
	struct rtnl_cls_ops *cops;

	cls_dump_line(obj, p);
	tca_dump_details((struct rtnl_tca *) cls, p);

	cops = rtnl_cls_lookup_ops(cls);
	if (cops && cops->co_dump[NL_DUMP_DETAILS])
		cops->co_dump[NL_DUMP_DETAILS](cls, p);
	else
		nl_dump(p, "no options\n");
}

static void cls_dump_stats(struct nl_object *obj, struct nl_dump_params *p)
{
	struct rtnl_cls *cls = (struct rtnl_cls *) obj;
	struct rtnl_cls_ops *cops;

	cls_dump_details(obj, p);
	tca_dump_stats((struct rtnl_tca *) cls, p);
	nl_dump(p, "\n");

	cops = rtnl_cls_lookup_ops(cls);
	if (cops && cops->co_dump[NL_DUMP_STATS])
		cops->co_dump[NL_DUMP_STATS](cls, p);
}

/**
 * @name Allocation/Freeing
 * @{
 */

struct rtnl_cls *rtnl_cls_alloc(void)
{
	return (struct rtnl_cls *) nl_object_alloc(&cls_obj_ops);
}

void rtnl_cls_put(struct rtnl_cls *cls)
{
	nl_object_put((struct nl_object *) cls);
}

/** @} */


/**
 * @name Attributes
 * @{
 */

void rtnl_cls_set_ifindex(struct rtnl_cls *f, int ifindex)
{
	tca_set_ifindex((struct rtnl_tca *) f, ifindex);
}

void rtnl_cls_set_handle(struct rtnl_cls *f, uint32_t handle)
{
	tca_set_handle((struct rtnl_tca *) f, handle);
}

void rtnl_cls_set_parent(struct rtnl_cls *f, uint32_t parent)
{
	tca_set_parent((struct rtnl_tca *) f, parent);
}

void rtnl_cls_set_kind(struct rtnl_cls *f, const char *kind)
{
	tca_set_kind((struct rtnl_tca *) f, kind);
	f->c_ops = __rtnl_cls_lookup_ops(kind);
}

void rtnl_cls_set_prio(struct rtnl_cls *cls, int prio)
{
	cls->c_prio = prio;
	cls->ce_mask |= CLS_ATTR_PRIO;
}

int rtnl_cls_get_prio(struct rtnl_cls *cls)
{
	if (cls->ce_mask & CLS_ATTR_PRIO)
		return cls->c_prio;
	else
		return 0;
}

void rtnl_cls_set_protocol(struct rtnl_cls *cls, int protocol)
{
	cls->c_protocol = protocol;
	cls->ce_mask |= CLS_ATTR_PROTOCOL;
}

int rtnl_cls_get_protocol(struct rtnl_cls *cls)
{
	if (cls->ce_mask & CLS_ATTR_PROTOCOL)
		return cls->c_protocol;
	else
		return ETH_P_ALL;
}

/** @} */

struct nl_object_ops cls_obj_ops = {
	.oo_name		= "route/cls",
	.oo_size		= sizeof(struct rtnl_cls),
	.oo_free_data		= cls_free_data,
	.oo_clone		= cls_clone,
	.oo_dump = {
	    [NL_DUMP_LINE]	= cls_dump_line,
	    [NL_DUMP_DETAILS]	= cls_dump_details,
	    [NL_DUMP_STATS]	= cls_dump_stats,
	},
	.oo_compare		= tca_compare,
	.oo_id_attrs		= (TCA_ATTR_IFINDEX | TCA_ATTR_HANDLE),
};

/** @} */
