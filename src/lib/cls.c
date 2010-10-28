/*
 * src/lib/cls.c     	CLI Classifier Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2010 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup cli
 * @defgroup cli_cls Classifiers
 * @{
 */

#include <netlink/cli/utils.h>
#include <netlink/cli/cls.h>
#include <netlink/route/cls/ematch.h>

struct rtnl_cls *nl_cli_cls_alloc(void)
{
	struct rtnl_cls *cls;

	cls = rtnl_cls_alloc();
	if (!cls)
		nl_cli_fatal(ENOMEM, "Unable to allocate classifier object");

	return cls;
}

struct nl_cache *nl_cli_cls_alloc_cache(struct nl_sock *sock, int ifindex,
					uint32_t parent)
{
	struct nl_cache *cache;
	int err;

	if ((err = rtnl_cls_alloc_cache(sock, ifindex, parent, &cache)) < 0)
		nl_cli_fatal(err, "Unable to allocate classifier cache: %s",
			     nl_geterror(err));

	return cache;
}

void nl_cli_cls_parse_kind(struct rtnl_cls *cls, char *arg)
{
	rtnl_cls_set_kind(cls, arg);
}

void nl_cli_cls_parse_proto(struct rtnl_cls *cls, char *arg)
{
	int proto;

	if ((proto = nl_str2ether_proto(arg)) < 0)
		nl_cli_fatal(proto, "Unknown protocol \"%s\".", arg);

	rtnl_cls_set_protocol(cls, proto);
}

struct rtnl_ematch_tree *nl_cli_cls_parse_ematch(struct rtnl_cls *cls, char *arg)
{
	struct rtnl_ematch_tree *tree;
	char *errstr = NULL;
	int err;

	if ((err = rtnl_ematch_parse_expr(arg, &errstr, &tree)) < 0)
		nl_cli_fatal(err, "Unable to parse ematch expression: %s",
				  errstr);
	
	if (errstr)
		free(errstr);

	return tree;
}

static NL_LIST_HEAD(cls_modules);

struct nl_cli_cls_module *__nl_cli_cls_lookup(struct rtnl_cls_ops *ops)
{
	struct nl_cli_cls_module *cm;

	nl_list_for_each_entry(cm, &cls_modules, cm_list)
		if (cm->cm_ops == ops)
			return cm;

	return NULL;
}

struct nl_cli_cls_module *nl_cli_cls_lookup(struct rtnl_cls_ops *ops)
{
	struct nl_cli_cls_module *cm;

	if ((cm = __nl_cli_cls_lookup(ops)))
		return cm;

	nl_cli_load_module("cli/cls", ops->co_kind);

	if (!(cm = __nl_cli_cls_lookup(ops)))  {
		nl_cli_fatal(EINVAL, "Application bug: The shared library for "
			"the classifier \"%s\" was successfully loaded but it "
			"seems that module did not register itself");
	}

	return cm;
}

void nl_cli_cls_register(struct nl_cli_cls_module *cm)
{
	struct rtnl_cls_ops *ops;

	if (!(ops = __rtnl_cls_lookup_ops(cm->cm_name))) {
		nl_cli_fatal(ENOENT, "Unable to register CLI classifier module "
		"\"%s\": No matching libnl cls module found.", cm->cm_name);
	}

	if (__nl_cli_cls_lookup(ops)) {
		nl_cli_fatal(EEXIST, "Unable to register CLI classifier module "
		"\"%s\": Module already registered.", cm->cm_name);
	}

	cm->cm_ops = ops;

	nl_list_add_tail(&cm->cm_list, &cls_modules);
}

void nl_cli_cls_unregister(struct nl_cli_cls_module *cm)
{
	nl_list_del(&cm->cm_list);
}

/** @} */
