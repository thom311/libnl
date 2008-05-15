/*
 * src/utils.c		Utilities
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 */

#include "utils.h"

#include <stdlib.h>

void nlt_print_version(void)
{
	printf("libnl tools version %s\n", LIBNL_VERSION);
	printf(
	"Copyright (C) 2003-2008 Thomas Graf\n"
	"\n"
	"This program comes with ABSOLUTELY NO WARRANTY. This is free \n"
	"software, and you are welcome to redistribute it under certain\n"
	"conditions. See the GNU General Public License for details.\n"
	);

	exit(0);
}

void fatal(int err, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "Error: ");

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");

	exit(abs(err));
}

int nlt_connect(struct nl_sock *sk, int protocol)
{
	int err;

	if ((err = nl_connect(sk, protocol)) < 0)
		fatal(err, "Unable to connect netlink socket: %s",
			nl_geterror(err));

	return err;
}

struct nl_sock *nlt_alloc_socket(void)
{
	struct nl_sock *sock;

	if (!(sock = nl_socket_alloc()))
		fatal(ENOBUFS, "Unable to allocate netlink socket");

	return sock;
}

struct nl_addr *nlt_addr_parse(const char *str, int family)
{
	struct nl_addr *addr;
	int err;

	if ((err = nl_addr_parse(str, family, &addr)) < 0)
		fatal(err, "Unable to parse address \"%s\": %s",
		      str, nl_geterror(err));

	return addr;
}

int nlt_parse_dumptype(const char *str)
{
	if (!strcasecmp(str, "brief"))
		return NL_DUMP_BRIEF;
	else if (!strcasecmp(str, "details") || !strcasecmp(str, "detailed"))
		return NL_DUMP_FULL;
	else if (!strcasecmp(str, "stats"))
		return NL_DUMP_STATS;
	else if (!strcasecmp(str, "xml"))
		return NL_DUMP_XML;
	else if (!strcasecmp(str, "env"))
		return NL_DUMP_ENV;
	else
		fatal(EINVAL, "Invalid dump type \"%s\".\n", str);

	return 0;
}

int nlt_confirm(struct nl_object *obj, struct nl_dump_params *params,
		int default_yes)
{
	int answer;

	nl_object_dump(obj, params);
	printf("Delete? (%c/%c) ",
		default_yes ? 'Y' : 'y',
		default_yes ? 'n' : 'N');

	do {
		answer = tolower(getchar());
		if (answer == '\n')
			answer = default_yes ? 'y' : 'n';
	} while (answer != 'y' && answer != 'n');

	return answer == 'y';
}

static struct nl_cache *alloc_cache(struct nl_sock *sock, const char *name,
			    int (*ac)(struct nl_sock *, struct nl_cache **))
{
	struct nl_cache *cache;
	int err;

	if ((err = ac(sock, &cache)) < 0)
		fatal(err, "Unable to allocate %s cache: %s",
		      name, nl_geterror(err));

	nl_cache_mngt_provide(cache);

	return cache;
}

struct nl_cache *nlt_alloc_link_cache(struct nl_sock *sk)
{
	return alloc_cache(sk, "link", rtnl_link_alloc_cache);
}

struct nl_cache *nlt_alloc_addr_cache(struct nl_sock *sk)
{
	return alloc_cache(sk, "address", rtnl_addr_alloc_cache);
}

struct rtnl_addr *nlt_alloc_addr(void)
{
	struct rtnl_addr *addr;

	addr = rtnl_addr_alloc();
	if (!addr)
		fatal(ENOMEM, "Unable to allocate address object");

	return addr;
}

struct nl_cache *nltool_alloc_neigh_cache(struct nl_sock *sk)
{
	return alloc_cache(sk, "neighbour", rtnl_neigh_alloc_cache);
}

struct nl_cache *nltool_alloc_neightbl_cache(struct nl_sock *sk)
{
	return alloc_cache(sk, "neighbour table", rtnl_neightbl_alloc_cache);
}

struct nl_cache *nltool_alloc_route_cache(struct nl_sock *sk, int flags)
{
	struct nl_cache *cache;
	int err;

	if ((err = rtnl_route_alloc_cache(sk, AF_UNSPEC, flags, &cache)) < 0)
		fatal(err, "Unable to allocate route cache: %s\n",
		      nl_geterror(err));

	nl_cache_mngt_provide(cache);

	return cache;
}

struct nl_cache *nltool_alloc_rule_cache(struct nl_sock *sk)
{
	struct nl_cache *cache;
	int err;

	if ((err = rtnl_rule_alloc_cache(sk, AF_UNSPEC, &cache)) < 0)
		fatal(err, "Unable to allocate routing rule cache: %s\n",
		      nl_geterror(err));

	nl_cache_mngt_provide(cache);

	return cache;
}

struct nl_cache *nltool_alloc_qdisc_cache(struct nl_sock *sk)
{
	return alloc_cache(sk, "queueing disciplines", rtnl_qdisc_alloc_cache);
}

