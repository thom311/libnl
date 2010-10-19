/*
 * lib/route/tc.c		Traffic Control
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup rtnl
 * @defgroup tc Traffic Control
 * @brief
 * @{
 */

#include <netlink-local.h>
#include <netlink-tc.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/link.h>
#include <netlink/route/tc.h>

/** @cond SKIP */

static struct nla_policy tc_policy[TCA_MAX+1] = {
	[TCA_KIND]	= { .type = NLA_STRING,
			    .maxlen = TCKINDSIZ },
	[TCA_STATS]	= { .minlen = sizeof(struct tc_stats) },
	[TCA_STATS2]	= { .type = NLA_NESTED },
};

int tca_parse(struct nlattr **tb, int maxattr, struct rtnl_tca *g,
	      struct nla_policy *policy)
{
	
	if (g->ce_mask & TCA_ATTR_OPTS)
		return nla_parse(tb, maxattr,
				 (struct nlattr *) g->tc_opts->d_data,
				 g->tc_opts->d_size, policy);
	else {
		/* Ugly but tb[] must be in a defined state even if no
		 * attributes can be found. */
		memset(tb, 0, sizeof(struct nlattr *) * (maxattr + 1));
		return 0;
	}
}

static struct nla_policy tc_stats2_policy[TCA_STATS_MAX+1] = {
	[TCA_STATS_BASIC]    = { .minlen = sizeof(struct gnet_stats_basic) },
	[TCA_STATS_RATE_EST] = { .minlen = sizeof(struct gnet_stats_rate_est) },
	[TCA_STATS_QUEUE]    = { .minlen = sizeof(struct gnet_stats_queue) },
};

int tca_msg_parser(struct nlmsghdr *n, struct rtnl_tca *g)
{
	struct nlattr *tb[TCA_MAX + 1];
	struct tcmsg *tm;
	int err;

	err = nlmsg_parse(n, sizeof(*tm), tb, TCA_MAX, tc_policy);
	if (err < 0)
		return err;

	if (tb[TCA_KIND] == NULL)
		return -NLE_MISSING_ATTR;

	nla_strlcpy(g->tc_kind, tb[TCA_KIND], TCKINDSIZ);

	tm = nlmsg_data(n);
	g->tc_family  = tm->tcm_family;
	g->tc_ifindex = tm->tcm_ifindex;
	g->tc_handle  = tm->tcm_handle;
	g->tc_parent  = tm->tcm_parent;
	g->tc_info    = tm->tcm_info;

	g->ce_mask = (TCA_ATTR_FAMILY | TCA_ATTR_IFINDEX | TCA_ATTR_HANDLE |
		      TCA_ATTR_PARENT | TCA_ATTR_INFO | TCA_ATTR_KIND);

	if (tb[TCA_OPTIONS]) {
		g->tc_opts = nl_data_alloc_attr(tb[TCA_OPTIONS]);
		if (!g->tc_opts)
			return -NLE_NOMEM;
		g->ce_mask |= TCA_ATTR_OPTS;
	}
	

	if (tb[TCA_STATS2]) {
		struct nlattr *tbs[TCA_STATS_MAX + 1];

		err = nla_parse_nested(tbs, TCA_STATS_MAX, tb[TCA_STATS2],
				       tc_stats2_policy);
		if (err < 0)
			return err;

		if (tbs[TCA_STATS_BASIC]) {
			struct gnet_stats_basic *bs;
			
			bs = nla_data(tbs[TCA_STATS_BASIC]);
			g->tc_stats[RTNL_TC_BYTES]	= bs->bytes;
			g->tc_stats[RTNL_TC_PACKETS]	= bs->packets;
		}

		if (tbs[TCA_STATS_RATE_EST]) {
			struct gnet_stats_rate_est *re;

			re = nla_data(tbs[TCA_STATS_RATE_EST]);
			g->tc_stats[RTNL_TC_RATE_BPS]	= re->bps;
			g->tc_stats[RTNL_TC_RATE_PPS]	= re->pps;
		}
		
		if (tbs[TCA_STATS_QUEUE]) {
			struct gnet_stats_queue *q;

			q = nla_data(tbs[TCA_STATS_QUEUE]);
			g->tc_stats[RTNL_TC_QLEN]	= q->qlen;
			g->tc_stats[RTNL_TC_BACKLOG]	= q->backlog;
			g->tc_stats[RTNL_TC_DROPS]	= q->drops;
			g->tc_stats[RTNL_TC_REQUEUES]	= q->requeues;
			g->tc_stats[RTNL_TC_OVERLIMITS]	= q->overlimits;
		}

		g->ce_mask |= TCA_ATTR_STATS;
		
		if (tbs[TCA_STATS_APP]) {
			g->tc_xstats = nl_data_alloc_attr(tbs[TCA_STATS_APP]);
			if (g->tc_xstats == NULL)
				return -NLE_NOMEM;
		} else
			goto compat_xstats;
	} else {
		if (tb[TCA_STATS]) {
			struct tc_stats *st = nla_data(tb[TCA_STATS]);

			g->tc_stats[RTNL_TC_BYTES]	= st->bytes;
			g->tc_stats[RTNL_TC_PACKETS]	= st->packets;
			g->tc_stats[RTNL_TC_RATE_BPS]	= st->bps;
			g->tc_stats[RTNL_TC_RATE_PPS]	= st->pps;
			g->tc_stats[RTNL_TC_QLEN]	= st->qlen;
			g->tc_stats[RTNL_TC_BACKLOG]	= st->backlog;
			g->tc_stats[RTNL_TC_DROPS]	= st->drops;
			g->tc_stats[RTNL_TC_OVERLIMITS]	= st->overlimits;

			g->ce_mask |= TCA_ATTR_STATS;
		}

compat_xstats:
		if (tb[TCA_XSTATS]) {
			g->tc_xstats = nl_data_alloc_attr(tb[TCA_XSTATS]);
			if (g->tc_xstats == NULL)
				return -NLE_NOMEM;
			g->ce_mask |= TCA_ATTR_XSTATS;
		}
	}


	return 0;
}

void tca_free_data(struct rtnl_tca *tca)
{
	nl_data_free(tca->tc_opts);
	nl_data_free(tca->tc_xstats);
}

int tca_clone(struct rtnl_tca *dst, struct rtnl_tca *src)
{
	if (src->tc_opts) {
		dst->tc_opts = nl_data_clone(src->tc_opts);
		if (!dst->tc_opts)
			return -NLE_NOMEM;
	}
	
	if (src->tc_xstats) {
		dst->tc_xstats = nl_data_clone(src->tc_xstats);
		if (!dst->tc_xstats)
			return -NLE_NOMEM;
	}

	return 0;
}

void tca_dump_line(struct rtnl_tca *g, const char *type,
		   struct nl_dump_params *p)
{
	char handle[32], parent[32];
	struct nl_cache *link_cache;
	
	link_cache = nl_cache_mngt_require("route/link");

	nl_dump_line(p, "%s %s ", g->tc_kind, type);

	if (link_cache) {
		char buf[32];
		nl_dump(p, "dev %s ",
			rtnl_link_i2name(link_cache, g->tc_ifindex,
					 buf, sizeof(buf)));
	} else
		nl_dump(p, "dev %u ", g->tc_ifindex);
	
	nl_dump(p, "handle %s parent %s",
		rtnl_tc_handle2str(g->tc_handle, handle, sizeof(handle)),
		rtnl_tc_handle2str(g->tc_parent, parent, sizeof(parent)));
}

void tca_dump_details(struct rtnl_tca *g, struct nl_dump_params *p)
{
	nl_dump_line(p, "  ");
}

void tca_dump_stats(struct rtnl_tca *g, struct nl_dump_params *p)
{
	char *unit, fmt[64];
	float res;
	strcpy(fmt, "        %7.2f %s %10u %10u %10u %10u %10u\n");

	nl_dump_line(p, 
		"    Stats:    bytes    packets      drops overlimits" \
		"       qlen    backlog\n");

	res = nl_cancel_down_bytes(g->tc_stats[RTNL_TC_BYTES], &unit);
	if (*unit == 'B')
		fmt[11] = '9';

	nl_dump_line(p, fmt, res, unit,
		g->tc_stats[RTNL_TC_PACKETS],
		g->tc_stats[RTNL_TC_DROPS],
		g->tc_stats[RTNL_TC_OVERLIMITS],
		g->tc_stats[RTNL_TC_QLEN],
		g->tc_stats[RTNL_TC_BACKLOG]);

	res = nl_cancel_down_bytes(g->tc_stats[RTNL_TC_RATE_BPS], &unit);

	strcpy(fmt, "        %7.2f %s/s%9u pps");

	if (*unit == 'B')
		fmt[11] = '9';

	nl_dump_line(p, fmt, res, unit, g->tc_stats[RTNL_TC_RATE_PPS]);
}

int tca_compare(struct nl_object *_a, struct nl_object *_b,
		uint32_t attrs, int flags)
{
	struct rtnl_tca *a = (struct rtnl_tca *) _a;
	struct rtnl_tca *b = (struct rtnl_tca *) _b;
	int diff = 0;

#define TC_DIFF(ATTR, EXPR) ATTR_DIFF(attrs, TCA_ATTR_##ATTR, a, b, EXPR)

	diff |= TC_DIFF(HANDLE,		a->tc_handle != b->tc_handle);
	diff |= TC_DIFF(PARENT,		a->tc_parent != b->tc_parent);
	diff |= TC_DIFF(IFINDEX,	a->tc_ifindex != b->tc_ifindex);
	diff |= TC_DIFF(KIND,		strcmp(a->tc_kind, b->tc_kind));

#undef TC_DIFF

	return diff;
}

void tca_set_ifindex(struct rtnl_tca *t, int ifindex)
{
	t->tc_ifindex = ifindex;
	t->ce_mask |= TCA_ATTR_IFINDEX;
}

int tca_get_ifindex(struct rtnl_tca *t)
{
	return t->tc_ifindex;
}

void tca_set_handle(struct rtnl_tca *t, uint32_t handle)
{
	t->tc_handle = handle;
	t->ce_mask |= TCA_ATTR_HANDLE;
}

uint32_t tca_get_handle(struct rtnl_tca *t)
{
	if (t->ce_mask & TCA_ATTR_HANDLE)
		return t->tc_handle;
	else
		return 0;
}

void tca_set_parent(struct rtnl_tca *t, uint32_t parent)
{
	t->tc_parent = parent;
	t->ce_mask |= TCA_ATTR_PARENT;
}

uint32_t tca_get_parent(struct rtnl_tca *t)
{
	if (t->ce_mask & TCA_ATTR_PARENT)
		return t->tc_parent;
	else
		return 0;
}

void tca_set_kind(struct rtnl_tca *t, const char *kind)
{
	strncpy(t->tc_kind, kind, sizeof(t->tc_kind) - 1);
	t->ce_mask |= TCA_ATTR_KIND;
}

char *tca_get_kind(struct rtnl_tca *t)
{
	if (t->ce_mask & TCA_ATTR_KIND)
		return t->tc_kind;
	else
		return NULL;
}

uint64_t tca_get_stat(struct rtnl_tca *t, int id)
{
	if (id < 0 || id > RTNL_TC_STATS_MAX)
		return 0;

	return t->tc_stats[id];
}

int tca_build_msg(struct rtnl_tca *tca, int type, int flags,
		  struct nl_msg **result)
{
	struct nl_msg *msg;
	struct tcmsg tchdr = {
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = tca->tc_ifindex,
		.tcm_handle = tca->tc_handle,
		.tcm_parent = tca->tc_parent,
	};

	msg = nlmsg_alloc_simple(type, flags);
	if (!msg)
		return -NLE_NOMEM;

	if (nlmsg_append(msg, &tchdr, sizeof(tchdr), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (tca->ce_mask & TCA_ATTR_KIND)
	    NLA_PUT_STRING(msg, TCA_KIND, tca->tc_kind);

	*result = msg;
	return 0;

nla_put_failure:
	nlmsg_free(msg);
	return -NLE_MSGSIZE;
}

/** @endcond */

/**
 * @name Utilities
 * @{
 */

/**
 * Calculate time required to transmit buffer at a specific rate
 * @arg bufsize		Size of buffer to be transmited in bytes.
 * @arg rate		Transmit rate in bytes per second.
 *
 * Calculates the number of micro seconds required to transmit a
 * specific buffer at a specific transmit rate.
 *
 * @f[
 *   txtime=\frac{bufsize}{rate}10^6
 * @f]
 * 
 * @return Required transmit time in micro seconds.
 */
int rtnl_tc_calc_txtime(int bufsize, int rate)
{
	double tx_time_secs;
	
	tx_time_secs = (double) bufsize / (double) rate;

	return tx_time_secs * 1000000.;
}

/**
 * Calculate buffer size able to transmit in a specific time and rate.
 * @arg txtime		Available transmit time in micro seconds.
 * @arg rate		Transmit rate in bytes per second.
 *
 * Calculates the size of the buffer that can be transmitted in a
 * specific time period at a specific transmit rate.
 *
 * @f[
 *   bufsize=\frac{{txtime} \times {rate}}{10^6}
 * @f]
 *
 * @return Size of buffer in bytes.
 */
int rtnl_tc_calc_bufsize(int txtime, int rate)
{
	double bufsize;

	bufsize = (double) txtime * (double) rate;

	return bufsize / 1000000.;
}

/**
 * Calculate the binary logarithm for a specific cell size
 * @arg cell_size	Size of cell, must be a power of two.
 * @return Binary logirhtm of cell size or a negative error code.
 */
int rtnl_tc_calc_cell_log(int cell_size)
{
	int i;

	for (i = 0; i < 32; i++)
		if ((1 << i) == cell_size)
			return i;

	return -NLE_INVAL;
}


/** @} */

/**
 * @name Rate Tables
 * @{
 */

/**
 * Compute a transmission time lookup table
 * @arg dst	 Destination buffer of RTNL_TC_RTABLE_SIZE uint32_t[].
 * @arg mpu	 Minimal size of a packet at all times.
 * @arg overhead Overhead to be added to each packet.
 * @arg cell	 Size of cell, i.e. size of step between entries in bytes.
 * @arg rate	 Rate in bytes per second.
 *
 * Computes a table of RTNL_TC_RTABLE_SIZE entries specyfing the
 * transmission times for various packet sizes, e.g. the transmission
 * time for a packet of size \c pktsize could be looked up:
 * @code
 * txtime = table[pktsize >> log2(cell)];
 * @endcode
 */
int rtnl_tc_build_rate_table(uint32_t *dst, uint8_t mpu, uint8_t overhead,
			     int cell, int rate)
{
	int i, size, cell_log;

	cell_log = rtnl_tc_calc_cell_log(cell);
	if (cell_log < 0)
		return cell_log;

	for (i = 0; i < RTNL_TC_RTABLE_SIZE; i++) {
		size = (i << cell_log) + overhead;
		if (size < mpu)
			size = mpu;

		dst[i] = rtnl_tc_calc_txtime(size, rate);
	}

	return 0;
}

/** @} */


/** @} */
