/*
 * lib/route/sch/htb.c	HTB Qdisc
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2011 Thomas Graf <tgraf@suug.ch>
 * Copyright (c) 2005-2006 Petr Gotthard <petr.gotthard@siemens.com>
 * Copyright (c) 2005-2006 Siemens AG Oesterreich
 */

/**
 * @ingroup qdisc
 * @ingroup class
 * @defgroup qdisc_htb Hierachical Token Bucket (HTB)
 * @{
 */

#include <netlink-local.h>
#include <netlink-tc.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/utils.h>
#include <netlink/route/tc-api.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/class.h>
#include <netlink/route/link.h>
#include <netlink/route/sch/htb.h>

/** @cond SKIP */
#define SCH_HTB_HAS_RATE2QUANTUM	0x01
#define SCH_HTB_HAS_DEFCLS		0x02

#define SCH_HTB_HAS_PRIO		0x001
#define SCH_HTB_HAS_RATE		0x002
#define SCH_HTB_HAS_CEIL		0x004
#define SCH_HTB_HAS_RBUFFER		0x008
#define SCH_HTB_HAS_CBUFFER		0x010
#define SCH_HTB_HAS_QUANTUM		0x020
/** @endcond */

static struct nla_policy htb_policy[TCA_HTB_MAX+1] = {
	[TCA_HTB_INIT]	= { .minlen = sizeof(struct tc_htb_glob) },
	[TCA_HTB_PARMS] = { .minlen = sizeof(struct tc_htb_opt) },
};

static int htb_qdisc_msg_parser(struct rtnl_tc *tc, void *data)
{
	struct nlattr *tb[TCA_HTB_MAX + 1];
	struct rtnl_htb_qdisc *htb = data;
	int err;

	if ((err = tca_parse(tb, TCA_HTB_MAX, tc, htb_policy)) < 0)
		return err;
	
	if (tb[TCA_HTB_INIT]) {
		struct tc_htb_glob opts;

		nla_memcpy(&opts, tb[TCA_HTB_INIT], sizeof(opts));
		htb->qh_rate2quantum = opts.rate2quantum;
		htb->qh_defcls = opts.defcls;

		htb->qh_mask = (SCH_HTB_HAS_RATE2QUANTUM | SCH_HTB_HAS_DEFCLS);
	}

	return 0;
}

static int htb_class_msg_parser(struct rtnl_tc *tc, void *data)
{
	struct nlattr *tb[TCA_HTB_MAX + 1];
	struct rtnl_htb_class *htb = data;
	int err;

	if ((err = tca_parse(tb, TCA_HTB_MAX, tc, htb_policy)) < 0)
		return err;
	
	if (tb[TCA_HTB_PARMS]) {
		struct tc_htb_opt opts;

		nla_memcpy(&opts, tb[TCA_HTB_PARMS], sizeof(opts));
		htb->ch_prio = opts.prio;
		rtnl_copy_ratespec(&htb->ch_rate, &opts.rate);
		rtnl_copy_ratespec(&htb->ch_ceil, &opts.ceil);
		htb->ch_rbuffer = rtnl_tc_calc_bufsize(opts.buffer, opts.rate.rate);
		htb->ch_cbuffer = rtnl_tc_calc_bufsize(opts.cbuffer, opts.ceil.rate);
		htb->ch_quantum = opts.quantum;

		rtnl_tc_set_mpu(tc, htb->ch_rate.rs_mpu);
		rtnl_tc_set_overhead(tc, htb->ch_rate.rs_overhead);

		htb->ch_mask = (SCH_HTB_HAS_PRIO | SCH_HTB_HAS_RATE |
				SCH_HTB_HAS_CEIL | SCH_HTB_HAS_RBUFFER |
				SCH_HTB_HAS_CBUFFER | SCH_HTB_HAS_QUANTUM);
	}

	return 0;
}

static void htb_qdisc_dump_line(struct rtnl_tc *tc, void *data,
				struct nl_dump_params *p)
{
	struct rtnl_htb_qdisc *htb = data;

	if (!htb)
		return;

	if (htb->qh_mask & SCH_HTB_HAS_RATE2QUANTUM)
		nl_dump(p, " r2q %u", htb->qh_rate2quantum);

	if (htb->qh_mask & SCH_HTB_HAS_DEFCLS) {
		char buf[32];
		nl_dump(p, " default %s",
			rtnl_tc_handle2str(htb->qh_defcls, buf, sizeof(buf)));
	}
}

static void htb_class_dump_line(struct rtnl_tc *tc, void *data,
				struct nl_dump_params *p)
{
	struct rtnl_htb_class *htb = data;

	if (!htb)
		return;

	if (htb->ch_mask & SCH_HTB_HAS_RATE) {
		double r, rbit;
		char *ru, *rubit;

		r = nl_cancel_down_bytes(htb->ch_rate.rs_rate, &ru);
		rbit = nl_cancel_down_bits(htb->ch_rate.rs_rate*8, &rubit);

		nl_dump(p, " rate %.2f%s/s (%.0f%s) log %u",
			r, ru, rbit, rubit, 1<<htb->ch_rate.rs_cell_log);
	}
}

static void htb_class_dump_details(struct rtnl_tc *tc, void *data,
				   struct nl_dump_params *p)
{
	struct rtnl_htb_class *htb = data;

	if (!htb)
		return;

	/* line 1 */
	if (htb->ch_mask & SCH_HTB_HAS_CEIL) {
		double r, rbit;
		char *ru, *rubit;

		r = nl_cancel_down_bytes(htb->ch_ceil.rs_rate, &ru);
		rbit = nl_cancel_down_bits(htb->ch_ceil.rs_rate*8, &rubit);

		nl_dump(p, " ceil %.2f%s/s (%.0f%s) log %u",
			r, ru, rbit, rubit, 1<<htb->ch_ceil.rs_cell_log);
	}

	if (htb->ch_mask & SCH_HTB_HAS_PRIO)
		nl_dump(p, " prio %u", htb->ch_prio);

	if (htb->ch_mask & SCH_HTB_HAS_RBUFFER) {
		double b;
		char *bu;

		b = nl_cancel_down_bytes(htb->ch_rbuffer, &bu);
		nl_dump(p, " rbuffer %.2f%s", b, bu);
	}

	if (htb->ch_mask & SCH_HTB_HAS_CBUFFER) {
		double b;
		char *bu;

		b = nl_cancel_down_bytes(htb->ch_cbuffer, &bu);
		nl_dump(p, " cbuffer %.2f%s", b, bu);
	}

	if (htb->ch_mask & SCH_HTB_HAS_QUANTUM)
		nl_dump(p, " quantum %u", htb->ch_quantum);
}

static int htb_qdisc_msg_fill(struct rtnl_tc *tc, void *data,
			      struct nl_msg *msg)
{
	struct rtnl_htb_qdisc *htb = data;
	struct tc_htb_glob opts = {0};

	opts.version = TC_HTB_PROTOVER;
	opts.rate2quantum = 10;

	if (htb) {
		if (htb->qh_mask & SCH_HTB_HAS_RATE2QUANTUM)
			opts.rate2quantum = htb->qh_rate2quantum;

		if (htb->qh_mask & SCH_HTB_HAS_DEFCLS)
			opts.defcls = htb->qh_defcls;
	}

	return nla_put(msg, TCA_HTB_INIT, sizeof(opts), &opts);
}

static int htb_class_msg_fill(struct rtnl_tc *tc, void *data,
			      struct nl_msg *msg)
{
	struct rtnl_htb_class *htb = data;
	uint32_t mtu, rtable[RTNL_TC_RTABLE_SIZE], ctable[RTNL_TC_RTABLE_SIZE];
	struct tc_htb_opt opts;
	int buffer, cbuffer;

	if (!htb || !(htb->ch_mask & SCH_HTB_HAS_RATE))
		BUG();

	/* if not set, zero (0) is used as priority */
	if (htb->ch_mask & SCH_HTB_HAS_PRIO)
		opts.prio = htb->ch_prio;

	memset(&opts, 0, sizeof(opts));

	mtu = rtnl_tc_get_mtu(tc);

	rtnl_tc_build_rate_table(tc, &htb->ch_rate, rtable);
	rtnl_rcopy_ratespec(&opts.rate, &htb->ch_rate);

	if (htb->ch_mask & SCH_HTB_HAS_CEIL) {
		rtnl_tc_build_rate_table(tc, &htb->ch_ceil, ctable);
		rtnl_rcopy_ratespec(&opts.ceil, &htb->ch_ceil);
	} else {
		/*
		 * If not set, configured rate is used as ceil, which implies
		 * no borrowing.
		 */
		memcpy(&opts.ceil, &opts.rate, sizeof(struct tc_ratespec));
	}

	if (htb->ch_mask & SCH_HTB_HAS_RBUFFER)
		buffer = htb->ch_rbuffer;
	else
		buffer = opts.rate.rate / nl_get_user_hz() + mtu; /* XXX */

	opts.buffer = rtnl_tc_calc_txtime(buffer, opts.rate.rate);

	if (htb->ch_mask & SCH_HTB_HAS_CBUFFER)
		cbuffer = htb->ch_cbuffer;
	else
		cbuffer = opts.ceil.rate / nl_get_user_hz() + mtu; /* XXX */

	opts.cbuffer = rtnl_tc_calc_txtime(cbuffer, opts.ceil.rate);

	if (htb->ch_mask & SCH_HTB_HAS_QUANTUM)
		opts.quantum = htb->ch_quantum;

	NLA_PUT(msg, TCA_HTB_PARMS, sizeof(opts), &opts);
	NLA_PUT(msg, TCA_HTB_RTAB, sizeof(rtable), &rtable);
	NLA_PUT(msg, TCA_HTB_CTAB, sizeof(ctable), &ctable);

	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

/**
 * @name Attribute Modifications
 * @{
 */

void rtnl_htb_set_rate2quantum(struct rtnl_qdisc *qdisc, uint32_t rate2quantum)
{
	struct rtnl_htb_qdisc *htb;

	if (!(htb = rtnl_tc_data(TC_CAST(qdisc))))
		BUG();

	htb->qh_rate2quantum = rate2quantum;
	htb->qh_mask |= SCH_HTB_HAS_RATE2QUANTUM;
}

/**
 * Set default class of the htb qdisc to the specified value
 * @arg qdisc		qdisc to change
 * @arg defcls		new default class
 */
void rtnl_htb_set_defcls(struct rtnl_qdisc *qdisc, uint32_t defcls)
{
	struct rtnl_htb_qdisc *htb;

	if (!(htb = rtnl_tc_data(TC_CAST(qdisc))))
		BUG();

	htb->qh_defcls = defcls;
	htb->qh_mask |= SCH_HTB_HAS_DEFCLS;
}

void rtnl_htb_set_prio(struct rtnl_class *class, uint32_t prio)
{
	struct rtnl_htb_class *htb;

	if (!(htb = rtnl_tc_data(TC_CAST(class))))
		BUG();

	htb->ch_prio = prio;
	htb->ch_mask |= SCH_HTB_HAS_PRIO;
}

/**
 * Set rate of HTB class.
 * @arg class		HTB class to be modified.
 * @arg rate		New rate in bytes per second.
 */
void rtnl_htb_set_rate(struct rtnl_class *class, uint32_t rate)
{
	struct rtnl_htb_class *htb;

	if (!(htb = rtnl_tc_data(TC_CAST(class))))
		BUG();

	htb->ch_rate.rs_cell_log = UINT8_MAX; /* use default value */
	htb->ch_rate.rs_rate = rate;
	htb->ch_mask |= SCH_HTB_HAS_RATE;
}

uint32_t rtnl_htb_get_rate(struct rtnl_class *class)
{
	struct rtnl_htb_class *htb;

	if (!(htb = rtnl_tc_data(TC_CAST(class))))
		return 0;

	return htb->ch_rate.rs_rate;
}

/**
 * Set ceil of HTB class.
 * @arg class		HTB class to be modified.
 * @arg ceil		New ceil in bytes per second.
 */
void rtnl_htb_set_ceil(struct rtnl_class *class, uint32_t ceil)
{
	struct rtnl_htb_class *htb;

	if (!(htb = rtnl_tc_data(TC_CAST(class))))
		BUG();

	htb->ch_ceil.rs_cell_log = UINT8_MAX; /* use default value */
	htb->ch_ceil.rs_rate = ceil;
	htb->ch_mask |= SCH_HTB_HAS_CEIL;
}

/**
 * Set size of the rate bucket of HTB class.
 * @arg class		HTB class to be modified.
 * @arg rbuffer		New size in bytes.
 */
void rtnl_htb_set_rbuffer(struct rtnl_class *class, uint32_t rbuffer)
{
	struct rtnl_htb_class *htb;

	if (!(htb = rtnl_tc_data(TC_CAST(class))))
		BUG();

	htb->ch_rbuffer = rbuffer;
	htb->ch_mask |= SCH_HTB_HAS_RBUFFER;
}

/**
 * Set size of the ceil bucket of HTB class.
 * @arg class		HTB class to be modified.
 * @arg cbuffer		New size in bytes.
 */
void rtnl_htb_set_cbuffer(struct rtnl_class *class, uint32_t cbuffer)
{
	struct rtnl_htb_class *htb;

	if (!(htb = rtnl_tc_data(TC_CAST(class))))
		BUG();

	htb->ch_cbuffer = cbuffer;
	htb->ch_mask |= SCH_HTB_HAS_CBUFFER;
}

/**
 * Set how much bytes to serve from leaf at once of HTB class {use r2q}.
 * @arg class		HTB class to be modified.
 * @arg quantum		New size in bytes.
 */
void rtnl_htb_set_quantum(struct rtnl_class *class, uint32_t quantum)
{
	struct rtnl_htb_class *htb;

	if (!(htb = rtnl_tc_data(TC_CAST(class))))
		BUG();

	htb->ch_quantum = quantum;
	htb->ch_mask |= SCH_HTB_HAS_QUANTUM;
}

/** @} */

static struct rtnl_tc_ops htb_qdisc_ops = {
	.to_kind		= "htb",
	.to_type		= RTNL_TC_TYPE_QDISC,
	.to_size		= sizeof(struct rtnl_htb_qdisc),
	.to_msg_parser		= htb_qdisc_msg_parser,
	.to_dump[NL_DUMP_LINE]	= htb_qdisc_dump_line,
	.to_msg_fill		= htb_qdisc_msg_fill,
};

static struct rtnl_tc_ops htb_class_ops = {
	.to_kind		= "htb",
	.to_type		= RTNL_TC_TYPE_CLASS,
	.to_size		= sizeof(struct rtnl_htb_class),
	.to_msg_parser		= htb_class_msg_parser,
	.to_dump = {
	    [NL_DUMP_LINE]	= htb_class_dump_line,
	    [NL_DUMP_DETAILS]	= htb_class_dump_details,
	},
	.to_msg_fill		= htb_class_msg_fill,
};

static void __init htb_init(void)
{
	rtnl_tc_register(&htb_qdisc_ops);
	rtnl_tc_register(&htb_class_ops);
}

static void __exit htb_exit(void)
{
	rtnl_tc_unregister(&htb_qdisc_ops);
	rtnl_tc_unregister(&htb_class_ops);
}

/** @} */
