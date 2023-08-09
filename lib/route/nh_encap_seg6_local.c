/* SPDX-License-Identifier: LGPL-2.1-only */

#include "nl-default.h"

#include <linux/ipv6.h>
#include <linux/seg6_local.h>
#include <linux/seg6.h>
#include <linux/lwtunnel.h>

#include <netlink/attr.h>
#include <netlink/route/nexthop.h>

#include "nl-route.h"
#include "nexthop-encap.h"
#include "seg6.h"

#include "nl-aux-core/nl-core.h"

#ifndef BIT
#define BIT(nr) (1ul << (nr))
#endif /* BIT */

#define SEG6_F_ATTR(i)          BIT(i)
#define SEG6_F_LOCAL_COUNTERS   SEG6_F_ATTR(SEG6_LOCAL_COUNTERS)

struct nh_encap_ops seg6_local_encap_ops;

struct seg6_action_desc {
	int action;
	unsigned long attrs;
	unsigned long optattrs;
	int static_headroom;
};

static struct nla_policy seg6_local_encap_policy[SEG6_LOCAL_MAX + 1] = {
	[SEG6_LOCAL_ACTION]     = { .type = NLA_U32 },
	[SEG6_LOCAL_SRH]        = { .minlen = sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr) },
	[SEG6_LOCAL_TABLE]      = { .type = NLA_U32 },
	[SEG6_LOCAL_NH4]        = { .minlen = sizeof(struct in_addr),
	                            .maxlen = sizeof(struct in_addr) },
	[SEG6_LOCAL_NH6]        = { .minlen = sizeof(struct in6_addr),
	                            .maxlen = sizeof(struct in6_addr) },
	[SEG6_LOCAL_IIF]        = { .type = NLA_U32 },
	[SEG6_LOCAL_OIF]        = { .type = NLA_U32 },
	[SEG6_LOCAL_BPF]        = { .type = NLA_NESTED },
	[SEG6_LOCAL_VRFTABLE]   = { .type = NLA_U32 },
	[SEG6_LOCAL_COUNTERS]   = { .type = NLA_NESTED },
	[SEG6_LOCAL_FLAVORS]    = { .type = NLA_NESTED },
};

static struct seg6_action_desc seg6_action_table[] = {
	{
		.action		= SEG6_LOCAL_ACTION_END,
		.attrs		= 0,
		.optattrs	= SEG6_F_LOCAL_COUNTERS |
				  SEG6_F_ATTR(SEG6_LOCAL_FLAVORS),
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_X,
		.attrs		= SEG6_F_ATTR(SEG6_LOCAL_NH6),
		.optattrs	= SEG6_F_LOCAL_COUNTERS,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_T,
		.attrs		= SEG6_F_ATTR(SEG6_LOCAL_TABLE),
		.optattrs	= SEG6_F_LOCAL_COUNTERS,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DX2,
		.attrs		= SEG6_F_ATTR(SEG6_LOCAL_OIF),
		.optattrs	= SEG6_F_LOCAL_COUNTERS,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DX6,
		.attrs		= SEG6_F_ATTR(SEG6_LOCAL_NH6),
		.optattrs	= SEG6_F_LOCAL_COUNTERS,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DX4,
		.attrs		= SEG6_F_ATTR(SEG6_LOCAL_NH4),
		.optattrs	= SEG6_F_LOCAL_COUNTERS,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DT4,
		.attrs		= SEG6_F_ATTR(SEG6_LOCAL_VRFTABLE),
		.optattrs	= SEG6_F_LOCAL_COUNTERS,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DT6,
		.attrs		= 0,
		.optattrs	= SEG6_F_LOCAL_COUNTERS		|
				  SEG6_F_ATTR(SEG6_LOCAL_TABLE) |
				  SEG6_F_ATTR(SEG6_LOCAL_VRFTABLE),
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_DT46,
		.attrs		= SEG6_F_ATTR(SEG6_LOCAL_VRFTABLE),
		.optattrs	= SEG6_F_LOCAL_COUNTERS,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_B6,
		.attrs		= SEG6_F_ATTR(SEG6_LOCAL_SRH),
		.optattrs	= SEG6_F_LOCAL_COUNTERS,
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_B6_ENCAP,
		.attrs		= SEG6_F_ATTR(SEG6_LOCAL_SRH),
		.optattrs	= SEG6_F_LOCAL_COUNTERS,
		.static_headroom	= sizeof(struct ipv6hdr),
	},
	{
		.action		= SEG6_LOCAL_ACTION_END_BPF,
		.attrs		= SEG6_F_ATTR(SEG6_LOCAL_BPF),
		.optattrs	= SEG6_F_LOCAL_COUNTERS,
	},
};

static struct seg6_action_desc *get_action_desc(int action)
{
	struct seg6_action_desc *desc;
	int i, count;

	count = ARRAY_SIZE(seg6_action_table);
	for (i = 0; i < count; i++) {
		desc = &seg6_action_table[i];
		if (desc->action == action)
			return desc;
	}

	return NULL;
}

struct bpf_lwt_prog {
	char *name;
	uint32_t prog;
};

struct seg6_end_dt_info {
	/* VRF device associated to the routing table used by the SRv6
	 * End.DT4/DT6 behavior for routing IPv4/IPv6 packets.
	 */
	int vrf_table;
};

struct seg6_local_counters {
	uint64_t packets;
	uint64_t bytes;
	uint64_t errors;
};

/* default length values (expressed in bits) for both Locator-Block and
 * Locator-Node Function.
 *
 * Both SEG6_LOCAL_LCBLOCK_DBITS and SEG6_LOCAL_LCNODE_FN_DBITS *must* be:
 *    i) greater than 0;
 *   ii) evenly divisible by 8. In other terms, the lengths of the
 *	 Locator-Block and Locator-Node Function must be byte-aligned (we can
 *	 relax this constraint in the future if really needed).
 *
 * Moreover, a third condition must hold:
 *  iii) SEG6_LOCAL_LCBLOCK_DBITS + SEG6_LOCAL_LCNODE_FN_DBITS <= 128.
 *
 * The correctness of SEG6_LOCAL_LCBLOCK_DBITS and SEG6_LOCAL_LCNODE_FN_DBITS
 * values are checked during the kernel compilation. If the compilation stops,
 * check the value of these parameters to see if they meet conditions (i), (ii)
 * and (iii).
 */
#define SEG6_LOCAL_LCBLOCK_DBITS	32
#define SEG6_LOCAL_LCNODE_FN_DBITS	16

/* The following next_csid_chk_{cntr,lcblock,lcblock_fn}_bits macros can be
 * used directly to check whether the lengths (in bits) of Locator-Block and
 * Locator-Node Function are valid according to (i), (ii), (iii).
 */
#define next_csid_chk_cntr_bits(blen, flen)		\
	((blen) + (flen) > 128)

#define next_csid_chk_lcblock_bits(blen)		\
({							\
	typeof(blen) __tmp = blen;			\
	(!__tmp || __tmp > 120 || (__tmp & 0x07));	\
})

#define next_csid_chk_lcnode_fn_bits(flen)		\
	next_csid_chk_lcblock_bits(flen)

/* Supported Flavor operations are reported in this bitmask */
#define SEG6_LOCAL_FLV_SUPP_OPS	(BIT(SEG6_LOCAL_FLV_OP_NEXT_CSID))

struct seg6_flavors_info {
	/* Flavor operations */
	uint32_t flv_ops;

	/* Locator-Block length, expressed in bits */
	uint8_t lcblock_bits;
	/* Locator-Node Function length, expressed in bits*/
	uint8_t lcnode_func_bits;
};

struct seg6_local_lwt {
	int action;
	struct ipv6_sr_hdr *srh;
	int table;
	struct in_addr nh4;
	struct in6_addr nh6;
	int iif;
	int oif;
	struct bpf_lwt_prog bpf;
	struct seg6_end_dt_info dt_info;
	struct seg6_flavors_info flv_info;

	struct seg6_local_counters counters;
	int counters_present;

	int headroom;
	struct seg6_action_desc *desc;
	/* unlike the required attrs, we have to track the optional attributes
	 * that have been effectively parsed.
	 */
	unsigned long parsed_optattrs;
};

/**
 * Copied from Linux 6.4: parse_nla_srh:net/ipv6/seg6_local.c
 * Author: David Lebrun <david.lebrun@uclouvain.be>
 */
static int parse_nla_srh(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;
	int len;

	srh = nla_data(attrs[SEG6_LOCAL_SRH]);
	len = nla_len(attrs[SEG6_LOCAL_SRH]);

	/* SRH must contain at least one segment */
	if (len < sizeof(*srh) + sizeof(struct in6_addr))
		return -NLE_INVAL;

	if (!seg6_validate_srh(srh, len, false))
		return -NLE_INVAL;

	slwt->srh = _nl_memdup(srh, len);
	if (!slwt->srh)
		return -NLE_NOMEM;

	slwt->headroom += len;

	return 0;
}

/**
 * Copied from Linux 6.4: put_nla_srh:net/ipv6/seg6_local.c
 * Author: David Lebrun <david.lebrun@uclouvain.be>
 */
static int put_nla_srh(struct nl_msg *msg, struct seg6_local_lwt *slwt)
{
	struct ipv6_sr_hdr *srh;
	struct nlattr *nla;
	int len;

	srh = slwt->srh;
	len = IPV6_EXTHDR_LEN(srh->hdrlen);

	nla = nla_reserve(msg, SEG6_LOCAL_SRH, len);
	if (!nla)
		return -NLE_MSGSIZE;

	memcpy(nla_data(nla), srh, len);

	return 0;
}

static int cmp_nla_srh(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	int len = IPV6_EXTHDR_LEN(a->srh->hdrlen);

	if (a->srh->hdrlen != b->srh->hdrlen)
		return 1;

	return memcmp(a->srh, b->srh, len);
}

static void
dump_nla_srh(struct seg6_local_lwt *slwt, struct nl_dump_params *dp)
{
	seg6_dump_srh(dp, slwt->srh);
}

static void destroy_attr_srh(struct seg6_local_lwt *slwt)
{
	free(slwt->srh);
}

static int parse_nla_table(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	slwt->table = nla_get_u32(attrs[SEG6_LOCAL_TABLE]);

	return 0;
}

static int put_nla_table(struct nl_msg *msg, struct seg6_local_lwt *slwt)
{
	NLA_PUT_U32(msg, SEG6_LOCAL_TABLE, slwt->table);

	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

static int cmp_nla_table(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	if (a->table != b->table)
		return 1;

	return 0;
}

static void
dump_nla_table(struct seg6_local_lwt *slwt, struct nl_dump_params *dp)
{
	nl_dump(dp, "table %d ", slwt->table);
}

static int parse_nla_nh4(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	memcpy(&slwt->nh4, nla_data(attrs[SEG6_LOCAL_NH4]), sizeof(struct in_addr));

	return 0;
}

static int put_nla_nh4(struct nl_msg *msg, struct seg6_local_lwt *slwt)
{
	struct nlattr *nla;

	nla = nla_reserve(msg, SEG6_LOCAL_NH4, sizeof(struct in_addr));
	if (!nla)
		return -NLE_MSGSIZE;

	memcpy(nla_data(nla), &slwt->nh4, sizeof(struct in_addr));

	return 0;
}

static int cmp_nla_nh4(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	return memcmp(&a->nh4, &b->nh4, sizeof(struct in_addr));
}

static int parse_nla_nh6(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	memcpy(&slwt->nh6, nla_data(attrs[SEG6_LOCAL_NH6]), sizeof(struct in6_addr));

	return 0;
}

static int put_nla_nh6(struct nl_msg *msg, struct seg6_local_lwt *slwt)
{
	struct nlattr *nla;

	nla = nla_reserve(msg, SEG6_LOCAL_NH6, sizeof(struct in6_addr));
	if (!nla)
		return -NLE_MSGSIZE;

	memcpy(nla_data(nla), &slwt->nh6, sizeof(struct in6_addr));

	return 0;
}

static int cmp_nla_nh6(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	return memcmp(&a->nh6, &b->nh6, sizeof(struct in6_addr));
}

static int parse_nla_iif(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	slwt->iif = nla_get_u32(attrs[SEG6_LOCAL_IIF]);

	return 0;
}

static int put_nla_iif(struct nl_msg *msg, struct seg6_local_lwt *slwt)
{
	NLA_PUT_U32(msg, SEG6_LOCAL_IIF, slwt->iif);

	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

static int cmp_nla_iif(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	if (a->iif != b->iif)
		return 1;

	return 0;
}

static int parse_nla_oif(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	slwt->oif = nla_get_u32(attrs[SEG6_LOCAL_OIF]);

	return 0;
}

static int put_nla_oif(struct nl_msg *msg, struct seg6_local_lwt *slwt)
{
	NLA_PUT_U32(msg, SEG6_LOCAL_OIF, slwt->oif);

	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

static int cmp_nla_oif(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	if (a->oif != b->oif)
		return 1;

	return 0;
}

#define MAX_PROG_NAME 256
static const struct nla_policy bpf_prog_policy[SEG6_LOCAL_BPF_PROG_MAX + 1] = {
	[SEG6_LOCAL_BPF_PROG]	   = { .type = NLA_U32, },
	[SEG6_LOCAL_BPF_PROG_NAME] = { .type = NLA_NUL_STRING,
				       .maxlen = MAX_PROG_NAME },
};

/**
 * Copied from Linux 6.4: parse_nla_bpf:net/ipv6/seg6_local.c
 * Author: Mathieu Xhonneux <m.xhonneux@gmail.com>
 */
static int parse_nla_bpf(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	struct nlattr *tb[SEG6_LOCAL_BPF_PROG_MAX + 1];
	int ret;

	ret = nla_parse_nested(tb, SEG6_LOCAL_BPF_PROG_MAX, attrs[SEG6_LOCAL_BPF], bpf_prog_policy);
	if (ret < 0)
		return ret;

	if (!tb[SEG6_LOCAL_BPF_PROG] || !tb[SEG6_LOCAL_BPF_PROG_NAME])
		return -NLE_INVAL;

	slwt->bpf.name = _nl_memdup(nla_data(tb[SEG6_LOCAL_BPF_PROG_NAME]),
				    nla_len(tb[SEG6_LOCAL_BPF_PROG_NAME]));
	if (!slwt->bpf.name)
		return -NLE_NOMEM;

	slwt->bpf.prog = nla_get_u32(tb[SEG6_LOCAL_BPF_PROG]);
	return 0;
}

/**
 * Copied from Linux 6.4: put_nla_bpf:net/ipv6/seg6_local.c
 * Author: Mathieu Xhonneux <m.xhonneux@gmail.com>
 */
static int put_nla_bpf(struct nl_msg *msg, struct seg6_local_lwt *slwt)
{
	struct nlattr *nest;

	if (!slwt->bpf.name)
		return 0;

	nest = nla_nest_start(msg, SEG6_LOCAL_BPF);
	if (!nest)
		return -NLE_MSGSIZE;

	NLA_PUT_U32(msg, SEG6_LOCAL_BPF_PROG, slwt->bpf.prog);

	if (slwt->bpf.name)
		NLA_PUT_STRING(msg, SEG6_LOCAL_BPF_PROG_NAME, slwt->bpf.name);

	return nla_nest_end(msg, nest);

nla_put_failure:
	return -NLE_MSGSIZE;
}

static int cmp_nla_bpf(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	if (!a->bpf.name && !b->bpf.name)
		return 0;

	if (!a->bpf.name || !b->bpf.name)
		return 1;

	return strcmp(a->bpf.name, b->bpf.name);
}

static void destroy_attr_bpf(struct seg6_local_lwt *slwt)
{
	free(slwt->bpf.name);
}

static int parse_nla_vrftable(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	slwt->dt_info.vrf_table = nla_get_u32(attrs[SEG6_LOCAL_VRFTABLE]);

	return 0;
}

static int put_nla_vrftable(struct nl_msg *msg, struct seg6_local_lwt *slwt)
{
	NLA_PUT_U32(msg, SEG6_LOCAL_VRFTABLE, slwt->dt_info.vrf_table);

	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

static int cmp_nla_vrftable(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	if (a->dt_info.vrf_table != b->dt_info.vrf_table)
		return 1;

	return 0;
}

static const struct
nla_policy seg6_local_counters_policy[SEG6_LOCAL_CNT_MAX + 1] = {
	[SEG6_LOCAL_CNT_PACKETS]	= { .type = NLA_U64 },
	[SEG6_LOCAL_CNT_BYTES]		= { .type = NLA_U64 },
	[SEG6_LOCAL_CNT_ERRORS]		= { .type = NLA_U64 },
};

/**
 * Copied from Linux 6.4: parse_nla_counters:net/ipv6/seg6_local.c
 * Author: Andrea Mayer <andrea.mayer@uniroma2.it>
 */
static int parse_nla_counters(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	struct nlattr *tb[SEG6_LOCAL_CNT_MAX + 1];
	int ret;

	ret = nla_parse_nested(tb, SEG6_LOCAL_CNT_MAX, attrs[SEG6_LOCAL_COUNTERS],
			       seg6_local_counters_policy);
	if (ret < 0)
		return ret;

	/* basic support for SRv6 Behavior counters requires at least:
	 * packets, bytes and errors.
	 */
	if (!tb[SEG6_LOCAL_CNT_PACKETS] || !tb[SEG6_LOCAL_CNT_BYTES] ||
	    !tb[SEG6_LOCAL_CNT_ERRORS])
		return -NLE_INVAL;


	slwt->counters.packets = nla_get_u64(tb[SEG6_LOCAL_CNT_PACKETS]);
	
	slwt->counters_present = 1;

	return 0;
}

/**
 * Copied from Linux 6.4: seg6_local_fill_nla_counters:net/ipv6/seg6_local.c
 * Author: Andrea Mayer <andrea.mayer@uniroma2.it>
 */
static int seg6_local_fill_nla_counters(struct nl_msg *msg,
					struct seg6_local_counters *counters)
{
	if (nla_put_u64(msg, SEG6_LOCAL_CNT_PACKETS, counters->packets))
		return -NLE_MSGSIZE;

	if (nla_put_u64(msg, SEG6_LOCAL_CNT_BYTES, counters->bytes))
		return -NLE_MSGSIZE;

	if (nla_put_u64(msg, SEG6_LOCAL_CNT_ERRORS, counters->errors))
		return -NLE_MSGSIZE;

	return 0;
}

/**
 * Copied from Linux 6.4: put_nla_counters:net/ipv6/seg6_local.c
 * Author: Andrea Mayer <andrea.mayer@uniroma2.it>
 */
static int put_nla_counters(struct nl_msg *msg, struct seg6_local_lwt *slwt)
{
	struct nlattr *nest;
	int rc;

	if (!slwt->counters_present)
		return 0;

	nest = nla_nest_start(msg, SEG6_LOCAL_COUNTERS);
	if (!nest)
		return -NLE_MSGSIZE;

	rc = seg6_local_fill_nla_counters(msg, &slwt->counters);
	if (rc < 0) {
		nla_nest_cancel(msg, nest);
		return rc;
	}

	return nla_nest_end(msg, nest);
}

static int cmp_nla_counters(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	/* a and b are equal if both have pcpu_counters set or not */
	return a->counters_present ^ b->counters_present;
}

static const
struct nla_policy seg6_local_flavors_policy[SEG6_LOCAL_FLV_MAX + 1] = {
	[SEG6_LOCAL_FLV_OPERATION]	= { .type = NLA_U32 },
	[SEG6_LOCAL_FLV_LCBLOCK_BITS]	= { .type = NLA_U8 },
	[SEG6_LOCAL_FLV_LCNODE_FN_BITS]	= { .type = NLA_U8 },
};

static bool seg6_next_csid_enabled(uint32_t fops)
{
	return fops & BIT(SEG6_LOCAL_FLV_OP_NEXT_CSID);
}

/**
 * Copied from Linux 6.4: seg6_chk_next_csid_cfg:net/ipv6/seg6_local.c
 * Author: Andrea Mayer <andrea.mayer@uniroma2.it>
 */
static int seg6_chk_next_csid_cfg(uint8_t block_len, uint8_t func_len)
{
	/* Locator-Block and Locator-Node Function cannot exceed 128 bits
	 * (i.e. C-SID container lenghts).
	 */
	if (next_csid_chk_cntr_bits(block_len, func_len))
		return -NLE_INVAL;

	/* Locator-Block length must be greater than zero and evenly divisible
	 * by 8. There must be room for a Locator-Node Function, at least.
	 */
	if (next_csid_chk_lcblock_bits(block_len))
		return -NLE_INVAL;

	/* Locator-Node Function length must be greater than zero and evenly
	 * divisible by 8. There must be room for the Locator-Block.
	 */
	if (next_csid_chk_lcnode_fn_bits(func_len))
		return -NLE_INVAL;

	return 0;
}

/**
 * Copied from Linux 6.4: seg6_parse_nla_next_csid_cfg:net/ipv6/seg6_local.c
 * Author: Andrea Mayer <andrea.mayer@uniroma2.it>
 */
static int seg6_parse_nla_next_csid_cfg(struct nlattr **tb,
					struct seg6_flavors_info *finfo)
{
	uint8_t func_len = SEG6_LOCAL_LCNODE_FN_DBITS;
	uint8_t block_len = SEG6_LOCAL_LCBLOCK_DBITS;
	int rc;

	if (tb[SEG6_LOCAL_FLV_LCBLOCK_BITS])
		block_len = nla_get_u8(tb[SEG6_LOCAL_FLV_LCBLOCK_BITS]);

	if (tb[SEG6_LOCAL_FLV_LCNODE_FN_BITS])
		func_len = nla_get_u8(tb[SEG6_LOCAL_FLV_LCNODE_FN_BITS]);

	rc = seg6_chk_next_csid_cfg(block_len, func_len);
	if (rc < 0) {
		NL_DBG(1, "Invalid Locator Block/Node Function lengths");
		return rc;
	}

	finfo->lcblock_bits = block_len;
	finfo->lcnode_func_bits = func_len;

	return 0;
}

/**
 * Copied from Linux 6.4: parse_nla_flavors:net/ipv6/seg6_local.c
 * Author: Andrea Mayer <andrea.mayer@uniroma2.it>
 */
static int parse_nla_flavors(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	struct seg6_flavors_info *finfo = &slwt->flv_info;
	struct nlattr *tb[SEG6_LOCAL_FLV_MAX + 1];
	unsigned long fops;
	int rc;

	rc = nla_parse_nested(tb, SEG6_LOCAL_FLV_MAX, attrs[SEG6_LOCAL_FLAVORS],
			      seg6_local_flavors_policy);
	if (rc < 0)
		return rc;

	/* this attribute MUST always be present since it represents the Flavor
	 * operation(s) to be carried out.
	 */
	if (!tb[SEG6_LOCAL_FLV_OPERATION])
		return -NLE_INVAL;

	fops = nla_get_u32(tb[SEG6_LOCAL_FLV_OPERATION]);
	if (fops & ~SEG6_LOCAL_FLV_SUPP_OPS) {
		NL_DBG(3, "Unsupported Flavor operation(s)");
		return -NLE_OPNOTSUPP;
	}

	finfo->flv_ops = fops;

	if (seg6_next_csid_enabled(fops)) {
		/* Locator-Block and Locator-Node Function lengths can be
		 * provided by the user space. Otherwise, default values are
		 * applied.
		 */
		rc = seg6_parse_nla_next_csid_cfg(tb, finfo);
		if (rc < 0)
			return rc;
	}

	return 0;
}

static int seg6_fill_nla_next_csid_cfg(struct nl_msg *msg,
				       struct seg6_flavors_info *finfo)
{
	NLA_PUT_U8(msg, SEG6_LOCAL_FLV_LCBLOCK_BITS, finfo->lcblock_bits);
	NLA_PUT_U8(msg, SEG6_LOCAL_FLV_LCNODE_FN_BITS, finfo->lcnode_func_bits);

	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

/**
 * Copied from Linux 6.4: put_nla_flavors:net/ipv6/seg6_local.c
 * Author: Andrea Mayer <andrea.mayer@uniroma2.it>
 */
static int put_nla_flavors(struct nl_msg *msg, struct seg6_local_lwt *slwt)
{
	struct seg6_flavors_info *finfo = &slwt->flv_info;
	uint32_t fops = finfo->flv_ops;
	struct nlattr *nest;
	int rc;

	nest = nla_nest_start(msg, SEG6_LOCAL_FLAVORS);
	if (!nest)
		return -NLE_MSGSIZE;

	if (nla_put_u32(msg, SEG6_LOCAL_FLV_OPERATION, fops)) {
		rc = -NLE_MSGSIZE;
		goto err;
	}

	if (seg6_next_csid_enabled(fops)) {
		rc = seg6_fill_nla_next_csid_cfg(msg, finfo);
		if (rc < 0)
			goto err;
	}

	return nla_nest_end(msg, nest);

err:
	nla_nest_cancel(msg, nest);
	return rc;
}

static int seg6_cmp_nla_next_csid_cfg(struct seg6_flavors_info *finfo_a,
				      struct seg6_flavors_info *finfo_b)
{
	if (finfo_a->lcblock_bits != finfo_b->lcblock_bits)
		return 1;

	if (finfo_a->lcnode_func_bits != finfo_b->lcnode_func_bits)
		return 1;

	return 0;
}

static int cmp_nla_flavors(struct seg6_local_lwt *a, struct seg6_local_lwt *b)
{
	struct seg6_flavors_info *finfo_a = &a->flv_info;
	struct seg6_flavors_info *finfo_b = &b->flv_info;

	if (finfo_a->flv_ops != finfo_b->flv_ops)
		return 1;

	if (seg6_next_csid_enabled(finfo_a->flv_ops)) {
		if (seg6_cmp_nla_next_csid_cfg(finfo_a, finfo_b))
			return 1;
	}

	return 0;
}

struct seg6_action_param {
	int (*parse)(struct nlattr **attrs, struct seg6_local_lwt *slwt);
	int (*put)(struct nl_msg *msg, struct seg6_local_lwt *slwt);
	int (*cmp)(struct seg6_local_lwt *a, struct seg6_local_lwt *b);
	void (*dump)(struct seg6_local_lwt *slwt, struct nl_dump_params *dp);

	/* optional destroy() callback useful for releasing resources which
	 * have been previously acquired in the corresponding parse()
	 * function.
	 */
	void (*destroy)(struct seg6_local_lwt *slwt);
};

static struct seg6_action_param seg6_action_params[SEG6_LOCAL_MAX + 1] = {
	[SEG6_LOCAL_SRH]	= { .parse = parse_nla_srh,
				    .put = put_nla_srh,
				    .cmp = cmp_nla_srh,
				    .dump = dump_nla_srh,
				    .destroy = destroy_attr_srh },

	[SEG6_LOCAL_TABLE]	= { .parse = parse_nla_table,
				    .put = put_nla_table,
				    .cmp = cmp_nla_table,
				    .dump = dump_nla_table },

	[SEG6_LOCAL_NH4]	= { .parse = parse_nla_nh4,
				    .put = put_nla_nh4,
				    .cmp = cmp_nla_nh4 },

	[SEG6_LOCAL_NH6]	= { .parse = parse_nla_nh6,
				    .put = put_nla_nh6,
				    .cmp = cmp_nla_nh6 },

	[SEG6_LOCAL_IIF]	= { .parse = parse_nla_iif,
				    .put = put_nla_iif,
				    .cmp = cmp_nla_iif },

	[SEG6_LOCAL_OIF]	= { .parse = parse_nla_oif,
				    .put = put_nla_oif,
				    .cmp = cmp_nla_oif },

	[SEG6_LOCAL_BPF]	= { .parse = parse_nla_bpf,
				    .put = put_nla_bpf,
				    .cmp = cmp_nla_bpf,
				    .destroy = destroy_attr_bpf },

	[SEG6_LOCAL_VRFTABLE]	= { .parse = parse_nla_vrftable,
				    .put = put_nla_vrftable,
				    .cmp = cmp_nla_vrftable },

	[SEG6_LOCAL_COUNTERS]	= { .parse = parse_nla_counters,
				    .put = put_nla_counters,
				    .cmp = cmp_nla_counters },

	[SEG6_LOCAL_FLAVORS]	= { .parse = parse_nla_flavors,
				    .put = put_nla_flavors,
				    .cmp = cmp_nla_flavors },
};

static void destroy_attrs(unsigned long parsed_attrs, int max_parsed,
			  struct seg6_local_lwt *slwt)
{
	struct seg6_action_param *param;
	int i;

	for (i = SEG6_LOCAL_SRH; i < max_parsed; ++i) {
		if (!(parsed_attrs & SEG6_F_ATTR(i)))
			continue;

		param = &seg6_action_params[i];

		if (param->destroy)
			param->destroy(slwt);
	}
}

/**
 * Copied from Linux 6.4: parse_nla_optional_attrs:net/ipv6/seg6_local.c
 * Author: Andrea Mayer <andrea.mayer@uniroma2.it>
 */
static int parse_nla_optional_attrs(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	struct seg6_action_desc *desc = slwt->desc;
	unsigned long parsed_optattrs = 0;
	struct seg6_action_param *param;
	int err, i;

	for (i = SEG6_LOCAL_SRH; i < SEG6_LOCAL_MAX + 1; ++i) {
		if (!(desc->optattrs & SEG6_F_ATTR(i)) || !attrs[i])
			continue;

		/* once here, the i-th attribute is provided by the
		 * userspace AND it is identified optional as well.
		 */
		param = &seg6_action_params[i];

		err = param->parse(attrs, slwt);
		if (err < 0)
			goto parse_optattrs_err;

		/* current attribute has been correctly parsed */
		parsed_optattrs |= SEG6_F_ATTR(i);
	}

	/* store in the tunnel state all the optional attributed successfully
	 * parsed.
	 */
	slwt->parsed_optattrs = parsed_optattrs;

	return 0;

parse_optattrs_err:
	destroy_attrs(parsed_optattrs, i, slwt);

	return err;
}

/**
 * Copied from Linux 6.4: parse_nla_optional_attrs:net/ipv6/seg6_local.c
 * Author: David Lebrun <david.lebrun@uclouvain.be>
 */
static int parse_nla_action(struct nlattr **attrs, struct seg6_local_lwt *slwt)
{
	struct seg6_action_param *param;
	struct seg6_action_desc *desc;
	unsigned long invalid_attrs;
	int i, err;

	desc = get_action_desc(slwt->action);
	if (!desc)
		return -NLE_INVAL;

	slwt->desc = desc;
	slwt->headroom += desc->static_headroom;

	/* Forcing the desc->optattrs *set* and the desc->attrs *set* to be
	 * disjoined, this allow us to release acquired resources by optional
	 * attributes and by required attributes independently from each other
	 * without any interference.
	 * In other terms, we are sure that we do not release some the acquired
	 * resources twice.
	 *
	 * Note that if an attribute is configured both as required and as
	 * optional, it means that the user has messed something up in the
	 * seg6_action_table. Therefore, this check is required for SRv6
	 * behaviors to work properly.
	 */
	invalid_attrs = desc->attrs & desc->optattrs;
	if (invalid_attrs) {
		NL_DBG(1, "An attribute cannot be both required AND optional");
		return -NLE_INVAL;
	}

	/* parse the required attributes */
	for (i = SEG6_LOCAL_SRH; i < SEG6_LOCAL_MAX + 1; i++) {
		if (desc->attrs & SEG6_F_ATTR(i)) {
			if (!attrs[i])
				return -NLE_INVAL;

			param = &seg6_action_params[i];

			err = param->parse(attrs, slwt);
			if (err < 0)
				goto parse_attrs_err;
		}
	}

	/* parse the optional attributes, if any */
	err = parse_nla_optional_attrs(attrs, slwt);
	if (err < 0)
		goto parse_attrs_err;

	return 0;

parse_attrs_err:
	/* release any resource that may have been acquired during the i-1
	 * parse() operations.
	 */
	destroy_attrs(desc->attrs, i, slwt);

	return err;
}

static void seg6_local_encap_destructor(void *priv)
{
	struct seg6_local_lwt *slwt = priv;
	unsigned long attrs = slwt->desc->attrs | slwt->parsed_optattrs;

	destroy_attrs(attrs, SEG6_LOCAL_MAX + 1, slwt);
}

/**
 * Copied from Linux 6.4: seg6_local_build_state:net/ipv6/seg6_local.c
 * Author: David Lebrun <david.lebrun@uclouvain.be>
 */
static int seg6_local_encap_parse_msg(struct nlattr *nla, struct rtnl_nexthop *nh)
{
	struct nlattr *tb[SEG6_LOCAL_MAX + 1];
	struct rtnl_nh_encap *	rtnh_encap;
	struct seg6_local_lwt *slwt;
	int err;

	err = nla_parse_nested(tb, SEG6_LOCAL_MAX, nla, seg6_local_encap_policy);
	if (err < 0)
		return err;

	if (!tb[SEG6_LOCAL_ACTION])
		return -NLE_INVAL;

	rtnh_encap = calloc(1, sizeof(*rtnh_encap));
	if (!rtnh_encap)
		return -NLE_NOMEM;

	slwt = calloc(1, sizeof(*slwt));
	if (slwt == NULL) {
		free(rtnh_encap);
		return -NLE_NOMEM;
	}

	slwt->action = nla_get_u32(tb[SEG6_LOCAL_ACTION]);

	err = parse_nla_action(tb, slwt);
	if (err < 0)
		goto err;

	rtnh_encap->priv = slwt;
	rtnh_encap->ops = &seg6_local_encap_ops;

	nh_set_encap(nh, rtnh_encap);

	return 0;

err:
	free(slwt);
	free(rtnh_encap);
	return err;
}

static int seg6_local_encap_build_msg(struct nl_msg *msg, void *priv)
{
	struct seg6_local_lwt *slwt = priv;
	struct seg6_action_param *param;
	unsigned long attrs;
	int i, err;

	NLA_PUT_U32(msg, SEG6_LOCAL_ACTION, slwt->action);

	attrs = slwt->desc->attrs | slwt->parsed_optattrs;

	for (i = SEG6_LOCAL_SRH; i < SEG6_LOCAL_MAX + 1; i++) {
		if (attrs & SEG6_F_ATTR(i)) {
			param = &seg6_action_params[i];
			err = param->put(msg, slwt);
			if (err < 0)
				return err;
		}
	}

	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

static int seg6_local_encap_compare(void *a, void *b)
{
	struct seg6_local_lwt *slwt_a, *slwt_b;
	struct seg6_action_param *param;
	unsigned long attrs_a, attrs_b;
	int i;

	slwt_a = a;
	slwt_b = b;

	if (slwt_a->action != slwt_b->action)
		return 1;

	attrs_a = slwt_a->desc->attrs | slwt_a->parsed_optattrs;
	attrs_b = slwt_b->desc->attrs | slwt_b->parsed_optattrs;

	if (attrs_a != attrs_b)
		return 1;

	for (i = SEG6_LOCAL_SRH; i < SEG6_LOCAL_MAX + 1; i++) {
		if (attrs_a & SEG6_F_ATTR(i)) {
			param = &seg6_action_params[i];
			if (param->cmp(slwt_a, slwt_b))
				return 1;
		}
	}

	return 0;
}

static const char *seg6_action_names[SEG6_LOCAL_ACTION_MAX + 1] = {
	[SEG6_LOCAL_ACTION_END]			= "End",
	[SEG6_LOCAL_ACTION_END_X]		= "End.X",
	[SEG6_LOCAL_ACTION_END_T]		= "End.T",
	[SEG6_LOCAL_ACTION_END_DX2]		= "End.DX2",
	[SEG6_LOCAL_ACTION_END_DX6]		= "End.DX6",
	[SEG6_LOCAL_ACTION_END_DX4]		= "End.DX4",
	[SEG6_LOCAL_ACTION_END_DT6]		= "End.DT6",
	[SEG6_LOCAL_ACTION_END_DT4]		= "End.DT4",
	[SEG6_LOCAL_ACTION_END_B6]		= "End.B6",
	[SEG6_LOCAL_ACTION_END_B6_ENCAP]	= "End.B6.Encaps",
	[SEG6_LOCAL_ACTION_END_BM]		= "End.BM",
	[SEG6_LOCAL_ACTION_END_S]		= "End.S",
	[SEG6_LOCAL_ACTION_END_AS]		= "End.AS",
	[SEG6_LOCAL_ACTION_END_AM]		= "End.AM",
	[SEG6_LOCAL_ACTION_END_BPF]		= "End.BPF",
	[SEG6_LOCAL_ACTION_END_DT46]		= "End.DT46",
};

static const char *format_action_type(int action)
{
	if (action < 0 || action > SEG6_LOCAL_ACTION_MAX)
		return "<invalid>";

	return seg6_action_names[action] ?: "<unknown>";
}

static void seg6_local_encap_dump(void *priv, struct nl_dump_params *dp)
{
	struct seg6_local_lwt *slwt;
	struct seg6_action_param *param;
	unsigned long attrs;
	int i;

	slwt = priv;
	nl_dump(dp, "action %s ", format_action_type(slwt->action));

	attrs = slwt->desc->attrs | slwt->parsed_optattrs;

	for (i = SEG6_LOCAL_SRH; i < SEG6_LOCAL_MAX + 1; i++) {
		if (attrs & SEG6_F_ATTR(i)) {
			param = &seg6_action_params[i];
			if (param->dump)
				param->dump(slwt, dp);
		}
	}
}

struct nh_encap_ops seg6_local_encap_ops = {
	.encap_type	= LWTUNNEL_ENCAP_SEG6_LOCAL,
	.build_msg	= seg6_local_encap_build_msg,
	.parse_msg	= seg6_local_encap_parse_msg,
	.compare	= seg6_local_encap_compare,
	.dump		= seg6_local_encap_dump,
	.destructor	= seg6_local_encap_destructor,
};

static struct seg6_local_lwt *
get_seg6_local_slwt(struct rtnl_nexthop *nh)
{
	if (!nh->rtnh_encap || nh->rtnh_encap->ops->encap_type != LWTUNNEL_ENCAP_SEG6_LOCAL)
		return NULL;

	return (struct seg6_local_lwt *)nh->rtnh_encap->priv;
}

int rtnl_route_nh_get_encap_seg6_local_action(struct rtnl_nexthop *nh)
{
	struct seg6_local_lwt *slwt;

	slwt = get_seg6_local_slwt(nh);
	if (slwt == NULL)
		return -NLE_NOATTR;

	return slwt->action;
}

int rtnl_route_nh_has_encap_seg6_local_attr(struct rtnl_nexthop * nh, int attr)
{
	unsigned long attrs;
	struct seg6_local_lwt *slwt;

	slwt = get_seg6_local_slwt(nh);
	if (slwt == NULL)
		return -NLE_NOATTR;

	attrs = slwt->desc->attrs | slwt->parsed_optattrs;
	
	if (attr < 0 || attr >= CHAR_BIT * sizeof(attrs))
		return -NLE_INVAL;

	return !!(attrs & SEG6_F_ATTR(attr));
}

int rtnl_route_nh_get_encap_seg6_local_table(struct rtnl_nexthop *nh)
{
	struct seg6_local_lwt *slwt;

	slwt = get_seg6_local_slwt(nh);
	if (slwt == NULL)
		return -NLE_NOATTR;

	return slwt->table;
}

int rtnl_route_nh_get_encap_seg6_local_vrftable(struct rtnl_nexthop *nh)
{
	struct seg6_local_lwt *slwt;

	slwt = get_seg6_local_slwt(nh);
	if (slwt == NULL)
		return -NLE_NOATTR;

	return slwt->dt_info.vrf_table;
}
