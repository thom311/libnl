/*
 * lib/route/cls/ematch/meta.c		Metadata Match
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2010 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup ematch
 * @defgroup em_meta Metadata Match
 *
 * @{
 */

#include <netlink-local.h>
#include <netlink-tc.h>
#include <netlink/netlink.h>
#include <netlink/route/cls/ematch.h>
#include <netlink/route/cls/ematch/meta.h>

struct rtnl_meta_value
{
	uint8_t			mv_type;
	uint8_t			mv_shift;
	uint16_t		mv_id;
	size_t			mv_len;
};

struct meta_data
{
	struct rtnl_meta_value *	left;
	struct rtnl_meta_value *	right;
	uint8_t				opnd;
};

static struct rtnl_meta_value *meta_alloc(uint8_t type, uint16_t id,
					  uint8_t shift, void *data,
					  size_t len)
{
	struct rtnl_meta_value *value;

	if (!(value = calloc(1, sizeof(*value) + len)))
		return NULL;

	value->mv_type = type;
	value->mv_id = id;
	value->mv_shift = shift;
	value->mv_len = len;

	memcpy(value + 1, data, len);

	return value;
}

struct rtnl_meta_value *rtnl_meta_value_alloc_int(uint64_t value)
{
	return meta_alloc(TCF_META_TYPE_INT, TCF_META_ID_VALUE, 0, &value, 8);
}

struct rtnl_meta_value *rtnl_meta_value_alloc_var(void *data, size_t len)
{
	return meta_alloc(TCF_META_TYPE_VAR, TCF_META_ID_VALUE, 0, data, len);
}

struct rtnl_meta_value *rtnl_meta_value_alloc_id(uint8_t type, uint16_t id,
						 uint8_t shift, uint64_t mask)
{
	size_t masklen = 0;

	if (id > TCF_META_ID_MAX)
		return NULL;

	if (mask) {
		if (type == TCF_META_TYPE_VAR)
			return NULL;

		masklen = 8;
	}

	return meta_alloc(type, id, shift, &mask, masklen);
}

void rtnl_meta_value_put(struct rtnl_meta_value *mv)
{
	free(mv);
}

void rtnl_ematch_meta_set_lvalue(struct rtnl_ematch *e, struct rtnl_meta_value *v)
{
	struct meta_data *m = rtnl_ematch_data(e);
	m->left = v;
}

void rtnl_ematch_meta_set_rvalue(struct rtnl_ematch *e, struct rtnl_meta_value *v)
{
	struct meta_data *m = rtnl_ematch_data(e);
	m->right = v;
}

void rtnl_ematch_meta_set_operand(struct rtnl_ematch *e, uint8_t opnd)
{
	struct meta_data *m = rtnl_ematch_data(e);
	m->opnd = opnd;
}

static struct nla_policy meta_policy[TCA_EM_META_MAX+1] = {
	[TCA_EM_META_HDR]	= { .minlen = sizeof(struct tcf_meta_hdr) },
	[TCA_EM_META_LVALUE]	= { .minlen = 1, },
	[TCA_EM_META_RVALUE]	= { .minlen = 1, },
};

static int meta_parse(struct rtnl_ematch *e, void *data, size_t len)
{
	struct meta_data *m = rtnl_ematch_data(e);
	struct nlattr *tb[TCA_EM_META_MAX+1];
	struct rtnl_meta_value *v;
	struct tcf_meta_hdr *hdr;
	void *vdata = NULL;
	size_t vlen = 0;
	int err;

	if ((err = nla_parse(tb, TCA_EM_META_MAX, data, len, meta_policy)) < 0)
		return err;

	if (!tb[TCA_EM_META_HDR])
		return -NLE_MISSING_ATTR;

	hdr = nla_data(tb[TCA_EM_META_HDR]);

	if (tb[TCA_EM_META_LVALUE]) {
		vdata = nla_data(tb[TCA_EM_META_LVALUE]);
		vlen = nla_len(tb[TCA_EM_META_LVALUE]);
	}

	v = meta_alloc(TCF_META_TYPE(hdr->left.kind),
		       TCF_META_ID(hdr->left.kind),
		       hdr->left.shift, vdata, vlen);
	if (!v)
		return -NLE_NOMEM;

	m->left = v;

	vlen = 0;
	if (tb[TCA_EM_META_RVALUE]) {
		vdata = nla_data(tb[TCA_EM_META_RVALUE]);
		vlen = nla_len(tb[TCA_EM_META_RVALUE]);
	}

	v = meta_alloc(TCF_META_TYPE(hdr->right.kind),
		       TCF_META_ID(hdr->right.kind),
		       hdr->right.shift, vdata, vlen);
	if (!v) {
		rtnl_meta_value_put(m->left);
		return -NLE_NOMEM;
	}

	m->right = v;
	m->opnd = hdr->left.op;

	return 0;
}

static struct trans_tbl meta_int[] = {
	__ADD(TCF_META_ID_VLAN_TAG, vlan)
	__ADD(TCF_META_ID_PKTLEN, pktlen)
};

static char *int_id2str(int id, char *buf, size_t size)
{
	return __type2str(id, buf, size, meta_int, ARRAY_SIZE(meta_int));
}

static struct trans_tbl meta_var[] = {
	__ADD(TCF_META_ID_DEV,devname)
	__ADD(TCF_META_ID_SK_BOUND_IF,sk_bound_if)
};

static char *var_id2str(int id, char *buf, size_t size)
{
	return __type2str(id, buf, size, meta_var, ARRAY_SIZE(meta_var));
}

static void dump_value(struct rtnl_meta_value *v, struct nl_dump_params *p)
{
	char buf[32];

	switch (v->mv_type) {
		case TCF_META_TYPE_INT:
			if (v->mv_id == TCF_META_ID_VALUE) {
				nl_dump(p, "%u",
					*(uint32_t *) (v + 1));
			} else {
				nl_dump(p, "%s",
					int_id2str(v->mv_id, buf, sizeof(buf)));

				if (v->mv_shift)
					nl_dump(p, " >> %u", v->mv_shift);

				if (v->mv_len == 4)
					nl_dump(p, " & %#x", *(uint32_t *) (v + 1));
				else if (v->mv_len == 8)
					nl_dump(p, " & %#x", *(uint64_t *) (v + 1));
			}
		break;

		case TCF_META_TYPE_VAR:
			if (v->mv_id == TCF_META_ID_VALUE) {
				nl_dump(p, "%s", (char *) (v + 1));
			} else {
				nl_dump(p, "%s",
					var_id2str(v->mv_id, buf, sizeof(buf)));

				if (v->mv_shift)
					nl_dump(p, " >> %u", v->mv_shift);
			}
		break;
	}
}

static void meta_dump(struct rtnl_ematch *e, struct nl_dump_params *p)
{
	struct meta_data *m = rtnl_ematch_data(e);
	char buf[32];

	nl_dump(p, "meta(");
	dump_value(m->left, p);

	nl_dump(p, " %s ", rtnl_ematch_opnd2txt(m->opnd, buf, sizeof(buf)));

	dump_value(m->right, p);
	nl_dump(p, ")");
}

static int meta_fill(struct rtnl_ematch *e, struct nl_msg *msg)
{
	struct meta_data *m = rtnl_ematch_data(e);
	struct tcf_meta_hdr hdr;

	if (!(m->left && m->right))
		return -NLE_MISSING_ATTR;

	memset(&hdr, 0, sizeof(hdr));
	hdr.left.kind = (m->left->mv_type << 12) & TCF_META_TYPE_MASK;
	hdr.left.kind |= m->left->mv_id & TCF_META_ID_MASK;
	hdr.left.shift = m->left->mv_shift;
	hdr.left.op = m->opnd;
	hdr.right.kind = (m->right->mv_type << 12) & TCF_META_TYPE_MASK;
	hdr.right.kind |= m->right->mv_id & TCF_META_ID_MASK;

	NLA_PUT(msg, TCA_EM_META_HDR, sizeof(hdr), &hdr);

	if (m->left->mv_len)
		NLA_PUT(msg, TCA_EM_META_LVALUE, m->left->mv_len, (m->left + 1));
	
	if (m->right->mv_len)
		NLA_PUT(msg, TCA_EM_META_RVALUE, m->right->mv_len, (m->right + 1));

	return 0;

nla_put_failure:
	return -NLE_NOMEM;
}

static void meta_free(struct rtnl_ematch *e)
{
	struct meta_data *m = rtnl_ematch_data(e);
	free(m->left);
	free(m->right);
}

static struct rtnl_ematch_ops meta_ops = {
	.eo_kind	= TCF_EM_META,
	.eo_name	= "meta",
	.eo_minlen	= sizeof(struct tcf_meta_hdr),
	.eo_datalen	= sizeof(struct meta_data),
	.eo_parse	= meta_parse,
	.eo_dump	= meta_dump,
	.eo_fill	= meta_fill,
	.eo_free	= meta_free,
};

static void __init meta_init(void)
{
	rtnl_ematch_register(&meta_ops);
}

/** @} */
