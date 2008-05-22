/*
 * src/ct-utils.h		Conntrack Helper
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __CT_UTILS_H_
#define __CT_UTILS_H_

#include "utils.h"
#include <netlink/netfilter/ct.h>
#include <linux/netfilter/nf_conntrack_common.h>

extern struct nfnl_ct *nlt_alloc_ct(void);
extern struct nl_cache *nlt_alloc_ct_cache(struct nl_sock *);
extern void parse_family(struct nfnl_ct *, char *);
extern void parse_protocol(struct nfnl_ct *, char *);
extern void parse_mark(struct nfnl_ct *, char *);
extern void parse_timeout(struct nfnl_ct *, char *);
extern void parse_id(struct nfnl_ct *, char *);
extern void parse_use(struct nfnl_ct *, char *);
extern void parse_src(struct nfnl_ct *, int, char *);
extern void parse_dst(struct nfnl_ct *, int, char *);
extern void parse_src_port(struct nfnl_ct *, int, char *);
extern void parse_dst_port(struct nfnl_ct *, int, char *);
extern void parse_tcp_state(struct nfnl_ct *, char *);
extern void parse_status(struct nfnl_ct *, char *);

#endif
