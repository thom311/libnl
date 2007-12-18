/*
 * netlink-local.h		Local Netlink Interface
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_LOCAL_H_
#define NETLINK_LOCAL_H_

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <assert.h>

#include <arpa/inet.h>
#include <netdb.h>

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#include <linux/types.h>

/* local header copies */
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <linux/gen_stats.h>
#include <linux/ip_mp_alg.h>

#include <netlink/netlink.h>
#include <netlink/handlers.h>
#include <netlink/cache.h>
#include <netlink/route/tc.h>
#include <netlink/object-api.h>
#include <netlink/cache-api.h>
#include <netlink-types.h>

struct trans_tbl {
	int i;
	const char *a;
};

#define __ADD(id, name) { .i = id, .a = #name },

struct trans_list {
	int i;
	char *a;
	struct nl_list_head list;
};

#define NL_DEBUG	1

#define NL_DBG(LVL,FMT,ARG...) \
	do {	\
		if (LVL <= nl_debug) \
			fprintf(stderr, "DBG<" #LVL ">: " FMT, ##ARG); \
	} while (0)

#define BUG()                            \
	do {                                 \
		fprintf(stderr, "BUG: %s:%d\n",  \
			__FILE__, __LINE__);         \
		assert(0);	\
	} while (0)

#define RET_ERR(R, E)                    \
    do {                                 \
		errno = E;                       \
		return -R;                       \
	} while (0)

extern int __nl_error(int, const char *, unsigned int,
	const char *, const char *, ...);

extern int __nl_read_num_str_file(const char *path,
				  int (*cb)(long, const char *));

#ifdef NL_ERROR_ASSERT
#include <assert.h>
static inline int __assert_error(const char *file, int line, char *func,
	const char *fmt, ...)
{
	va_list args;
	fprintf(stderr, "%s:%d:%s: ", file, line, func);
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, "\n");
	assert(0);
	return 0;
}
#define nl_error(E, FMT,ARG...) \
	__assert_error(__FILE__, __LINE__, __FUNCTION__, FMT, ##ARG)

#else
#define nl_error(E, FMT,ARG...) \
	__nl_error(E, __FILE__, __LINE__, __FUNCTION__, FMT, ##ARG)

#endif

#define nl_errno(E)	nl_error(E, NULL)

/* backwards compat */
#define dp_new_line(params, line)	nl_new_line(params, line)
#define dp_dump(params, fmt, arg...)	nl_dump(params, fmt, ##arg)

static inline int __trans_list_add(int i, const char *a,
				   struct nl_list_head *head)
{
	struct trans_list *tl;

	tl = calloc(1, sizeof(*tl));
	if (!tl)
		return nl_errno(ENOMEM);

	tl->i = i;
	tl->a = strdup(a);

	nl_list_add_tail(&tl->list, head);

	return 0;
}

static inline void __trans_list_clear(struct nl_list_head *head)
{
	struct trans_list *tl, *next;

	nl_list_for_each_entry_safe(tl, next, head, list) {
		free(tl->a);
		free(tl);
	}
}

static inline char *__type2str(int type, char *buf, size_t len,
			       struct trans_tbl *tbl, size_t tbl_len)
{
	int i;
	for (i = 0; i < tbl_len; i++) {
		if (tbl[i].i == type) {
			snprintf(buf, len, "%s", tbl[i].a);
			return buf;
		}
	}

	snprintf(buf, len, "0x%x", type);
	return buf;
}

static inline char *__list_type2str(int type, char *buf, size_t len,
				    struct nl_list_head *head)
{
	struct trans_list *tl;

	nl_list_for_each_entry(tl, head, list) {
		if (tl->i == type) {
			snprintf(buf, len, "%s", tl->a);
			return buf;
		}
	}

	snprintf(buf, len, "0x%x", type);
	return buf;
}

static inline char *__flags2str(int flags, char *buf, size_t len,
				struct trans_tbl *tbl, size_t tbl_len)
{
	int i;
	int tmp = flags;

	memset(buf, 0, len);
	
	for (i = 0; i < tbl_len; i++) {
		if (tbl[i].i & tmp) {
			tmp &= ~tbl[i].i;
			strncat(buf, tbl[i].a, len - strlen(buf) - 1);
			if ((tmp & flags))
				strncat(buf, ",", len - strlen(buf) - 1);
		}
	}

	return buf;
}

static inline int __str2type(const char *buf, struct trans_tbl *tbl,
			     size_t tbl_len)
{
	unsigned long l;
	char *end;
	int i;

	if (*buf == '\0')
		return -1;

	for (i = 0; i < tbl_len; i++)
		if (!strcasecmp(tbl[i].a, buf))
			return tbl[i].i;

	l = strtoul(buf, &end, 0);
	if (l == ULONG_MAX || *end != '\0')
		return -1;

	return (int) l;
}

static inline int __list_str2type(const char *buf, struct nl_list_head *head)
{
	struct trans_list *tl;
	unsigned long l;
	char *end;

	if (*buf == '\0')
		return -1;

	nl_list_for_each_entry(tl, head, list) {
		if (!strcasecmp(tl->a, buf))
			return tl->i;
	}

	l = strtoul(buf, &end, 0);
	if (l == ULONG_MAX || *end != '\0')
		return -1;

	return (int) l;
}

static inline int __str2flags(const char *buf, struct trans_tbl *tbl,
			      size_t tbl_len)
{
	int i, flags = 0, len;
	char *p = (char *) buf, *t;

	for (;;) {
		if (*p == ' ')
			p++;
	
		t = strchr(p, ',');
		len = t ? t - p : strlen(p);
		for (i = 0; i < tbl_len; i++)
			if (!strncasecmp(tbl[i].a, p, len))
				flags |= tbl[i].i;

		if (!t)
			return flags;

		p = ++t;
	}

	return 0;
}

static inline void __dp_dump(struct nl_dump_params *parms, const char *fmt,
			     va_list args)
{
	if (parms->dp_fd)
		vfprintf(parms->dp_fd, fmt, args);
	else if (parms->dp_buf || parms->dp_cb) {
		char *buf = NULL;
		vasprintf(&buf, fmt, args);
		if (parms->dp_cb)
			parms->dp_cb(parms, buf);
		else
			strncat(parms->dp_buf, buf,
			        parms->dp_buflen - strlen(parms->dp_buf) - 1);
		free(buf);
	}
}

static inline void dp_dump_line(struct nl_dump_params *parms, int line,
				const char *fmt, ...)
{
	va_list args;

	nl_new_line(parms, line);

	va_start(args, fmt);
	__dp_dump(parms, fmt, args);
	va_end(args);
}

static inline void dump_from_ops(struct nl_object *obj,
				 struct nl_dump_params *params)
{
	int type = params->dp_type;

	if (type < 0 || type > NL_DUMP_MAX)
		BUG();

	if (params->dp_dump_msgtype) {
#if 0
		/* XXX */
		char buf[64];

		dp_dump_line(params, 0, "%s ",
			     nl_cache_mngt_type2name(obj->ce_ops,
			     			     obj->ce_ops->co_protocol,
						     obj->ce_msgtype,
						     buf, sizeof(buf)));
#endif
		params->dp_pre_dump = 1;
	} else
		dp_new_line(params, 0);

	if (obj->ce_ops->oo_dump[type])
		obj->ce_ops->oo_dump[type](obj, params);
}

static inline struct nl_cache *dp_cache(struct nl_object *obj)
{
	if (obj->ce_cache == NULL)
		return nl_cache_mngt_require(obj->ce_ops->oo_name);

	return obj->ce_cache;
}

static inline int nl_cb_call(struct nl_cb *cb, int type, struct nl_msg *msg)
{
	return cb->cb_set[type](msg, cb->cb_args[type]);
}

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define __init __attribute__ ((constructor))
#define __exit __attribute__ ((destructor))

#define P_ACCEPT 0
#define P_IGNORE 0

#define min(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })

#define max(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })

#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

extern int nl_cache_parse(struct nl_cache_ops *, struct sockaddr_nl *,
			  struct nlmsghdr *, struct nl_parser_param *);


static inline void rtnl_copy_ratespec(struct rtnl_ratespec *dst,
				      struct tc_ratespec *src)
{
	dst->rs_cell_log = src->cell_log;
	dst->rs_feature = src->feature;
	dst->rs_addend = src->addend;
	dst->rs_mpu = src->mpu;
	dst->rs_rate = src->rate;
}

static inline void rtnl_rcopy_ratespec(struct tc_ratespec *dst,
				       struct rtnl_ratespec *src)
{
	dst->cell_log = src->rs_cell_log;
	dst->feature = src->rs_feature;
	dst->addend = src->rs_addend;
	dst->mpu = src->rs_mpu;
	dst->rate = src->rs_rate;
}

static inline char *nl_cache_name(struct nl_cache *cache)
{
	return cache->c_ops ? cache->c_ops->co_name : "unknown";
}

#define GENL_FAMILY(id, name) \
	{ \
		{ id, NL_ACT_UNSPEC, name }, \
		END_OF_MSGTYPES_LIST, \
	}

#endif
