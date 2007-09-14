/*
 * netlink/netfilter/log.h	Netfilter Log
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 * Copyright (c) 2007 Philip Craig <philipc@snapgear.com>
 * Copyright (c) 2007 Secure Computing Corporation
 */

#ifndef NETLINK_LOG_H_
#define NETLINK_LOG_H_

#include <netlink/netlink.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nl_handle;
struct nlmsghdr;
struct nfnl_log;

extern struct nl_object_ops log_obj_ops;

/* General */
extern struct nfnl_log *nfnl_log_alloc(void);
extern struct nfnl_log *nfnlmsg_log_parse(struct nlmsghdr *);

extern void		nfnl_log_get(struct nfnl_log *);
extern void		nfnl_log_put(struct nfnl_log *);

extern struct nl_msg *	nfnl_log_build_bind(uint16_t);;
extern int		nfnl_log_bind(struct nl_handle *, uint16_t);
extern struct nl_msg *	nfnl_log_build_unbind(uint16_t);
extern int		nfnl_log_unbind(struct nl_handle *, uint16_t);
extern struct nl_msg *	nfnl_log_build_pf_bind(uint8_t);
extern int		nfnl_log_pf_bind(struct nl_handle *, uint8_t);
extern struct nl_msg *	nfnl_log_build_pf_unbind(uint8_t);
extern int		nfnl_log_pf_unbind(struct nl_handle *, uint8_t);
extern struct nl_msg *	nfnl_log_build_mode(uint16_t, uint8_t, uint32_t);
extern int		nfnl_log_set_mode(struct nl_handle *, uint16_t,
					  uint8_t, uint32_t);

extern void		nfnl_log_set_family(struct nfnl_log *, uint8_t);
extern uint8_t		nfnl_log_get_family(const struct nfnl_log *);

extern void		nfnl_log_set_hwproto(struct nfnl_log *, uint16_t);
extern int		nfnl_log_test_hwproto(const struct nfnl_log *);
extern uint16_t		nfnl_log_get_hwproto(const struct nfnl_log *);

extern void		nfnl_log_set_hook(struct nfnl_log *, uint8_t);
extern int		nfnl_log_test_hook(const struct nfnl_log *);
extern uint8_t		nfnl_log_get_hook(const struct nfnl_log *);

extern void		nfnl_log_set_mark(struct nfnl_log *, uint32_t);
extern int		nfnl_log_test_mark(const struct nfnl_log *);
extern uint32_t		nfnl_log_get_mark(const struct nfnl_log *);

extern void		nfnl_log_set_timestamp(struct nfnl_log *,
					       struct timeval *);
extern const struct timeval *nfnl_log_get_timestamp(const struct nfnl_log *);

extern void		nfnl_log_set_indev(struct nfnl_log *, uint32_t);
extern uint32_t		nfnl_log_get_indev(const struct nfnl_log *);

extern void		nfnl_log_set_outdev(struct nfnl_log *, uint32_t);
extern uint32_t		nfnl_log_get_outdev(const struct nfnl_log *);

extern void		nfnl_log_set_physindev(struct nfnl_log *, uint32_t);
extern uint32_t		nfnl_log_get_physindev(const struct nfnl_log *);

extern void		nfnl_log_set_physoutdev(struct nfnl_log *, uint32_t);
extern uint32_t		nfnl_log_get_physoutdev(const struct nfnl_log *);

extern void		nfnl_log_set_hwaddr(struct nfnl_log *, uint8_t *, int);
extern const uint8_t *	nfnl_log_get_hwaddr(const struct nfnl_log *, int *);

extern int		nfnl_log_set_payload(struct nfnl_log *, uint8_t *, int);
extern const void *	nfnl_log_get_payload(const struct nfnl_log *, int *);

extern int		nfnl_log_set_prefix(struct nfnl_log *, void *);
extern const char *	nfnl_log_get_prefix(const struct nfnl_log *);

extern void		nfnl_log_set_uid(struct nfnl_log *, uint32_t);
extern int		nfnl_log_test_uid(const struct nfnl_log *);
extern uint32_t		nfnl_log_get_uid(const struct nfnl_log *);

extern void		nfnl_log_set_seq(struct nfnl_log *, uint32_t);
extern int		nfnl_log_test_seq(const struct nfnl_log *);
extern uint32_t		nfnl_log_get_seq(const struct nfnl_log *);

extern void		nfnl_log_set_seq_global(struct nfnl_log *, uint32_t);
extern int		nfnl_log_test_seq_global(const struct nfnl_log *);
extern uint32_t		nfnl_log_get_seq_global(const struct nfnl_log *);

#ifdef __cplusplus
}
#endif

#endif

