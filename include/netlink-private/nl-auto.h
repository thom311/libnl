/* SPDX-License-Identifier: LGPL-2.1-only */

#ifndef NETLINK_NL_AUTO_H_
#define NETLINK_NL_AUTO_H_

#include <stdlib.h>

#define _nl_auto(fcn)               __attribute__ ((__cleanup__(fcn)))

#define _NL_AUTO_DEFINE_FCN_VOID0(CastType, name, func) \
static inline void name(void *v) \
{ \
	if (*((CastType *) v)) \
		func(*((CastType *) v)); \
} \
struct _nl_dummy_for_tailing_semicolon

#define _NL_AUTO_DEFINE_FCN_STRUCT(CastType, name, func) \
static inline void name(CastType *v) \
{ \
	if (v) \
		func(v); \
} \
struct _nl_dummy_for_tailing_semicolon

#define _NL_AUTO_DEFINE_FCN_TYPED0(CastType, name, func) \
static inline void name(CastType *v) \
{ \
	if (*v) \
		func(*v); \
} \
struct _nl_dummy_for_tailing_semicolon

#define _nl_auto_free _nl_auto(_nl_auto_free_fcn)
_NL_AUTO_DEFINE_FCN_VOID0(void *, _nl_auto_free_fcn, free);

struct nl_addr;
void nl_addr_put(struct nl_addr *);
#define _nl_auto_nl_addr _nl_auto(_nl_auto_nl_addr_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct nl_addr *, _nl_auto_nl_addr_fcn, nl_addr_put);

struct nl_data;
void nl_data_free(struct nl_data *data);
#define _nl_auto_nl_data _nl_auto(_nl_auto_nl_data_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct nl_data *, _nl_auto_nl_data_fcn, nl_data_free);

struct nl_msg;
void nlmsg_free(struct nl_msg *);
#define _nl_auto_nl_msg _nl_auto(_nl_auto_nl_msg_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct nl_msg *, _nl_auto_nl_msg_fcn, nlmsg_free);

struct rtnl_link;
void rtnl_link_put(struct rtnl_link *);
#define _nl_auto_rtnl_link _nl_auto(_nl_auto_rtnl_link_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct rtnl_link *, _nl_auto_rtnl_link_fcn, rtnl_link_put);

struct rtnl_route;
void rtnl_route_put(struct rtnl_route *);
#define _nl_auto_rtnl_route _nl_auto(_nl_auto_rtnl_route_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct rtnl_route *, _nl_auto_rtnl_route_fcn, rtnl_route_put);

struct rtnl_mdb;
void rtnl_mdb_put(struct rtnl_mdb *);
#define _nl_auto_rtnl_mdb _nl_auto(_nl_auto_rtnl_mdb_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct rtnl_mdb *, _nl_auto_rtnl_mdb_fcn, rtnl_mdb_put);

struct rtnl_nexthop;
void rtnl_route_nh_free(struct rtnl_nexthop *);
#define _nl_auto_rtnl_nexthop _nl_auto(_nl_auto_rtnl_nexthop_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct rtnl_nexthop *, _nl_auto_rtnl_nexthop_fcn, rtnl_route_nh_free);

struct nl_cache;
void nl_cache_put(struct nl_cache *);
#define _nl_auto_nl_cache _nl_auto(_nl_auto_nl_cache_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct nl_cache *, _nl_auto_nl_cache_fcn, nl_cache_put);

struct rtnl_link_af_ops;
void rtnl_link_af_ops_put(struct rtnl_link_af_ops *);
#define _nl_auto_rtnl_link_af_ops _nl_auto(_nl_auto_rtnl_link_af_ops_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct rtnl_link_af_ops *, _nl_auto_rtnl_link_af_ops_fcn, rtnl_link_af_ops_put);

struct rtnl_act;
void rtnl_act_put(struct rtnl_act *);
#define _nl_auto_rtnl_act _nl_auto(_nl_auto_rtnl_act_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct rtnl_act *, _nl_auto_rtnl_act_fcn, rtnl_act_put);

struct rtnl_ematch_tree;
void rtnl_ematch_tree_free(struct rtnl_ematch_tree *);
#define _nl_auto_rtnl_ematch_tree _nl_auto(_nl_auto_rtnl_ematch_tree_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct rtnl_ematch_tree *, _nl_auto_rtnl_ematch_tree_fcn, rtnl_ematch_tree_free);

struct rtnl_cls;
void rtnl_cls_put(struct rtnl_cls *);
#define _nl_auto_rtnl_cls _nl_auto(_nl_auto_rtnl_cls_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct rtnl_cls *, _nl_auto_rtnl_cls_fcn, rtnl_cls_put);

struct nl_sock;
void nl_socket_free(struct nl_sock *);
#define _nl_auto_nl_socket _nl_auto(_nl_auto_nl_socket_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct nl_sock *, _nl_auto_nl_socket_fcn, nl_socket_free);

#endif /* NETLINK_NL_AUTO_H_ */
