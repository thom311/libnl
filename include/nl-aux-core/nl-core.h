/* SPDX-License-Identifier: LGPL-2.1-only */

#ifndef NETLINK_NL_AUTO_H_
#define NETLINK_NL_AUTO_H_

#include "base/nl-base-utils.h"

struct nl_addr;
void nl_addr_put(struct nl_addr *);
#define _nl_auto_nl_addr _nl_auto(_nl_auto_nl_addr_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct nl_addr *, _nl_auto_nl_addr_fcn, nl_addr_put);

struct nl_data;
void nl_data_free(struct nl_data *data);
#define _nl_auto_nl_data _nl_auto(_nl_auto_nl_data_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct nl_data *, _nl_auto_nl_data_fcn,
			   nl_data_free);

struct nl_msg;
void nlmsg_free(struct nl_msg *);
#define _nl_auto_nl_msg _nl_auto(_nl_auto_nl_msg_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct nl_msg *, _nl_auto_nl_msg_fcn, nlmsg_free);

struct nl_cache;
void nl_cache_put(struct nl_cache *);
#define _nl_auto_nl_cache _nl_auto(_nl_auto_nl_cache_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct nl_cache *, _nl_auto_nl_cache_fcn,
			   nl_cache_put);

struct nl_sock;
void nl_socket_free(struct nl_sock *);
#define _nl_auto_nl_socket _nl_auto(_nl_auto_nl_socket_fcn)
_NL_AUTO_DEFINE_FCN_TYPED0(struct nl_sock *, _nl_auto_nl_socket_fcn,
			   nl_socket_free);

#endif /* NETLINK_NL_AUTO_H_ */
