/*
 * netlink/inetdiag/inetdiagnl.h		Inetdiag Netlink
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2013 Sassano Systems LLC <joe@sassanosystems.com>
 */

#ifndef NETLINK_INETDIAGNL_H_
#define NETLINK_INETDIAGNL_H_

#include <netlink/netlink.h>
#include <netinet/tcp.h>
#include <linux/inet_diag.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	INETDIAG_SS_UNKNOWN,
	INETDIAG_SS_ESTABLISHED,
	INETDIAG_SS_SYN_SENT,
	INETDIAG_SS_SYN_RECV,
	INETDIAG_SS_FIN_WAIT1,
	INETDIAG_SS_FIN_WAIT2,
	INETDIAG_SS_TIME_WAIT,
	INETDIAG_SS_CLOSE,
	INETDIAG_SS_CLOSE_WAIT,
	INETDIAG_SS_LAST_ACK,
	INETDIAG_SS_LISTEN,
	INETDIAG_SS_CLOSING,
	INETDIAG_SS_MAX
};

#define INETDIAG_SS_ALL ((1<<INETDIAG_SS_MAX)-1)

extern int		inetdiagnl_connect(struct nl_sock *);
extern int		inetdiagnl_send_simple(struct nl_sock *, uint8_t, uint8_t,
					 int, uint8_t, uint16_t);

extern uint8_t		inetdiagnl_family(struct nlmsghdr *nlh);
extern uint8_t		inetdiagnl_state(struct nlmsghdr *nlh);
extern uint8_t		inetdiagnl_timer(struct nlmsghdr *nlh);
extern uint8_t		inetdiagnl_retrans(struct nlmsghdr *nlh);
extern uint32_t		inetdiagnl_expires(struct nlmsghdr *nlh);
extern uint32_t		inetdiagnl_rqueue(struct nlmsghdr *nlh);
extern uint32_t		inetdiagnl_wqueue(struct nlmsghdr *nlh);
extern uint32_t		inetdiagnl_uid(struct nlmsghdr *nlh);
extern uint32_t		inetdiagnl_inode(struct nlmsghdr *nlh);
extern uint16_t		inetdiagnl_sport(struct nlmsghdr *nlh);
extern uint16_t		inetdiagnl_dport(struct nlmsghdr *nlh);
extern uint32_t		inetdiagnl_if(struct nlmsghdr *nlh);
extern struct nl_addr *	inetdiagnl_saddr(struct nlmsghdr *nlh);
extern struct nl_addr *	inetdiagnl_daddr(struct nlmsghdr *nlh);
extern uint32_t		inetdiagnl_states(struct nlmsghdr *nlh);
extern uint32_t		inetdiagnl_dbs(struct nlmsghdr *nlh);

#ifdef __cplusplus
}
#endif

#endif
