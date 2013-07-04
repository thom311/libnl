/* lib/inetdiag/inetdiag.c    Inet Diag Netlink
 *
 * Copyright (c) 2013 Sassano Systems LLC <joe@sassanosystems.com>
 */

/**
 * @defgroup  inetdiag Inet Diag library (libnl-inetdiag)
 */

#include <netlink-private/netlink.h>
#include <netlink/netlink.h>
#include <netlink/inetdiag/inetdiagnl.h>
#include <inttypes.h>

/**
 * @name Socket Creation
 * @{
 */

/**
 * Create and connect inetdiag netlink socket.
 * @arg sk    Netlink socket.
 *
 * Creates a NETLINK_INET_DIAG socket, binds the socket, and issues a connection
 * attemp.
 *
 * @see nl_connect()
 *
 * @return 0 on success or a negative error code.
 */
int inetdiagnl_connect(struct nl_sock *sk)
{
	return nl_connect(sk, NETLINK_INET_DIAG);
}

/**
 * Send trivial inetdiag netlink message
 * @arg sk		Netlink socket.
 * @arg subsys_id	inetdiagnetlink subsystem
 * @arg	type		inetdiagnetlink type
 * @arg flags		message flags
 * @arg	family		inetdiagnetlink	address family
 * @arg	sock_states	socket states to query
 *
 * @return Newly allocated netlink message or NULL.
 */
int inetdiagnl_send_simple(struct nl_sock *sk,
		int flags, uint8_t family, uint16_t sock_states)
{
  struct inet_diag_req req;

  memset(&req, 0, sizeof(req));

  flags |= NLM_F_ROOT;

  req.idiag_family = family;
  req.idiag_states = sock_states;

  return nl_send_simple(sk, TCPDIAG_GETSOCK, flags, &req, sizeof(req));
}

/** @} */


/** @name Message Parsing
 * @{
 */

uint8_t inetdiagnl_family(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return msg->idiag_family;
}

uint8_t inetdiagnl_state(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return msg->idiag_state;
}

uint8_t inetdiagnl_timer(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return msg->idiag_timer;
}

uint8_t inetdiagnl_retrans(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return msg->idiag_retrans;
}

uint32_t inetdiagnl_expires(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return msg->idiag_expires;
}

uint32_t inetdiagnl_rqueue(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return msg->idiag_wqueue;
}

uint32_t inetdiagnl_wqueue(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return msg->idiag_wqueue;
}

uint32_t inetdiagnl_uid(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return msg->idiag_uid;
}

uint32_t inetdiagnl_inode(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return msg->idiag_inode;
}

uint16_t inetdiagnl_sport(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return msg->id.idiag_sport;
}

uint16_t inetdiagnl_dport(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return msg->id.idiag_dport;
}

uint32_t inetdiagnl_if(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return msg->id.idiag_dport;
}

struct nl_addr *inetdiagnl_saddr(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return nl_addr_build(msg->idiag_family, msg->id.idiag_src,
		  sizeof(msg->id.idiag_src));
}

struct nl_addr *inetdiagnl_daddr(struct nlmsghdr *nlh)
{
  struct inet_diag_msg *msg = nlmsg_data(nlh);
  return nl_addr_build(msg->idiag_family, msg->id.idiag_dst,
		  sizeof(msg->id.idiag_dst));
}

/** @} */
