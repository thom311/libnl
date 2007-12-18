/*
 * lib/socket.c		Netlink Socket Handle
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup nl
 * @defgroup socket Socket
 * @brief Handle representing a netlink socket.
 *
 * The socket is represented in a structure called the netlink handle,
 * besides the socket, it stores various settings and values related
 * to the socket. Every socket handle has a mandatory association with
 * a set of callbacks which can be used to modify the behaviour when
 * sending/receiving data from the socket.
 *
 * @par Socket Attributes
 * - \b Local \b Port: The local port is a netlink port identifying the
 *   local endpoint. It is used as source address for outgoing messages
 *   and will be addressed in replies. It must therefore be unique among
 *   all userspace applications. When the socket handle is allocated, a
 *   unique port number is generated automatically in the form of 22 bits
 *   Process Identifier + 10 bits Arbitary Number. Therefore the library
 *   is capable of generating 1024 unique local port numbers for every
 *   process. If more sockets are required, the application has to manage
 *   port numbers itself using nl_socket_set_local_port().
 * - \b Group \b Subscriptions: A socket can subscribe to any number of
 *   multicast groups. It will then receive a copy of all messages sent
 *   to one of the groups. This method is mainly used for event notification.
 *   Prior to kernel 2.6.14, the group subscription was done via bitmask
 *   which limited to a total number of groups of 32. With 2.6.14 a new
 *   method was added based on continous identifiers which supports an
 *   arbitary number of groups. Both methods are supported, see
 *   nl_join_groups() respectively nl_socket_add_membership() and
 *   nl_socket_drop_membership().
 * - \b Peer \b Port: The peer port is a netlink port identifying the
 *   peer's endpoint. If no peer port is specified, the kernel will try to
 *   autobind to a socket of the specified netlink family automatically.
 *   This is very common as typically only one listening socket exists
 *   on the kernel side. The peer port can be modified using
 *   nl_socket_set_peer_port().
 * - \b Peer \b Groups:
 * - \b File \b Descriptor: The file descriptor of the socket, it can be
 *   accessed via nl_socket_get_fd() to change socket options or monitor
 *   activity using poll()/select().
 * - \b Protocol: Once connected, the socket is bound to stick to one
 *   netlink family. This field is invisible, it is maintained automatically.
 *   (See nl_connect())
 * - \b Next \b Sequence \b Number: Next available sequence number to be used
 *   for the next message being sent out. (Initial value: UNIX time when the
 *   socket was allocated.) Sequence numbers can be used via
 *   nl_socket_use_seq().
 * - \b Expected \b Sequence \b Number: Expected sequence number in the next
 *   message received from the socket. (Initial value: Equal to next sequence
 *   number.)
 * - \b Callbacks \b Configuration:
 *
 * @par 1) Creating the netlink handle
 * @code
 * struct nl_handle *handle;
 *
 * // Allocate and initialize a new netlink handle
 * handle = nl_handle_alloc();
 *
 * // Use nl_socket_get_fd() to fetch the file description, for example to
 * // put a socket into non-blocking i/o mode.
 * fcntl(nl_socket_get_fd(handle), F_SETFL, O_NONBLOCK);
 * @endcode
 *
 * @par 2) Group Subscriptions
 * @code
 * // Event notifications are typically sent to multicast addresses which
 * // represented by groups. Join a group to f.e. receive link notifications.
 * nl_socket_add_membership(handle, RTNLGRP_LINK);
 * @endcode
 *
 * @par 6) Cleaning up
 * @code
 * // Finally destroy the netlink handle
 * nl_handle_destroy(handle);
 * @endcode
 * 
 * @{
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/handlers.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

static int default_cb = NL_CB_DEFAULT;

static void __init init_default_cb(void)
{
	char *nlcb;

	if ((nlcb = getenv("NLCB"))) {
		if (!strcasecmp(nlcb, "default"))
			default_cb = NL_CB_DEFAULT;
		else if (!strcasecmp(nlcb, "verbose"))
			default_cb = NL_CB_VERBOSE;
		else if (!strcasecmp(nlcb, "debug"))
			default_cb = NL_CB_DEBUG;
		else {
			fprintf(stderr, "Unknown value for NLCB, valid values: "
				"{default | verbose | debug}\n");
		}
	}
}

static uint32_t used_ports_map[32];

static uint32_t generate_local_port(void)
{
	int i, n;
	uint32_t pid = getpid() & 0x3FFFFF;

	for (i = 0; i < 32; i++) {
		if (used_ports_map[i] == 0xFFFFFFFF)
			continue;

		for (n = 0; n < 32; n++) {
			if (1UL & (used_ports_map[i] >> n))
				continue;

			used_ports_map[i] |= (1UL << n);
			n += (i * 32);

			/* PID_MAX_LIMIT is currently at 2^22, leaving 10 bit
			 * to, i.e. 1024 unique ports per application. */
			return pid + (n << 22);

		}
	}

	/* Out of sockets in our own PID namespace, what to do? FIXME */
	return UINT_MAX;
}

static void release_local_port(uint32_t port)
{
	int nr;

	if (port == UINT_MAX)
		return;
	
	nr = port >> 22;
	used_ports_map[nr / 32] &= ~((nr % 32) + 1);
}

/**
 * @name Allocation
 * @{
 */

static struct nl_handle *__alloc_handle(struct nl_cb *cb)
{
	struct nl_handle *handle;

	handle = calloc(1, sizeof(*handle));
	if (!handle) {
		nl_errno(ENOMEM);
		return NULL;
	}

	handle->h_fd = -1;
	handle->h_cb = cb;
	handle->h_local.nl_family = AF_NETLINK;
	handle->h_peer.nl_family = AF_NETLINK;
	handle->h_seq_expect = handle->h_seq_next = time(0);
	handle->h_local.nl_pid = generate_local_port();
	if (handle->h_local.nl_pid == UINT_MAX) {
		nl_handle_destroy(handle);
		nl_error(ENOBUFS, "Out of local ports");
		return NULL;
	}

	return handle;
}

/**
 * Allocate new netlink socket handle.
 *
 * @return Newly allocated netlink socket handle or NULL.
 */
struct nl_handle *nl_handle_alloc(void)
{
	struct nl_cb *cb;
	
	cb = nl_cb_alloc(default_cb);
	if (!cb) {
		nl_errno(ENOMEM);
		return NULL;
	}

	return __alloc_handle(cb);
}

/**
 * Allocate new socket handle with custom callbacks
 * @arg cb		Callback handler
 *
 * The reference to the callback handler is taken into account
 * automatically, it is released again upon calling nl_handle_destroy().
 *
 *@return Newly allocted socket handle or NULL.
 */
struct nl_handle *nl_handle_alloc_cb(struct nl_cb *cb)
{
	if (cb == NULL)
		BUG();

	return __alloc_handle(nl_cb_get(cb));
}

/**
 * Destroy netlink handle.
 * @arg handle		Netlink handle.
 */
void nl_handle_destroy(struct nl_handle *handle)
{
	if (!handle)
		return;

	if (handle->h_fd >= 0)
		close(handle->h_fd);

	if (!(handle->h_flags & NL_OWN_PORT))
		release_local_port(handle->h_local.nl_pid);

	nl_cb_put(handle->h_cb);
	free(handle);
}

/** @} */

/**
 * @name Sequence Numbers
 * @{
 */

static int noop_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}


/**
 * Disable sequence number checking.
 * @arg handle		Netlink handle.
 *
 * Disables checking of sequence numbers on the netlink handle. This is
 * required to allow messages to be processed which were not requested by
 * a preceding request message, e.g. netlink events.
 *
 * @note This function modifies the NL_CB_SEQ_CHECK configuration in
 * the callback handle associated with the socket.
 */
void nl_disable_sequence_check(struct nl_handle *handle)
{
	nl_cb_set(handle->h_cb, NL_CB_SEQ_CHECK,
		  NL_CB_CUSTOM, noop_seq_check, NULL);
}

/**
 * Use next sequence number
 * @arg handle		Netlink handle
 *
 * Uses the next available sequence number and increases the counter
 * by one for subsequent calls.
 *
 * @return Unique serial sequence number
 */
unsigned int nl_socket_use_seq(struct nl_handle *handle)
{
	return handle->h_seq_next++;
}

/** @} */

/**
 * @name Source Idenficiation
 * @{
 */

uint32_t nl_socket_get_local_port(struct nl_handle *handle)
{
	return handle->h_local.nl_pid;
}

/**
 * Set local port of socket
 * @arg handle		Netlink handle
 * @arg port		Local port identifier
 *
 * Assigns a local port identifier to the socket. If port is 0
 * a unique port identifier will be generated automatically.
 */
void nl_socket_set_local_port(struct nl_handle *handle, uint32_t port)
{
	if (port == 0) {
		port = generate_local_port(); 
		handle->h_flags &= ~NL_OWN_PORT;
	} else  {
		if (!(handle->h_flags & NL_OWN_PORT))
			release_local_port(handle->h_local.nl_pid);
		handle->h_flags |= NL_OWN_PORT;
	}

	handle->h_local.nl_pid = port;
}

/** @} */

/**
 * @name Group Subscriptions
 * @{
 */

/**
 * Join a group
 * @arg handle		Netlink handle
 * @arg group		Group identifier
 *
 * Joins the specified group using the modern socket option which
 * is available since kernel version 2.6.14. It allows joining an
 * almost arbitary number of groups without limitation.
 *
 * Make sure to use the correct group definitions as the older
 * bitmask definitions for nl_join_groups() are likely to still
 * be present for backward compatibility reasons.
 *
 * @return 0 on sucess or a negative error code.
 */
int nl_socket_add_membership(struct nl_handle *handle, int group)
{
	int err;

	if (handle->h_fd == -1)
		return nl_error(EBADFD, "Socket not connected");

	err = setsockopt(handle->h_fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
			 &group, sizeof(group));
	if (err < 0)
		return nl_error(errno, "setsockopt(NETLINK_ADD_MEMBERSHIP) "
				       "failed");

	return 0;
}

/**
 * Leave a group
 * @arg handle		Netlink handle
 * @arg group		Group identifier
 *
 * Leaves the specified group using the modern socket option
 * which is available since kernel version 2.6.14.
 *
 * @see nl_socket_add_membership
 * @return 0 on success or a negative error code.
 */
int nl_socket_drop_membership(struct nl_handle *handle, int group)
{
	int err;

	if (handle->h_fd == -1)
		return nl_error(EBADFD, "Socket not connected");

	err = setsockopt(handle->h_fd, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
			 &group, sizeof(group));
	if (err < 0)
		return nl_error(errno, "setsockopt(NETLINK_DROP_MEMBERSHIP) "
				       "failed");

	return 0;
}

/**
 * Join multicast groups (deprecated)
 * @arg handle		Netlink handle.
 * @arg groups		Bitmask of groups to join.
 *
 * This function defines the old way of joining multicast group which
 * has to be done prior to calling nl_connect(). It works on any kernel
 * version but is very limited as only 32 groups can be joined.
 */
void nl_join_groups(struct nl_handle *handle, int groups)
{
	handle->h_local.nl_groups |= groups;
}


/** @} */

/**
 * @name Peer Identfication
 * @{
 */

uint32_t nl_socket_get_peer_port(struct nl_handle *handle)
{
	return handle->h_peer.nl_pid;
}

void nl_socket_set_peer_port(struct nl_handle *handle, uint32_t port)
{
	handle->h_peer.nl_pid = port;
}

/** @} */

/**
 * @name File Descriptor
 * @{
 */

int nl_socket_get_fd(struct nl_handle *handle)
{
	return handle->h_fd;
}

/**
 * Set file descriptor of socket handle to non-blocking state
 * @arg handle		Netlink socket
 *
 * @return 0 on success or a negative error code.
 */
int nl_socket_set_nonblocking(struct nl_handle *handle)
{
	if (handle->h_fd == -1)
		return nl_error(EBADFD, "Socket not connected");

	if (fcntl(handle->h_fd, F_SETFL, O_NONBLOCK) < 0)
		return nl_error(errno, "fcntl(F_SETFL, O_NONBLOCK) failed");

	return 0;
}

/**
 * Enable use of MSG_PEEK when reading from socket
 * @arg handle		Netlink socket
 */
void nl_socket_enable_msg_peek(struct nl_handle *handle)
{
	handle->h_flags |= NL_MSG_PEEK;
}

/**
 * Disable use of MSG_PEEK when reading from socket
 * @arg handle		Netlink socket
 */
void nl_socket_disable_msg_peek(struct nl_handle *handle)
{
	handle->h_flags &= ~NL_MSG_PEEK;
}

/** @} */

/**
 * @name Callback Handler
 * @{
 */

struct nl_cb *nl_socket_get_cb(struct nl_handle *handle)
{
	return nl_cb_get(handle->h_cb);
}

void nl_socket_set_cb(struct nl_handle *handle, struct nl_cb *cb)
{
	nl_cb_put(handle->h_cb);
	handle->h_cb = nl_cb_get(cb);
}

/**
 * Modify the callback handler associated to the socket
 * @arg handle		netlink handle
 * @arg type		which type callback to set
 * @arg kind		kind of callback
 * @arg func		callback function
 * @arg arg		argument to be passwd to callback function
 *
 * @see nl_cb_set
 */
int nl_socket_modify_cb(struct nl_handle *handle, enum nl_cb_type type,
			enum nl_cb_kind kind, nl_recvmsg_msg_cb_t func,
			void *arg)
{
	return nl_cb_set(handle->h_cb, type, kind, func, arg);
}

/** @} */

/**
 * @name Utilities
 * @{
 */

/**
 * Set socket buffer size of netlink handle.
 * @arg handle		Netlink handle.
 * @arg rxbuf		New receive socket buffer size in bytes.
 * @arg txbuf		New transmit socket buffer size in bytes.
 *
 * Sets the socket buffer size of a netlink handle to the specified
 * values \c rxbuf and \c txbuf. Providing a value of \c 0 assumes a
 * good default value.
 *
 * @note It is not required to call this function prior to nl_connect().
 * @return 0 on sucess or a negative error code.
 */
int nl_set_buffer_size(struct nl_handle *handle, int rxbuf, int txbuf)
{
	int err;

	if (rxbuf <= 0)
		rxbuf = 32768;

	if (txbuf <= 0)
		txbuf = 32768;

	if (handle->h_fd == -1)
		return nl_error(EBADFD, "Socket not connected");
	
	err = setsockopt(handle->h_fd, SOL_SOCKET, SO_SNDBUF,
			 &txbuf, sizeof(txbuf));
	if (err < 0)
		return nl_error(errno, "setsockopt(SO_SNDBUF) failed");

	err = setsockopt(handle->h_fd, SOL_SOCKET, SO_RCVBUF,
			 &rxbuf, sizeof(rxbuf));
	if (err < 0)
		return nl_error(errno, "setsockopt(SO_RCVBUF) failed");

	handle->h_flags |= NL_SOCK_BUFSIZE_SET;

	return 0;
}

/**
 * Enable/disable credential passing on netlink handle.
 * @arg handle		Netlink handle
 * @arg state		New state (0 - disabled, 1 - enabled)
 *
 * @return 0 on success or a negative error code
 */
int nl_set_passcred(struct nl_handle *handle, int state)
{
	int err;

	if (handle->h_fd == -1)
		return nl_error(EBADFD, "Socket not connected");

	err = setsockopt(handle->h_fd, SOL_SOCKET, SO_PASSCRED,
			 &state, sizeof(state));
	if (err < 0)
		return nl_error(errno, "setsockopt(SO_PASSCRED) failed");

	if (state)
		handle->h_flags |= NL_SOCK_PASSCRED;
	else
		handle->h_flags &= ~NL_SOCK_PASSCRED;

	return 0;
}

/**
 * Enable/disable receival of additional packet information
 * @arg handle		Netlink handle
 * @arg state		New state (0 - disabled, 1 - enabled)
 *
 * @return 0 on success or a negative error code
 */
int nl_socket_recv_pktinfo(struct nl_handle *handle, int state)
{
	int err;

	if (handle->h_fd == -1)
		return nl_error(EBADFD, "Socket not connected");

	err = setsockopt(handle->h_fd, SOL_NETLINK, NETLINK_PKTINFO,
			 &state, sizeof(state));
	if (err < 0)
		return nl_error(errno, "setsockopt(NETLINK_PKTINFO) failed");

	return 0;
}

/** @} */

/** @} */
