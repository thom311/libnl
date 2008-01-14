/*
 * lib/nl.c		Core Netlink Interface
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @defgroup nl Core Netlink API
 * @brief
 *
 * @par Receiving Semantics
 * @code
 *          nl_recvmsgs_default(socket)
 *                 |
 *                 | cb = nl_socket_get_cb(socket)
 *                 v
 *          nl_recvmsgs(socket, cb)
 *                 |           [Application provides nl_recvmsgs() replacement]
 *                 |- - - - - - - - - - - - - - - v
 *                 |                     cb->cb_recvmsgs_ow()
 *                 |
 *                 |               [Application provides nl_recv() replacement]
 * +-------------->|- - - - - - - - - - - - - - - v
 * |           nl_recv()                   cb->cb_recv_ow()
 * |  +----------->|<- - - - - - - - - - - - - - -+
 * |  |            v
 * |  |      Parse Message
 * |  |            |- - - - - - - - - - - - - - - v
 * |  |            |                         NL_CB_MSG_IN()
 * |  |            |<- - - - - - - - - - - - - - -+
 * |  |            |
 * |  |            |- - - - - - - - - - - - - - - v
 * |  |      Sequence Check                NL_CB_SEQ_CHECK()
 * |  |            |<- - - - - - - - - - - - - - -+
 * |  |            |
 * |  |            |- - - - - - - - - - - - - - - v  [ NLM_F_ACK is set ]
 * |  |            |                      NL_CB_SEND_ACK()
 * |  |            |<- - - - - - - - - - - - - - -+
 * |  |            |
 * |  |      +-----+------+--------------+----------------+--------------+
 * |  |      v            v              v                v              v
 * |  | Valid Message    ACK        NOOP Message  End of Multipart  Error Message
 * |  |      |            |              |                |              |
 * |  |      v            v              v                v              v
 * |  |NL_CB_VALID()  NL_CB_ACK()  NL_CB_SKIPPED()  NL_CB_FINISH()  cb->cb_err()
 * |  |      |            |              |                |              |
 * |  |      +------------+--------------+----------------+              v
 * |  |                                  |                           (FAILURE)
 * |  |                                  |  [Callback returned NL_SKIP]
 * |  |  [More messages to be parsed]    |<-----------
 * |  +----------------------------------|
 * |                                     |
 * |         [Multipart message]         |
 * +-------------------------------------|  [Callback returned NL_STOP]
 *                                       |<-----------
 *                                       v
 *                                   (SUCCESS)
 *
 *                          At any time:
 *                                Message Format Error
 *                                         |- - - - - - - - - - - - v
 *                                         v                  NL_CB_INVALID()
 *                                     (FAILURE)
 *
 *                                Message Overrun (Kernel Lost Data)
 *                                         |- - - - - - - - - - - - v
 *                                         v                  NL_CB_OVERRUN()
 *                                     (FAILURE)
 *
 *                                Callback returned negative error code
 *                                     (FAILURE)
 * @endcode
 *
 * @par Sending Semantics
 * @code
 *     nl_send_auto_complete()
 *             |
 *             | Automatically fill in PID and/or sequence number
 *             |
 *             |                   [Application provides nl_send() replacement]
 *             |- - - - - - - - - - - - - - - - - - - - v
 *             v                                 cb->cb_send_ow()
 *         nl_send()
 *             | Add destination address and credentials
 *             v
 *        nl_sendmsg()
 *             | Set source address
 *             |
 *             |- - - - - - - - - - - - - - - - - - - - v
 *             |                                 NL_CB_MSG_OUT()
 *             |<- - - - - - - - - - - - - - - - - - - -+
 *             v
 *         sendmsg()
 * @endcode
 *
 * @par 1) Connecting the socket
 * @code
 * // Bind and connect the socket to a protocol, NETLINK_ROUTE in this example.
 * nl_connect(handle, NETLINK_ROUTE);
 * @endcode
 *
 * @par 2) Sending data
 * @code
 * // The most rudimentary method is to use nl_sendto() simply pushing
 * // a piece of data to the other netlink peer. This method is not
 * // recommended.
 * const char buf[] = { 0x01, 0x02, 0x03, 0x04 };
 * nl_sendto(handle, buf, sizeof(buf));
 *
 * // A more comfortable interface is nl_send() taking a pointer to
 * // a netlink message.
 * struct nl_msg *msg = my_msg_builder();
 * nl_send(handle, nlmsg_hdr(msg));
 *
 * // nl_sendmsg() provides additional control over the sendmsg() message
 * // header in order to allow more specific addressing of multiple peers etc.
 * struct msghdr hdr = { ... };
 * nl_sendmsg(handle, nlmsg_hdr(msg), &hdr);
 *
 * // You're probably too lazy to fill out the netlink pid, sequence number
 * // and message flags all the time. nl_send_auto_complete() automatically
 * // extends your message header as needed with an appropriate sequence
 * // number, the netlink pid stored in the netlink handle and the message
 * // flags NLM_F_REQUEST and NLM_F_ACK
 * nl_send_auto_complete(handle, nlmsg_hdr(msg));
 *
 * // Simple protocols don't require the complex message construction interface
 * // and may favour nl_send_simple() to easly send a bunch of payload
 * // encapsulated in a netlink message header.
 * nl_send_simple(handle, MY_MSG_TYPE, 0, buf, sizeof(buf));
 * @endcode
 *
 * @par 3) Receiving data
 * @code
 * // nl_recv() receives a single message allocating a buffer for the message
 * // content and gives back the pointer to you.
 * struct sockaddr_nl peer;
 * unsigned char *msg;
 * nl_recv(handle, &peer, &msg);
 *
 * // nl_recvmsgs() receives a bunch of messages until the callback system
 * // orders it to state, usually after receving a compolete multi part
 * // message series.
 * nl_recvmsgs(handle, my_callback_configuration);
 *
 * // nl_recvmsgs_default() acts just like nl_recvmsg() but uses the callback
 * // configuration stored in the handle.
 * nl_recvmsgs_default(handle);
 *
 * // In case you want to wait for the ACK to be recieved that you requested
 * // with your latest message, you can call nl_wait_for_ack()
 * nl_wait_for_ack(handle);
 * @endcode
 *
 * @par 4) Closing
 * @code
 * // Close the socket first to release kernel memory
 * nl_close(handle);
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

/**
 * @name Connection Management
 * @{
 */

/**
 * Create and connect netlink socket.
 * @arg handle		Netlink handle.
 * @arg protocol	Netlink protocol to use.
 *
 * Creates a netlink socket using the specified protocol, binds the socket
 * and issues a connection attempt.
 *
 * @return 0 on success or a negative error code.
 */
int nl_connect(struct nl_handle *handle, int protocol)
{
	int err;
	socklen_t addrlen;

	handle->h_fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (handle->h_fd < 0) {
		err = nl_error(1, "socket(AF_NETLINK, ...) failed");
		goto errout;
	}

	if (!(handle->h_flags & NL_SOCK_BUFSIZE_SET)) {
		err = nl_set_buffer_size(handle, 0, 0);
		if (err < 0)
			goto errout;
	}

	err = bind(handle->h_fd, (struct sockaddr*) &handle->h_local,
		   sizeof(handle->h_local));
	if (err < 0) {
		err = nl_error(1, "bind() failed");
		goto errout;
	}

	addrlen = sizeof(handle->h_local);
	err = getsockname(handle->h_fd, (struct sockaddr *) &handle->h_local,
			  &addrlen);
	if (err < 0) {
		err = nl_error(1, "getsockname failed");
		goto errout;
	}

	if (addrlen != sizeof(handle->h_local)) {
		err = nl_error(EADDRNOTAVAIL, "Invalid address length");
		goto errout;
	}

	if (handle->h_local.nl_family != AF_NETLINK) {
		err = nl_error(EPFNOSUPPORT, "Address format not supported");
		goto errout;
	}

	handle->h_proto = protocol;

	return 0;
errout:
	close(handle->h_fd);
	handle->h_fd = -1;

	return err;
}

/**
 * Close/Disconnect netlink socket.
 * @arg handle		Netlink handle
 */
void nl_close(struct nl_handle *handle)
{
	if (handle->h_fd >= 0) {
		close(handle->h_fd);
		handle->h_fd = -1;
	}

	handle->h_proto = 0;
}

/** @} */

/**
 * @name Send
 * @{
 */

/**
 * Send raw data over netlink socket.
 * @arg handle		Netlink handle.
 * @arg buf		Data buffer.
 * @arg size		Size of data buffer.
 * @return Number of characters written on success or a negative error code.
 */
int nl_sendto(struct nl_handle *handle, void *buf, size_t size)
{
	int ret;

	ret = sendto(handle->h_fd, buf, size, 0, (struct sockaddr *)
		     &handle->h_peer, sizeof(handle->h_peer));
	if (ret < 0)
		return nl_errno(errno);

	return ret;
}

/**
 * Send netlink message with control over sendmsg() message header.
 * @arg handle		Netlink handle.
 * @arg msg		Netlink message to be sent.
 * @arg hdr		Sendmsg() message header.
 * @return Number of characters sent on sucess or a negative error code.
 */
int nl_sendmsg(struct nl_handle *handle, struct nl_msg *msg, struct msghdr *hdr)
{
	struct nl_cb *cb;
	int ret;

	struct iovec iov = {
		.iov_base = (void *) nlmsg_hdr(msg),
		.iov_len = nlmsg_hdr(msg)->nlmsg_len,
	};

	hdr->msg_iov = &iov;
	hdr->msg_iovlen = 1;

	nlmsg_set_src(msg, &handle->h_local);

	cb = handle->h_cb;
	if (cb->cb_set[NL_CB_MSG_OUT])
		if (nl_cb_call(cb, NL_CB_MSG_OUT, msg) != NL_OK)
			return 0;

	ret = sendmsg(handle->h_fd, hdr, 0);
	if (ret < 0)
		return nl_errno(errno);

	return ret;
}


/**
 * Send netlink message.
 * @arg handle		Netlink handle
 * @arg msg		Netlink message to be sent.
 * @see nl_sendmsg()
 * @return Number of characters sent on success or a negative error code.
 */
int nl_send(struct nl_handle *handle, struct nl_msg *msg)
{
	struct sockaddr_nl *dst;
	struct ucred *creds;
	
	struct msghdr hdr = {
		.msg_name = (void *) &handle->h_peer,
		.msg_namelen = sizeof(struct sockaddr_nl),
	};

	/* Overwrite destination if specified in the message itself, defaults
	 * to the peer address of the handle.
	 */
	dst = nlmsg_get_dst(msg);
	if (dst->nl_family == AF_NETLINK)
		hdr.msg_name = dst;

	/* Add credentials if present. */
	creds = nlmsg_get_creds(msg);
	if (creds != NULL) {
		char buf[CMSG_SPACE(sizeof(struct ucred))];
		struct cmsghdr *cmsg;

		hdr.msg_control = buf;
		hdr.msg_controllen = sizeof(buf);

		cmsg = CMSG_FIRSTHDR(&hdr);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_CREDENTIALS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
		memcpy(CMSG_DATA(cmsg), creds, sizeof(struct ucred));
	}

	return nl_sendmsg(handle, msg, &hdr);
}

/**
 * Send netlink message and check & extend header values as needed.
 * @arg handle		Netlink handle.
 * @arg msg		Netlink message to be sent.
 *
 * Checks the netlink message \c nlh for completness and extends it
 * as required before sending it out. Checked fields include pid,
 * sequence nr, and flags.
 *
 * @see nl_send()
 * @return Number of characters sent or a negative error code.
 */
int nl_send_auto_complete(struct nl_handle *handle, struct nl_msg *msg)
{
	struct nlmsghdr *nlh;
	struct nl_cb *cb = handle->h_cb;

	nlh = nlmsg_hdr(msg);
	if (nlh->nlmsg_pid == 0)
		nlh->nlmsg_pid = handle->h_local.nl_pid;

	if (nlh->nlmsg_seq == 0)
		nlh->nlmsg_seq = handle->h_seq_next++;

	if (msg->nm_protocol == -1)
		msg->nm_protocol = handle->h_proto;
	
	nlh->nlmsg_flags |= (NLM_F_REQUEST | NLM_F_ACK);

	if (cb->cb_send_ow)
		return cb->cb_send_ow(handle, msg);
	else
		return nl_send(handle, msg);
}

/**
 * Send simple netlink message using nl_send_auto_complete()
 * @arg handle		Netlink handle.
 * @arg type		Netlink message type.
 * @arg flags		Netlink message flags.
 * @arg buf		Data buffer.
 * @arg size		Size of data buffer.
 *
 * Builds a netlink message with the specified type and flags and
 * appends the specified data as payload to the message.
 *
 * @see nl_send_auto_complete()
 * @return Number of characters sent on success or a negative error code.
 */
int nl_send_simple(struct nl_handle *handle, int type, int flags, void *buf,
		   size_t size)
{
	int err;
	struct nl_msg *msg;

	msg = nlmsg_alloc_simple(type, flags);
	if (!msg)
		return nl_errno(ENOMEM);

	if (buf && size) {
		err = nlmsg_append(msg, buf, size, NLMSG_ALIGNTO);
		if (err < 0)
			goto errout;
	}
	

	err = nl_send_auto_complete(handle, msg);
errout:
	nlmsg_free(msg);

	return err;
}

/** @} */

/**
 * @name Receive
 * @{
 */

/**
 * Receive data from netlink socket
 * @arg handle		Netlink handle.
 * @arg nla		Destination pointer for peer's netlink address.
 * @arg buf		Destination pointer for message content.
 * @arg creds		Destination pointer for credentials.
 *
 * Receives a netlink message, allocates a buffer in \c *buf and
 * stores the message content. The peer's netlink address is stored
 * in \c *nla. The caller is responsible for freeing the buffer allocated
 * in \c *buf if a positive value is returned.  Interruped system calls
 * are handled by repeating the read. The input buffer size is determined
 * by peeking before the actual read is done.
 *
 * A non-blocking sockets causes the function to return immediately with
 * a return value of 0 if no data is available.
 *
 * @return Number of octets read, 0 on EOF or a negative error code.
 */
int nl_recv(struct nl_handle *handle, struct sockaddr_nl *nla,
	    unsigned char **buf, struct ucred **creds)
{
	int n;
	int flags = 0;
	static int page_size = 0;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = (void *) nla,
		.msg_namelen = sizeof(struct sockaddr_nl),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};
	struct cmsghdr *cmsg;

	if (handle->h_flags & NL_MSG_PEEK)
		flags |= MSG_PEEK;

	if (page_size == 0)
		page_size = getpagesize();

	iov.iov_len = page_size;
	iov.iov_base = *buf = calloc(1, iov.iov_len);

	if (handle->h_flags & NL_SOCK_PASSCRED) {
		msg.msg_controllen = CMSG_SPACE(sizeof(struct ucred));
		msg.msg_control = calloc(1, msg.msg_controllen);
	}
retry:

	n = recvmsg(handle->h_fd, &msg, flags);
	if (!n)
		goto abort;
	else if (n < 0) {
		if (errno == EINTR) {
			NL_DBG(3, "recvmsg() returned EINTR, retrying\n");
			goto retry;
		} else if (errno == EAGAIN) {
			NL_DBG(3, "recvmsg() returned EAGAIN, aborting\n");
			goto abort;
		} else {
			free(msg.msg_control);
			free(*buf);
			return nl_error(errno, "recvmsg failed");
		}
	}

	if (iov.iov_len < n ||
	    msg.msg_flags & MSG_TRUNC) {
		/* Provided buffer is not long enough, enlarge it
		 * and try again. */
		iov.iov_len *= 2;
		iov.iov_base = *buf = realloc(*buf, iov.iov_len);
		goto retry;
	} else if (msg.msg_flags & MSG_CTRUNC) {
		msg.msg_controllen *= 2;
		msg.msg_control = realloc(msg.msg_control, msg.msg_controllen);
		goto retry;
	} else if (flags != 0) {
		/* Buffer is big enough, do the actual reading */
		flags = 0;
		goto retry;
	}

	if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
		free(msg.msg_control);
		free(*buf);
		return nl_error(EADDRNOTAVAIL, "socket address size mismatch");
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_CREDENTIALS) {
			*creds = calloc(1, sizeof(struct ucred));
			memcpy(*creds, CMSG_DATA(cmsg), sizeof(struct ucred));
			break;
		}
	}

	free(msg.msg_control);
	return n;

abort:
	free(msg.msg_control);
	free(*buf);
	return 0;
}

#define NL_CB_CALL(cb, type, msg) \
do { \
	err = nl_cb_call(cb, type, msg); \
	switch (err) { \
	case NL_OK: \
		err = 0; \
		break; \
	case NL_SKIP: \
		goto skip; \
	case NL_STOP: \
		goto stop; \
	default: \
		goto out; \
	} \
} while (0)

static int recvmsgs(struct nl_handle *handle, struct nl_cb *cb)
{
	int n, err = 0, multipart = 0;
	unsigned char *buf = NULL;
	struct nlmsghdr *hdr;
	struct sockaddr_nl nla = {0};
	struct nl_msg *msg = NULL;
	struct ucred *creds = NULL;

continue_reading:
	NL_DBG(3, "Attempting to read from %p\n", handle);
	if (cb->cb_recv_ow)
		n = cb->cb_recv_ow(handle, &nla, &buf, &creds);
	else
		n = nl_recv(handle, &nla, &buf, &creds);

	if (n <= 0)
		return n;

	NL_DBG(3, "recvmsgs(%p): Read %d bytes\n", handle, n);

	hdr = (struct nlmsghdr *) buf;
	while (nlmsg_ok(hdr, n)) {
		NL_DBG(3, "recgmsgs(%p): Processing valid message...\n",
		       handle);

		nlmsg_free(msg);
		msg = nlmsg_convert(hdr);
		if (!msg) {
			err = nl_errno(ENOMEM);
			goto out;
		}

		nlmsg_set_proto(msg, handle->h_proto);
		nlmsg_set_src(msg, &nla);
		if (creds)
			nlmsg_set_creds(msg, creds);

		/* Raw callback is the first, it gives the most control
		 * to the user and he can do his very own parsing. */
		if (cb->cb_set[NL_CB_MSG_IN])
			NL_CB_CALL(cb, NL_CB_MSG_IN, msg);

		/* Sequence number checking. The check may be done by
		 * the user, otherwise a very simple check is applied
		 * enforcing strict ordering */
		if (cb->cb_set[NL_CB_SEQ_CHECK])
			NL_CB_CALL(cb, NL_CB_SEQ_CHECK, msg);
		else if (hdr->nlmsg_seq != handle->h_seq_expect) {
			if (cb->cb_set[NL_CB_INVALID])
				NL_CB_CALL(cb, NL_CB_INVALID, msg);
			else {
				err = nl_error(EINVAL,
					"Sequence number mismatch");
				goto out;
			}
		}

		if (hdr->nlmsg_type == NLMSG_DONE ||
		    hdr->nlmsg_type == NLMSG_ERROR ||
		    hdr->nlmsg_type == NLMSG_NOOP ||
		    hdr->nlmsg_type == NLMSG_OVERRUN) {
			/* We can't check for !NLM_F_MULTI since some netlink
			 * users in the kernel are broken. */
			handle->h_seq_expect++;
			NL_DBG(3, "recvmsgs(%p): Increased expected " \
			       "sequence number to %d\n",
			       handle, handle->h_seq_expect);
		}

		if (hdr->nlmsg_flags & NLM_F_MULTI)
			multipart = 1;
	
		/* Other side wishes to see an ack for this message */
		if (hdr->nlmsg_flags & NLM_F_ACK) {
			if (cb->cb_set[NL_CB_SEND_ACK])
				NL_CB_CALL(cb, NL_CB_SEND_ACK, msg);
			else {
				/* FIXME: implement */
			}
		}

		/* messages terminates a multpart message, this is
		 * usually the end of a message and therefore we slip
		 * out of the loop by default. the user may overrule
		 * this action by skipping this packet. */
		if (hdr->nlmsg_type == NLMSG_DONE) {
			multipart = 0;
			if (cb->cb_set[NL_CB_FINISH])
				NL_CB_CALL(cb, NL_CB_FINISH, msg);
		}

		/* Message to be ignored, the default action is to
		 * skip this message if no callback is specified. The
		 * user may overrule this action by returning
		 * NL_PROCEED. */
		else if (hdr->nlmsg_type == NLMSG_NOOP) {
			if (cb->cb_set[NL_CB_SKIPPED])
				NL_CB_CALL(cb, NL_CB_SKIPPED, msg);
			else
				goto skip;
		}

		/* Data got lost, report back to user. The default action is to
		 * quit parsing. The user may overrule this action by retuning
		 * NL_SKIP or NL_PROCEED (dangerous) */
		else if (hdr->nlmsg_type == NLMSG_OVERRUN) {
			if (cb->cb_set[NL_CB_OVERRUN])
				NL_CB_CALL(cb, NL_CB_OVERRUN, msg);
			else {
				err = nl_error(EOVERFLOW, "Overrun");
				goto out;
			}
		}

		/* Message carries a nlmsgerr */
		else if (hdr->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *e = nlmsg_data(hdr);

			if (hdr->nlmsg_len < nlmsg_msg_size(sizeof(*e))) {
				/* Truncated error message, the default action
				 * is to stop parsing. The user may overrule
				 * this action by returning NL_SKIP or
				 * NL_PROCEED (dangerous) */
				if (cb->cb_set[NL_CB_INVALID])
					NL_CB_CALL(cb, NL_CB_INVALID, msg);
				else {
					err = nl_error(EINVAL,
					        "Truncated error message");
					goto out;
				}
			} else if (e->error) {
				/* Error message reported back from kernel. */
				if (cb->cb_err) {
					err = cb->cb_err(&nla, e,
							   cb->cb_err_arg);
					if (err < 0)
						goto out;
					else if (err == NL_SKIP)
						goto skip;
					else if (err == NL_STOP) {
						err = nl_error(-e->error,
						         "Netlink Error");
						goto out;
					}
				} else {
					err = nl_error(-e->error,
						  "Netlink Error");
					goto out;
				}
			} else if (cb->cb_set[NL_CB_ACK])
				NL_CB_CALL(cb, NL_CB_ACK, msg);
		} else {
			/* Valid message (not checking for MULTIPART bit to
			 * get along with broken kernels. NL_SKIP has no
			 * effect on this.  */
			if (cb->cb_set[NL_CB_VALID])
				NL_CB_CALL(cb, NL_CB_VALID, msg);
		}
skip:
		err = 0;
		hdr = nlmsg_next(hdr, &n);
	}
	
	nlmsg_free(msg);
	free(buf);
	free(creds);
	buf = NULL;
	msg = NULL;
	creds = NULL;

	if (multipart) {
		/* Multipart message not yet complete, continue reading */
		goto continue_reading;
	}
stop:
	err = 0;
out:
	nlmsg_free(msg);
	free(buf);
	free(creds);

	return err;
}

/**
 * Receive a set of messages from a netlink socket.
 * @arg handle		netlink handle
 * @arg cb		set of callbacks to control behaviour.
 *
 * Repeatedly calls nl_recv() or the respective replacement if provided
 * by the application (see nl_cb_overwrite_recv()) and parses the
 * received data as netlink messages. Stops reading if one of the
 * callbacks returns NL_STOP or nl_recv returns either 0 or a negative error code.
 *
 * A non-blocking sockets causes the function to return immediately if
 * no data is available.
 *
 * @return 0 on success or a negative error code from nl_recv().
 */
int nl_recvmsgs(struct nl_handle *handle, struct nl_cb *cb)
{
	if (cb->cb_recvmsgs_ow)
		return cb->cb_recvmsgs_ow(handle, cb);
	else
		return recvmsgs(handle, cb);
}

/**
 * Receive a set of message from a netlink socket using handlers in nl_handle.
 * @arg handle		netlink handle
 *
 * Calls nl_recvmsgs() with the handlers configured in the netlink handle.
 */
int nl_recvmsgs_default(struct nl_handle *handle)
{
	return nl_recvmsgs(handle, handle->h_cb);

}

static int ack_wait_handler(struct nl_msg *msg, void *arg)
{
	return NL_STOP;
}

/**
 * Wait for ACK.
 * @arg handle		netlink handle
 * @pre The netlink socket must be in blocking state.
 *
 * Waits until an ACK is received for the latest not yet acknowledged
 * netlink message.
 */
int nl_wait_for_ack(struct nl_handle *handle)
{
	int err;
	struct nl_cb *cb;

	cb = nl_cb_clone(handle->h_cb);
	if (cb == NULL)
		return nl_get_errno();

	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_wait_handler, NULL);
	err = nl_recvmsgs(handle, cb);
	nl_cb_put(cb);

	return err;
}

/** @} */

/** @} */
