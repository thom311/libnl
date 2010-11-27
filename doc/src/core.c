/**
 * \cond skip
 * vim:syntax=c.doxygen
 * \endcond

\page core_doc Netlink Core Library (-lnl)

\section core_intro Introduction

The core library contains the fundamentals required to communicate over
netlink sockets. It deals with connecting and disconnectng of sockets,
sending and receiving of data, construction and parsing of messages,
provides a customizeable receiving state machine, and provides a abstract
data type framework which eases the implementation of object based netlink
protocols where objects are added, removed, or modified with the help of
netlink messages.

\section core_toc Table of Contents

- \ref core_lib
  - \ref core_lib_howto
  - \ref core_lib_link
- \ref proto_fund
  - \ref core_format
  - \ref core_msg_type
    - \ref core_multipart
    - \ref core_errmsg
    - \ref core_ack
  - \ref core_msg_flags
  - \ref core_seq
  - \ref core_multicast
- \ref sk_doc
  - \ref core_sk_alloc
  - \ref core_sk_seq_num
  - \ref core_sk_groups
  - \ref core_sk_cb
  - \ref core_sk_attrs
    - \ref core_sk_local_port
    - \ref core_sk_peer_port
    - \ref core_sk_fd
    - \ref core_sk_buffer_size
    - \ref core_sk_cred
    - \ref core_sk_auto_ack
    - \ref core_sk_msg_peek
    - \ref core_sk_pktinfo
- \ref core_send_recv
  - \ref core_send
    - \ref core_nl_send
    - \ref core_nl_send_iovec
    - \ref core_nl_sendmsg
    - \ref core_send_raw
    - \ref core_send_simple
  - \ref core_recv
    - \ref core_nl_recvmsgs
    - \ref core_recvmsgs
    - \ref core_recv_parse
  - \ref core_auto_ack
- \ref core_msg
  - \ref core_msg_format
    - \ref core_msg_fmt_align
  - \ref core_msg_parse
    - \ref core_msg_split
    - \ref core_msg_payload
    - \ref core_msg_parse_attr
    - \ref core_nlmsg_parse
  - \ref core_msg_constr
    - \ref core_msg_alloc
    - \ref core_msg_nlmsg_put
    - \ref core_msg_reserve
    - \ref core_msg_append
- \ref core_attr
  - \ref core_attr_format
  - \ref core_attr_parse
    - \ref core_attr_parse_split
    - \ref core_attr_payload
    - \ref core_attr_validation
    - \ref core_attr_nla_parse
    - \ref core_attr_find
    - \ref core_attr_iterate
  - \ref core_attr_constr
    - \ref core_attr_exception
  - \ref core_attr_data_type
    - \ref core_attr_int
    - \ref core_attr_string
    - \ref core_attr_flag
    - \ref core_attr_nested
    - \ref core_attr_unspec
  - \ref core_attr_examples
    - \ref core_attr_example_constr
    - \ref core_attr_example_parse
- \ref core_cb
  - \ref core_cb_hooks
    - \ref core_cb_default
    - \ref core_cb_msg_proc
    - \ref core_cb_errmsg
    - \ref core_cb_example
  - \ref core_cb_overwrite
    - \ref core_cb_ow_recvmsgs
    - \ref core_cb_ow_recv
    - \ref core_cb_ow_send
- \ref core_cache
- \ref core_abstract_types
  - \ref core_abstract_addr
    - \ref core_abstract_addr_alloc
    - \ref core_abstract_addr_ref
    - \ref core_abstract_addr_attr
    - \ref core_abstract_addr_prefix
    - \ref core_abstract_addr_helpers
  - \ref core_abstract_data
    - \ref core_abstract_data_alloc
    - \ref core_abstract_data_access
    - \ref core_abstract_data_helpers

\section core_lib 1. Introduction to the Library

\subsection core_lib_howto 1.1 How To Read This Documentation

The documentation consists of this manual and the API reference pages.
Both contain references to each other and as many examples as possible.

Even though the library tries to be as consistent and as intuitive as
possible it may be difficult to understand where to start looking for
information.



\subsection core_lib_link 1.2 Linking to this Library


\subsection flags Flags to Character StringTranslations

All functions converting a set of flags to a character string follow
the same principles, therefore, the following information applies
to all functions convertings flags to a character string and vice versa.

\subsubsection flags2str Flags to Character String
\code
char *<object name>_flags2str(int flags, char *buf, size_t len)
\endcode
\arg flags		Flags.
\arg buf		Destination buffer.
\arg len		Buffer length.

Converts the specified flags to a character string separated by
commas and stores it in the specified destination buffer.

\return The destination buffer

\subsubsection str2flags Character String to Flags
\code
int <object name>_str2flags(const char *name)
\endcode
\arg name		Name of flag.

Converts the provided character string specifying a flag
to the corresponding numeric value.

\return Link flag or a negative value if none was found.

\subsubsection type2str Type to Character String
\code
char *<object name>_<type>2str(int type, char *buf, size_t len)
\endcode
\arg type		Type as numeric value
\arg buf		Destination buffer.
\arg len		Buffer length.

Converts an identifier (type) to a character string and stores
it in the specified destination buffer.

\return The destination buffer or the type encoded in hexidecimal
        form if the identifier is unknown.

\subsubsection str2type Character String to Type
\code
int <object name>_str2<type>(const char *name)
\endcode
\arg name		Name of identifier (type).

Converts the provided character string specifying a identifier
to the corresponding numeric value.

\return Identifier as numeric value or a negative value if none was found.


\section proto_fund 1. Netlink Protocol Fundamentals

The netlink protocol is a socket based IPC mechanism used for communication
between userspace processes and the kernel or between userspace processes
themselves. The netlink protocol is based on BSD sockets and uses the
\c AF_NETLINK address family. Every netlink protocol uses its own protocol
number (e.g. NETLINK_ROUTE, NETLINK_NETFILTER, etc). Its addressing schema
is based on a 32 bit port number, formerly referred to as PID, which uniquely
identifies each peer.

\subsection core_format 1.1 Message Format

A netlink protocol is typically based on messages and consists of the
netlink message header (struct nlmsghdr) plus the payload attached to it.
The payload can consist of arbitary data but usually contains a fixed
size protocol specific header followed by a stream of attributes.

The netlink message header (struct nlmsghdr) has the following format:

\code   
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------------------------------------+
|                          Length                             |
+------------------------------+------------------------------+
|            Type              |           Flags              |
+------------------------------+------------------------------+
|                      Sequence Number                        |
+-------------------------------------------------------------+
|                       Port (Address)                        |
+-------------------------------------------------------------+
\endcode

\subsection core_msg_type 1.2 Message Types

Netlink differs between requests, notifications, and replies. Requests
are messages which have the \c NLM_F_REQUEST flag set and are meant to
request an action from the receiver. A request is typically sent from
a userspace process to the kernel. While not strictly enforced, requests
should carry a sequence number incremented for each request sent.

Depending on the nature of the request, the receiver may reply to the
request with another netlink message. The sequence number of a reply
must match the sequence number of the request it relates to.

Notifications are of informal nature and no reply is expected, therefore
the sequence number is typically set to 0.

\msc
A,B;
A=>B [label="GET (seq=1, NLM_F_REQUEST)"];
A<=B [label="PUT (seq=1)"];
...;
A<=B [label="NOTIFY (seq=0)"];
\endmsc

The type of message is primarly identified by its 16 bit message type set
in the message header. The following standard message types are defined:

- \c NLMSG_NOOP - No operation, message must be discarded
- \c NLMSG_ERROR - Error message or ACK, see \ref core_errmsg,
  respectively \ref core_ack
- \c NLMSG_DONE - End of multipart sequence, see \ref core_multipart.
- \c NLMSG_OVERRUN - Overrun notification (Error)

Every netlink protocol is free to define own message types. Note that
message type values  < \c NLMSG_MIN_TYPE (0x10) are reserved and may not
be used.

It is common practice to use own message types to implement RPC schemas.
Suppose the goal of the netlink protocol you are implementing is allow
configuration of a particular network device, therefore you want to
provide read/write access to various configuration options. The typical
"netlink way" of doing this would be to define two message types
\c MSG_SETCFG, \c MSG_GETCFG:

\code
#define MSG_SETCFG	0x11
#define MSG_GETCFG	0x12
\endcode

Sending a \c MSG_GETCFG request message will typically trigger a reply
with the message type \c MSG_SETCFG containing the current configuration.
In object oriented terms one would describe this as "the kernel sets
the local copy of the configuration in userspace".

\msc
A,B;
A=>B [label="MSG_GETCFG (seq=1, NLM_F_REQUEST)"];
A<=B [label="MSG_SETCFG (seq=1)"];
\endmsc

The configuration may be changed by sending a \c MSG_SETCFG which will
be responded to with either a ACK (see \ref core_ack) or a error
message (see \ref core_errmsg).

\msc
A,B;
A=>B [label="MSG_SETCFG (seq=1, NLM_F_REQUEST, NLM_F_ACK)"];
A<=B [label="ACK (seq=1)"];
\endmsc

Optionally, the kernel may send out notifications for configuration
changes allowing userspace to listen for changes instead of polling
frequently. Notifications typically reuse an existing message type
and rely on the application using a separate socket to differ between
requests and notifications but you may also specify a separate message
type.

\msc
A,B;
A<=B [label="MSG_SETCFG (seq=0)"];
\endmsc

\subsubsection core_multipart 1.2.1 Multipart Messages

Although in theory a netlink message can be up to 4GiB in size. The socket
buffers are very likely not large enough to hold message of such sizes.
Therefore it is common to limit messages to one page size (PAGE_SIZE) and
use the multipart mechanism to split large pieces of data into several
messages.  A multipart message has the \c flag NLM_F_MULTI set and the
receiver is expected to continue receiving and parsing until the special
message type \c NLMSG_DONE is received.

Multipart messages unlike fragmented ip packets must not be reassmbled
even though it is perfectly legal to do so if the protocols wishes to
work this way. Often multipart message are used to send lists or trees
of objects were each multipart message simply carries multiple objects
allow for each message to be parsed independently.

\msc
A,B;
A=>B [label="GET (seq=1, NLM_F_REQUEST)"];
A<=B [label="PUT (seq=1, NLM_F_MULTI)"];
...;
A<=B [label="PUT (seq=1, NLM_F_MULTI)"];
A<=B [label="NLMSG_DONE (seq=1)"];
\endmsc

\subsubsection core_errmsg 1.2.2 Error Message

Error messages can be sent in response to a request. Error messages must
use the standard message type \c NLMSG_ERROR. The payload consists of a
error code and the original netlink mesage header of the request. 

\code
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------------------------------------+
|                            Length                           |
+------------------------------+------------------------------+
|  .nlmsg_type = NLMSG_ERROR   |       .nlmsg_flags = 0       |
+------------------------------+------------------------------+
|              Sequence number of the orig request            |
+-------------------------------------------------------------+
|                Port number of the orig request              |
+-------------------------------------------------------------+
|                     Error Code (e.g. EINVAL)                |
+-------------------------------------------------------------+
|             Netlink Message Header of orig. request         |
.                                                             .
.                                                             .
+-------------------------------------------------------------+
\endcode

Error messages should set the sequence number to the sequence number
of the request which caused the error.

\msc
A,B;
A=>B [label="GET (seq=1, NLM_F_REQUEST)"];
A<=B [label="NLMSG_ERROR code=EINVAL (seq=1)"];
\endmsc

\subsubsection core_ack 1.2.3 ACKs

A sender can request an ACK message to be sent back for each request
processed by setting the \c NLM_F_ACK flag in the request. This is typically
used to allow the sender to synchronize further processing until the
request has been processed by the receiver.

\msc
A,B;
A=>B [label="GET (seq=1, NLM_F_REQUEST | NLM_F_ACK)"];
A<=B [label="ACK (seq=1)"];
\endmsc

ACK messages also use the message type \c NLMSG_ERROR and payload format
but the error code is set to 0.

\subsubsection core_msg_flags 1.3 Message Flags

The following standard flags are defined

\code
#define NLM_F_REQUEST		1
#define NLM_F_MULTI		2
#define NLM_F_ACK		4
#define NLM_F_ECHO		8
\endcode

- \c NLM_F_REQUEST - Message is a request, see \ref core_msg_type.
- \c NLM_F_MULTI - Multipart message, see \ref core_multipart.
- \c NLM_F_ACK - ACK message requested, see \ref core_ack.
- \c NLM_F_ECHO - Request to echo the request.

The flag \c NLM_F_ECHO is similar to the \c NLM_F_ACK flag. It can be
used in combination with \c NLM_F_REQUEST and causes a notification
which is sent as a result of a request to also be sent to the sender
regardless of whether the sender has subscribed to the corresponding
multicast group or not. See \ref core_multicast.

Additional universal message flags are defined which only apply for
\c GET requests:

\code
#define NLM_F_ROOT	0x100
#define NLM_F_MATCH	0x200
#define NLM_F_ATOMIC	0x400
#define NLM_F_DUMP	(NLM_F_ROOT|NLM_F_MATCH)
\endcode

- \c NLM_F_ROOT - Return based on root of tree.
- \c NLM_F_MATCH - Return all matching entries.
- \c NLM_F_ATOMIC - Obsoleted, once used to request an atomic operation.
- \c NLM_F_DUMP - Return a list of all objects \c (NLM_F_ROOT|NLM_F_MATCH).

Use of these flags is completely optional and many netlink protocols only
make use of the \c NLM_F_DUMP flag which typically requests the receiver
to send a list of all objects in the context of the message type as a
sequence of multipart messages (see \ref core_multipart).

Another set of flags exist related to \c NEW or \c SET requests. These
flags are mutually exclusive to the \c GET flags:

\code
#define NLM_F_REPLACE	0x100
#define NLM_F_EXCL	0x200
#define NLM_F_CREATE	0x400
#define NLM_F_APPEND	0x800
\endcode

- \c NLM_F_REPLACE - Replace an existing object if it exists.
- \c NLM_F_EXCL - Do not update object if it exists already.
- \c NLM_F_CREATE - Create object if it does not exist yet.
- \c NLM_F_APPEND - Add object at end of list.

Behaviour of these flags may differ slightly between different netlink
protocols.

\subsection core_seq 1.4 Sequence Numbers

Netlink allows the use of sequence numbers to help relate replies to
requests. It should be noted that unlike in protocols such as TCP there
is no strict enforcment of the sequence number. The sole purpose of
sequence numbers is to assist a sender in relating replies to the
corresponding requests. See \ref core_msg_type for more information.

Sequence numbers are managed on a per socket basis, see
\ref core_sk_seq_num for more information on how to use sequence numbers.

\subsection core_multicast 1.5 Multicast Groups

TODO

See \ref core_sk_groups.

\section sk_doc 2. Netlink Sockets

In order to use the netlink protocol, a netlink socket is required. Each
socket defines a completely independent context for sending and receiving
of messages. An application may use multiple sockets for the same netlink
protocol, e.g. one socket to send requests and receive replies and another
socket subscribed to a multicast group to receive notifications.

\subsection core_sk_alloc 2.1 Socket Allocation & Freeing

The netlink socket and all its related attributes are represented by
struct nl_sock.

\code
#include <netlink/socket.h>

struct nl_sock *nl_socket_alloc(void)
void nl_socket_free(struct nl_sock *sk)
\endcode

\subsection core_sk_seq_num 2.2 Sequence Numbers

The library will automatically take care of sequence number handling for
the application. A sequence number counter is stored in struct nl_sock which
is meant to be used when sending messages which will produce a reply, error
or any other message which needs to be related to the original message.

The counter can be used directly with the function nl_socket_use_seq()
which will return the current value of the counter and increment it by
one afterwards.

\code
#include <netlink/socket.h>

unsigned int nl_socket_use_seq(struct nl_sock *sk);
\endcode

Most applications will not want to deal with sequence number handling
themselves though. When using nl_send_auto() the sequence number is
filled out automatically and matched again on the receiving side. See
\ref core_send_recv for more information.

This behaviour can and must be disabled if the netlink protocol
implemented does not use a request/reply model, e.g. when a socket is
used to receive notification messages.

\code
#include <netlink/socket.h>

void nl_socket_disable_seq_check(struct nl_sock *sk);
\endcode

\subsection core_sk_groups 2.3 Multicast Group Subscriptions

Each socket can subscribe to any number of multicast groups of the
netlink protocol it is connected to. The socket will then receive a copy
of each message sent to any of the groups. Multicast groups are commonly
used to implement event notifications.

Prior to kernel 2.6.14 the group subscription was performed using a bitmask
which limited the number of groups per protocol family to 32. This outdated
interface can still be accessed via the function nl_join_groups even though
it is not recommended for new code.

\code
#include <netlink/socket.h>

void nl_join_groups(struct nl_sock *sk, int bitmask);
\endcode

Starting with 2.6.14 a new method was introduced which supports subscribing
to an almost infinite number of multicast groups.

\code
#include <netlink/socket.h>

int nl_socket_add_memberships(struct nl_sock *sk, int group, ...);
int nl_socket_drop_memberships(struct nl_sock *sk, int group, ...);
\endcode

\subsubsection core_sk_group_example 2.3.1 Multicast Example

\include sk_group_example.c

\subsection core_sk_cb 2.4 Modifiying Socket Callback Configuration

See \ref core_cb for more information on callback hooks and overwriting
capabilities

Each socket is assigned a callback configuration which controls the
behaviour of the socket. This is f.e. required to have a separate message
receive function per socket. It is perfectly legal to share callback
configurations between sockets though.

The following functions can be used to access and set the callback
configuration of a socket:

\code
#include <netlink/socket.h>

struct nl_cb *nl_socket_get_cb(const struct nl_sock *sk);
void nl_socket_set_cb(struct nl_sock *sk, struct nl_cb *cb);
\endcode

Additionaly a shortcut exists to modify the callback configuration assigned
to a socket directly:

\code
#include <netlink/socket.h>

int nl_socket_modify_cb(struct nl_sock *sk, enum nl_cb_type type, enum nl_cb_kind kind,
                        nl_recvmsg_msg_cb_t func, void *arg);
\endcode

Example:
\code
#include <netlink/socket.h>

// Call my_input() for all valid messages received in socket sk
nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, my_input, NULL);
\endcode

\subsection core_sk_attrs 2.5 Socket Attributes

\subsubsection core_sk_local_port 2.5.1 Local Port

The local port number uniquely identifies the socket and is used to
address it. A unique local port is generated automatically when the socket
is allocated. It will consist of the Process ID (22 bits) and a random
number (10 bits) thus allowing up to 1024 sockets per process.

\code
#include <netlink/socket.h>

uint32_t nl_socket_get_local_port(const struct nl_sock *sk);
void nl_socket_set_local_port(struct nl_sock *sk, uint32_t port);
\endcode

\b Note: Overwriting the local port is possible but you have to ensure
that the provided value is unique and no other socket in any other
application is using the same value.

\subsubsection core_sk_peer_port 2.5.2 Peer Port

A peer port can be assigned to the socket which will result in all unicast
messages sent over the socket to be addresses to the peer. If no peer is
specified, the message is sent to the kernel which will try to automatically
bind the socket to a kernel side socket of the same netlink protocol family.
It is common practice not to bind the socket to a peer port as typically
only one kernel side socket exists per netlink protocol family.

\code
#include <netlink/socket.h>

uint32_t nl_socket_get_peer_port(const struct nl_sock *sk);
void nl_socket_set_peer_port(struct nl_sock *sk, uint32_t port);
\endcode

\subsubsection core_sk_fd 2.5.3 File Descriptor

Netlink uses the BSD socket interface, therefore a file descriptor
is behind each socket and you may use it directly.

\code
#include <netlink/socket.h>

int nl_socket_get_fd(const struct nl_sock *sk);
\endcode

If a socket is used to only receive notifications it usually is best
to put the socket in non-blocking mode and periodically poll for new
notifications.

\code
#include <netlink/socket.h>

int nl_socket_set_nonblocking(const struct nl_sock *sk);
\endcode

\subsubsection core_sk_buffer_size 2.5.4 Send/Receive Buffer Size

The socket buffer is used to queue netlink messages between sender
and receiver. The size of these buffers specifies the maximum size
you will be able to write() to a netlink socket, i.e. it will indirectly
define the maximum message size. The default is 32KiB.

\code
#include <netlink/socket.h>

int nl_socket_set_buffer_size(struct nl_sock *sk, int rx, int tx);
\endcode


\subsubsection core_sk_cred 2.5.5 Enable/Disable Credentials

TODO

\code
#include <netlink/socket.h>

int nl_socket_set_passcred(struct nl_sock *sk, int state);
\endcode

\subsubsection core_sk_auto_ack 2.5.6 Enable/Disable Auto-ACK Mode

The following functions allow to enable/disable Auto-ACK mode on a
socket. See \ref core_auto_ack for more information on what implications
that has. Auto-ACK mode is enabled by default.

\code
#include <netlink/socket.h>

void nl_socket_enable_auto_ack(struct nl_sock *sk);
void nl_socket_disable_auto_ack(struct nl_sock *sk);
\endcode

\subsubsection core_sk_msg_peek 2.5.7 Enable/Disable Message Peeking

If enabled, message peeking causes nl_recv() to try and use MSG_PEEK to
retrieve the size of the next message received and allocate a buffer
of that size. Message peeking is enabled by default but can be disabled
using the following function:

\code
#include <netlink/socket.h>

void nl_socket_enable_msg_peek(struct nl_sock *sk);
void nl_socket_disable_msg_peek(struct nl_sock *sk);
\endcode

\subsubsection core_sk_pktinfo 2.5.8 Enable/Disable Receival of Packet Information

If enabled, each received netlink message from the kernel will include an
additional struct nl_pktinfo in the control message. The following function
can be used to enable/disable receival of packet information.

\code
#include <netlink/socket.h>

int nl_socket_recv_pktinfo(struct nl_sock *sk, int state);
\endcode

\b Note: Processing of NETLINK_PKTINFO has not been implemented yet.

\section core_send_recv 3. Sending and Receiving of Messages / Data

\subsection core_send 3.1 Sending Netlink Messages

The standard method of sending a netlink message over a netlink socket
is to use the function nl_send_auto(). It will automatically complete
the netlink message by filling the missing bits and pieces in the
netlink message header and will deal with addressing based on the
options and address set in the netlink socket. The message is then passed
on to nl_send().

If the default sending semantics implemented by nl_send() do not suit the
application, it may overwrite the sending function nl_send() by
specifying an own implementation using the function nl_cb_overwrite_send().

\code
   nl_send_auto(sk, msg)
         |
         |-----> nl_complete_msg(sk, msg)
         |
         |
         |              Own send function specified via nl_cb_overwrite_send()
         |- - - - - - - - - - - - - - - - - - - -
         v                                      v
   nl_send(sk, msg)                         send_func()
\endcode

\subsubsection core_nl_send 3.1.1 Using nl_send()

If you do not require any of the automatic message completion functionality
you may use nl_send() directly but beware that any internal calls to
nl_send_auto() by the library to send netlink messages will still use
nl_send(). Therefore if you wish to use any higher level interfaces and the
behaviour of nl_send() is to your dislike then you must overwrite the
nl_send() function via nl_cb_overwrite_send()

The purpose of nl_send() is to embed the netlink message into a iovec
structure and pass it on to nl_send_iovec().

\code
   nl_send(sk, msg)
         |
         v
   nl_send_iovec(sk, msg, iov, iovlen)
\endcode

\subsubsection core_nl_send_iovec 3.1.2 Using nl_send_iovec()

nl_send_iovec() expects a finalized netlink message and fills out the
struct msghdr used for addressing. It will first check if the struct nl_msg
is addressed to a specific peer (see nlmsg_set_dst()). If not, it will try
to fall back to the peer address specified in the socket (see
nl_socket_set_peer_port(). Otherwise the message will be sent unaddressed
and it is left to the kernel to find the correct peer.

nl_send_iovec() also adds credentials if present and enabled
(see \ref core_sk_cred).

The message is then passed on to nl_sendmsg().

\code
   nl_send_iovec(sk, msg, iov, iovlen)
         |
         v
   nl_sendmsg(sk, msg, msghdr)
\endcode

\subsubsection core_nl_sendmsg 3.1.3 Using nl_sendmsg()

nl_sendmsg() expects a finalized netlink message and an optional struct
msghdr containing the peer address. It will copy the local address as
defined in the socket (see nl_socket_set_local_port()) into the netlink
message header.

At this point, construction of the message finished and it is ready to
be sent.

\code
   nl_sendmsg(sk, msg, msghdr)
         |- - - - - - - - - - - - - - - - - - - - v
         |                                 NL_CB_MSG_OUT()
         |<- - - - - - - - - - - - - - - - - - - -+
         v
   sendmsg()
\endcode

Before sending the application has one last chance to modify the message.
It is passed to the NL_CB_MSG_OUT callback function which may inspect or
modify the message and return an error code. If this error code is NL_OK
the message is sent using sendmsg() resulting in the number of bytes
written being returned. Otherwise the message sending process is aborted
and the error code specified by the callback function is returned. See
\ref core_sk_cb for more information on how to set callbacks.

\subsubsection core_send_raw 3.1.4 Sending Raw Data with nl_sendto()

If you wish to send raw data over a netlink socket, the following
function will pass on any buffer provided to it directly to sendto():

\code
#include <netlink/netlink.h>

int nl_sendto(struct nl_sock *sk, void *buf, size_t size);
\endcode

\subsubsection core_send_simple 3.1.5 Sending of Simple Messages

A special interface exists for sending of trivial messages. The function
expects the netlink message type, optional netlink message flags, and an
optional data buffer and data length.  
\code
#include <netlink/netlink.h>

int nl_send_simple(struct nl_sock *sk, int type, int flags,
                   void *buf, size_t size);
\endcode

The function will construct a netlink message header based on the message
type and flags provided and append the data buffer as message payload. The
newly constructed message is sent with nl_send_auto().

The following example will send a netlink request message causing the
kernel to dump a list of all network links to userspace:
\include nl_send_simple.c

\subsection core_recv 3.2 Receiving Netlink Messages

The easiest method to receive netlink messages is to call nl_recvmsgs_default().
It will receive messages based on the semantics defined in the socket. The
application may customize these in detail although the default behaviour will
probably suit most applications.

nl_recvmsgs_default() will also be called internally by the library whenever
it needs to receive and parse a netlink message.

The function will fetch the callback configuration stored in the socket and
call nl_recvmsgs():

\code
   nl_recvmsgs_default(sk)
         |
         | cb = nl_socket_get_cb(sk)
         v
   nl_recvmsgs(sk, cb)
\endcode

\subsubsection core_nl_recvmsgs 3.2.1 Using nl_recvmsgs()

nl_recvmsgs() implements the actual receiving loop, it blocks until a
netlink message has been received unless the socket has been put into
non-blocking mode.

See \ref core_recvmsgs for more information on the behaviour of
nl_recvmsgs().

For the unlikely scenario that certain required receive characteristics
can not be achieved by fine tuning the internal recvmsgs function using
the callback configuration (see \ref core_sk_cb) the application may
provide a complete own implementation of it and overwrite all calls to
nl_recvmsgs() with the function nl_cb_overwrite_recvmsgs().

\code
   nl_recvmsgs(sk, cb)
         |
         |     Own recvmsgs function specified via nl_cb_overwrite_recvmsgs()
         |- - - - - - - - - - - - - - - - - - - -
         v                                      v
   internal_recvmsgs()                    my_recvmsgs()
\endcode

\subsubsection core_recvmsgs 3.2.2 Receive Characteristics

If the application does not provide its own recvmsgs() implementation
with the function nl_cb_overwrite_recvmsgs() the following characteristics
apply while receiving data from a netlink socket:

\code
        internal_recvmsgs()
                |
+-------------->|     Own recv function specified with nl_cb_overwrite_recv()
|               |- - - - - - - - - - - - - - - -
|               v                              v
|           nl_recv()                      my_recv()
|               |<- - - - - - - - - - - - - - -+
|               |<-------------+
|               v              | More data to parse? (nlmsg_next())
|         Parse Message        | 
|               |--------------+
|               v
+------- NLM_F_MULTI set?
                |
                v
            (SUCCESS)
\endcode

The function nl_recv() is invoked first to receive data from the netlink
socket.  This function may be overwritten by the application by an own
implementation using the function nl_cb_overwrite_recv(). This may be
useful if the netlink byte stream is in fact not received from a socket
directly but is read from a file or another source.

If data has been read, it will be attemped to parse the data
(see \ref core_recv_parse). This will be done repeately until the parser
returns NL_STOP, an error was returned or all data has been parsed.

In case the last message parsed successfully was a multipart message
(see \ref core_multipart) and the parser did not quit due to either an
error or NL_STOP nl_recv() respectively the applications own implementation
will be called again and the parser starts all over.

See \ref core_recv_parse for information on how to extract valid netlink
messages from the parser and on how to control the behaviour of it.

\subsubsection core_recv_parse 3.2.3 Parsing Characteristics

The internal parser is invoked for each netlink message received from a
netlink socket. It is typically fed by nl_recv() (see \ref core_recvmsgs).

The parser will first ensure that the length of the data stream provided
is sufficient to contain a netlink message header and that the message
length as specified in the message header does not exceed it.

If this criteria is met, a new struct nl_msg is allocated and the message
is passed on to the the callback function NL_CB_MSG_IN if one is set. Like
any other callback function, it may return NL_SKIP to skip the current
message but continue parsing the next message or NL_STOP to stop parsing
completely.

The next step is to check the sequence number of the message against the
currently expected sequence number. The application may provide its own
sequence number checking algorithm by setting the callback function
NL_CB_SEQ_CHECK to its own implementation. In fact, calling
nl_socket_disable_seq_check() to disable sequence number checking will
do nothing more than set the NL_CB_SEQ_CHECK hook to a function which
always returns NL_OK.

Another callback hook NL_CB_SEND_ACK exists which is called if the
message has the NLM_F_ACK flag set. Although I am not aware of any
userspace netlink socket doing this, the application may want to send
an ACK message back to the sender (see \ref core_ack).

\code
        parse()
          |
          v
      nlmsg_ok() --> Ignore
          |
          |- - - - - - - - - - - - - - - v
          |                         NL_CB_MSG_IN()
          |<- - - - - - - - - - - - - - -+
          |
          |- - - - - - - - - - - - - - - v
     Sequence Check                NL_CB_SEQ_CHECK()
          |<- - - - - - - - - - - - - - -+
          |
          |              Message has NLM_F_ACK set
          |- - - - - - - - - - - - - - - v 
          |                      NL_CB_SEND_ACK()
          |<- - - - - - - - - - - - - - -+
          |
 Handle Message Type
\endcode

\subsection core_auto_ack 3.3 Auto-ACK Mode

TODO

\section core_msg 4. Netlink Message Parsing & Construction

\subsection core_msg_format 4.1 Message Format

See \ref proto_fund for an introduction to the netlink protocol and its
message format.

\subsubsection core_msg_fmt_align 4.1.1 Alignment

Most netlink protocols enforce a strict alignment policy for all boundries.
The alignment value is defined by NLMSG_ALIGNTO and is fixed to 4 bytes.
Therefore all netlink message headers, begin of payload sections, protocol
specific headers, and attribute sections must start at an offset which is
a multiple of NLMSG_ALIGNTO.

\code
#include <netlink/msg.h>

int nlmsg_size(int payloadlen);
int nlmsg_total_size(int payloadlen);
\endcode

The library provides a set of function to handle alignment requirements
automatically. The function nlmsg_total_size() returns the total size
of a netlink message including the padding to ensure the next message
header is aligned correctly.

\code
     <----------- nlmsg_total_size(len) ------------>
     <----------- nlmsg_size(len) ------------>
    +-------------------+- - -+- - - - - - - - +- - -+-------------------+- - -
    |  struct nlmsghdr  | Pad |     Payload    | Pad |  struct nlsmghdr  |
    +-------------------+- - -+- - - - - - - - +- - -+-------------------+- - -
     <---- NLMSG_HDRLEN -----> <- NLMSG_ALIGN(len) -> <---- NLMSG_HDRLEN ---
\endcode

If you need to know if padding needs to be added at the end of a message,
nlmsg_padlen() returns the number of padding bytes that need to be added
for a specific payload length.

\code
#include <netlink/msg.h>
int nlmsg_padlen(int payloadlen);
\endcode

\subsection core_msg_parse 4.2 Parsing a Message

The library offers two different methods of parsing netlink messages.
It offers a low level interface for applications which want to do all
the parsing manually. This method is described below. Alternatively
the library also offers an interface to implement a parser as part of
a cache operations set which is especially useful when your protocol
deals with objects of any sort such as network links, routes, etc.
This high level interface is described in \ref core_cache.

\subsubsection core_msg_split 4.2.1 Splitting a byte stream into separate messages

What you receive from a netlink socket is typically a stream of
messages. You will be given a buffer and its length, the buffer may
contain any number of netlink messages.

The first message header starts at the beginning of message stream. Any
subsequent message headers are access by calling nlmsg_next() on the
previous header.

\code
#include <netlink/msg.h>

struct nlmsghdr *nlmsg_next(struct nlmsghdr *hdr, int *remaining);
\endcode

The function nlmsg_next() will automatically substract the size of
the previous message from the remaining number of bytes.

Please note, there is no indication in the previous message whether
another message follows or not. You must assume that more messages
follow until all bytes of the message stream have been processed.

To simplify this, the function nlmsg_ok() exists which returns true if
another message fits into the remaining number of bytes in the message
stream. nlmsg_valid_hdr() is similar, it checks whether a specific
netlink message contains at least a minimum of payload.

\code
#include <netlink/msg.h>

int nlmsg_valid_hdr(const struct nlmsghdr *hdr, int payloadlen);
int nlmsg_ok(const struct nlmsghdr *hdr, int remaining);
\endcode

A typical use of these functions looks like this:

\include my_parse.c

\b Note: nlmsg_ok() only returns true if the \b complete message including
         the message payload fits into the remaining buffer length. It will
	 return false if only a part of it fits.

The above can also be written using the iterator nlmsg_for_each():

\include nlmsg_for_each.c


\subsubsection core_msg_payload 4.2.2 Message Payload

The message payload is appended to the message header and is guranteed
to start at a multiple of NLMSG_ALIGNTO. Padding at the end of the
message header is added if necessary to ensure this. The function
nlmsg_data() will calculate the necessary offset based on the message
and returns a pointer to the start of the message payload.

\code
#include <netlink/msg.h>

void *nlmsg_data(const struct nlmsghdr *nlh);
void *nlmsg_tail(const struct nlmsghdr *nlh);
int nlmsg_datalen(const struct nlmsghdr *nlh);
\endcode

The length of the message payload is returned by nlmsg_datalen().

\code
                               <--- nlmsg_datalen(nlh) --->
    +-------------------+- - -+----------------------------+- - -+
    |  struct nlmsghdr  | Pad |           Payload          | Pad |
    +-------------------+- - -+----------------------------+- - -+
nlmsg_data(nlh) ---------------^                                  ^
nlmsg_tail(nlh) --------------------------------------------------^
\endcode

The payload may consist of arbitary data but may have strict alignment
and formatting rules depening on the actual netlink protocol.

\subsubsection core_msg_parse_attr 4.2.3 Message Attributes

Most netlink protocols use netlink attributes. It not only makes the
protocol self documenting but also gives flexibility in expanding
the protocol at a later point. New attributes can be added at any time
and older attributes can be obsoleted by newer ones without breaking
binary compatibility of the protocol.

\code
                               <---------------------- payload ------------------------->
                               <----- hdrlen ---->       <- nlmsg_attrlen(nlh, hdrlen) ->
    +-------------------+- - -+-----  ------------+- - -+--------------------------------+- - -+
    |  struct nlmsghdr  | Pad |  Protocol Header  | Pad |           Attributes           | Pad |
    +-------------------+- - -+-------------------+- - -+--------------------------------+- - -+
nlmsg_attrdata(nlh, hdrlen) -----------------------------^
\endcode

The function nlmsg_attrdata() returns a pointer to the begin of the
attributes section. The length of the attributes section is returned
by the function nlmsg_attrlen().

\code
#include <netlink/msg.h>

struct nlattr *nlmsg_attrdata(const struct nlmsghdr *hdr, int hdrlen);
int nlmsg_attrlen(const struct nlmsghdr *hdr, int hdrlen);
\endcode

See \ref core_attr for more information on how to use netlink attributes.

\subsubsection core_nlmsg_parse 4.2.4 Parsing a Message the Easy Way

The function nlmsg_parse() validate a complete netlink message in
one step. If \p hdrlen > 0 it will first call nlmsg_valid_hdr() to
check if the protocol header fits into the message. If there is
more payload to parse, it will assume it to be attributes and parse
the payload accordingly. The function behaves exactly like nla_parse()
when parsing attributes, see \ref core_attr_nla_parse.

\code
int nlmsg_parse(struct nlmsghdr *hdr, int hdrlen, struct nlattr **attrs,
                int maxtype, struct nla_policy *policy);
\endcode

The function nlmsg_validate() is based on nla_validate() and behaves
exactly the same as nlmsg_parse() except that it only validates and will
not fill a array with pointers to each attribute.

\code
int nlmsg_validate(struct nlmsghdr *hdr, int hdrlen, intmaxtype,
                   struct nla_policy *policy);
\endcode

See \ref core_attr_nla_parse for an example and more information on
attribute parsing.

\subsection core_msg_constr 4.3 Construction of a Message

See \ref core_msg_format for information on the netlink message format
and alignment requirements.

Message construction is based on struct nl_msg which uses an internal
buffer to store the actual netlink message. struct nl_msg \b does \b not
point to the netlink message header. Use nlmsg_hdr() to retrieve a
pointer to the netlink message header.

At allocation time, a maximum message size is specified. It defaults to
a page (PAGE_SIZE). The application constructing the message will reserve
space out of this maximum message size repeatedly for each header or
attribute added. This allows construction of messages across various
layers of code where lower layers do not need to know about the space
requirements of upper layers.

<b>Why is setting the maximum message size necessary?</b> This question
is often raised in combination with the proposed solution of reallocating
the message payload buffer on the fly using realloc(). While it is
possible to reallocate the buffer during construction using nlmsg_expand()
it will make all pointers into the message buffer become stale. This
breaks usage of nlmsg_hdr(), nla_nest_start(), and nla_nest_end() and is
therefore not acceptable as default behaviour.

\subsubsection core_msg_alloc 4.3.1 Allocating struct nl_msg

The first step in constructing a new netlink message it to allocate a
\c struct \c nl_msg to hold the message header and payload. Several
functions exist to simplify various tasks.

\code
#include <netlink/msg.h>

struct nl_msg *nlmsg_alloc(void);
void nlmsg_free(struct nl_msg *msg);
\endcode

The function nlmsg_alloc() is the default message allocation function.
It allocates a new message using the default maximum message size which
equals to one page (PAGE_SIZE). The application can change the default
size for messages by calling nlmsg_set_default_size():

\code
void	  nlmsg_set_default_size(size_t);
\endcode

\b Note: Calling nlmsg_set_default_size() does not change the maximum
         message size of already allocated messages.

\code
struct nl_msg *nlmsg_alloc_size(size_t max);
\endcode

Instead of changing the default message size, the function
nlmsg_alloc_size() can be used to allocate a message with a individual
maximum message size.


If the netlink message header is already known at allocation time, the
application may sue nlmsg_inherit(). It will allocate a message using
the default maximum message size and copy the header into the message.
Calling nlmsg_inherit with \p set to NULL is equivalent to calling
nlmsg_alloc().

\code
struct nl_msg *nlmsg_inherit(struct nlmsghdr *hdr);
\endcode

Alternatively nlmsg_alloc_simple() takes a netlink message type and
netlink message flags. It is equivalent to nlmsg_inherit() except that it
takes the two common header fields as arguments instead of a complete
header.

\code
#include <netlink/msg.h>

struct nl_msg *nlmsg_alloc_simple(int nlmsg_type, int flags);
\endcode

\subsubsection core_msg_nlmsg_put 4.3.2 Appending the netlink message header

After allocating struct nl_msg, the netlink message header needs to be
added unless one of the function nlmsg_alloc_simple() or nlmsg_inherit()
have been used for allocation in which case this step will replace the
netlink message header already in place.

\code
#include <netlink/msg.h>

struct nlmsghdr *nlmsg_put(struct nl_msg *msg, uint32_t port, uint32_t seqnr,
                           int nlmsg_type, int payload, int nlmsg_flags);
\endcode

The function nlmsg_put() will build a netlink message header out of
\p nlmsg_type, \p nlmsg_flags, \p seqnr, and \p port and copy it into
the netlink message. \p seqnr can be set to \p NL_AUTO_SEQ to indiciate
that the next possible sequence number should be used automatically. To
use this feature, the message must be sent using the function
nl_send_auto(). Like \p port, the argument \p seqnr can be set to
\c NL_AUTO_PORT indicating that the local port assigned to the socket
should be used as source port. This is generally a good idea unless you
are replying to a request. See \ref proto_fund for more information on
how to fill the header.

The argument \p payload can be used by the application to reserve room
for additional data after the header. A value of > 0 is equivalent to
calling nlmsg_reserve(msg, payload, NLMSG_ALIGNTO). See
\ref core_msg_reserve for more information on reserving room for data.

\b Example:
\include nlmsg_put.c

\subsubsection core_msg_reserve 4.3.3 Reserving room at the end of the message

Most functions described later on will automatically take care of
reserving room for the data that is added to the end of the netlink
message. In some situations it may be requried for the application
to reserve room directly though.

\code
#include <netlink/msg.h>

void *nlmsg_reserve(struct nl_msg *msg, size_t len, int pad);
\endcode

The function nlmsg_reserve() reserves \p len bytes at the end of the
netlink message and returns a pointer to the start of the reserved area.
The \p pad argument can be used to request \p len to be aligned to any
number of bytes prior to reservation.

The following example requests to reserve a 17 bytes area at the end of
message aligned to 4 bytes. Therefore a total of 20 bytes will be
reserved.

\code
#include <netlink/msg.h>

void *buf = nlmsg_reserve(msg, 17, 4);
\endcode

\b Note: nlmsg_reserve() will \b not align the start of the buffer. Any
         alignment requirements must be provided by the owner of the
	 previous message section.

\subsubsection core_msg_append 4.3.4 Appending data at the end of the message

The function nlmsg_append() appends \p len bytes at the end of the message,
padding it if requested and necessary.

\code
#include <netlink/msg.h>

int nlmsg_append(struct nl_msg *msg, void *data, size_t len, int pad);
\endcode

It is equivalent to calling nlmsg_reserve() and memcpy()ing the data into
the freshly reserved data section.

\b Note: nlmsg_append() will \b not align the start of the data. Any
         alignment requirements must be provided by the owner of the
	 previous message section.

\subsubsection core_msg_put_attr 4.3.5 Adding attribtues to a message

Construction of attributes and addition of attribtues to the message is
covereted in section \ref core_attr.

\section core_attr 5. Netlink Attributes

Any form of payload should be encoded as netlink attributes whenever
possible. Use of attributes allows to extend any netlink protocol in
the future without breaking binary compatibility. F.e. Suppose your
device may currently be using 32 bit counters for statistics but years
later the device switches to maintaining 64 bit counters to account
for faster network hardware. If your protocol is using attributes the
move to 64 bit counters is trivial and only involves in sending an
additional attribute containing the 64 bit variants while still
providing the old legacy 32 bit counters. If your protocol is not using
attributes you will not be able to switch data types without breaking
all existing users of the protocol. 

The concept of nested attributes also allows for subsystems of your
protocol to implement and maintain their own attribute schemas. Suppose
a new generation of network device is introduced which requires a
completely new set of configuration settings which was unthinkable when
the netlink protocol was initially designed. Using attributes the new
generation of devices may define a new attribute and fill it with its
own new structure of attributes which extend or even obsolete the old
attributes.

Therefore, \e always use attributes even if you are almost certain that
the message format will never ever change in the future.

\subsection core_attr_format 5.1 Attribute Format

Netlink attributes allow for any number of data chunks of arbitary
length to be attached to a netlink message. See \ref core_msg_parse_attr
for more information on where attributes are stored in the message.

The format of the attributes data returned by nlmsg_attrdata() is as
follows:

\code
     <----------- nla_total_size(payload) ----------->
     <---------- nla_size(payload) ----------->
    +-----------------+- - -+- - - - - - - - - +- - -+-----------------+- - -
    |  struct nlattr  | Pad |     Payload      | Pad |  struct nlattr  |
    +-----------------+- - -+- - - - - - - - - +- - -+-----------------+- - -
     <---- NLA_HDRLEN -----> <--- NLA_ALIGN(len) ---> <---- NLA_HDRLEN ---
\endcode

Every attribute must start at an offset which is a multiple of
\c NLA_ALIGNTO (4 bytes). If you need to know whether an attribute needs
to be padded at the end, the function nla_padlen() returns the number
of padding bytes that will or need to be added.

\code   
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-------------------------------------------------------------+
|           Length             |            Type              |
+------------------------------+------------------------------+
|                     Attribute Payload                       |
.                                                             .
.                                                             .
+-------------------------------------------------------------+
\endcode

Every attribute is encoded with a type and length field, both 16 bits,
stored in the attribute header (struct nlattr) preceding the attribute
payload. The length of an attribute is used to calculate the offset to
the next attribute.

\subsection core_attr_parse 5.2 Parsing Attributes

\subsubsection core_attr_parse_split 5.2.1 Splitting an Attributes Stream into Attributes

Although most applications will use one of the functions from the
nlmsg_parse() family (See \ref core_attr_nla_parse) an interface
exists to split the attributes stream manually.

As described in \ref core_attr_format the attributes section contains a
infinite sequence or stream of attributes. The pointer returned by
nlmsg_attrdata() (See \ref core_msg_parse_attr) points to the first
attribute header. Any subsequent attribute is accessed with the function
nla_next() based on the previous header.

\code
#include <netlink/attr.h>

struct nlattr *nla_next(const struct nlattr *attr, int *remaining);
\endcode

The semantics are equivalent to nlmsg_next() and thus nla_next() will also
subtract the size of the previous attribute from the remaining number of
bytes in the attributes stream.

Like messages, attributes do not contain an indicator whether another
attribute follows or not. The only indication is the number of bytes left
in the attribute stream. The function nla_ok() exists to determine whether
another attribute fits into the remaining number of bytes or not.

\code
#include <netlink/attr.h>

int nla_ok(const struct nlattr *attr, int remaining);
\endcode

A typical use of nla_ok() and nla_next() looks like this:

\include nla_ok.c

\b Note: nla_ok() only returns true if the \b complete attributes
         including the attribute payload fits into the remaining number
	 of bytes.

\subsubsection core_attr_payload 5.2.2 Accessing Attribute Header and Payload

Once the individual attributes have been sorted out by either splitting
the attributes stream or using another interface the attribute header
and payload can be accessed.

\code
                             <- nla_len(hdr) ->
    +-----------------+- - -+- - - - - - - - - +- - -+
    |  struct nlattr  | Pad |     Payload      | Pad |
    +-----------------+- - -+- - - - - - - - - +- - -+
nla_data(hdr) ---------------^
\endcode

The functions nla_len() and nla_type() can be used to access the attribute
header. nla_len() will return the length of the payload not including
eventual padding bytes. nla_type returns the attribute type.

\code
#include <netlink/attr.h>

int nla_len(const struct nlattr *hdr);
int nla_type(const struct nlattr *hdr);
\endcode

The function nla_data() will return a pointer to the attribute payload.
Please note that due to NLA_ALIGNTO being 4 bytes it may not be safe to
cast and dereference the pointer for any datatype larger than 32 bit
depending on the architecture the application is run on.

\code
#include <netlink/attr.h>

void *nla_data(const struct nlattr *hdr);
\endcode

\b Note: Never rely on the size of a payload being what you expect it to
         be. \e Always verify the payload size and make sure that it
	 matches your expectations. See \ref core_attr_validation.

\subsubsection core_attr_validation 5.2.3 Attribute Validation

When receiving netlink attributes, the receiver has certain expections
on how the attributes should look like. These expectations must be
defined to make sure the sending side meets our expecations. For this
purpose, a attribute validation interface exists which must be used
prior to accessing any payload.

All functions providing attribute validation functionality are based
on struct nla_policy:

\code
struct nla_policy {
	uint16_t	type;
	uint16_t	minlen;
	uint16_t	maxlen;
};
\endcode

The \p type member specifies the datatype of the attribute, e.g.
NLA_U32, NLA_STRING, NLA_FLAG. The default is NLA_UNSPEC. The \p minlen
member defines the minmum payload length of an attribute to be
considered a valid attribute. The value for \p minlen is implicit for
most basic datatypes such as integers or flags. The \p maxlen member
can be used to define a maximum payload length for an attribute to
still be considered valid.

\b Note: Specyfing a maximum payload length is not recommended when
encoding structures in an attribute as it will prevent any extension of
the structure in the future. Something that is frequently done in
netlink protocols and does not break backwards compatibility.

One of the functions which use struct nla_policy is nla_validate().
The function expects an array of struct nla_policy and will access the
array using the attribute type as index. If an attribute type is out
of bounds the attribute is assumed to be valid. This is intentional
behaviour to allow older applications not yet aware of recently
introduced attributes to continue functioning.

\code
#include <netlink/attr.h>

int nla_validate(struct nlattr *head, int len, int maxtype,
                 struct nla_policy *policy);
\endcode

The function nla_validate() returns 0 if all attributes are valid,
otherwise a validation failure specific error code is returned.

Most applications will rarely use nla_validate() directly but use
nla_parse() instead which takes care of validation in the same way but
also parses the the attributes in the same step. See
\ref core_attr_nla_parse for an example and more information.

The validation process in detail:
-# If attribute type is 0 or exceeds \p maxtype attribute is 
   considered valid, 0 is returned.
-# If payload length is < \p minlen, -NLE_ERANGE is returned.
-# If \p maxlen is defined and payload exceeds it, NLE_ERANGE
   is returned.
-# Datatype specific requirements rules, see \ref core_attr_data_type.
-# If all is ok, 0 is returned.

\subsubsection core_attr_nla_parse 5.2.4 Parsing Attributes the Easy Way

Most applications will not want to deal with splitting attribute streams
themselves as described in \ref core_attr_parse_split. A much easier
method is to use nla_parse().

\code
#include <netlink/attr.h>

int nla_parse(struct nlattr **attrs, int maxtype, struct nlattr *head,
              int len, struct nla_policy *policy);
\endcode

The function nla_parse() will iterate over a stream of attributes,
validate each attribute as described in \ref core_attr_validation.  If
the validation of all attributes succeeds, a pointer to each attribute
is stored in the \p attrs array at \c attrs[nla_type(attr)].

As an alernative to nla_parse() the function nlmsg_parse() can be used
to parse the message and its attributes in one step. See
\ref core_nlmsg_parse for information on how to use these functions.

\b Example:

The following example demonstrates how to parse a netlink message sent
over a netlink protocol which does not use protocol headers. The example
does enforce a attribute policy however, the attribute MY_ATTR_FOO must
be a 32 bit integer, and the attribute MY_ATTR_BAR must be a string with
a maximum length of 16 characters.

\include nlmsg_parse.c

\subsubsection core_attr_find 5.2.5 Locating a Single Attribute

An application only interested in a single attribute can use one of the
functions nla_find() or  nlmsg_find_attr(). These function will iterate
over all attributes, search for a matching attribute and return a pointer
to the corresponding attribute header.

\code
#include <netlink/attr.h>

struct nlattr *nla_find(struct nlattr *head, int len, int attrtype);
\endcode

\code
#include <netlink/msg.h>

struct nlattr *nlmsg_find_attr(struct nlmsghdr *hdr, int hdrlen, int attrtype);
\endcode

\b Note: nla_find() and nlmsg_find_attr() will \b not search in nested
         attributes recursively, see \ref core_attr_nested.

\subsubsection core_attr_iterate 5.2.6 Iterating over a Stream of Attributes

In some situations it does not make sense to assign a unique attribute
type to each attribute in the attribute stream. For example a list may
be transferd using a stream of attributes and even if the attribute type
is incremented for each attribute it may not make sense to use the
nlmsg_parse() or nla_parse() function to fill an array.

Therefore methods exist to iterate over a stream of attributes:

\code
#include <netlink/attr.h>

nla_for_each_attr(attr, head, len, remaining)
\endcode

nla_for_each_attr() is a macro which can be used in front of a code
block:

\include nla_for_each_attr.c

\subsection core_attr_constr 5.3 Attribute Construction

The interface to add attributes to a netlink message is based on the
regular message construction interface. It assumes that the message
header and an eventual protocol header has been added to the message
already.

\code
struct nlattr *nla_reserve(struct nl_msg *msg, int attrtype, int len);
\endcode

The function nla_reserve() adds an attribute header at the end of the
message and reserves room for \p len bytes of payload. The function
returns a pointer to the attribute payload section inside the message.
Padding is added at the end of the attribute to ensure the next
attribute is properly aligned.

\code
int nla_put(struct nl_msg *msg, int attrtype, int attrlen, const void *data);
\endcode

The function nla_put() is base don nla_reserve() but takes an additional
pointer \p data pointing to a buffer containing the attribute payload.
It will copy the buffer into the message automatically.

\b Example:

\include nla_put.c

See \ref core_attr_data_type for datatype specific attribute construction
functions.

\subsubsection core_attr_exception 5.3.1 Exception Based Attribute Construction

Like in the kernel API an exception based construction interface is
provided. The behaviour of the macros is identical to their regular
function counterparts except that in case of an error, the target
\c nla_put_failure is jumped.

\b Example:

\include NLA_PUT.c

See \ref core_attr_data_type for more information on the datatype
specific exception based variants.

\subsection core_attr_data_type 5.4 Attribute Data Types

A number of basic data types have been defined to simplify access and
validation of attributes. The datatype is not encoded in the attribute,
therefore bthe sender and receiver are required to use the same
definition on what attribute is of what type.

Besides simplified access to the payload of such datatypes, the major
advantage is the automatic validation of each attribute based on a
policy. The validation ensures safe access to the payload by checking
for minimal payload size and can also be used to enforce maximum
payload size for some datatypes.

\subsubsection core_attr_int 5.4.1 Integer Attributes

The most frequently used datatypes are integers. Integers come in four
different sizes:
- \c NLA_U8 - 8bit integer
- \c NLA_U16 - 16bit integer
- \c NLA_U32 - 32bit integer
- \c NLA_U64 - 64bit integer

Note that due to the alignment requirements of attributes the integer
attribtue \c NLA_u8 and \c NLA_U16 will not result in space savings in
the netlink message. Their use is intended to limit the range of values.

<b>Parsing Integer Attributes</b>

\code
#include <netlink/attr.h>

uint8_t  nla_get_u8(struct nlattr *hdr);
uint16_t nla_get_u16(struct nlattr *hdr);
uint32_t nla_get_u32(struct nlattr *hdr);
uint64_t nla_get_u64(struct nlattr *hdr);
\endcode

Example:

\code
if (attrs[MY_ATTR_FOO])
	uint32_t val = nla_get_u32(attrs[MY_ATTR_FOO]);
\endcode

<b>Constructing Integer Attributes</b>

\code
#include <netlink/attr.h>

int nla_put_u8(struct nl_msg *msg, int attrtype, uint8_t value);
int nla_put_u16(struct nl_msg *msg, int attrtype, uint16_t value);
int nla_put_u32(struct nl_msg *msg, int attrtype, uint32_t value);
int nla_put_u64(struct nl_msg *msg, int attrtype, uint64_t value);
\endcode

Exception based:

\code
NLA_PUT_U8(msg, attrtype, value)
NLA_PUT_U16(msg, attrtype, value)
NLA_PUT_U32(msg, attrtype, value)
NLA_PUT_U64(msg, attrtype, value)
\endcode

<b>Validation</b>

Use \p NLA_U8, \p NLA_U16, \p NLA_U32, or \p NLA_U64 to define the type
of integer when filling out a struct nla_policy array. It will
automatically enforce the correct minimum payload length policy.

Validation does not differ between signed and unsigned integers, only
the size matters. If the appliaction wishes to enforce particular value
ranges it must do so itself.

\code
static struct nla_policy my_policy[ATTR_MAX+1] = {
	[ATTR_FOO] = { .type = NLA_U32 },
	[ATTR_BAR] = { .type = NLA_U8 },
};
\endcode

The above is equivalent to:
\code
static struct nla_policy my_policy[ATTR_MAX+1] = {
	[ATTR_FOO] = { .minlen = sizeof(uint32_t) },
	[ATTR_BAR] = { .minlen = sizeof(uint8_t) },
};
\endcode

\subsubsection core_attr_string 5.4.2 String Attributes

The string datatype represents a NUL termianted character string of
variable length. It is not intended for binary data streams.

The payload of string attributes can be accessed with the function
nla_get_string(). nla_strdup() calls strdup() on the payload and returns
the newly allocated string.

\code
#include <netlink/attr.h>

char *nla_get_string(struct nlattr *hdr);
char *nla_strdup(struct nlattr *hdr);
\endcode

String attributes are constructed with the function nla_put_string()
respectively NLA_PUT_STRING(). The length of the payload will be strlen()+1,
the trailing NUL byte is included.

\code
int nla_put_string(struct nl_msg *msg, int attrtype, const char *data);

NLA_PUT_STRING(msg, attrtype, data)
\endcode

For validation purposes the type \p NLA_STRING can be used in
struct nla_policy definitions. It implies a minimum payload length of 1
byte and checks for a trailing NUL byte. Optionally the \p maxlen member
defines the maximum length of a character string (including the trailing
NUL byte).

\code
static struct nla_policy my_policy[] = {
	[ATTR_FOO] = { .type = NLA_STRING,
		       .maxlen = IFNAMSIZ },
};
\endcode

\subsubsection core_attr_flag 5.4.3 Flag Attributes

The flag attribute represents a boolean datatype. The presence of the
attribute implies a value of \p true, the absence of the attribute
implies the value \p false. Therefore the payload length of flag
attributes is always 0.

\code
int nla_get_flag(struct nlattr *hdr);
int nla_put_flag(struct nl_msg *msg, int attrtype);
\endcode

The type \p NLA_FLAG is used for validation purposes. It implies a 
\p maxlen value of 0 and thus enforces a maximum payload length of 0.

\b Example:

\include nla_flag.c

\subsubsection core_attr_nested 5.4.4 Nested Attributes

As described in \ref core_attr, attributes can be nested allowing for
complex tree structures of attributes. It is commonly used to delegate
the responsibility of a subsection of the message to a subsystem.
Nested attributes are also commonly used for transmitting list of
objects.

When nesting attributes, the nested attributes are included as payload
of a container attribute.

<b>IMPORTANT NOTICE:</b> When validating the attributes using
nlmsg_validate(), nlmsg_parse(), nla_validate(), or nla_parse() only
the attributes on the first level are being validated. None of these
functions will validate attributes recursively. Therefore you must
explicitely call nla_validate() or use nla_parse_nested() for each
level of nested attributes.

The type \p NLA_NESTED should be used when defining nested attributes
in a struct nla_policy definition. It will not enforce any minimum
payload length unless \p minlen is specified explicitely. This is
because some netlink protocols implicitely allow empty container
attributes.

\code
static struct nla_policy my_policy[] = {
	[ATTR_OPTS] = { .type = NLA_NESTED },
};
\endcode

<b>Parsing of Nested Attributes</b>

The function nla_parse_nested() is used to parse nested attributes.
Its behaviour is identical to nla_parse() except that it takes a
struct nlattr as argument and will use the payload as stream of
attributes.

\include nla_parse_nested.c

<b>Construction of Nested Attributes</b>

Attributes are nested by surrounding them with calls to nla_nest_start()
and nla_nest_end(). nla_nest_start() will add a attribute header to
the message but no actual payload. All data added to the message from
this point on will be part of the container attribute until nla_nest_end()
is called which "closes" the attribute, correcting its payload length to
include all data length.

\include nla_nest_start.c

\subsubsection core_attr_unspec 5.4.5 Unspecified Attribute

This is the default attribute type and used when none of the basic
datatypes is suitable. It represents data of arbitary type and length.

See \ref core_abstract_addr_alloc for a more information on a special
interface allowing the allocation of abstract address object based on
netlink attributes which carry some form of network address.

See \ref core_abstract_data_alloc for more information on how to
allocate abstract data objects based on netlink attributes.

Use the function nla_get() and nla_put() to access the payload and
construct attributes. See \ref core_attr_constr for an example.

\subsection core_attr_examples 5.5 Examples

\subsubsection core_attr_example_constr 5.5.1 Constructing a Netlink Message with Attributes

\include msg_constr_attr.c

\subsubsection core_attr_example_parse 5.5.2 Parsing a Netlink Message with Attributes

\include msg_parse_attr.c

\section core_cb 6. Callback Configurations

Callback hooks and overwriting capabilities are provided in various places
inside library to control the behaviour of several functions. All the
callback and overwrite functions are packed together in struct nl_cb which
is attached to a netlink socket or passed on to functions directly.

\subsection core_cb_hooks 6.1 Callback Hooks

Callback hooks are spread across the library to provide entry points for
message processing and to take action upon certain events.

Callback functions may return the following return codes:
\code
Return Code      | Description
-------------------------------------------------------------------------
NL_OK            | Proceed.
NL_SKIP          | Skip message currently being processed and continue
                 | parsing the receive buffer.
NL_STOP          | Stop parsing and discard all remaining data in the
                 | receive buffer.
\endcode

\subsubsection core_cb_default 6.1.1 Default Callback Implementations

The library provides three sets of default callback implementations:
- \b NL_CB_DEFAULT This is the default set. It implets the default behaviour.
     See the table below for more information on the return codes of each
     function.
- \b NL_CB_VERBOSE This set is based on the default set but will cause an
     error message to be printed to stderr for error messages, invalid
     messages, message overruns and unhandled valid messages. The \p arg
     pointer in nl_cb_set() and nl_cb_err() can be used to provide a FILE *
     which overwrites stderr.
- \b NL_CB_DEBUG This set is intended for debugging purposes. It is based
     on the verbose set but will decode and dump each message sent or
     received to the console.

\subsubsection core_cb_msg_proc 6.1.2 Message Processing Callbacks

nl_sendmsg() callback hooks:
\code
Callback ID        | Description                       | Default Return Value
-----------------------------------------------------------------------------
NL_CB_MSG_OUT      | Each message sent                 | NL_OK
\endcode

Any function called by NL_CB_MSG_OUT may return a negative error code to
prevent the message from being sent and the error code being returned.

nl_recvmsgs() callback hooks (ordered by priority):
\code
Callback ID        | Description                       | Default Return Value
-----------------------------------------------------------------------------
NL_CB_MSG_IN       | Each message received             | NL_OK
NL_CB_SEQ_CHECK    | May overwrite sequence check algo | NL_OK
NL_CB_INVALID      | Invalid messages                  | NL_STOP
NL_CB_SEND_ACK     | Messages with NLM_F_ACK flag set  | NL_OK
NL_CB_FINISH       | Messages of type NLMSG_DONE       | NL_STOP
NL_CB_SKIPPED      | Messages of type NLMSG_NOOP       | NL_SKIP
NL_CB_OVERRUN      | Messages of type NLMSG_OVERRUN    | NL_STOP
NL_CB_ACK          | ACK Messages                      | NL_STOP
NL_CB_VALID        | Each valid message                | NL_OK
\endcode

Any of these functions may return NL_OK, NL_SKIP, or NL_STOP.

Message processing callback functions are set with nl_cb_set():
\code
#include <netlink/handlers.h>

int nl_cb_set(struct nl_cb *cb, enum nl_cb_type type, enum nl_cb_kind kind,
              nl_recvmsg_msg_cb_t func, void *cb);

typedef int (*nl_recvmsg_msg_cb_t)(struct nl_msg *msg, void *arg);
\endcode

\subsubsection core_cb_errmsg 6.1.4 Callback for Error Messages

A special function prototype is used for the error message callback hook:

\code
#include <netlink/handlers.h>

int nl_cb_err(struct nl_cb *cb, enum nl_cb_kind kind, nl_recvmsg_err_cb_t func, void * arg);

typedef int(* nl_recvmsg_err_cb_t)(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg);
\endcode

\subsubsection core_cb_example 6.1.4 Example: Setting up a callback set
\include nl_cb_set.c

\subsection core_cb_overwrite 6.2 Overwriting of Internal Functions

When the library needs to send or receive netlink messages in high level
interfaces it does so by calling its own low level API. In the case the
default characteristics are not sufficient for the application, it may
overwrite several internal function calls with own implementations.

\subsubsection core_cb_ow_recvmsgs 6.2.1 Overwriting recvmsgs()

See \ref core_recv for more information on how and when recvmsgs() is
called internally.

\code
#include <netlink/handlers.h>

void nl_cb_overwrite_recvmsgs(struct nl_cb *cb,
                              int (*func)(struct nl_sock *sk, struct nl_cb *cb));
\endcode

The following criteras must be met if a recvmsgs() implementation is
supposed to work with high level interfaces:
- MUST respect the callback configuration in \c cb, therefore:
  - MUST call NL_CB_VALID for all valid messages, passing on 
  - MUST call NL_CB_ACK for all ACK messages
  - MUST correctly handle multipart messages, calling NL_CB_VALID for
    each message until a NLMSG_DONE message is received.
- MUST report error code if a NLMSG_ERROR or NLMSG_OVERRUN mesasge is
  received.

\subsubsection core_cb_ow_recv 6.2.2 Overwriting nl_recv()

Often it is sufficient to overwrite nl_recv() which is responsible from
receiving the actual data from the socket instead of replacing the complete
recvmsgs() logic.

See \ref core_recvmsgs for more information on how and when nl_recv()
is called internally.

\code
#include <netlink/handlers.h>

void nl_cb_overwrite_recv(struct nl_cb *cb,
                          int (*func)(struct nl_sock * sk,
                                      struct sockaddr_nl *addr,
                                      unsigned char **buf,
                                      struct ucred **cred));
\endcode

The following criteras must be met for an own nl_recv() implementation:
- MUST return the number of bytes read or a negative error code if an
  error occured. The function may also return 0 to indicate that no
  data has been read.
- MUST set \c *buf to a buffer containing the data read. It must be safe
  for the caller to access the number of bytes read returned as return code.
- MAY fill out \c *addr with the netlink address of the peer the data
  has been received from.
- MAY set \c *cred to a newly allocated struct ucred containg credentials.

\subsubsection core_cb_ow_send 6.2.3 Overwriting nl_send()

See \ref core_send for more information on how and when nl_send() is
called internally.

\code
#include <netlink/handlers.h>

void nl_cb_overwrite_send(struct nl_cb *cb, int (*func)(struct nl_sock *sk,
                                                        struct nl_msg *msg));
\endcode

Own implementations must send the netlink message and return 0 on success
or a negative error code.

\section core_cache 7. Cache System

\subsection cache_alloc 7.1 Allocation of Caches

Almost all subsystem provide a function to allocate a new cache
of some form. The function usually looks like this:
\code
struct nl_cache *<object name>_alloc_cache(struct nl_sock *sk);
\endcode

These functions allocate a new cache for the own object type,
initializes it properly and updates it to represent the current
state of their master, e.g. a link cache would include all
links currently configured in the kernel.

Some of the allocation functions may take additional arguments
to further specify what will be part of the cache.

All such functions return a newly allocated cache or NULL
in case of an error.

\section core_abstract_types 8. Abstract Data Types

A few high level abstract data types which are used by a majority netlink
protocols are implemented in the core library. More may be added in the
future if the need arises.

\subsection core_abstract_addr 8.1 Abstract Address

Most netlink protocols deal with networking related topics and thus
dealing with network addresses is a common task.

Currently the following address families are supported:
- AF_INET
- AF_INET6
- AF_LLC
- AF_DECnet
- AF_UNSPEC

\subsubsection core_abstract_addr_alloc 8.1.1 Address Allocation

The function nl_addr_alloc() allocates a new empty address. The
\p maxsize argument defines the maximum length of an address in bytes.
The size of an address is address family specific. If the address
family and address data are known at allocation time the function
nl_addr_build() can be used alternatively. You may also clone
an address by calling nl_addr_clone()

\code
#include <netlink/addr.h>

struct nl_addr *nl_addr_alloc(size_t maxsize);
struct nl_addr *nl_addr_clone(struct nl_addr *addr);
struct nl_addr *nl_addr_build(int family, void *addr, size_t size);
\endcode

If the address is transported in a netlink attribute, the function
nl_addr_alloc_attr() allocates a new address based on the payload
of the attribute provided. The \p family argument is used to specify
the address family of the address, set to \p AF_UNSPEC if unknown.

\code
#include <netlink/addr.h>

struct nl_addr *nl_addr_alloc_attr(struct nlattr *attr, int family);
\endcode

If the address is provided by a user, it is usually stored in a human
readable format. The function nl_addr_parse() parses a character
string representing an address and allocates a new address based on
it.

\code
#include <netlink/addr.h>

int nl_addr_parse(const char *addr, int hint, struct nl_addr **result);
\endcode

If parsing succeeds the function returns 0 and the allocated address
is stored in \p *result.

\b Note: Make sure to return the reference to an address using
         nl_addr_put() after usage to allow memory being freed.

\subsubsection core_abstract_addr_ref 8.1.2 Address References

Abstract addresses use reference counting to account for all users of
a particular address. After the last user has returned the reference
the address is freed.

If you pass on a address object to another function and you are not
sure how long it will be used, make sure to call nl_addr_get() to
acquire an additional reference and have that function or code path
call nl_addr_put() as soon as it has finished using the address.

\code
#include <netlink/addr.h>

struct nl_addr *nl_addr_get(struct nl_addr *addr);
void nl_addr_put(struct nl_addr *addr);
int nl_addr_shared(struct nl_addr *addr);
\endcode

You may call nl_addr_shared() at any time to check if you are the only
user of an address.

\subsubsection  core_abstract_addr_attr 8.1.3 Address Attributes

The address is usually set at allocation time. If it was unknown at that
time it can be specified later by calling nl_addr_set_family() and is
accessed with the function nl_addr_get_family().

\code
#include <netlink/addr.h>

void nl_addr_set_family(struct nl_addr *addr, int family);
int nl_addr_get_family(struct nl_addr *addr);
\endcode

The same is true for the actual address data. It is typically present
at allocation time. For exceptions it can be specified later or
overwritten with the function nl_addr_set_binary_addr(). Beware that
the length of the address may not exceed \p maxlen specified at
allocation time. The address data is returned by the function
nl_addr_get_binary_addr() and its length by the function
nl_addr_get_len().

\code
#include <netlink/addr.h>

int nl_addr_set_binary_addr(struct nl_addr *addr, void *data, size_t size);
void *nl_addr_get_binary_addr(struct nl_addr *addr);
unsigned int nl_addr_get_len(struct nl_addr *addr);
\endcode

If you only want to check if the address data consists of all zeros
the function nl_addr_iszero() is a shortcut to that.

\code
#include <netlink/addr.h>

int nl_addr_iszero(struct nl_addr *addr);
\endcode

\subsubsection core_abstract_addr_prefix 8.1.4 Address Prefix Length

Although this functionality is somewhat specific to routing it has
been implemented here. Addresses can have a prefix length assigned
which implies that only the first n bits are of importance. This
is f.e. used to implement subnets.

Use set functions nl_addr_set_prefixlen() and nl_addr_get_prefixlen()
to work with prefix lengths.

\code
#include <netlink/addr.h>

void nl_addr_set_prefixlen(struct nl_addr *addr, int n);
unsigned int nl_addr_get_prefixlen(struct nl_addr *addr);
\endcode

\b Note: The default prefix length is set to (address length * 8)

\subsubsection core_abstract_addr_helpers 8.1.5 Address Helpers

Several functions exist to help when dealing with addresses. The
function nl_addr_cmp() compares two addresses and returns an integer
less than, equal to or greater than zero without considering the prefix
length at all. If you want to consider the prefix length, use the
function nl_addr_cmp_prefix().

\code
#include <netlink/addr.h>

int nl_addr_cmp(struct nl_addr *addr, struct nl_addr *addr);
int nl_addr_cmp_prefix(struct nl_addr *addr, struct nl_addr *addr);
\endcode

If an abstract address needs to presented to the user it should be done
in a human readable format which differs depending on the address
family. The function nl_addr2str() takes care of this by calling the
appropriate conversion functions internaly. It expects a \p buf of
length \p size to write the character string into and returns a pointer
to \p buf for easy printf() usage.

\code
#include <netlink/addr.h>

char *nl_addr2str(struct nl_addr *addr, char *buf, size_t size);
\endcode

If the address family is unknown, the address data will be printed in
hexadecimal format AA:BB:CC:DD:...

Often the only way to figure out the address family is by looking at
the length of the address. The function nl_addr_guess_family() does just
this and returns the address family guessed based on the address size.

\code
#include <netlink/addr.h>

int nl_addr_guess_family(struct nl_addr *addr);
\endcode

Before allocating an address you may want to check if the character
string actually represents a valid address of the address family you are
expecting. The function nl_addr_valid() can be used for that, it returns
1 if the supplised \p addr is a valid address in the context of \p family.
See inet_pton(3), dnet_pton(3) for more information on valid adddress
formats.

\code
#include <netlink/addr.h>

int nl_addr_valid(char *addr, int family);
\endcode

\subsection core_abstract_data 8.2 Abstract Data

The abstract data type is a trivial datatype with the primary purpose
to simplify usage of netlink attributes of arbitary length.

\subsubsection core_abstract_data_alloc 8.2.1 Allocation of a Data Object

The function nl_data_alloc() alloctes a new abstract data object and
fill it with the provided data. nl_data_alloc_attr() does the same but
bases the data on the payload of a netlink attribute. New data objects
can also be allocated by cloning existing ones by using nl_data_clone().

\code
struct nl_data *nl_data_alloc(void *buf, size_t size);
struct nl_data *nl_data_alloc_attr(struct nlattr *attr);
struct nl_data *nl_data_clone(struct nl_data *data);
void nl_data_free(struct nl_data *data);
\endcode

\subsubsection core_abstract_data_access 8.2.2 Access to Data

The function nl_data_get() returns a pointer to the data, the size of
data is returned by nl_data_get_size().

\code
void *nl_data_get(struct nl_data *data);
size_t nl_data_get_size(struct nl_data *data);
\endcode

\subsubsection core_abstract_data_helpers 8.2.3 Data Helpers

The function nl_data_append() reallocates the internal data buffers and
appends the specified \p buf to the existing data.

\code
int nl_data_append(struct nl_data *data, void *buf, size_t size);
\endcode

\b Note: Call nl_data_append() invalidates all pointers returned by
         nl_data_get().

\code
int nl_data_cmp(struct nl_data *data, struct nl_data *data);
\endcode

*/
