/**
 * \cond skip
 * vim:syntax=doxygen
 * \endcond

\page core_doc Netlink Core Library (-lnl)

\section core_intro Introduction

The core library contains the fundamentals required to communicate over
netlink sockets. It deals with connecting and disconnectng of sockets,
sending and receiving of data, provides a customizeable receiving state
machine, and provides a abstract data type framework which eases the
implementation of object based netlink protocols where objects are added,
removed, or modified with the help of netlink messages.

\section core_toc Table of Contents

- \ref proto_fund
  - \ref core_format
  - \ref core_msgtype
  - \ref core_multipart
  - \ref core_errmsg
  - \ref core_ack
- \ref sk_doc
  - \ref core_sk_alloc
  - \ref core_sk_local_port
  - \ref core_sk_peer_port
  - \ref core_sk_fd
  - \ref core_sk_buffer_size
  - \ref core_sk_groups
- \ref core_send_recv
  - \ref core_send
  - \ref core_recv
- \ref core_msg
- \ref core_cb

\section proto_fund 1. Netlink Protocol Fundamentals

The netlink protocol is a socket based IPC mechanism used for communication
between any number of userspace processes and the kernel. The netlink
protocol is based on BSD sockets and uses the \c AF_NETLINK address family.
It uses a protocol type for each subsystem protocol (e.g. NETLINK_ROUTE,
NETLINK_NETFILTER, etc). Its addressing schema is based on a 32 bit port
number, formerly referred to as PID, which uniquely identifies each peer.

\subsection core_format 1.1 Message Format

A netlink protocol is typicall based on messages and consists of the
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

\subsection core_msgtype 1.2 Message Types

Netlink differs between requests, notifications, and replies. Requests
are messages which have the \c NLM_F_REQUEST flag set and are meant to
request an action from the receiver. A request is typically sent from
a userspace process to the kernel. While not strictly enforced, requests
should carry a sequence number incremented for each request sent.

Depending on the nature of the request, the receiver may reply to the
request with another netlink message. The sequence number of a reply
must match the sequence number of the request it relates to.

Notifications are of informal nature and no reply is expected, therefore
the sequence number is typically set to 0. It should be noted that unlike
in protocols such as TCP there is no strict enforcment of the sequence
number. The sole purpose of sequence numbers is to assist a sender in
relating replies to the corresponding requests.

\msc
A,B;
A=>B [label="GET (seq=1, NLM_F_REQUEST)"];
A<=B [label="PUT (seq=1)"];
...;
A<=B [label="NOTIFY (seq=0)"];
\endmsc

\subsection core_multipart 1.3 Multipart Messages (NLM_F_MULTI)

If the size of a reply exceeds the size of a memory page and thus exceeds
the maximum message size, the reply can be split into a series of multipart
messages. A multipart message has the \c flag NLM_F_MULTI set and the
receiver is expected to continue parsing the reply until the special
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

\subsection core_errmsg 1.4 Error Message

Error messages can be sent in response to a request. Error messages must
use the standard message type \c NLMSG_ERROR. The payload consists of a
error code and the original netlink mesage header of the request. Error
messages should set the sequence number to the sequence number of the
request which caused the error.

\msc
A,B;
A=>B [label="GET (seq=1, NLM_F_REQUEST)"];
A<=B [label="NLMSG_ERROR code=EINVAL (seq=1)"];
\endmsc

\subsection core_ack 1.5 ACKs

A sender can request an ACK message to be sent back for each request
processed by setting the \c NLM_F_ACK flag in the request. This is typically
used to allow the sender to synchronize further processing until the
request has been processed by the receiver.

ACK messages also use the message type \c NLMSG_ERROR and payload format
but the error code is set to 0.

\msc
A,B;
A=>B [label="GET (seq=1, NLM_F_REQUEST | NLM_F_ACK)"];
A<=B [label="ACK (seq=1)"];
\endmsc

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
struct nl_sock *nl_socket_alloc(void)
void nl_socket_free(struct nl_sock *sk)
\endcode


\subsection core_sk_local_port 2.2 Local Port

The local port number uniquely identifies the socket and is used to
address it. A unique local port is generated automatically when the socket
is allocated. It will consist of the Process ID (22 bits) and a random
number (10 bits) thus allowing up to 1024 sockets per process.

\code
uint32_t nl_socket_get_local_port(const struct nl_sock *sk);
void nl_socket_set_local_port(struct nl_sock *sk, uint32_t port);
\endcode

\b Note: Overwriting the local port is possible but you have to ensure
that the provided value is unique and no other socket in any other
application is using the same value.

\subsection core_sk_peer_port 2.3 Peer Port

A peer port can be assigned to the socket which will result in all unicast
messages sent over the socket to be addresses to the peer. If no peer is
specified, the message is sent to the kernel which will try to automatically
bind the socket to a kernel side socket of the same netlink protocol family.
It is common practice not to bind the socket to a peer port as typically
only one kernel side socket exists per netlink protocol family.

\code
uint32_t nl_socket_get_peer_port(const struct nl_sock *sk);
void nl_socket_set_peer_port(struct nl_sock *sk, uint32_t port);
\endcode

\subsection core_sk_fd 2.4 File Descriptor

Netlink uses the BSD socket interface, therefore a file descriptor
is behind each socket and you may use it directly.

\code
int nl_socket_get_fd(const struct nl_sock *sk);
\endcode

If a socket is used to only receive notifications it usually is best
to put the socket in non-blocking mode and periodically poll for new
notifications.

\code
int nl_socket_set_nonblocking(const struct nl_sock *sk);
\endcode

\subsection core_sk_buffer_size 2.5 Buffer Size

The socket buffer is used to queue netlink messages between sender
and receiver. The size of these buffers specifies the maximum size
you will be able to write() to a netlink socket, i.e. it will indirectly
define the maximum message size. The default is 32KiB.

\code
int nl_socket_set_buffer_size(struct nl_sock *sk, int rx, int tx);
\endcode

\subsection core_sk_seq_num 2.6 Sequence Numbers

The library will automatically take care of sequence number handling for
the application. A sequence number counter is stored in struct nl_sock which
is meant to be used when sending messages which will produce a reply.

The following function will return the sequence number counter and increment
it afterwards.

\code
unsigned int nl_socket_use_seq(struct nl_sock *sk);
\endcode


if nl_send_auto_complete() is used to send messages.

See \ref core_send_recv.



It will return the current sequence number and increment the counter
afterwards.

When receiving netlink messages on a socket, the sequence number of
each received message will be automatically compared to the last
sequence number used, therefore ensuring that each reply relates to
a request.

This behaviour can and must be disabled if the netlink protocol
implemented does not use a request/reply model:

\code
void nl_socket_disable_seq_check(struct nl_sock *sk);
\endcode

\subsection core_sk_groups 2.6 Multicast Groups

Each socket can subscribe to any number of multicast groups of the
netlink protocol it is connected to. The socket will then receive a copy
of each message sent to any of the groups. Multicast groups are commonly
used to implement event notifications.

Prior to kernel 2.6.14 the group subscription was performed using a bitmask
which limited the number of groups per protocol family to 32. This outdated
interface can still be accessed via the function nl_join_groups even though
it is not recommended for new code.

\code
void nl_join_groups(struct nl_sock *sk, int bitmask); /* obsolete */
\endcode

Starting with 2.6.14 a new method was introduced which supports subscribing
to an almost infinite number of multicast groups.

\code
int nl_socket_add_memberships(struct nl_sock *sk, int group, ...);
int nl_socket_drop_memberships(struct nl_sock *sk, int group, ...);
\endcode

\subsubsection core_sk_group_example 2.6.1 Multicast Example

\code
// This function will be called for each valid netlink message received
// in nl_recvmsgs_default()
static int my_func(struct nl_msg *msg, void *arg)
{
	return 0;
}

struct nl_sock *sk;

// Allocate a new socket
sk = nl_socket_alloc();

// Notifications do not use sequence numbers, disable sequence number
// checking.
nl_socket_disable_seq_check(sk);

// Define a callback function, which will be called for each notification
// received
nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, my_func, NULL);

// Connect to routing netlink protocol
nl_connect(sk, NETLINK_ROUTE);

// Subscribe to link notifications group
nl_socket_add_memberships(sk, RTNLGRP_LINK);

// Start receiving messages. The function nl_recvmsgs_default() will block
// until one or more netlink messages (notification) are received which
// will be passed on to my_func().
while (1)
	nl_recvmsgs_default(sock);
\endcode


\subsection core_sk_cb 2.7 Callback Configuration
Every socket is associated a callback configuration which enables the
applications to hook into various internal functions and control the
receiving and sendings semantics. For more information, see section
\ref core_cb.

\code
nl_socket_alloc_cb(cb)                 Allocate socket based on callback set.
nl_socket_get_cb(sk)                   Return callback configuration.
nl_socket_set_cb(sk, cb)               Replace callback configuration.
nl_socket_modify_cb(sk, ...)           Modify a specific callback function.
\endcode

\subsection core_sk_cred 2.8 Credentials

\subsection sk_other Other Functions
\code
nl_socket_enable_auto_ack(sock)        Enable automatic request of ACK.
nl_socket_disable_auto_ack(sock)       Disable automatic request of ACK.
nl_socket_enable_msg_peek(sock)        Enable message peeking.
nl_socket_disable_msg_peek(sock)       Disable message peeking.
nl_socket_set_passcred(sk, state)      Enable/disable credential passing.
nl_socket_recv_pktinfo(sk, state)      Enable/disable packet information.
\endcode

\section core_send_recv 3. Sending and Receiving of Messages / Data

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

\subsection core_send 3.1 Sending Netlink Messages

The standard method of sending a netlink message over a netlink socket
is to use the function nl_send_auto(). It will automatically complete
the netlink message by filling the missing bits and pieces in the
netlink message header and will deal with addressing based on the
options and address set in the netlink socket. The message is then based
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
         |- - - - - - - - - - - - - - - - - - - - v
         |                                 NL_CB_MSG_OUT()
         |<- - - - - - - - - - - - - - - - - - - -+
         v
   sendmsg()
\endcode

\subsubsection core_nl_sendmsg 3.1.3 Using nl_sendmsg()

nl_sendmsg() expects a finalized netlink message and an optional struct
msghdr containing the peer address. It will copy the local address as
defined in the socket (see nl_socket_set_local_port()) into the netlink
message header.

At this point, construction of the message finished and it is ready to
be sent.

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
int nl_sendto(struct nl_sock *sk, void *buf, size_t size);
\endcode

\subsubsection core_send_simple 3.1.5 Sending of Simple Messages

A special interface exists for sending of trivial messages. The function
expects the netlink message type, optional netlink message flags, and an
optional data buffer and data length.  
\code
int nl_send_simple(struct nl_sock *sk, int type, int flags,
                   void *buf, size_t size);
\endcode

The function will construct a netlink message header based on the message
type and flags provided and append the data buffer as message payload. The
newly constructed message is sent with nl_send_auto().

The following example will send a netlink request message causing the
kernel to dump a list of all network links to userspace:
\code
struct nl_sock *sk;
struct rtgenmsg rt_hdr = {
	.rtgen_family = AF_UNSPEC,
};

sk = nl_socket_alloc();
nl_connect(sk, NETLINK_ROUTE);

nl_send_simple(sock, RTM_GETLINK, NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
\endcode

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

\section core_msg 4. Message Construction & Parsing

\subsection core_msg_format 4.1 Message Format

\section core_cb 5. Callback Configurations

Callback hooks and overwriting capabilities are provided in various places
inside library code to control the behaviour of several functions. All
the callback and overwrite functions are packed together in struct nl_cb
which is attached to a netlink socket or passed on to functions directly.

\subsection cb_func 5.1 Callback Function Formats

\subsubsection cb_func_recvmsgs 5.1.1 Callbacks for nl_recvmsgs() and nl_sendmsg()

Both nl_recvmsgs() and nl_sendmsg() provide callback hooks for functions to
control their behaviour. Every callback function must have the following
prototype:

\code
typedef int(* nl_recvmsg_msg_cb_t)(struct nl_msg *msg, void *arg);
\endcode

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

All these callback hooks can control the flow of the callee by returning
appropriate error codes:
\code
Return Code      | Description
-------------------------------------------------------------------------
NL_OK            | Proceed.
NL_SKIP          | Skip message currently being processed and continue
                 | parsing the receive buffer.
NL_STOP          | Stop parsing and discard all remaining data in the
                 | receive buffer.
\endcode

\subsubsection cb_func_error 5.1.2 Callback for Error Messages

A special function prototype is used for the error message callback hook:

\code
typedef int(* nl_recvmsg_err_cb_t)(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg);
\endcode

\subsubsection cb_cb_set 5.1.3 Setting Callback Functions

In order to simplify typical usages of the library, different sets of
default callback implementations exist:
\code
NL_CB_DEFAULT: No additional actions
NL_CB_VERBOSE: Automatically print warning and error messages to a file
               descriptor as appropriate. This is useful for CLI based
               applications.
NL_CB_DEBUG:   Print informal debugging information for each message
               received. This will result in every message beint sent or
               received to be printed to the screen in a decoded,
               human-readable format.
\endcode

\subsubsection core_cb_example 5.1.4 Example: Setting up a callback set
\code
// Allocate a callback set and initialize it to the verbose default set
struct nl_cb *cb = nl_cb_alloc(NL_CB_VERBOSE);

// Modify the set to call my_func() for all valid messages
nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, my_func, NULL);

// Set the error message handler to the verbose default implementation
// and direct it to print all errors to the given file descriptor.
FILE *file = fopen(...);
nl_cb_err(cb, NL_CB_VERBOSE, NULL, file);
\endcode

\section remarks Remarks

\subsection cache_alloc Allocation of Caches

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

\subsection addr Setting of Addresses
\code
int <object name>_set_addr(struct nl_object *, struct nl_addr *)
\endcode

All attribute functions avaiable for assigning addresses to objects
take a struct nl_addr argument. The provided address object is
validated against the address family of the object if known already.
The assignment fails if the address families mismatch. In case the
address family has not been specified yet, the address family of
the new address is elected to be the new requirement.

The function will acquire a new reference on the address object
before assignment, the caller is NOT responsible for this.

All functions return 0 on success or a negative error code.

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


*/
