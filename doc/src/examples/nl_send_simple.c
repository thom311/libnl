#include <netlink/netlink.h>

struct nl_sock *sk;
struct rtgenmsg rt_hdr = {
	.rtgen_family = AF_UNSPEC,
};

sk = nl_socket_alloc();
nl_connect(sk, NETLINK_ROUTE);

nl_send_simple(sock, RTM_GETLINK, NLM_F_DUMP, &rt_hdr, sizeof(rt_hdr));
