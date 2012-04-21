#include <netlink/cli/utils.h>

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_msg *msg;
	void *hdr;
	int err;

	sock = nl_cli_alloc_socket();
	nl_cli_connect(sock, NETLINK_GENERIC);

	msg = nlmsg_alloc();
	if (msg == NULL)
		nl_cli_fatal(NLE_NOMEM, "Unable to allocate netlink message");

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, GENL_ID_CTRL,
			  0, 0, CTRL_CMD_GETFAMILY, 1);
	if (hdr == NULL)
		nl_cli_fatal(ENOMEM, "Unable to write genl header");

	if ((err = nla_put_u32(msg, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL)) < 0)
		nl_cli_fatal(err, "Unable to add attribute: %s", nl_geterror(err));

	if ((err = nl_send_auto_complete(sock, msg)) < 0)
		nl_cli_fatal(err, "Unable to send message: %s", nl_geterror(err));

	if ((err = nl_recvmsgs_default(sock)) < 0)
		nl_cli_fatal(err, "Unable to receive message: %s", nl_geterror(err));

	nlmsg_free(msg);
	nl_close(sock);
	nl_socket_free(sock);

	return 0;
}
