#include "../src/utils.h"

int main(int argc, char *argv[])
{
	struct nl_handle *h;
	struct nl_msg *msg;
	void *hdr;

	if (nltool_init(argc, argv) < 0)
		return -1;

	h = nltool_alloc_handle();
	if (!h) {
		nl_perror("nl_handle_alloc");
		return -1;
	}

	if (genl_connect(h) < 0) {
		nl_perror("genl_connect");
		return -1;
	}

	msg = nlmsg_alloc();
	if (msg == NULL) {
		nl_perror("nlmsg_alloc");
		return -1;
	}

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, GENL_ID_CTRL,
			  0, 0, CTRL_CMD_GETFAMILY, 1);
	if (hdr == NULL) {
		nl_perror("genlmsg_put");
		return -1;
	}

	if (nla_put_u32(msg, CTRL_ATTR_FAMILY_ID, GENL_ID_CTRL) < 0) {
		nl_perror("nla_put_u32(CTRL_ATTR_FAMILY_ID)");
		return -1;
	}

	if (nl_send_auto_complete(h, msg) < 0) {
		nl_perror("nl_send_auto_complete");
		return -1;
	}

	if (nl_recvmsgs_default(h) < 0) {
		nl_perror("nl_recvmsgs_def");
		return -1;
	}

	nlmsg_free(msg);

	nl_close(h);

	return 0;
}
