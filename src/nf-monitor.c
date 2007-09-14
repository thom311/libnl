/*
 * src/nf-monitor.c     Monitor netfilter events
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 * Copyright (c) 2007 Philip Craig <philipc@snapgear.com>
 * Copyright (c) 2007 Secure Computing Corporation
 */

#include "utils.h"
#include <netlink/netfilter/nfnl.h>

static void obj_input(struct nl_object *obj, void *arg)
{
	struct nl_dump_params dp = {
		.dp_type = NL_DUMP_STATS,
		.dp_fd = stdout,
		.dp_dump_msgtype = 1,
	};

	nl_object_dump(obj, &dp);
}

static int event_input(struct nl_msg *msg, void *arg)
{
	if (nl_msg_parse(msg, &obj_input, NULL) < 0)
		fprintf(stderr, "<<EVENT>> Unknown message type\n");

	/* Exit nl_recvmsgs_def() and return to the main select() */
	return NL_STOP;
}

int main(int argc, char *argv[])
{
	struct nl_handle *nlh;
	int err = 1;
	int i, idx;

	static const struct {
		enum nfnetlink_groups gr_id;
		const char* gr_name;
	} known_groups[] = {
		{ NFNLGRP_CONNTRACK_NEW, "ct-new" },
		{ NFNLGRP_CONNTRACK_UPDATE, "ct-update" },
		{ NFNLGRP_CONNTRACK_DESTROY, "ct-destroy" },
		{ NFNLGRP_NONE, NULL }
	};

	if (nltool_init(argc, argv) < 0)
		return -1;

	nlh = nltool_alloc_handle();
	if (nlh == NULL)
		return -1;

	nl_disable_sequence_check(nlh);

	nl_socket_modify_cb(nlh, NL_CB_VALID, NL_CB_CUSTOM, event_input, NULL);

	if (argc > 1 && !strcasecmp(argv[1], "-h")) {
		printf("Usage: nf-monitor [<groups>]\n");

		printf("Known groups:");
		for (i = 0; known_groups[i].gr_id != NFNLGRP_NONE; i++)
			printf(" %s", known_groups[i].gr_name);
		printf("\n");
		return 2;
	}

	if (nfnl_connect(nlh) < 0) {
		fprintf(stderr, "%s\n", nl_geterror());
		goto errout;
	}

	for (idx = 1; argc > idx; idx++) {
		for (i = 0; known_groups[i].gr_id != NFNLGRP_NONE; i++) {
			if (!strcmp(argv[idx], known_groups[i].gr_name)) {

				if (nl_socket_add_membership(nlh, known_groups[i].gr_id) < 0) {
					fprintf(stderr, "%s: %s\n", argv[idx], nl_geterror());
					goto errout;
				}

				break;
			}
		}
		if (known_groups[i].gr_id == NFNLGRP_NONE)
			fprintf(stderr, "Warning: Unknown group: %s\n", argv[idx]);
	}

	while (1) {
		fd_set rfds;
		int fd, retval;

		fd = nl_socket_get_fd(nlh);

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		/* wait for an incoming message on the netlink socket */
		retval = select(fd+1, &rfds, NULL, NULL, NULL);

		if (retval) {
			/* FD_ISSET(fd, &rfds) will be true */
			nl_recvmsgs_default(nlh);
		}
	}

	nl_close(nlh);
errout:
	return err;
}
