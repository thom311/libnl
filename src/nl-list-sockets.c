/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2003-2009 Thomas Graf <tgraf@suug.ch>
 */

#include "nl-default.h"

#include <netlink/cli/utils.h>

#define PROC_NETLINK "/proc/net/netlink"

int main(int argc, char *argv[])
{
	FILE *fd;
	char buf[2048], p[64];

	fd = fopen(PROC_NETLINK, "re");
	if (fd == NULL) {
		perror("fopen");
		return -1;
	}

	printf("Address            Family           PID    Groups   rmem   "
	       "wmem   CB         refcnt\n");

	while (fgets(buf, sizeof(buf), fd)) {
		unsigned long sk, cb;
		int ret, proto, pid, rmem, wmem, refcnt;
		unsigned int groups;
		
		ret = sscanf(buf, "%lx %d %d %08x %d %d %lx %d\n",
			     &sk, &proto, &pid, &groups, &rmem, &wmem,
			     &cb, &refcnt);
		if (ret != 8)
			continue;
		
		printf("0x%016lx %-16s %-6d %08x %-6d %-6d 0x%08lx %d\n",
			sk, nl_nlfamily2str(proto, p, sizeof(p)), pid,
			groups, rmem, wmem, cb, refcnt);
	}

	fclose(fd);

	return 0;
}
