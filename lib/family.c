/*
 * lib/family.c		Netlink Family
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @defgroup nlfam Netlink Families
 * @brief
 *
 * @{
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>

/**
 * @name Netlink Family Name Translation
 * @{
 */

static struct trans_tbl nlfamilies[] = {
	__ADD(NETLINK_ROUTE,route)
	__ADD(NETLINK_USERSOCK,usersock)
	__ADD(NETLINK_FIREWALL,firewall)
	__ADD(NETLINK_INET_DIAG,inetdiag)
	__ADD(NETLINK_NFLOG,nflog)
	__ADD(NETLINK_XFRM,xfrm)
	__ADD(NETLINK_SELINUX,selinux)
	__ADD(NETLINK_ISCSI,iscsi)
	__ADD(NETLINK_AUDIT,audit)
	__ADD(NETLINK_FIB_LOOKUP,fib_lookup)
	__ADD(NETLINK_CONNECTOR,connector)
	__ADD(NETLINK_NETFILTER,netfilter)
	__ADD(NETLINK_IP6_FW,ip6_fw)
	__ADD(NETLINK_DNRTMSG,dnrtmsg)
	__ADD(NETLINK_KOBJECT_UEVENT,kobject_uevent)
	__ADD(NETLINK_GENERIC,generic)
	__ADD(NETLINK_SCSITRANSPORT,scsitransport)
	__ADD(NETLINK_ECRYPTFS,ecryptfs)
};

char * nl_nlfamily2str(int family, char *buf, size_t size)
{
	return __type2str(family, buf, size, nlfamilies,
			  ARRAY_SIZE(nlfamilies));
}

int nl_str2nlfamily(const char *name)
{
	return __str2type(name, nlfamilies, ARRAY_SIZE(nlfamilies));
}

/** @} */

/** @} */
