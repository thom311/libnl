/*
 * netlink-private/utils.h	Local Utility Functions
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2012 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_UTILS_PRIV_H_
#define NETLINK_UTILS_PRIV_H_

#include <byteswap.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#define ntohll(x) (x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define ntohll(x) bswap_64((x))
#endif
#define htonll(x) ntohll(x)

extern const char *	nl_strerror_l(int err);

/* internal macro to calculate the size of a struct @type up to (and including) @field.
 * this will be used for .minlen policy fields, so that we require only a field of up
 * to the given size. */
#define _nl_offsetofend(type, field) (offsetof (type, field) + sizeof (((type *) NULL)->field))

#endif
