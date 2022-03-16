/* SPDX-License-Identifier: LGPL-2.1-only */

#ifndef __NL_TEST_UTIL_H__
#define __NL_TEST_UTIL_H__

#include <errno.h>
#include <check.h>

#include "netlink/object.h"
#include "netlink/cache.h"

/*****************************************************************************/

#ifndef ck_assert_ptr_nonnull
#define ck_assert_ptr_nonnull(ptr) ck_assert(ptr)
#endif

#define _nltst_assert_errno(expr)                                              \
	do {                                                                   \
		if (expr) {                                                    \
		} else {                                                       \
			const int _errno = (errno);                            \
                                                                               \
			ck_assert_msg(0, "assert(%s) failed (errno=%d, %s)",   \
				      #expr, _errno, strerror(_errno));        \
		}                                                              \
	} while (0)

#define _nltst_close(fd)                                                       \
	do {                                                                   \
		int _r;                                                        \
                                                                               \
		_r = _nl_close((fd));                                          \
		_nltst_assert_errno(_r == 0);                                  \
	} while (0)

/*****************************************************************************/

void nltst_netns_fixture_setup(void);
void nltst_netns_fixture_teardown(void);

struct nltst_netns;

struct nltst_netns *nltst_netns_enter(void);
void nltst_netns_leave(struct nltst_netns *nsdata);

/*****************************************************************************/

void _nltst_object_identical(const void *a, const void *b);

struct nl_object **_nltst_cache_get_all(struct nl_cache *cache,
					size_t *out_len);

struct nl_sock *_nltst_socket(int protocol);

void _nltst_add_link(struct nl_sock *sk, const char *ifname, const char *kind);

#endif /* __NL_TEST_UTIL_H__ */
