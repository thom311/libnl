/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2003-2012 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_UTILS_PRIV_H_
#define NETLINK_UTILS_PRIV_H_

#include <byteswap.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if __BYTE_ORDER == __BIG_ENDIAN
#define ntohll(x) (x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define ntohll(x) bswap_64((x))
#endif
#define htonll(x) ntohll(x)

/*****************************************************************************/

#define _NL_STRINGIFY_ARG(contents)       #contents
#define _NL_STRINGIFY(macro_or_string)    _NL_STRINGIFY_ARG (macro_or_string)

/*****************************************************************************/

#if defined (__GNUC__)
#define _NL_PRAGMA_WARNING_DO(warning)       _NL_STRINGIFY(GCC diagnostic ignored warning)
#elif defined (__clang__)
#define _NL_PRAGMA_WARNING_DO(warning)       _NL_STRINGIFY(clang diagnostic ignored warning)
#endif

/* you can only suppress a specific warning that the compiler
 * understands. Otherwise you will get another compiler warning
 * about invalid pragma option.
 * It's not that bad however, because gcc and clang often have the
 * same name for the same warning. */

#if defined (__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#define _NL_PRAGMA_WARNING_DISABLE(warning) \
        _Pragma("GCC diagnostic push") \
        _Pragma(_NL_PRAGMA_WARNING_DO("-Wpragmas")) \
        _Pragma(_NL_PRAGMA_WARNING_DO(warning))
#elif defined (__clang__)
#define _NL_PRAGMA_WARNING_DISABLE(warning) \
        _Pragma("clang diagnostic push") \
        _Pragma(_NL_PRAGMA_WARNING_DO("-Wunknown-warning-option")) \
        _Pragma(_NL_PRAGMA_WARNING_DO(warning))
#else
#define _NL_PRAGMA_WARNING_DISABLE(warning)
#endif

#if defined (__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6))
#define _NL_PRAGMA_WARNING_REENABLE \
    _Pragma("GCC diagnostic pop")
#elif defined (__clang__)
#define _NL_PRAGMA_WARNING_REENABLE \
    _Pragma("clang diagnostic pop")
#else
#define _NL_PRAGMA_WARNING_REENABLE
#endif

/*****************************************************************************/

#define _nl_unused                  __attribute__ ((__unused__))
#define _nl_auto(fcn)               __attribute__ ((__cleanup__(fcn)))

/*****************************************************************************/

#ifdef thread_local
#define _nl_thread_local thread_local
/*
 * Don't break on glibc < 2.16 that doesn't define __STDC_NO_THREADS__
 * see http://gcc.gnu.org/bugzilla/show_bug.cgi?id=53769
 */
#elif __STDC_VERSION__ >= 201112L &&                                           \
	!(defined(__STDC_NO_THREADS__) ||                                      \
	  (defined(__GNU_LIBRARY__) && __GLIBC__ == 2 &&                       \
	   __GLIBC_MINOR__ < 16))
#define _nl_thread_local _Thread_local
#else
#define _nl_thread_local __thread
#endif

/*****************************************************************************/

#define _NL_STATIC_ASSERT(cond) ((void) sizeof (char[(cond) ? 1 : -1]))

/*****************************************************************************/

#if defined(NL_MORE_ASSERTS) && NL_MORE_ASSERTS > 0
#define _nl_assert(cond) assert(cond)
#else
#define _nl_assert(cond) do { if (0) { assert(cond); } } while (0)
#endif

#define _nl_assert_not_reached() assert(0)

/*****************************************************************************/

#define _nl_assert_addr_family_or_unspec(addr_family)                          \
	do {                                                                   \
		typeof(addr_family) _addr_family = (addr_family);              \
                                                                               \
		_nl_assert(_addr_family == AF_UNSPEC ||                        \
			   _addr_family == AF_INET ||                          \
			   _addr_family == AF_INET6);                          \
	} while (0)

#define _nl_assert_addr_family(addr_family)                                    \
	do {                                                                   \
		typeof(addr_family) _addr_family = (addr_family);              \
                                                                               \
		_nl_assert(_addr_family == AF_INET ||                          \
			   _addr_family == AF_INET6);                          \
	} while (0)

/*****************************************************************************/

#define _NL_SWAP(pa, pb)                                                       \
	do {                                                                   \
		typeof(*(pa)) *_pa = (pa);                                     \
		typeof(*(pb)) *_pb = (pb);                                     \
		typeof(*_pa) _tmp;                                             \
                                                                               \
		_nl_assert(_pa);                                               \
		_nl_assert(_pb);                                               \
		_tmp = *_pa;                                                   \
		*_pa = *_pb;                                                   \
		*_pb = _tmp;                                                   \
	} while (0)

/*****************************************************************************/

#define _NL_N_ELEMENTS(arr) (sizeof(arr) / sizeof((arr)[0]))

/*****************************************************************************/

extern const char *nl_strerror_l(int err);

/*****************************************************************************/

/* internal macro to calculate the size of a struct @type up to (and including) @field.
 * this will be used for .minlen policy fields, so that we require only a field of up
 * to the given size. */
#define _nl_offsetofend(type, field) (offsetof (type, field) + sizeof (((type *) NULL)->field))

/*****************************************************************************/

#define _nl_clear_pointer(pp, destroy) \
	({ \
		__typeof__ (*(pp)) *_pp = (pp); \
		__typeof__ (*_pp) _p; \
		int _changed = 0; \
		\
		if (   _pp \
			&& (_p = *_pp)) { \
			_nl_unused const void *const _p_check_is_pointer = _p; \
			\
			*_pp = NULL; \
			\
			(destroy) (_p); \
			\
			_changed = 1; \
		} \
		_changed; \
	})

#define _nl_clear_free(pp) _nl_clear_pointer (pp, free)

#define _nl_steal_pointer(pp) \
	({ \
		__typeof__ (*(pp)) *const _pp = (pp); \
		__typeof__ (*_pp) _p = NULL; \
		\
		if (   _pp \
		    && (_p = *_pp)) { \
			*_pp = NULL; \
		} \
		\
		_p; \
	})

/*****************************************************************************/

#define _nl_malloc_maybe_a(alloca_maxlen, bytes, to_free) \
	({ \
		const size_t _bytes = (bytes); \
		__typeof__ (to_free) _to_free = (to_free); \
		__typeof__ (*_to_free) _ptr; \
		\
		_NL_STATIC_ASSERT ((alloca_maxlen) <= 500); \
		_nl_assert (_to_free && !*_to_free); \
		\
		if (_bytes <= (alloca_maxlen)) { \
			_ptr = alloca (_bytes); \
		} else { \
			_ptr = malloc (_bytes); \
			*_to_free = _ptr; \
		}; \
		\
		_ptr; \
	})

/*****************************************************************************/

static inline bool _nl_streq(const char *a, const char *b)
{
	return !strcmp(a, b);
}

static inline bool _nl_streq0(const char *a, const char *b)
{
	return a == b || (a && b && _nl_streq(a, b));
}

static inline char *
_nl_strncpy_trunc(char *dst, const char *src, size_t len)
{
	/* we don't use/reimplement strlcpy(), because we want the fill-all-with-NUL
	 * behavior of strncpy(). This is just strncpy() with gracefully handling truncation
	 * (and disabling the "-Wstringop-truncation" warning).
	 *
	 * Note that truncation is silently accepted.
	 */

	_NL_PRAGMA_WARNING_DISABLE ("-Wstringop-truncation");
	_NL_PRAGMA_WARNING_DISABLE ("-Wstringop-overflow");

	if (len > 0) {
		_nl_assert(dst);
		_nl_assert(src);

		strncpy(dst, src, len);

		dst[len - 1] = '\0';
	}

	_NL_PRAGMA_WARNING_REENABLE;
	_NL_PRAGMA_WARNING_REENABLE;

	return dst;
}

static inline char *
_nl_strncpy_assert(char *dst, const char *src, size_t len)
{
	/* we don't use/reimplement strlcpy(), because we want the fill-all-with-NUL
	 * behavior of strncpy(). This is just strncpy() with assertion against truncation
	 * (and disabling the "-Wstringop-truncation" warning).
	 *
	 * Note that truncation is still a bug and there is an _nl_assert()
	 * against that.
	 */

	_NL_PRAGMA_WARNING_DISABLE ("-Wstringop-truncation");
	_NL_PRAGMA_WARNING_DISABLE ("-Wstringop-overflow");

	if (len > 0) {
		_nl_assert(dst);
		_nl_assert(src);

		strncpy(dst, src, len);

		_nl_assert (dst[len - 1] == '\0');

		dst[len - 1] = '\0';
	}

	_NL_PRAGMA_WARNING_REENABLE;
	_NL_PRAGMA_WARNING_REENABLE;

	return dst;
}

#include "nl-auto.h"

#define _NL_RETURN_ON_ERR(cmd) \
	do { \
		int _err; \
		\
		_err = (cmd); \
		if (_err < 0) \
			return _err; \
	} while (0)

#define _NL_RETURN_E_ON_ERR(e, cmd) \
	do { \
		int _err; \
		\
		_err = (cmd); \
		if (_err < 0) { \
			_NL_STATIC_ASSERT((e) > 0); \
			return -(e); \
		} \
	} while (0)

/* _NL_RETURN_ON_PUT_ERR() shall only be used with a put command (nla_put or nlmsg_append).
 * These commands can either fail with a regular error code (which gets propagated)
 * or with -NLE_NOMEM. However, they don't really try to allocate memory, so we don't
 * want to propagate -NLE_NOMEM. Instead, we coerce such failure to -NLE_MSGSIZE. */
#define _NL_RETURN_ON_PUT_ERR(put_cmd) \
	do { \
		int _err; \
		\
		_err = (put_cmd); \
		if (_err < 0) { \
			if (_err == -NLE_NOMEM) { \
				/* nla_put() returns -NLE_NOMEM in case of out of buffer size. We don't
				 * want to propagate that error and map it to -NLE_MSGSIZE. */ \
				return -NLE_MSGSIZE; \
			} \
			/* any other error can only be due to invalid parameters. Propagate the
			 * error, however also assert that it cannot be reached. */ \
			_nl_assert_not_reached (); \
			return _err; \
		} else \
			_nl_assert (_err == 0); \
	} while (0)

static inline int
_nl_close(int fd)
{
	int r;

	r = close(fd);
	_nl_assert(r == 0 || fd < 0 || errno != EBADF);
	return r;
}

static inline void *
_nl_memdup(const void *ptr, size_t len)
{
	void *p;

	if (len == 0) {
		/* malloc() leaves it implementation defined whether to return NULL.
		 * Callers rely on returning NULL if len is zero. */
		return NULL;
	}

	p = malloc(len);
	if (!p)
		return NULL;
	memcpy(p, ptr, len);
	return p;
}

#define _nl_memdup_ptr(ptr) ((__typeof__(ptr)) _nl_memdup((ptr), sizeof(*(ptr))))

/*****************************************************************************/

typedef union {
	in_addr_t addr4;
	struct in_addr a4;
	struct in6_addr a6;
} _NLIPAddr;

static inline char *_nl_inet_ntop(int addr_family, const void *addr,
				  char buf[static INET_ADDRSTRLEN])
{
	char *r;

	_nl_assert_addr_family(addr_family);
	_nl_assert(addr);

	/* inet_ntop() is documented to fail, but if we pass a known address family
	 * and a suitably large buffer, it cannot. Assert for that. */

	r = (char *)inet_ntop(addr_family, addr, buf,
			      (addr_family == AF_INET) ? INET_ADDRSTRLEN :
							       INET6_ADDRSTRLEN);
	_nl_assert(r == buf);
	_nl_assert(strlen(r) < ((addr_family == AF_INET) ? INET_ADDRSTRLEN :
								 INET6_ADDRSTRLEN));

	return r;
}

static inline char *_nl_inet_ntop_dup(int addr_family, const void *addr)
{
	return (char *)_nl_inet_ntop(addr_family, addr,
				     malloc((addr_family == AF_INET) ?
						    INET_ADDRSTRLEN :
							  INET6_ADDRSTRLEN));
}

#endif
