/* SPDX-License-Identifier: LGPL-2.1-only */

#include "nl-default.h"

#include "nl-test-util.h"

#include <fcntl.h>
#include <fnmatch.h>
#include <sched.h>
#include <stdio.h>
#include <sys/mount.h>

#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/socket.h>

#include "lib/route/nl-route.h"

#include "nl-aux-route/nl-route.h"

/*****************************************************************************/

void _nltst_get_urandom(void *ptr, size_t len)
{
	int fd;
	ssize_t nread;

	ck_assert_int_gt(len, 0);
	ck_assert_ptr_nonnull(ptr);

	fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOCTTY);
	_nltst_assert_errno(fd >= 0);

	nread = read(fd, ptr, len);
	_nltst_assert_errno(nread >= 0 && ((size_t)nread) == len);

	_nltst_close(fd);
}

uint32_t _nltst_rand_u32(void)
{
	_nl_thread_local static unsigned short entropy[3];
	_nl_thread_local static bool has_entropy = false;

	if (!has_entropy) {
		unsigned long long seed;
		uint64_t seed64;
		const char *s;
		char *s_end;

		memset(entropy, 0, sizeof(entropy));
		s = getenv("NLTST_SEED_RAND");
		if (!s)
			seed = 0;
		else if (s[0] != '\0') {
			errno = 0;
			seed = strtoull(s, &s_end, 10);
			if (errno != 0 || s_end[0] != '\0') {
				ck_assert_msg(
					0,
					"invalid NLTST_SEED_RAND=\"%s\". Must be an integer to seed the random numbers",
					s);
			}
		} else
			_nltst_get_urandom(&seed, sizeof(seed));

		seed64 = seed;
		printf("runs with NLTST_SEED_RAND=%" PRIu64 "\n", seed64);

		entropy[0] = (seed64 >> 0) ^ (seed64 >> 48);
		entropy[1] = (seed64 >> 16) ^ (seed64 >> 0);
		entropy[2] = (seed64 >> 32) ^ (seed64 >> 16);
		has_entropy = true;
	}

	_NL_STATIC_ASSERT(sizeof(long) >= sizeof(uint32_t));
	return jrand48(entropy);
}

/*****************************************************************************/

#define _CANARY 539339

struct nltst_netns {
	int canary;
};

/*****************************************************************************/

#define _assert_nltst_netns(nsdata)                           \
	do {                                                  \
		const struct nltst_netns *_nsdata = (nsdata); \
                                                              \
		ck_assert_ptr_nonnull(_nsdata);               \
		ck_assert_int_eq(_nsdata->canary, _CANARY);   \
	} while (0)

static struct {
	struct nltst_netns *nsdata;
} _netns_fixture_global;

void nltst_netns_fixture_setup(void)
{
	ck_assert(!_netns_fixture_global.nsdata);

	_netns_fixture_global.nsdata = nltst_netns_enter();
	_assert_nltst_netns(_netns_fixture_global.nsdata);
}

void nltst_netns_fixture_teardown(void)
{
	_assert_nltst_netns(_netns_fixture_global.nsdata);
	_nl_clear_pointer(&_netns_fixture_global.nsdata, nltst_netns_leave);
}

/*****************************************************************************/

static void unshare_user(void)
{
	const uid_t uid = geteuid();
	const gid_t gid = getegid();
	FILE *f;
	int r;

	/* Become a root in new user NS. */
	r = unshare(CLONE_NEWUSER);
	_nltst_assert_errno(r == 0);

	/* Since Linux 3.19 we have to disable setgroups() in order to map users.
	 * Just proceed if the file is not there. */
	f = fopen("/proc/self/setgroups", "we");
	if (f) {
		r = fprintf(f, "deny");
		_nltst_assert_errno(r > 0);
		_nltst_fclose(f);
	}

	/* Map current UID to root in NS to be created. */
	f = fopen("/proc/self/uid_map", "we");
	if (!f) {
		if (errno == EACCES) {
			/* Accessing uid_map might fail due to sandboxing.
			 * We ignore that error and proceed with the test. It will probably
			 * still work. */
			return;
		}
		_nltst_assert_errno(f);
	}
	r = fprintf(f, "0 %d 1", uid);
	_nltst_assert_errno(r > 0);
	_nltst_fclose(f);

	/* Map current GID to root in NS to be created. */
	f = fopen("/proc/self/gid_map", "we");
	_nltst_assert_errno(f);
	r = fprintf(f, "0 %d 1", gid);
	_nltst_assert_errno(r > 0);
	_nltst_fclose(f);
}

struct nltst_netns *nltst_netns_enter(void)
{
	struct nltst_netns *nsdata;
	int r;

	nsdata = calloc(1, sizeof(struct nltst_netns));
	ck_assert(nsdata);

	nsdata->canary = _CANARY;

	unshare_user();

	r = unshare(CLONE_NEWNET | CLONE_NEWNS);
	_nltst_assert_errno(r == 0);

	/* We need a read-only /sys so that the platform knows there's no udev. */
	mount(NULL, "/sys", "sysfs", MS_SLAVE, NULL);
	r = mount("sys", "/sys", "sysfs", MS_RDONLY, NULL);
	_nltst_assert_errno(r == 0);

	return nsdata;
}

void nltst_netns_leave(struct nltst_netns *nsdata)
{
	ck_assert(nsdata);
	ck_assert_int_eq(nsdata->canary, _CANARY);

	/* nltst_netns_leave() was supposed to enter the original namespaces again
	 * and undo enter.
	 *
	 * However, I could get it to work (setns() always fails with EPERM)
	 * and valgrind on current Ubuntu seems not to support setns() call.
	 *
	 * So, do nothing. It's not really a problem, because the next test
	 * either should unshare yet another namespace, or not care about
	 * such things. */

	free(nsdata);
}

/*****************************************************************************/

void _nltst_object_identical(const void *a, const void *b)
{
	struct nl_object *o_a = (void *)a;
	struct nl_object *o_b = (void *)b;

	ck_assert(a);
	ck_assert(b);

	ck_assert_int_eq(nl_object_identical(o_a, o_b), 1);
	ck_assert_int_eq(nl_object_identical(o_b, o_a), 1);
	ck_assert_int_eq(nl_object_diff64(o_b, o_a), 0);
	ck_assert_int_eq(nl_object_diff64(o_a, o_b), 0);
	ck_assert_int_eq(nl_object_diff(o_a, o_b), 0);
	ck_assert_int_eq(nl_object_diff(o_b, o_a), 0);
}

/*****************************************************************************/

char *_nltst_object_to_string(const struct nl_object *obj)
{
	size_t L = 1024;
	size_t l;
	char *s;
	struct nl_dump_params dp;
	char canary;

	if (!obj)
		return strdup("(null)");

	s = malloc(L);
	ck_assert_ptr_nonnull(s);

	canary = _nltst_rand_u32();
	s[L - 1u] = canary;

	dp = (struct nl_dump_params){
		.dp_type = NL_DUMP_LINE,
		.dp_buf = s,
		.dp_buflen = L - 1u,
	};

	nl_object_dump((struct nl_object *)obj, &dp);

	l = strlen(s);
	ck_assert_int_ge(l, 2);
	ck_assert_int_lt(l, L);
	ck_assert(canary == s[L - 1u]);
	s = realloc(s, l + 1);
	ck_assert_ptr_nonnull(s);

	ck_assert_msg(s[l - 1u] == '\n',
		      "expects newline after dump. Got \"%s\"", s);
	s[l - 1u] = '\0';

	ck_assert_msg(!strchr(s, '\n'),
		      "no further newline expected. Got \"%s\"", s);

	return s;
}

struct cache_get_all_data {
	struct nl_object **arr;
	size_t len;
	size_t idx;
};

static void _cache_get_all_fcn(struct nl_object *obj, void *user_data)
{
	struct cache_get_all_data *data = user_data;
	size_t i;

	ck_assert(obj);
	ck_assert_int_lt(data->idx, data->len);

	for (i = 0; i < data->idx; i++)
		ck_assert_ptr_ne(data->arr[i], obj);

	data->arr[data->idx++] = obj;
}

struct nl_object **_nltst_cache_get_all(struct nl_cache *cache, size_t *out_len)
{
	int nitems;
	struct cache_get_all_data data = {
		.idx = 0,
		.len = 0,
	};
	size_t len2 = 0;
	size_t i;
	size_t j;

	ck_assert(cache);

	nitems = nl_cache_nitems(cache);
	ck_assert_int_ge(nitems, 0);

	data.len = nitems;
	data.arr = malloc(sizeof(struct nl_object *) * (data.len + 1));
	ck_assert_ptr_nonnull(data.arr);

	nl_cache_foreach(cache, _cache_get_all_fcn, &data);

	ck_assert_int_eq(data.idx, data.len);

	ck_assert_int_le(data.len, SSIZE_MAX);

	data.arr[data.len] = NULL;
	if (out_len)
		*out_len = data.len;

	/* double check the result. */
	for (struct nl_object *obj = nl_cache_get_first(cache); obj;
	     obj = nl_cache_get_next(obj)) {
		ck_assert_ptr_eq(data.arr[len2], obj);
		len2++;
	}
	ck_assert_ptr_null(data.arr[len2]);

	for (i = 0; i < data.len; i++) {
		ck_assert_ptr_nonnull(data.arr[i]);
		for (j = i + 1; j < data.len; j++)
			ck_assert_ptr_ne(data.arr[i], data.arr[j]);
	}

	return data.arr;
}

struct rtnl_link *_nltst_cache_get_link(struct nl_cache *cache,
					const char *ifname)
{
	_nl_auto_free struct nl_object **objs = NULL;
	struct rtnl_link *link = NULL;
	size_t i;

	ck_assert_ptr_nonnull(cache);
	ck_assert_ptr_nonnull(ifname);

	objs = _nltst_cache_get_all(cache, NULL);
	for (i = 0; objs[i]; i++) {
		if (_nl_streq(rtnl_link_get_name((struct rtnl_link *)objs[i]),
			      ifname)) {
			ck_assert_ptr_null(link);
			link = (struct rtnl_link *)objs[i];
		}
	}

	if (_nltst_rand_u32_range(5) == 0) {
		_nl_auto_rtnl_link struct rtnl_link *link2 = NULL;

		link2 = rtnl_link_get_by_name(cache, ifname);
		ck_assert_ptr_eq(link2, link);
	}

	return link;
}

/*****************************************************************************/

struct nl_sock *_nltst_socket(int protocol)
{
	struct nl_sock *sk;
	int r;

	sk = nl_socket_alloc();
	ck_assert(sk);

	r = nl_connect(sk, protocol);
	ck_assert_int_eq(r, 0);

	if (_nltst_rand_u32_range(5) == 0)
		nl_cache_free(_nltst_rtnl_link_alloc_cache(sk, AF_UNSPEC, 0));

	if (_nltst_rand_u32_range(5) == 0)
		nl_cache_free(_nltst_rtnl_route_alloc_cache(
			sk, _nltst_rand_select(AF_UNSPEC, AF_INET, AF_INET6)));

	return sk;
}

void _nltst_add_link(struct nl_sock *sk, const char *ifname, const char *kind,
		     int *out_ifindex)
{
	_nl_auto_nl_socket struct nl_sock *sk_free = NULL;
	_nl_auto_rtnl_link struct rtnl_link *link = NULL;
	_nl_auto_nl_cache struct nl_cache *cache = NULL;
	struct rtnl_link *link2;
	int ifindex;
	int r;

	ck_assert(ifname);
	ck_assert(kind);

	if (_nltst_rand_u32_range(5) == 0)
		_nltst_assert_link_not_exists(ifname);

	if (!sk) {
		sk = _nltst_socket(NETLINK_ROUTE);
		sk_free = sk;
	}

	link = rtnl_link_alloc();
	ck_assert(link);

	r = rtnl_link_set_type(link, kind);
	ck_assert_int_eq(r, 0);

	rtnl_link_set_name(link, ifname);

	r = rtnl_link_add(sk, link, NLM_F_CREATE);
	ck_assert_int_eq(r, 0);

	if (!out_ifindex && _nltst_rand_u32_range(5) != 0)
		return;

	cache = _nltst_rtnl_link_alloc_cache(sk, AF_UNSPEC, 0);

	link2 = _nltst_cache_get_link(cache, ifname);
	ck_assert_ptr_nonnull(link2);

	ifindex = rtnl_link_get_ifindex(link2);
	ck_assert_int_gt(ifindex, 0);

	if (out_ifindex)
		*out_ifindex = ifindex;
}

void _nltst_delete_link(struct nl_sock *sk, const char *ifname)
{
	_nl_auto_nl_socket struct nl_sock *sk_free = NULL;
	_nl_auto_rtnl_link struct rtnl_link *link = NULL;

	_nltst_assert_link_exists(ifname);

	if (!sk) {
		sk = _nltst_socket(NETLINK_ROUTE);
		sk_free = sk;
	}

	if (_nltst_rand_u32_range(5) == 0) {
		_nl_auto_nl_cache struct nl_cache *cache = NULL;

		cache = _nltst_rtnl_link_alloc_cache(sk, AF_UNSPEC, 0);
		ck_assert_ptr_nonnull(_nltst_cache_get_link(cache, ifname));
	}

	link = rtnl_link_alloc();
	ck_assert_ptr_nonnull(link);

	rtnl_link_set_name(link, ifname);

	_nltst_assert_retcode(rtnl_link_delete(sk, link));

	_nltst_assert_link_not_exists(ifname);
}

void _nltst_get_link(struct nl_sock *sk, const char *ifname, int *out_ifindex,
		     struct rtnl_link **out_link)
{
	_nl_auto_nl_cache struct nl_cache *cache = NULL;
	struct rtnl_link *link;

	if (_nltst_rand_u32_range(5) == 0)
		_nltst_assert_link_exists(ifname);

	cache = _nltst_rtnl_link_alloc_cache(sk, AF_UNSPEC, 0);

	link = _nltst_cache_get_link(cache, ifname);
	ck_assert(link);

	if (out_ifindex)
		*out_ifindex = rtnl_link_get_ifindex(link);

	if (out_link) {
		nl_object_get((struct nl_object *)link);
		*out_link = link;
	}
}

struct nl_cache *_nltst_rtnl_link_alloc_cache(struct nl_sock *sk,
					      int addr_family, unsigned flags)
{
	_nl_auto_nl_socket struct nl_sock *sk_free = NULL;
	struct nl_cache *cache;
	int r;

	if (!sk) {
		sk = _nltst_socket(NETLINK_ROUTE);
		sk_free = sk;
	}

	if (flags == 0 && _nltst_rand_bool())
		r = rtnl_link_alloc_cache(sk, addr_family, &cache);
	else
		r = rtnl_link_alloc_cache_flags(sk, addr_family, &cache, flags);

	_nltst_assert_retcode(r);

	if (_nltst_rand_u32_range(5) == 0)
		free(_nltst_cache_get_all(cache, NULL));

	return _nltst_assert(cache);
}

struct nl_cache *_nltst_rtnl_route_alloc_cache(struct nl_sock *sk,
					       int addr_family)
{
	struct nl_cache *cache;

	ck_assert_ptr_nonnull(sk);
	ck_assert(addr_family == AF_UNSPEC || addr_family == AF_INET ||
		  addr_family == AF_INET6);

	_nltst_assert_retcode(
		rtnl_route_alloc_cache(sk, addr_family, 0, &cache));

	if (_nltst_rand_u32_range(5) == 0)
		free(_nltst_cache_get_all(cache, NULL));

	return _nltst_assert(cache);
}

/*****************************************************************************/

char *_nltst_strtok(const char **p_str)
{
	const char *str;
	_nl_auto_free char *dst = NULL;
	size_t dst_len = 0;
	size_t dst_alloc = 0;
	size_t i;

	ck_assert_ptr_nonnull(p_str);

	str = _nltst_str_skip_space(*p_str);

	if (str[0] == '\0') {
		*p_str = str;
		return NULL;
	}

	dst_len = 0;
	dst_alloc = 10;
	dst = malloc(dst_alloc);
	ck_assert_ptr_nonnull(dst);

	i = 0;
	while (true) {
		char ch1 = '\0';
		char ch2 = '\0';

		/* We take the first word, up until whitespace. Note that backslash
		 * escape is honored, so you can backslash escape spaces. The returned
		 * string will NOT have backslashes removed. */

		if (str[i] == '\0') {
			*p_str = &str[i];
			break;
		}
		if (_nltst_char_is_space(str[i])) {
			*p_str = _nltst_str_skip_space(&str[i + 1]);
			break;
		}
		ch1 = str[i];
		if (str[i] == '\\') {
			if (str[i + 1] != '\0') {
				ch2 = str[i + 1];
				i += 2;
			} else
				i += 1;
		} else
			i += 1;

		if (dst_len + 3 >= dst_alloc) {
			dst_alloc *= 2;
			dst = realloc(dst, dst_alloc);
			ck_assert_ptr_nonnull(dst);
		}
		dst[dst_len++] = ch1;
		if (ch2 != '\0')
			dst[dst_len++] = ch2;
	}

	ck_assert_int_gt(dst_len, 0);
	return strndup(dst, dst_len);
}

char **_nltst_strtokv(const char *str)
{
	_nl_auto_free char *s = NULL;
	_nltst_auto_strfreev char **result = NULL;
	size_t r_len = 0;
	size_t r_alloc = 0;

	if (!str)
		return NULL;

	r_alloc = 4;
	result = malloc(sizeof(char *) * r_alloc);
	ck_assert_ptr_nonnull(result);

	while ((s = _nltst_strtok(&str))) {
		if (r_len + 2 >= r_alloc) {
			r_alloc *= 2;
			result = realloc(result, sizeof(char *) * r_alloc);
			ck_assert_ptr_nonnull(result);
		}
		result[r_len++] = _nl_steal_pointer(&s);
	}
	ck_assert_int_lt(r_len, r_alloc);
	result[r_len] = NULL;
	return _nl_steal_pointer(&result);
}

/*****************************************************************************/

void _nltst_assert_link_exists_full(const char *ifname, bool exists)
{
	_nl_auto_nl_cache struct nl_cache *cache = NULL;
	_nl_auto_rtnl_link struct rtnl_link *link_clone = NULL;
	struct rtnl_link *link;
	char path[100];
	struct stat st;
	int rnd;
	int r;

	ck_assert_pstr_ne(ifname, NULL);
	ck_assert_int_lt(strlen(ifname), IFNAMSIZ);

	strcpy(path, "/sys/class/net/");
	strcat(path, ifname);
	ck_assert_int_lt(strlen(path), sizeof(path));

	r = stat(path, &st);
	if (exists) {
		if (r != 0) {
			const int errsv = (errno);

			ck_assert_msg(
				0,
				"link(%s) does not exist (stat(%s) failed with r=%d, errno=%d (%s)",
				ifname, path, r, errsv, strerror(errsv));
		}
	} else {
		if (r != -1 && errno != ENOENT) {
			const int errsv = (errno);

			ck_assert_msg(
				0,
				"link(%s) should not exist but stat(%s) gave r=%d, errno=%d (%s)",
				ifname, path, r, errsv, strerror(errsv));
		}
	}

	rnd = _nltst_rand_u32_range(3);

	if (rnd == 0)
		return;

	cache = _nltst_rtnl_link_alloc_cache(NULL, AF_UNSPEC, 0);

	link = _nltst_cache_get_link(cache, ifname);
	if (exists)
		ck_assert_ptr_nonnull(link);
	else
		ck_assert_ptr_null(link);

	if (!link || rnd == 1)
		return;

	link_clone =
		(struct rtnl_link *)nl_object_clone((struct nl_object *)link);
	ck_assert(link_clone);

	/* FIXME: we would expect that the cloned object is identical. It is not. */
	/* _nltst_object_identical(link, link_clone); */
}

/*****************************************************************************/

bool _nltst_in_ci(void)
{
	return _nl_streq0(getenv("NLTST_IN_CI"), "1");
}

/*****************************************************************************/

bool _nltst_has_iproute2(void)
{
	static int has = -1;

	if (has == -1)
		has = (system("ip link &>/dev/null") == 0);

	return has;
}

bool _nltst_skip_no_iproute2(const char *msg)
{
	if (_nltst_has_iproute2())
		return false;

	ck_assert_msg(
		!_nltst_in_ci(),
		"We seem to not have iproute2, but we are in NLTST_IN_CI=1. This is fatal.");

	printf("skip test due to missing iproute2%s%s%s\n", msg ? " (" : "",
	       msg ?: "", msg ? ")" : "");
	return true;
}

/*****************************************************************************/

void _nltst_select_route_clear(NLTstSelectRoute *select_route)
{
	_nltst_assert_select_route(select_route);

	_nl_clear_free(&select_route->addr);
	_nl_clear_free(&select_route->addr_pattern);
}

int _nltst_select_route_cmp(const NLTstSelectRoute *select_route1,
			    const NLTstSelectRoute *select_route2)
{
	_NL_CMP_SELF(select_route1, select_route2);
	_NL_CMP_FIELD_STR0(select_route1, select_route2, addr);
	_NL_CMP_FIELD_STR0(select_route1, select_route2, addr_pattern);
	_NL_CMP_FIELD(select_route1, select_route2, addr_family);
	_NL_CMP_FIELD(select_route1, select_route2, ifindex);
	_NL_CMP_FIELD(select_route1, select_route2, plen);
	return 0;
}

char *_nltst_select_route_to_string(const NLTstSelectRoute *select_route)
{
	char buf[1024];
	const char *family;
	char b_plen[100];

	_nltst_assert_select_route(select_route);

	if (select_route->addr_family == AF_INET)
		family = "4 ";
	else if (select_route->addr_family == AF_INET6)
		family = "6 ";
	else
		family = "";

	b_plen[0] = '\0';
	if (select_route->plen != -1)
		_nltst_sprintf_arr(b_plen, "/%d", select_route->plen);

	_nltst_sprintf_arr(buf,
			   "%s"
			   "%s"
			   "%s"
			   "",
			   family,
			   select_route->addr_pattern ?: select_route->addr,
			   b_plen);
	return _nltst_strdup(buf);
}

void _nltst_select_route_parse(const char *str,
			       NLTstSelectRoute *out_select_route)
{
	_nltst_auto_strfreev char **tokens0 = NULL;
	const char *const *tokens;
	int addr_family = AF_UNSPEC;
	int addr_family2 = AF_UNSPEC;
	NLTstIPAddr addr;
	int plen = -1;
	_nl_auto_free char *addr_free = NULL;
	const char *s_addr_pattern;
	const char *s_addr = NULL;
	const char *s;
	const char *s1;

	ck_assert_ptr_nonnull(str);
	_nltst_assert_select_route(out_select_route);

	tokens0 = _nltst_strtokv(str);
	tokens = (const char *const *)tokens0;

	s = tokens[0];
	if (!s)
		ck_abort_msg("invalid empty route pattern \"%s\"", str);
	if (_nl_streq(s, "4") || _nl_streq(s, "inet") ||
	    _nl_streq(s, "inet4")) {
		addr_family = AF_INET;
		tokens++;
	} else if (_nl_streq(s, "6") || _nl_streq(s, "inet6")) {
		addr_family = AF_INET6;
		tokens++;
	}

	s_addr_pattern = tokens[0];
	if (!s_addr_pattern) {
		ck_abort_msg(
			"the route pattern \"%s\" is invalid and contains no destination address",
			str);
	}
	tokens++;

	s = strchr(s_addr_pattern, '/');
	if (s) {
		long int plen2;

		if (s == s_addr_pattern) {
			ck_abort_msg(
				"the route pattern \"%s\" contains no valid destination address",
				str);
		}
		addr_free = strndup(s_addr_pattern, s - s_addr_pattern);
		s_addr_pattern = addr_free;
		s++;

		errno = 0;
		plen2 = strtol(s, (char **)&s1, 10);
		if (errno != 0 || s1[0] != '\0' || plen2 < 0 || plen2 > 128 ||
		    ((_nltst_str_find_first_not_from_charset(
			     s, "0123456789"))[0] != '\0')) {
			ck_abort_msg(
				"the route pattern \"%s\" contains no valid destination address",
				str);
		}
		plen = plen2;
	}
	if ((_nltst_str_find_first_not_from_charset(
		    s_addr_pattern, "abcdefABCDEF0123456789:.?*"))[0] != '\0') {
		ck_abort_msg(
			"the route pattern \"%s\" contains no valid destination address",
			str);
	}
	if (_nltst_inet_pton(addr_family, s_addr_pattern, &addr_family2,
			     &addr)) {
		free(addr_free);
		addr_free = _nltst_inet_ntop_dup(addr_family2, &addr);
		s_addr_pattern = addr_free;
		addr_family = addr_family2;
	} else {
		if (addr_family == AF_UNSPEC) {
			ck_abort_msg(
				"the route pattern \"%s\" contains a wild card address, it requires the address family",
				str);
		}
	}

	ck_assert(addr_family == AF_INET || addr_family == AF_INET6);

	if (plen > (addr_family == AF_INET ? 32 : 128)) {
		ck_abort_msg(
			"the route pattern \"%s\" contains no valid destination address (prefix length too large)",
			str);
	}
	ck_assert_int_ge(plen, -1);

	s = tokens[0];
	if (s) {
		ck_abort_msg("the route pattern \"%s\" contains extra tokens",
			     str);
	}

	if (_nltst_inet_valid(addr_family, s_addr_pattern))
		_NL_SWAP(&s_addr, &s_addr_pattern);

	_nltst_select_route_clear(out_select_route);
	memset(out_select_route, 0, sizeof(*out_select_route));
	*out_select_route = (NLTstSelectRoute){
		.addr_family = addr_family,
		.plen = plen,
		.ifindex = 0,
		.addr = s_addr ? strdup(s_addr) : NULL,
		.addr_pattern = s_addr_pattern ? strdup(s_addr_pattern) : NULL,
	};
	ck_assert(!s_addr || out_select_route->addr);
	ck_assert(!s_addr_pattern || out_select_route->addr_pattern);
	_nltst_assert_select_route(out_select_route);
}

bool _nltst_select_route_match(struct nl_object *route,
			       const NLTstSelectRoute *select_route,
			       bool do_assert)
{
	struct nl_addr *addr;
	struct rtnl_route *route_;
	int i;
	char sbuf1[200];

	ck_assert_ptr_nonnull(route);
	ck_assert_str_eq(nl_object_get_type(route), "route/route");

	if (!select_route)
		return true;

	route_ = (struct rtnl_route *)route;

	_nltst_assert_select_route(select_route);

#define _check(cond, msg, ...)                                                                                   \
	do {                                                                                                     \
		if (do_assert) {                                                                                 \
			_nl_auto_free char *s1 = NULL;                                                           \
			_nl_auto_free char *s2 = NULL;                                                           \
                                                                                                                 \
			ck_assert_msg(                                                                           \
				(cond),                                                                          \
				"Checking condition \"%s\" for route \"%s\" (expected \"%s\") failed (msg: " msg \
				")",                                                                             \
				#cond, (s1 = _nltst_object_to_string(route)),                                    \
				(s2 = _nltst_select_route_to_string(                                             \
					 select_route)),                                                         \
				##__VA_ARGS__);                                                                  \
		} else if (cond) {                                                                               \
		} else {                                                                                         \
			return false;                                                                            \
		}                                                                                                \
	} while (0)

	if (select_route->addr_family != AF_UNSPEC) {
		_check(rtnl_route_get_family(route_) ==
			       select_route->addr_family,
		       "mismatching address family");
	}

	if (select_route->ifindex != 0) {
		struct nl_list_head *list;
		struct rtnl_nexthop *nh;
		size_t n;
		struct rtnl_nexthop *nh2;

		list = rtnl_route_get_nexthops(route_);
		_check(list, "no nexthops for ifindex");

		n = 0;
		nl_list_for_each_entry(nh, list, rtnh_list) {
			nh2 = nh;
			n++;
		}
		_check(n == 1, "expects one nexthop for ifindex but got %zu",
		       n);
		ck_assert_ptr_nonnull(nh2);

		i = rtnl_route_nh_get_ifindex(nh2);
		_check(i == select_route->ifindex,
		       "route has unexpected ifindex %d for next hop", i);
	}

	addr = rtnl_route_get_dst(route_);

	if (addr) {
		if (select_route->addr_family != AF_UNSPEC) {
			_check(nl_addr_get_family(addr) ==
				       select_route->addr_family,
			       "unexecpted address family of dst");
		}
	}

	if (select_route->plen != -1) {
		_check(addr, "missing address");
		_check(nl_addr_get_prefixlen(addr) ==
			       (unsigned)select_route->plen,
		       "unexpected prefix length");
	}
	if (select_route->addr || select_route->addr_pattern) {
		_check(addr, "missing address");

		_nl_inet_ntop(nl_addr_get_family(addr),
			      nl_addr_get_binary_addr(addr), sbuf1);

		ck_assert(strlen(sbuf1) > 0);
		ck_assert(strlen(sbuf1) < sizeof(sbuf1));

		if (select_route->addr) {
			_check(_nl_streq(sbuf1, select_route->addr),
			       "unexpected address, \"%s\" does not match \"%s\"",
			       sbuf1, select_route->addr);
		}
		if (select_route->addr_pattern) {
			_check(fnmatch(select_route->addr_pattern, sbuf1, 0) ==
				       0,
			       "unexpected address, \"%s\" does not match pattern \"%s\"",
			       sbuf1, select_route->addr_pattern);
		}
	}

#undef _check

	return false;
}

/*****************************************************************************/

void _nltst_assert_route_list(struct nl_object *const *objs, ssize_t len,
			      const char *const *expected_routes)
{
	size_t l;
	size_t i;

	if (len < 0) {
		l = 0;
		if (objs) {
			while (objs[l])
				l++;
		}
	} else
		l = len;

	for (i = 0; i < l; i++) {
		struct nl_object *route = objs[i];
		_nltst_auto_clear_select_route NLTstSelectRoute select_route = {
			0
		};
		_nl_auto_free char *s = _nltst_object_to_string(route);

		if (!expected_routes[i]) {
			ck_abort_msg(
				"No more expected route, but have route %zu (of %zu) as %s",
				i + 1, l, s);
		}

		_nltst_select_route_parse(expected_routes[i], &select_route);

		_nltst_select_route_match(route, &select_route, true);
	}
}

void _nltst_assert_route_cache_v(struct nl_cache *cache,
				 const char *const *expected_routes)
{
	_nl_auto_free struct nl_object **objs = NULL;
	size_t len;

	ck_assert(cache);
	ck_assert(expected_routes);

	objs = _nltst_cache_get_all(cache, &len);

	_nltst_assert_route_list(objs, len, expected_routes);
}
