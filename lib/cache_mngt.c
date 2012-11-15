/*
 * lib/cache_mngt.c	Cache Management
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2012 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup core
 * @defgroup cache_mngt Caching System
 *
 * Related sections in the development guide:
 * - @core_doc{core_cache, Caching System}
 *
 * @{
 *
 * Header
 * ------
 * ~~~~{.c}
 * #include <netlink/cache.h>
 * ~~~~
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/utils.h>

static struct nl_cache_ops *cache_ops;
static NL_RW_LOCK(cache_ops_lock);

/**
 * @name Cache Operations Sets
 * @{
 */

struct nl_cache_ops *__nl_cache_ops_lookup(const char *name)
{
	struct nl_cache_ops *ops;

	for (ops = cache_ops; ops; ops = ops->co_next)
		if (!strcmp(ops->co_name, name))
			return ops;

	return NULL;
}

/**
 * Increment reference counter
 * @arg ops		Cache operations
 */
void nl_cache_ops_get(struct nl_cache_ops *ops)
{
	ops->co_refcnt++;
}

/**
 * Decrement reference counter
 * @arg ops		Cache operations
 */
void nl_cache_ops_put(struct nl_cache_ops *ops)
{
	ops->co_refcnt--;
}

/**
 * Lookup the set cache operations of a certain cache type
 * @arg name		name of the cache type
 *
 * @return The cache operations or NULL if no operations
 *         have been registered under the specified name.
 */
struct nl_cache_ops *nl_cache_ops_lookup(const char *name)
{
	struct nl_cache_ops *ops;

	nl_read_lock(&cache_ops_lock);
	ops = __nl_cache_ops_lookup(name);
	nl_read_unlock(&cache_ops_lock);

	return ops;
}

/**
 * Associate a message type to a set of cache operations
 * @arg protocol		netlink protocol
 * @arg msgtype			netlink message type
 *
 * Associates the specified netlink message type with
 * a registered set of cache operations.
 *
 * @return The cache operations or NULL if no association
 *         could be made.
 */
struct nl_cache_ops *nl_cache_ops_associate(int protocol, int msgtype)
{
	int i;
	struct nl_cache_ops *ops;

	nl_read_lock(&cache_ops_lock);
	for (ops = cache_ops; ops; ops = ops->co_next) {
		if (ops->co_protocol != protocol)
			continue;

		for (i = 0; ops->co_msgtypes[i].mt_id >= 0; i++) {
			if (ops->co_msgtypes[i].mt_id == msgtype) {
				nl_read_unlock(&cache_ops_lock);
				return ops;
			}
		}
	}
	nl_read_unlock(&cache_ops_lock);

	return NULL;
}

/**
 * Lookup message type cache association
 * @arg ops			cache operations
 * @arg msgtype			netlink message type
 *
 * Searches for a matching message type association ing the specified
 * cache operations.
 *
 * @return A message type association or NULL.
 */
struct nl_msgtype *nl_msgtype_lookup(struct nl_cache_ops *ops, int msgtype)
{
	int i;

	for (i = 0; ops->co_msgtypes[i].mt_id >= 0; i++)
		if (ops->co_msgtypes[i].mt_id == msgtype)
			return &ops->co_msgtypes[i];

	return NULL;
}

/* Must hold cache_ops_lock */
static struct nl_cache_ops *cache_ops_lookup_for_obj(struct nl_object_ops *obj_ops)
{
	struct nl_cache_ops *ops;

	for (ops = cache_ops; ops; ops = ops->co_next)
		if (ops->co_obj_ops == obj_ops)
			return ops;

	return NULL;

}

/**
 * Call a function for each registered cache operation
 * @arg cb		Callback function to be called
 * @arg arg		User specific argument.
 */
void nl_cache_ops_foreach(void (*cb)(struct nl_cache_ops *, void *), void *arg)
{
	struct nl_cache_ops *ops;

	nl_read_lock(&cache_ops_lock);
	for (ops = cache_ops; ops; ops = ops->co_next)
		cb(ops, arg);
	nl_read_unlock(&cache_ops_lock);
}

/**
 * Set default flags for caches of this type
 * @arg ops		Cache ops
 * @arg flags		Flags to set
 *
 * The cache operation flags will be derived to all caches allocates
 * based on this set of cache operations.
 */
void nl_cache_ops_set_flags(struct nl_cache_ops *ops, unsigned int flags)
{
	ops->co_flags |= flags;
}

/**
 * Register a set of cache operations
 * @arg ops		cache operations
 *
 * Called by users of caches to announce the avaibility of
 * a certain cache type.
 *
 * @return 0 on success or a negative error code.
 */
int nl_cache_mngt_register(struct nl_cache_ops *ops)
{
	if (!ops->co_name || !ops->co_obj_ops)
		return -NLE_INVAL;

	nl_write_lock(&cache_ops_lock);
	if (__nl_cache_ops_lookup(ops->co_name)) {
		nl_write_unlock(&cache_ops_lock);
		return -NLE_EXIST;
	}

	ops->co_refcnt = 0;
	ops->co_next = cache_ops;
	cache_ops = ops;
	nl_write_unlock(&cache_ops_lock);

	NL_DBG(1, "Registered cache operations %s\n", ops->co_name);

	return 0;
}

/**
 * Unregister a set of cache operations
 * @arg ops		cache operations
 *
 * Called by users of caches to announce a set of
 * cache operations is no longer available. The
 * specified cache operations must have been registered
 * previously using nl_cache_mngt_register()
 *
 * @return 0 on success or a negative error code
 */
int nl_cache_mngt_unregister(struct nl_cache_ops *ops)
{
	struct nl_cache_ops *t, **tp;
	int err = 0;

	nl_write_lock(&cache_ops_lock);

	if (ops->co_refcnt > 0) {
		err = -NLE_BUSY;
		goto errout;
	}

	for (tp = &cache_ops; (t=*tp) != NULL; tp = &t->co_next)
		if (t == ops)
			break;

	if (!t) {
		err = -NLE_NOCACHE;
		goto errout;
	}

	NL_DBG(1, "Unregistered cache operations %s\n", ops->co_name);

	*tp = t->co_next;
errout:
	nl_write_unlock(&cache_ops_lock);

	return err;
}

/** @} */

/**
 * @name Global Cache Provisioning/Requiring
 * @{
 */

/**
 * Provide a cache for global use
 * @arg cache		cache to provide
 *
 * Offers the specified cache to be used by other modules.
 * Only one cache per type may be shared at a time,
 * a previsouly provided caches will be overwritten.
 */
void nl_cache_mngt_provide(struct nl_cache *cache)
{
	struct nl_cache_ops *ops;

	nl_write_lock(&cache_ops_lock);

	ops = cache_ops_lookup_for_obj(cache->c_ops->co_obj_ops);
	if (!ops)
		BUG();
	else {
		nl_cache_get(cache);
		ops->co_major_cache = cache;
	}

	nl_write_unlock(&cache_ops_lock);
}

/**
 * Unprovide a cache for global use
 * @arg cache		cache to unprovide
 *
 * Cancels the offer to use a cache globally. The
 * cache will no longer be returned via lookups but
 * may still be in use.
 */
void nl_cache_mngt_unprovide(struct nl_cache *cache)
{
	struct nl_cache_ops *ops;

	nl_write_lock(&cache_ops_lock);

	ops = cache_ops_lookup_for_obj(cache->c_ops->co_obj_ops);
	if (!ops)
		BUG();
	else if (ops->co_major_cache == cache) {
		nl_cache_free(ops->co_major_cache);
		ops->co_major_cache = NULL;
	}

	nl_write_unlock(&cache_ops_lock);
}

struct nl_cache *__nl_cache_mngt_require(const char *name)
{
	struct nl_cache_ops *ops;

	ops = nl_cache_ops_lookup(name);
	if (ops)
		return ops->co_major_cache;
	
	return NULL;
}

/**
 * Demand the use of a global cache
 * @arg name		name of the required object type
 *
 * Trys to find a cache of the specified type for global
 * use.
 *
 * @return A cache provided by another subsystem of the
 *         specified type marked to be available.
 */
struct nl_cache *nl_cache_mngt_require(const char *name)
{
	struct nl_cache *cache;

	if (!(cache = __nl_cache_mngt_require(name)))
		fprintf(stderr, "Application BUG: Your application must "
			"call nl_cache_mngt_provide() and\nprovide a valid "
			"%s cache to be used for internal lookups.\nSee the "
			" API documentation for more details.\n", name);
	
	return cache;
}

/** @} */

/** @} */
