/*
 * netlink/hashtable.c      Netlink hashtable Utilities
 *
 *      This library is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU Lesser General Public
 *      License as published by the Free Software Foundation version 2.1
 *      of the License.
 *
 * Copyright (c) 2012 Cumulus Networks, Inc
 */
#include <string.h>
#include <netlink-private/netlink.h>
#include <netlink/object.h>
#include <netlink/hash.h>
#include <netlink/hashtable.h>

static nl_hash_node_t *nl_hash_table_list_head_alloc()
{
	nl_hash_node_t *head;

	head = calloc(1, sizeof(*head));
	if (!head)
		return NULL;

	nl_init_list_head(&head->list);

	return head;
}

/**
 * @ingroup core_types
 * @defgroup hashtable Hashtable
 * @{
 */

/**
 * Allocate hashtable
 * @arg size		Size of hashtable in number of elements
 *
 * @return Allocated hashtable or NULL.
 */
nl_hash_table_t *nl_hash_table_alloc(int size)
{
	nl_hash_table_t *ht;

	ht = calloc(1, sizeof (*ht));
	if (!ht)
		goto errout;

	ht->nodes = calloc(size, sizeof (*ht->nodes));
	if (!ht->nodes) {
		free(ht);
		goto errout;
	}

	ht->size = size;

	return ht;
errout:
	return NULL;
}

/**
 * Free hashtable including all nodes
 * @arg ht		Hashtable
 *
 * @note Reference counter of all objects in the hashtable will be decremented.
 */
void nl_hash_table_free(nl_hash_table_t *ht)
{
	int i;

	for(i = 0; i < ht->size; i++) {
		nl_hash_node_t *node, *head = ht->nodes[i], *tmp;

		if (!head)
			continue;

		nl_list_for_each_entry_safe(node, tmp, &head->list, list) {
			nl_list_del(&node->list);
			free(node);
		}
	}

	free(ht->nodes);
	free(ht);
}

/**
 * Lookup identical object in hashtable
 * @arg ht		Hashtable
 * @arg	obj		Object to lookup
 *
 * Generates hashkey for `obj` and traverses the corresponding chain calling
 * `nl_object_identical()` on each trying to find a match.
 *
 * @return Pointer to object if match was found or NULL.
 */
struct nl_object* nl_hash_table_lookup(nl_hash_table_t *ht,
				       struct nl_object *obj)
{
	nl_hash_node_t *node, *head;
	uint32_t key_hash;

	nl_object_keygen(obj, &key_hash, ht->size);
	head = ht->nodes[key_hash];
	if (!head)
		return NULL;

	nl_list_for_each_entry(node, &head->list, list) {
		if (nl_object_identical(node->obj, obj))
		   return node->obj;
	}

	return NULL;
}

/**
 * Lookup identical object in hashtable
 * @arg ht		Hashtable
 * @arg obj		Object to lookup
 * @arg mask		Attribute mask to use during lookup
 *
 * Generates hashkey for `obj` and traverses the corresponding chain calling
 * `nl_object_diff_mask()` on each trying to find a match. similar to
 * nl_hash_table_lookup but uses an user provided attribute mask.
 *
 * @return Pointer to object if match was found or NULL.
 */

struct nl_object* nl_hash_table_lookup_mask(nl_hash_table_t *ht,
					    struct nl_object *obj,
					    uint32_t mask)
{
	nl_hash_node_t *node, *head;
	uint32_t key_hash;

	nl_object_keygen(obj, &key_hash, ht->size);
	head = ht->nodes[key_hash];

	if (!head)
		return NULL;

	nl_list_for_each_entry(node, &head->list, list) {
	       if (!nl_object_diff_mask(node->obj, obj, mask))
		   return node->obj;
	}

	return NULL;
}

/**
 * Add object to hashtable
 * @arg ht		Hashtable
 * @arg obj		Object to add
 *
 * Adds `obj` to the hashtable. Object type must support hashing, otherwise all
 * objects will be added to the chain `0`.
 *
 * @note The reference counter of the object is incremented.
 *
 * @return 0 on success or a negative error code
 * @retval -NLE_EXIST Identical object already present in hashtable
 */
int nl_hash_table_add(nl_hash_table_t *ht, struct nl_object *obj)
{
	nl_hash_node_t *node, *head;
	uint32_t key_hash;

	nl_object_keygen(obj, &key_hash, ht->size);
	head = ht->nodes[key_hash];
	if (head != NULL) {
		nl_list_for_each_entry(node, &head->list, list) {
			if (nl_object_identical(node->obj, obj)) {
				NL_DBG(2, "Warning: Add to hashtable found "
					"duplicate...\n");
				return -NLE_EXIST;
			}
		}
	} else {
		/* Initialize head (This can also be done in hash table alloc
		 * function. Its done here so that we only allocate nodes
		 * when needed)
		 */
		ht->nodes[key_hash] = nl_hash_table_list_head_alloc();
		if (!ht->nodes[key_hash])
			return -NLE_NOMEM;
	}

	NL_DBG (5, "adding cache entry of obj %p in table %p, with hash 0x%x\n",
		obj, ht, key_hash);

	node = malloc(sizeof(nl_hash_node_t));
	if (!node)
		return -NLE_NOMEM;
	nl_object_get(obj);
	node->obj = obj;
	node->key = key_hash;
	node->key_size = sizeof(uint32_t);
	nl_init_list_head(&node->list);

	if ((obj->ce_msgflags & NLM_F_APPEND) ||
		(obj->ce_flags & NL_OBJ_DUMP))
		nl_list_add_tail(&node->list, &ht->nodes[key_hash]->list);
	else
		nl_list_add_head(&node->list, &ht->nodes[key_hash]->list);

	return 0;
}

/**
 * Remove object from hashtable
 * @arg ht		Hashtable
 * @arg obj		Object to remove
 *
 * Remove `obj` from hashtable if it exists.
 *
 * @note Reference counter of object will be decremented.
 *
 * @return 0 on success or a negative error code.
 * @retval -NLE_OBJ_NOTFOUND Object not present in hashtable.
 */
int nl_hash_table_del(nl_hash_table_t *ht, struct nl_object *obj)
{
	nl_hash_node_t *node, *head;
	uint32_t key_hash;

	nl_object_keygen(obj, &key_hash, ht->size);
	head = ht->nodes[key_hash];
	if (!head)
		return -NLE_OBJ_NOTFOUND;

	nl_list_for_each_entry(node, &head->list, list) {
	       if (nl_object_identical(node->obj, obj)) {
			nl_object_put(obj);
			nl_list_del(&node->list);
			free(node);
			if (nl_list_empty(&head->list)) {
				free(ht->nodes[key_hash]);
				ht->nodes[key_hash] = NULL;
			}
			return 0;
	       }
	}

	return -NLE_OBJ_NOTFOUND;
}

uint32_t nl_hash(void *k, size_t length, uint32_t initval)
{
	return(__nl_hash(k, length, initval));
}

/** @} */
