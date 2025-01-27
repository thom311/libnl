/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_LIST_H_
#define NETLINK_LIST_H_

/* For internal uses consider using "third_party/c-list/src/c-list.h" instead.
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nl_list_head
{
	struct nl_list_head *	next;
	struct nl_list_head *	prev;
};

static inline void NL_INIT_LIST_HEAD(struct nl_list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __nl_list_add(struct nl_list_head *obj,
				 struct nl_list_head *prev,
				 struct nl_list_head *next)
{
	prev->next = obj;
	obj->prev = prev;
	next->prev = obj;
	obj->next = next;
}

static inline void nl_list_add_tail(struct nl_list_head *obj,
				    struct nl_list_head *head)
{
	__nl_list_add(obj, head->prev, head);
}

static inline void nl_list_add_head(struct nl_list_head *obj,
				    struct nl_list_head *head)
{
	__nl_list_add(obj, head, head->next);
}

static inline void nl_list_insert_before(struct nl_list_head *obj,
					 struct nl_list_head *ref)
{
	__nl_list_add(obj, ref->prev, ref);
}

static inline void nl_list_insert_after(struct nl_list_head *obj,
					struct nl_list_head *ref)
{
	__nl_list_add(obj, ref, ref->next);
}

static inline void nl_list_insert_list_after(struct nl_list_head *head,
					     struct nl_list_head *ref)
{
	ref->next->prev = head->prev;
	head->prev->next = ref->next;
	ref->next = head->next;
	head->next->prev = ref;
	head->next = head;
	head->prev = head;
}

static inline void nl_list_join(struct nl_list_head *head_1,
				struct nl_list_head *head_2)
{
	nl_list_insert_list_after(head_2, head_1->prev);
}

static inline void nl_list_del(struct nl_list_head *obj)
{
	obj->next->prev = obj->prev;
	obj->prev->next = obj->next;
}

static inline int nl_list_empty(struct nl_list_head *head)
{
	return head->next == head;
}

#define nl_container_of(ptr, type, member) ({			\
        const __typeof__( ((type *)0)->member ) *__mptr = (ptr);\
        (type *)( (char *)__mptr - (offsetof(type, member)));})

#define nl_list_entry(ptr, type, member) \
	nl_container_of(ptr, type, member)

#define nl_list_at_tail(pos, head, member) \
	((pos)->member.next == (head))

#define nl_list_at_head(pos, head, member) \
	((pos)->member.prev == (head))

#define NL_LIST_HEAD(name) \
	struct nl_list_head name = { &(name), &(name) }

#define nl_list_first_entry(head, type, member)			\
	nl_list_entry((head)->next, type, member)

#define nl_list_last_entry(head, type, member)			\
	nl_list_entry((head)->prev, type, member)

#define nl_list_for_each_entry(pos, head, member)				\
	for (pos = nl_list_entry((head)->next, __typeof__(*pos), member);	\
	     &(pos)->member != (head); 	\
	     (pos) = nl_list_entry((pos)->member.next, __typeof__(*(pos)), member))

#define nl_list_for_each_entry_reverse(pos, head, member)			\
	for (pos = nl_list_entry((head)->prev, __typeof__(*pos), member);	\
	     &(pos)->member != (head); 	\
	     (pos) = nl_list_entry((pos)->member.prev, __typeof__(*(pos)), member))

#define nl_list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = nl_list_entry((head)->next, __typeof__(*pos), member),	\
		n = nl_list_entry(pos->member.next, __typeof__(*pos), member);	\
	     &(pos)->member != (head); 					\
	     pos = n, n = nl_list_entry(n->member.next, __typeof__(*n), member))

#define nl_list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = nl_list_entry((head)->prev, __typeof__(*pos), member),	\
		n = nl_list_entry(pos->member.prev, __typeof__(*pos), member);	\
	     &(pos)->member != (head); 					\
	     pos = n, n = nl_list_entry(n->member.prev, __typeof__(*n), member))

#define nl_init_list_head(head) \
	do { (head)->next = (head); (head)->prev = (head); } while (0)

#ifdef __cplusplus
}
#endif

#endif
