#ifndef _LIST_H
#define _LIST_H

#include <stddef.h>

typedef struct list_s {
	struct list_s *next;
	struct list_s *prev;
}list_t;

#define CONTAINING_RECORD(address, type, field) ((type *)( (char*)(address) - (unsigned long*)(&((type*)0)->field)))


#define MINISTACK_LIST_HEAD(name) \
    struct ministack_list_head name = { &(name), &(name) }

static inline void ministack_list_init(struct list_s *head)
{
	head->prev = head->next = head;
}

static inline void ministack_list_add(struct list_s *new_head, struct list_s *head)
{
	head->next->prev = new_head;
	new_head->next = head->next;
	new_head->prev = head;
	head->next = new_head;
}

static inline void ministack_list_add_tail(struct list_s *new_head, struct list_s *head)
{
	head->prev->next = new_head;
	new_head->prev = head->prev;
	new_head->next = head;
	head->prev = new_head;
}
static _inline int ministack_list_unhashed(struct list_s *node)
{
	return !node->prev;
}
static inline void ministack_list_del(struct list_s *elem)
{
	struct list_s *prev = elem->prev;
	struct list_s *next = elem->next;

	prev->next = next;
	next->prev = prev;
}

#define ministack_list_entry(ptr, type, member) \
    ((type *) ((char *) (ptr) - offsetof(type, member)))

#define list_first_entry(ptr, type, member) \
    ministack_list_entry((ptr)->next, type, member)

#define ministack_list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

#define ministack_list_for_each_safe(pos, p, head)    \
    for (pos = (head)->next, p = pos->next; \
         pos != (head);                     \
         pos = p, p = pos->next)

static inline int ministack_list_empty(struct list_s *head)
{
	return head->next == head;
}

#endif
