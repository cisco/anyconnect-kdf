/*
 *****************************************************************************
 * Copyright (C) 2017, Cisco Systems
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 ****************************************************************************
 *
 *  File:    llist.c
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 ***************************************************************************
 *
 *  This file contains the apis for list manipulations used by the module
 *  This re-uses the <linux/list.h> implementation.
 *
 **************************************************************************
 */

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "defines.h"
#include "llist.h"

/*
*   \brief initialize the list head
*   \param[out] **head list head
*   \return true if success else false
*/
bool list_init(struct llist **head)
{
	if (!head)
		return false;

	*head = (struct llist *)KMALLOC(sizeof(struct llist));
	if (NULL != *head) {
		INIT_LIST_HEAD(&(*head)->list);
		(*head)->data = NULL;
		(*head)->size = 0;
		return true;
	}
	return false;
}

/*
*   \brief insert an entry to the beginning of the list
*   \param[in] head list head
*   \param[in] in_data data to be inserted
*   \param[in] no_wait flag to denote if the api can sleep
*   \return true is inserted, else false
*/
bool list_insert(struct llist *head, void *in_data, bool no_wait)
{
	struct llist *new = NULL;

	if (!head)
		return false;

	if (no_wait)
		new = (struct llist *)KMALLOC_ATOMIC(sizeof(struct llist));
	else
		new = (struct llist *)KMALLOC(sizeof(struct llist));

	if (NULL == new)
		return false;

	memset(new, 0, sizeof(struct llist));
	new->data = in_data;

	list_add(&new->list, &head->list);
	head->size += 1;
	return true;
}

/*
*   \brief insert an entry to the end of the list
*   \param[in] head list head
*   \param[in] in_data data to be inserted
*   \param[in] no_wait flag to denote if the api can sleep
*   \return true is inserted, else false
*/
bool list_insert_tail(struct llist *head, void *in_data, bool no_wait)
{
	struct llist *new = NULL;

	if (!head)
		return false;

	if (no_wait)
		new = (struct llist *)KMALLOC_ATOMIC(sizeof(struct llist));
	else
		new = (struct llist *)KMALLOC(sizeof(struct llist));

	if (NULL == new)
		return false;

	memset(new, 0, sizeof(struct llist));
	new->data = in_data;

	list_add_tail(&new->list, &head->list);
	head->size += 1;
	return true;
}

/*
*   \brief delete an entry from the list
*   \param[in] head list head
*   \param[in] in_data data to be deleted
*   \return
*/
void list_delete(struct llist *head, struct llist *node)
{
	if (!node || !head)
		return;

	list_del(&node->list);
	head->size -= 1;
	KFREE(node);
}

/*
*   \brief get the next element from the list
*   \param[in] current current element
*   \param[out] **node next element
*   \param[out] **in_data data in the next element
*   \return
*/
void list_get_next(struct llist *in_current, struct llist **in_node,
		   void **in_data)
{
	struct llist *tmp = NULL;

	if (!in_current || !in_node || !in_data)
		return;

	tmp = list_next_entry(in_current, list);
	*in_node = tmp;
	*in_data = tmp->data;
}

/*
*   \brief check if the list is empty
*   \param[in] head list head
*   \return true if empty, else false
*/
bool is_list_empty(struct llist *head)
{
	return (!!list_empty(&head->list));
}

/*
*   \brief destroy the head
*   \param[in] head list head
*   \return
*/
void list_destroy(struct llist *head)
{
	if (head)
		KFREE(head);
}

/*
*   \brief return number of elements in the list
*   \param[in] head list head
*   \return number of elements
*/
int list_size(struct llist *head)
{
	if (head)
		return head->size;

	return 0;
}
