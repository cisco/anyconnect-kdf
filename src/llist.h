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
 *  File:    llist.h
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 ***************************************************************************
 *
 *  This file contains the apis for list manipulations used by the module
 *  This re-uses the <linux/list.h> implementation.
 *
 **************************************************************************
 */

#ifndef __LLIST_H__
#define __LLIST_H__

#include <linux/list.h>
/*
*   \brief wrapper to kernel double linked list
*/

/* List node */
struct llist {
	struct list_head list;
	void *data;
	int size;
};

bool list_init(struct llist **head);
bool list_insert(struct llist *head, void *in_data, bool no_wait);
bool list_insert_tail(struct llist *head, void *in_data, bool no_wait);
void list_delete(struct llist *head, struct llist *node);
void list_get_next(struct llist *in_current, struct llist **in_node,
		   void **in_data);
bool is_list_empty(struct llist *head);
void list_destroy(struct llist *head);
int list_size(struct llist *head);

#endif
