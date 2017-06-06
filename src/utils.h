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
 *****************************************************************************
 *
 *  File:    utils.h
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 ****************************************************************************
 *
 *  This file contains the utility apis
 *
 **************************************************************************
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include "defines.h"
#include <linux/module.h>
#include <linux/version.h>
#include <linux/hashtable.h>

/*
 * Task methods
 */
struct task_struct;

struct task_struct *get_curr_task(void);
pid_t get_pid_of_task(struct task_struct *task);
struct task_struct *get_task_from_pid(pid_t uPid);
struct task_struct *get_parent(struct task_struct *task);
uint16_t get_exepath_from_curr_task(struct task_struct *task, char *path_buffer,
				    uint16_t buffer_size);
uint16_t get_exepath_from_task(struct task_struct *task, char *path_buffer,
			       uint16_t buffer_size);
void unref_task(struct task_struct *task);

/* Api to get the current time */
uint32_t get_unix_systime(void);
/* Get the task name with the path */
uint16_t get_taskname(struct task_struct *task, char *name_buffer,
		      uint16_t buffer_size);

/* socket send method */
struct socket;
error_code socket_sendto(struct socket *local, struct sockaddr_in *dest,
			   const uint8_t *pBuffer, size_t buff_len);

/*
 * Hash list related macros
 */
/*
*   \brief wrapper to kernel hashtable
*/

/* custom hash list node */
struct hash_list {
	struct hlist_node next;
	void *data;
	uint32_t key;
};

#define IS_IP_VERSION4(x) (4 == x)
#define LOOPBACK_ADDR_V4_BE  (0x0100007fU)

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3, 8, 0))

#define HLIST_ITER struct hlist_node *temp

#define for_each_hlist(table, bkt, tmp, node, member) \
	hash_for_each_safe(table, bkt, temp, tmp, node, member)

#define for_each_hlist_match(table, node, member, key) \
	hash_for_each_possible(table, node, temp, member, key)

#else				/*LINUX VERSION */

#define HLIST_ITER

#define for_each_hlist(table, bkt, tmp, node, member) \
	hash_for_each_safe(table, bkt, tmp, node, member)

#define for_each_hlist_match(table, node, member, key) \
	hash_for_each_possible(table, node, member, key)

#endif				/*LINUX VERSION */

#define hlist_add(hashtable, entry, entry_key) \
	{ \
	struct hash_list *new = KMALLOC(sizeof(struct hash_list)); \
	if (NULL == new) \
		return; \
	memset(new, 0, sizeof(struct hash_list)); \
	new->data = entry; \
	new->key = entry_key; \
	hash_add(hashtable, &new->next, new->key); \
	}

#define hlist_del(a) \
	{ \
	hash_del(&a->next); \
	KFREE(a); \
	a = NULL; \
	}

#endif
