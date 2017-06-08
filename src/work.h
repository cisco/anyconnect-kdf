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
 *  File:    work.h
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 ******************************************************************************
 *
 *  This file contains the apis for scheduling a work to be done by a kernel
 *  worker in a separate context
 *
 *****************************************************************************
 */

#ifndef _WORK_H_
#define _WORK_H_

#include <linux/workqueue.h>
#include <linux/threads.h>

typedef void fWorkFn_t(void *context);

/*
*   \brief wrapper structure for the kernel work struct
*/
struct work {
	struct work_struct work;
	fWorkFn_t *fp_work;
	void *context;
};

/*
*   \brief wrapper structure to the kernel workqueue
*/
struct workqueue {
	struct workqueue_struct *wq;
};

/*
 * Common strcut encapsulating a work on a dedicated queue
 */
struct work_on_q {
	struct work work;
	struct workqueue work_queue;
};

bool create_work_on_queue(struct work_on_q *workqueue, const char *name,
			  fWorkFn_t *fp_work_fn, void *context);
bool schedule_work_on_queue(struct work_on_q *workqueue);
void destroy_work_on_queue(struct work_on_q *workqueue);

#endif
