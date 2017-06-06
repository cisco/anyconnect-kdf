/*
 *************************************************************************
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
 *************************************************************************
 *
 *  File:    delayed_work.h
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 ************************************************************************
 *
 *  This file contains the apis for scheduling a work to be done by kernel
 *  worker in a separate context at a delayed time in the future
 *
 ***********************************************************************
 */

#ifndef _DELAYED_WORK_H_
#define _DELAYED_WORK_H_

#include <linux/workqueue.h>
#include "work.h"

/*
*   \brief wrapper structure for the kernel delayed work struct
*/
struct _delayed_work {
	struct delayed_work d_work;
	fWorkFn_t *fn_work;
	void *context;
};

/*
*   \brief wrapper structure to the kernel workqueue
*/
struct _delayed_workqueue {
	struct workqueue_struct *wq;
};

/*
 * Common strcut encapsulating a work on a dedicated queue
 */
struct delayed_work_on_q {
	struct _delayed_work work;
	struct _delayed_workqueue work_queue;
};

bool create_delayed_work_on_queue(struct delayed_work_on_q *workqueue,
				  const char *name, fWorkFn_t *fpWorkFn,
				  void *context);
bool schedule_delayed_work_on_queue(struct delayed_work_on_q *workqueue,
				    unsigned long delayInSecs);
void destroy_delayed_work_on_queue(struct delayed_work_on_q *workqueue);

#endif
