/*
 ************************************************************************
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
 ************************************************************************
 *
 *  File:    delayed_work.c
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 **********************************************************************
 *
 *  This file contains the apis for scheduling a work to be done by kernel
 *  worker a separate context at a delayed time in the future
 *
 **********************************************************************
 */

#include <linux/slab.h>
#include <linux/version.h>
#include <linux/param.h>
#include "defines.h"
#include "delayed_work.h"
#include "dbgout.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 7, 0))
#define create_rt_workqueue(name) \
	alloc_workqueue("%s", WQ_MEM_RECLAIM | WQ_UNBOUND | WQ_HIGHPRI, \
			 0, (name))
#endif

/*
*   \brief callback to the worker
*/
static void work_handler(struct work_struct *work_struct)
{
	struct _delayed_work *work = NULL;

	if (NULL == work_struct)
		return;
	work =
	    container_of(to_delayed_work(work_struct), struct _delayed_work,
			 d_work);

	if (NULL != work && NULL != work->fn_work)
		work->fn_work(work->context);
}

/*
*   \brief function to create a delayed work queue with a provided name
*   \param[in] name name of the queue
*   \return true/false
*/
static bool
create_delayed_workqueue(struct _delayed_workqueue *work_q, const char *name)
{
	if (!name || !work_q)
		return false;

	work_q->wq = create_rt_workqueue(name);

	if (!work_q->wq)
		return false;

	return true;
}

/*
*   \brief function to create a delayed work
*   \param[in] fpWorkFn pointer to the worker function
*   \param[in] context user context that needs to be passed to the callback
*   \return true/false
*/
static bool
create_delayed_work(struct _delayed_work *work, fWorkFn_t *fpWorkFn,
		    void *context)
{
	if (NULL == fpWorkFn || NULL == work) {
		TRACE(ERROR, LOG("Invalid arguments"));
		return false;
	}

	INIT_DELAYED_WORK(&work->d_work, work_handler);
	work->fn_work = fpWorkFn;
	work->context = context;

	return true;
}

/*
*   \brief function to schedule work on given queue
*   \param[in] pWq workqueue
*   \param[in] work worker struct
*   \param[in] delay_in_secs delay in seconds
*   \return true or false
*/
static bool
schedule_delayed_workon(struct _delayed_workqueue *pWq,
			struct _delayed_work *work,
			unsigned long delay_in_secs)
{
	if (NULL != work && (NULL != pWq && NULL != pWq->wq)) {
		/*
		 * This api takes the delay in jiffies which is a counter
		 * incremented every clock tick.
		 * In a second there are HZ number of clock ticks.
		 * HZ is a symbol defined in <linux/param.h>
		 */
		return queue_delayed_work(pWq->wq, &work->d_work,
					  (delay_in_secs * HZ));
	}
	return false;
}

/*
*   \brief function to Destroy worker
*   \param[in] work worker struct
*   \return
*/
static void destroy_delayed_work(struct _delayed_work *work)
{
	if (NULL != work)
		cancel_delayed_work(&work->d_work);
}

/*
*   \brief function to Destroy work queue
*   \param[in] pWq workqueue
*   \return
*/
static void destroy_delayed_workqueue(struct _delayed_workqueue *pWq)
{
	if (NULL != pWq && NULL != pWq->wq)
		destroy_workqueue(pWq->wq);
}

/*
 * Create a work and associated queue
 */
bool
create_delayed_work_on_queue(struct delayed_work_on_q *work,
			     const char *name, fWorkFn_t *fpWorkFn,
			     void *context)
{
	if (NULL == work)
		return false;

	if (true != create_delayed_work(&work->work, fpWorkFn, context))
		return false;

	if (true != create_delayed_workqueue(&work->work_queue, name)) {
		destroy_delayed_work(&work->work);
		return false;
	}
	return true;
}

/*
 * Schedule work
 */
bool
schedule_delayed_work_on_queue(struct delayed_work_on_q *workqueue,
			       unsigned long delayInSecs)
{
	if (NULL == workqueue)
		return false;

	return schedule_delayed_workon(&workqueue->work_queue, &workqueue->work,
				       delayInSecs);
}

/*
 * Destroy queue
 */
void destroy_delayed_work_on_queue(struct delayed_work_on_q *workqueue)
{
	if (NULL != workqueue) {
		destroy_delayed_work(&workqueue->work);
		destroy_delayed_workqueue(&workqueue->work_queue);
	}
}
