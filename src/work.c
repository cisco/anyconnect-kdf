/*
 ******************************************************************************
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
 ******************************************************************************
 *
 *  File:    work.c
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 ****************************************************************************
 *
 *  This file contains the apis for scheduling a work to be done by a kernel
 *  worker in a separate context
 *
 ***************************************************************************
 */

#include <linux/slab.h>
#include <linux/version.h>
#include "defines.h"
#include "work.h"
#include "dbgout.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 7, 0))
#define create_rt_workqueue(name) \
	alloc_workqueue("%s", \
		WQ_MEM_RECLAIM | WQ_UNBOUND | WQ_HIGHPRI, 0, (name))
#endif

/*
*   \brief callback to the worker
*/
static void work_handler(struct work_struct *work_struct)
{
	struct work *work = NULL;

	if (NULL == work_struct)
		return;

	work = container_of(work_struct, struct work, work);

	if (NULL != work && NULL != work->fp_work)
		work->fp_work(work->context);
}

/*
*   \brief function to create a  work queue with a provided name
*   \param[in] name name of the queue
*   \return true/false
*/
static bool create_workq(struct workqueue *workq, const char *name)
{
	if (!name || !workq)
		return false;

	workq->wq = create_rt_workqueue(name);

	if (!workq->wq)
		return false;

	return true;
}

/*
*   \brief function to create a  work
*   \param[in] fp_work_fn pointer to the worker function
*   \param[in] context user context that needs to be passed to the callback
*   \return true/false
*/
static bool create_work(struct work *work, fWorkFn_t *fp_work_fn,
			void *context)
{
	if (NULL == fp_work_fn || NULL == work) {
		TRACE(ERROR, LOG("Invalid arguments"));
		return false;
	}

	INIT_WORK(&work->work, work_handler);
	work->fp_work = fp_work_fn;
	work->context = context;

	return true;
}

/*
*   \brief function to schedule work on given queue
*   \param[in] pWq workqueue
*   \param[in] work worker struct
*   \return true or false
*/
static bool schedule_workOn(struct workqueue *pWq, struct work *work)
{
	if (NULL != work && (NULL != pWq && NULL != pWq->wq))
		return queue_work(pWq->wq, &work->work);

	return false;
}

/*
*   \brief function to Destroy worker
*   \param[in] work worker struct
*   \return
*/
static void destroy_work(struct work *work)
{
	if (NULL != work)
		cancel_work_sync(&work->work);
}

/*
*   \brief function to Destroy work queue
*   \param[in] pWq workqueue
*   \return
*/
static void destroy_workq(struct workqueue *pWq)
{
	if (NULL != pWq && NULL != pWq->wq)
		destroy_workqueue(pWq->wq);
}

/*
 * Create a work and associated queue
 */
bool
create_work_on_queue(struct work_on_q *work, const char *name,
		     fWorkFn_t *fp_work_fn, void *context)
{
	if (NULL == work)
		return false;

	if (true != create_work(&work->work, fp_work_fn, context))
		return false;

	if (true != create_workq(&work->work_queue, name)) {
		destroy_work(&work->work);
		return false;
	}
	return true;
}

/*
 * Schedule work
 */
bool schedule_work_on_queue(struct work_on_q *workqueue)
{
	if (NULL == workqueue)
		return false;

	return schedule_workOn(&workqueue->work_queue, &workqueue->work);
}

/*
 * Destroy queue
 */
void destroy_work_on_queue(struct work_on_q *workqueue)
{
	if (NULL != workqueue) {
		destroy_work(&workqueue->work);
		destroy_workq(&workqueue->work_queue);
	}
}
