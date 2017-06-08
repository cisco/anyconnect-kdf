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
 *  File:    utils.c
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 ****************************************************************************
 *
 *  This file contains the utility apis
 *
 *****************************************************************************
 */

#include <linux/net.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/time.h>
#include <linux/slab.h>
#include "defines.h"
#include "utils.h"
#include "dbgout.h"

static const char default_name[] = "Unknown";	/*default task name */

/*
*   \brief Get the current task_struct
*/
struct task_struct *get_curr_task(void)
{
	struct task_struct *ret_val = current;

	if (NULL != ret_val)
		get_task_struct(ret_val);
	return ret_val;
}

/*
*   \brief Get the processid from the task_struct
*/
pid_t get_pid_of_task(struct task_struct *task)
{
	/*for a process, pid == tgid, for a thread pid != tgid and
	 * the tgid is the actual pid of the process */
	return (NULL == task) ? 0 : task->tgid;
}

struct task_struct *get_task_from_pid(pid_t uPid)
{
	if (0 == uPid)
		return NULL;
	return get_pid_task(find_vpid(uPid), PIDTYPE_PID);
}

/*
*   \brief Get the Parent task struct from the current task struct
*/
struct task_struct *get_parent(struct task_struct *task)
{
	struct task_struct *ret_val = (NULL == task) ? NULL : task->parent;

	if (NULL != ret_val)
		get_task_struct(ret_val);
	return ret_val;
}

/*
*   \brief Remove reference to a retrieved task struct
*/
void unref_task(struct task_struct *task)
{
	if (NULL != task)
		put_task_struct(task);
}

/*
*   \brief Get the executable path from the task struct
*/
uint16_t GetExePathFromTaskGeneric(struct task_struct *task, char *path_buffer,
				   uint16_t buffer_size, bool bCurrent)
{
	uint16_t retval = 0;
	struct mm_struct *mem_mgr = NULL;
	char *temp_buffer = NULL;
	const char *path = default_name;

	if (NULL == task || NULL == path_buffer || 0 == buffer_size) {
		TRACE(ERROR, LOG("Invalid parameters"));
		return retval;
	}

	temp_buffer = KMALLOC(PATH_MAX);
	if (NULL == temp_buffer) {
		TRACE(ERROR, LOG("Failed to allocate temporary buffer"));
		return retval;
	}
	memset(temp_buffer, 0, PATH_MAX);
	/* We are not calling get_task_mm/mmput as we
	   are in the context of the same task and mmput can sleep() */
	mem_mgr = (bCurrent) ? task->mm : get_task_mm(task);
	if (NULL == mem_mgr || NULL == mem_mgr->exe_file) {
		TRACE(WARNING, LOG("Failed to get task details"));
		goto done;
	}
	down_read(&mem_mgr->mmap_sem);
	path = d_path(&mem_mgr->exe_file->f_path, temp_buffer, PATH_MAX);
	if (IS_ERR(path)) {
		TRACE(WARNING, LOG("Failed to get file path"));
		path = default_name;
	}
	up_read(&mem_mgr->mmap_sem);
 done:
	if (NULL != mem_mgr && !bCurrent)
		mmput(mem_mgr);

	retval = snprintf(path_buffer, (buffer_size - 1), path);
	if (NULL != temp_buffer)
		KFREE(temp_buffer);

	return retval;
}

/*
*   \brief Wrapper to get the executable path from the current task struct
*/
uint16_t
get_exepath_from_curr_task(struct task_struct *task, char *path_buffer,
			   uint16_t buffer_size)
{
	return GetExePathFromTaskGeneric(task, path_buffer, buffer_size, true);
}

/*
*   \brief Wrapper to get the executable path from a task struct
*/
uint16_t get_exepath_from_task(struct task_struct *task, char *path_buffer,
			       uint16_t buffer_size)
{
	return GetExePathFromTaskGeneric(task, path_buffer, buffer_size, false);
}

/*
 * Api to get the current time
 */
uint32_t get_unix_systime(void)
{
	struct timeval val;

	do_gettimeofday(&val);
	return val.tv_sec;
}

/*
*   \brief Get the executable name from the task struct
*/
uint16_t get_taskname(struct task_struct *task, char *name_buffer,
		      uint16_t buffer_size)
{
	uint16_t retVal = 0;

	if (NULL == task || NULL == name_buffer || 0 == buffer_size
	    || buffer_size <= TASK_COMM_LEN) {
		TRACE(ERROR, LOG("Invalid parameters"));
		return retVal;
	}
	get_task_comm(name_buffer, task);
	if ('\0' == name_buffer[0])
		retVal = snprintf(name_buffer, (buffer_size - 1), default_name);
	else
		retVal = strlen(name_buffer);

	return retVal;
}

/**
 * \brief sends data over socket
 * \description
 *
 * \param[in] local local socket via which the data is to be sent
 * \param[in] dest destination socket
 * \param[in] buffer data to be sent
 * \param[in] buff_len length of the buffer to be sent
 *
 * \return status code
*/
error_code socket_sendto(struct socket *local, struct sockaddr_in *dest,
			   const uint8_t *buffer, size_t buff_len)
{
	struct msghdr msg;
	struct kvec vec;
	size_t bytes_sent = 0;

	if ((NULL == local) || (NULL == dest) || (NULL == buffer)) {
		TRACE(ERROR,
		      LOG
		      ("Unable to send data over socket. Invalid parameters"));
		return ERROR_BAD_PARAM;
	}

	msg.msg_flags = MSG_DONTWAIT;
	msg.msg_name = dest;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	vec.iov_base = (uint8_t *) buffer;
	vec.iov_len = buff_len;

	bytes_sent = kernel_sendmsg(local, &msg, &vec, 1, vec.iov_len);

	return ((buff_len == bytes_sent) ? SUCCESS : ERROR);
}
