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
 *****************************************************************************
 *
 *  File:    dbgout.c
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 *****************************************************************************
 *
 *  This file contains the module logging mechanism impl
 *
 ****************************************************************************
 */

#include <linux/printk.h>
#include <linux/kernel.h>
#include "dbgout.h"

#define MAX_DEBUG_MSG_LEN 960	/* stack frame size is 1024 */
int debug_flags = DEBUG;

void debug_print(const char *func_name, const char *format, ...)
{
	va_list args;
	char debug_log[MAX_DEBUG_MSG_LEN] = { 0 };

	snprintf(debug_log, (MAX_DEBUG_MSG_LEN - 1), "%s: %s", func_name,
		 format);

	va_start(args, format);

	vprintk(debug_log, args);

	va_end(args);
}
