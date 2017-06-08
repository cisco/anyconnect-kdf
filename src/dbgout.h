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
 *  File:    dbgout.h
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 ************************************************************************
 *
 *  This file contains the module logging mechanism impl
 *
 ***********************************************************************
 */

#ifndef _DBG_OUT_H_
#define _DBG_OUT_H_

/*------------------------------------------------------------------------
 * Debug flag bits
 *-----------------------------------------------------------------------
 */
#define EMERGENCY  0
#define ALERT      1
#define CRITICAL   2
#define ERROR      3
#define WARNING    4
#define NOTICE     5
#define INFO       6
#define DEBUG      7

extern int debug_flags;

/*
 * debug_print function
 */
void debug_print(const char *func_name, const char *format, ...);

#define KERN_SOH_UNSAFE "\001"
#define LOG(fmt, ...) \
	debug_print(__func__, KERN_SOH_UNSAFE fmt "\n", ##__VA_ARGS__)

/*-------------------------------------------------------------------------
 * Debug macro.  If the specified bit is set in debug_flags then execute
 * the specified code.
 * -----------------------------------------------------------------------
 */

#define TRACE(bits, code) \
	{ \
		if (debug_flags >= (bits)) \
			code; \
	}

#endif
