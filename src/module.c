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
 *****************************************************************************
 *
 *  File:   module.c
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 *****************************************************************************
 *
 *  This file contains the module Entry and Exit points
 *
 *****************************************************************************
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sysctl.h>
#include "dbgout.h"
#include "defines.h"
#include "netlink_interface.h"
#include "netfilter_interface.h"

int min_debug_flags = EMERGENCY;
int max_debug_flags = DEBUG;

/*  Represent the following file entries:
 *      debugLevel
 *  Ultimately, this table will be added into /proc/sys/ac_kdf/ folder
 *  such that we have the following files entries -
 *     /proc/sys/ac_kdf/debugLevel
 */
struct ctl_table debugLevel_table[] = {
	{
	 .procname = "debugLevel",
	 .data = &debug_flags,
	 .maxlen = sizeof(int),
	 .mode = 0644,
	 .proc_handler = &proc_dointvec_minmax,
	 .extra1 = &min_debug_flags,
	 .extra2 = &max_debug_flags},
	{}
};

/*  Represent the ac_kdf/ folder that will host the above file entries */
struct ctl_table sys_ackdf_table[] = {
	{
	 .procname = "ac_kdf",
	 .mode = 0555,
	 .child = debugLevel_table},
	{}
};

struct ctl_table_header *ackdf_sysctl_header;

static __init int kdf_module_init(void)
{
	ackdf_sysctl_header = register_sysctl_table(sys_ackdf_table);
	if (!netlink_init())
		return 1;

	return load_ACKDF()?0 : 1;
}

static __exit void kdf_module_exit(void)
{
	unregister_sysctl_table(ackdf_sysctl_header);
	netlink_release();
	unload_ACKDF();
}

module_init(kdf_module_init);
module_exit(kdf_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cisco Systems <ac-nvm-admins@cisco.com>");
MODULE_DESCRIPTION("Cisco AnyConnect Flow Interceptor");
