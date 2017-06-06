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
 *  File:   user_cmd_hndl.c
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 *****************************************************************************
 *
 *  This file contains the handlers for the userspace commands
 *
 ***************************************************************************
 */

#include <linux/slab.h>
#include "dbgout.h"
#include "defines.h"
#include "nvm_user_kernel_types.h"
#include "dns_user_kernel_types.h"
#include "nvm_plugin.h"
#include "dns_plugin.h"
/**
 * \brief handle the userspace command
 */
void process_userspace_cmd(char *pData, size_t size)
{
	uint32_t command;
	struct nvm_info nvm_info;
	struct dns_info dns_info;
	uint32_t reportInterval = 0;

	memcpy(&command, pData, sizeof(command));
	switch (command) {
	case NVM_PLUGIN_COMMAND_ENABLE_APPFLOW:
		TRACE(DEBUG,
		      LOG("command ENABLE_APPFLOW(%d) received", command));
		memcpy(&nvm_info, (pData + sizeof(struct nvm_io_ctrl)),
		       sizeof(nvm_info));
		g_nvm_plugin.exporter_address.sin_family = AF_INET;
		g_nvm_plugin.exporter_address.sin_addr.s_addr =
		    nvm_info.to_local.ipv4.s_addr;
		g_nvm_plugin.exporter_address.sin_port = nvm_info.to_local_port;
		nvm_plugin_start();
		break;
	case NVM_PLUGIN_COMMAND_DISABLE_APPFLOW:
		TRACE(DEBUG,
		      LOG("command DISABLE_APPFLOW(%d) received", command));
		nvm_plugin_stop();
		break;
	case NVM_PLUGIN_COMMAND_SET_FLOW_REPORT_INTERVAL:
		memcpy(&reportInterval, (pData + sizeof(struct nvm_io_ctrl)),
		       sizeof(reportInterval));
		nvm_plugin_update_periodic_report_interval(reportInterval);
		break;
	case DNS_PLUGIN_COMMAND_ENABLE:
		TRACE(DEBUG, LOG("command DNS_ENABLE(%d) received", command));
		memcpy(&dns_info, (pData + sizeof(struct dns_io_ctrl)),
		       sizeof(dns_info));
		g_dns_plugin.exporter_address.sin_family = AF_INET;
		g_dns_plugin.exporter_address.sin_addr.s_addr =
		    dns_info.to_local.ipv4.s_addr;
		g_dns_plugin.exporter_address.sin_port = dns_info.to_local_port;

		dns_plugin_start();
		break;
	case DNS_PLUGIN_COMMAND_DISABLE:
		TRACE(DEBUG, LOG("command DNS_DISABLE(%d) received", command));
		dns_plugin_stop();
		break;
	default:
		break;
	}
}
