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
 *  File:    dns_plugin.h
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 ******************************************************************************
 *
 *  This file contains the implementation of the DNS Plugin
 *  This plugin inspects the DNS packets and sends the DNS responses
 *  to a userspace DNS
 *
 ******************************************************************************
 */

#ifndef _DNSPLUGIN_H_
#define _DNSPLUGIN_H_

#include <linux/spinlock.h>
#include "defines.h"
#include "utils.h"
#include "work.h"
#include "llist.h"

struct dns_plugin {
	struct socket *pSocket;
	struct sockaddr_in exporter_address;

	spinlock_t dnsmessagelist_lock;
	struct llist *dns_msg_list;
	struct work_on_q send_dns_message_wq;	/* processing work */
	bool started;
};

extern struct dns_plugin g_dns_plugin;

error_code dns_plugin_start(void);
error_code dns_plugin_stop(void);
error_code dns_plugin_notify_network_packet(struct nw_pkt_meta *pNwPkt);

#endif				/* _DNSPLUGIN_H_ */
