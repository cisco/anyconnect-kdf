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
 *  File:   netlink_interface.c
 *  Author: Koushik Chakravarty <kouchakr@cisco.com>
 *
 ****************************************************************************
 *
 *  This file contains methods to work on netlink sockets.
 *  It listens on incoming control commands from userspace
 *  and delivers appropriate actions.
 *
 **************************************************************************
 */

#include <linux/module.h>
#include <linux/version.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include "defines.h"
#include "dbgout.h"
#include "user_cmd_hndl.h"

#define NETLINK_NVM_USER 30

struct sock *netlink_sk;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0))
struct netlink_kernel_cfg cfg;
#endif

/**
 * \brief Callback invoked by a incoming netlink socket data
 */
void netlink_recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = NULL;

	nlh = (struct nlmsghdr *)skb->data;
	if (NULL == nlh) {
		TRACE(ERROR, LOG("Invalid data received via netlink"));
		return;
	}
	/* process the message */
	process_userspace_cmd((char *)NLMSG_DATA(nlh), nlh->nlmsg_len);
}

/**
 * \brief netlink_init -
 *  initializes the netlink socket and listens for incoming commands
 */
bool netlink_init(void)
{
	TRACE(DEBUG, LOG("Setting up Netlink socket"));

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 6, 0))
	netlink_sk =
	    netlink_kernel_create(&init_net, NETLINK_NVM_USER, 0,
				  netlink_recv_msg, NULL, THIS_MODULE);
#else
	cfg.input = netlink_recv_msg;
	netlink_sk = netlink_kernel_create(&init_net, NETLINK_NVM_USER, &cfg);
#endif
	if (NULL == netlink_sk) {
		TRACE(DEBUG, LOG("Error creating socket"));
		return false;
	}
	return true;
}

/**
 * \brief releases the netlink socket
 */
void netlink_release(void)
{
	TRACE(DEBUG, LOG("Tearing down the netlink socket"));
	netlink_kernel_release(netlink_sk);
	netlink_sk = NULL;
}
