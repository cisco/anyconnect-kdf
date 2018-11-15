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
 *  File:   nvplugin.h
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 *************************************************************************
 *
 *  This file contains the implementation of the NVM Plugin
 *  This plugin inspects the TCP and UDP packets and extract
 *  flow information and send that to the NVM userspace agent
 *
 *************************************************************************
 */

#ifndef _NVMPLUGIN_H_
#define _NVMPLUGIN_H_

#include <linux/spinlock.h>
#include <linux/mutex.h>
#include "defines.h"
#include "nvm_user_kernel_types.h"
#include "utils.h"
#include "llist.h"
#include "work.h"
#include "delayed_work.h"

/*
 * Hash bucket sizes for TCP and UDP hashtables in power of 2
 * each bucket will require 4b of memory
 */
#define TCP_HASH_BUCKET_SIZE_BITS 5
#define UDP_HASH_BUCKET_SIZE_BITS 5

struct TrackAppFlow {
	struct app_flow *flow;
	uint8_t sent_flags;	/* a bitset of all TCP flags sent. */
	uint8_t recv_flags;	/* similar to sent_flags, just received. */
	bool finished;		/* Marks a tracking object for disposal. */
	bool connected;		/* True if TCP connection is established.*/
	/* timestamp for the last packet tracked for this flow */
	uint32_t last_timestamp;
};

/*
 * L4 Info that needs to be captured
 */
struct l4info {
	uint8_t flags;		/* tcp only */
	uint16_t sport;
	uint16_t dport;
	uint16_t len;
};

struct l3info {
	uint8_t proto;		/* protocol */
	struct ac_addr saddr;
	struct ac_addr daddr;
};

struct nwk_packet_info {
	uint32_t pid;
	uint32_t start_time;
	enum direction_e edirection;
	struct l3info l3;
	struct l4info l4;
};

struct nvm_plugin {
	struct socket *pSocket;
	struct sockaddr_in exporter_address;

	/* lock to manipulate untrackedpackets list */
	spinlock_t spin_untrack_lock;
	struct mutex mutex_track_lock;	/* lock to manipulate tracked flows */
	/* lock to manipulate list of flows to be sent out */
	struct mutex mutex_send_lock;

	struct llist *untracked_pkt_list;
	struct llist *send_list;
	DECLARE_HASHTABLE(tcp_flows, TCP_HASH_BUCKET_SIZE_BITS);
	DECLARE_HASHTABLE(udp_flows, UDP_HASH_BUCKET_SIZE_BITS);

	struct work_on_q track_work;	/* processing work */
	struct work_on_q send_work;	/* sender work */
	struct delayed_work_on_q cleanup_work;	/* clean-up delayed work */
	struct delayed_work_on_q *periodic_work;	/* periodic work*/
	/*
	 * time interval in seconds indicating when to send a
	 * report on an open flow
	 * values:  -1 - only send report at the end of a flow (default),
	 *           0 - send at start and end,
	 *           > 0 - send periodic reports and at flow start and end.
	 */
	int32_t flow_report_interval;
	bool started;
};

extern struct nvm_plugin g_nvm_plugin;

error_code nvm_plugin_start(void);
error_code nvm_plugin_stop(void);
error_code nvm_plugin_update_periodic_report_interval(uint32_t
							report_interval);
error_code nvm_plugin_notify_network_packet(struct nw_pkt_meta *pNwPkt);

#endif
