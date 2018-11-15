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
 ***************************************************************************
 *
 *  File:   nvm_plugin.c
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 ***************************************************************************
 *
 *  This file contains the implementation of the NVM Plugin
 *
 ***************************************************************************
 */

#include <linux/slab.h>
#include <linux/net.h>
#include <linux/in6.h>
#include "dbgout.h"
#include "nvm_plugin.h"
#include "nvm_user_kernel_types.h"

#define FLAG_FIN (1)
#define FLAG_SYN (1 << 1)
#define FLAG_RST (1 << 2)
#define FLAG_ACK (1 << 4)
#define IS_SET(bitset, flag) (((bitset) & (flag)) == (flag))
#define CLEANUP_DELAY 10
#define UDP_FLOW_TIMEOUT_SECS 120
#define TCP_FLOW_TIMEOUT_SECS 120

#define DEFERRED_SENDER_WQ      "ACKDFSender"
#define DEFERRED_PROCESSOR_WQ   "ACKDFProcessor"
#define DEFERRED_CLEANUP_WQ     "ACKDFCleanup"
#define DEFERRED_PERIODIC_WQ     "ACKDFPeriodicFlows"

#define MIN_FLOW_REPORT_INTERVAL_SEC         60
#define MAX_FLOW_REPORT_INTERVAL_SEC        360

struct nvm_plugin g_nvm_plugin;

/*
*   \brief Method to clear all the various lists
*/
static void nvm_plugin_list_clear(void)
{
	void *iter_data = NULL;
	struct llist *iter = NULL;
	struct llist *tmp = NULL;
	struct app_flow *flow = NULL;
	struct nwk_packet_info *pNwkPktInfo = NULL;

	list_get_next(g_nvm_plugin.send_list, &iter, &iter_data);
	for (; (iter) && iter != g_nvm_plugin.send_list;) {
		flow = (struct app_flow *)iter_data;
		KFREE(flow);
		tmp = iter;
		list_get_next(iter, &iter, &iter_data);
		list_delete(g_nvm_plugin.send_list, tmp);
	}

	iter_data = NULL;
	iter = NULL;
	list_get_next(g_nvm_plugin.untracked_pkt_list, &iter, &iter_data);
	for (; (iter) && iter != g_nvm_plugin.untracked_pkt_list;) {
		pNwkPktInfo = (struct nwk_packet_info *)iter_data;
		KFREE(pNwkPktInfo);
		tmp = iter;
		list_get_next(iter, &iter, &iter_data);
		list_delete(g_nvm_plugin.untracked_pkt_list, tmp);
	}
}

/*
*   \brief Method to handle packets being delivered
*/
error_code nvm_plugin_notify_network_packet(struct nw_pkt_meta *pNwPkt)
{
	struct l4info l4_info;
	struct ip_hdr *ip_header = NULL;
	struct tcphdr *tcp_header = NULL;
	struct udphdr *udp_header = NULL;
	struct nwk_packet_info *packet_info = NULL;
	struct task_struct *curr = NULL;
	struct l3info l3_info = {0};
	unsigned long flags = 0;
	bool retcode = false;
	uint16_t ip_payload_len = 0;
	struct in6_addr in6addr_loopback_be = IN6ADDR_LOOPBACK_INIT;

	if (!g_nvm_plugin.started)
		return SUCCESS;

	if (NULL == g_nvm_plugin.pSocket) {
		TRACE(ERROR, LOG("No socket available for flow reporting"));
		return ERROR_NOT_INITIALIZED;
	}
	if (NULL == pNwPkt || NULL == pNwPkt->ip_header
		|| NULL == pNwPkt->l4_header) {
		TRACE(ERROR, LOG("Malformed packet"));
		return ERROR_ERROR;
	}

	ip_header = pNwPkt->ip_header;
	if (IS_IP_VERSION4(ip_header->h_ip4.version)) {
		/* IPv4 */
		/* Skip local host packets */
		if ((LOOPBACK_ADDR_V4_BE == ip_header->h_ip4.saddr)
		    || (LOOPBACK_ADDR_V4_BE == ip_header->h_ip4.daddr)) {
			return SUCCESS;
		}
		l3_info.proto = ip_header->h_ip4.protocol;
		/* IP Payload len = IP total len - IP Header len */
		/* IP Header len is ihl number of 32 bits*/
		ip_payload_len = ntohs(ip_header->h_ip4.tot_len) - (ip_header->h_ip4.ihl * 4);
		l3_info.saddr.family = AF_INET;
		l3_info.saddr.ipv4.s_addr = ip_header->h_ip4.saddr;
		l3_info.daddr.family = AF_INET;
		l3_info.daddr.ipv4.s_addr = ip_header->h_ip4.daddr;
	}
	else {
		/* IPv6 */
		/* Skip local host packets */
		if ((!memcmp(&in6addr_loopback_be, &ip_header->h_ip6.saddr, sizeof(struct in6_addr)))
		    || (!memcmp(&in6addr_loopback_be, &ip_header->h_ip6.daddr, sizeof(struct in6_addr)))) {
			return SUCCESS;
		}
		l3_info.proto = ip_header->h_ip6.nexthdr;
		ip_payload_len = ntohs(ip_header->h_ip6.payload_len);
		l3_info.saddr.family = AF_INET6;
		l3_info.saddr.ipv6 = ip_header->h_ip6.saddr;
		l3_info.daddr.family = AF_INET6;
		l3_info.daddr.ipv6 = ip_header->h_ip6.daddr;
	}
	memset(&l4_info, 0, sizeof(struct l4info));
	if (IPPROTO_TCP == l3_info.proto) {
		tcp_header = &(pNwPkt->l4_header->h_tcp);
		l4_info.sport = tcp_header->source;
		l4_info.dport = tcp_header->dest;
		l4_info.flags |= (tcp_header->ack) << 4;
		l4_info.flags |= (tcp_header->rst) << 2;
		l4_info.flags |= (tcp_header->syn) << 1;
		l4_info.flags |= (tcp_header->fin);
		/*TCP payload length = IP Payload len - TCP Header*/
		l4_info.len = ip_payload_len - (tcp_header->doff * 4);
	} else if (IPPROTO_UDP == l3_info.proto) {
		udp_header = &(pNwPkt->l4_header->h_udp);
		l4_info.sport = udp_header->source;
		l4_info.dport = udp_header->dest;
		/* in case of UDP, the header size is 8 bytes.*/
		l4_info.len = ntohs(udp_header->len) - 8;
	} else {
		return SUCCESS;
	}

	packet_info = (struct nwk_packet_info *)
	    KMALLOC_ATOMIC(sizeof(struct nwk_packet_info));
	if (NULL == packet_info) {
		TRACE(ERROR, LOG("Failed to construct packet object"));
		return ERROR_ERROR;
	}
	memset(packet_info, 0, sizeof(struct nwk_packet_info));

	curr = get_curr_task();
	if (NULL == curr) {
		TRACE(ERROR, LOG("Failed to get current task struct"));
		KFREE(packet_info);
		return ERROR_ERROR;
	}
	packet_info->pid = get_pid_of_task(curr);
	unref_task(curr);

	packet_info->edirection = pNwPkt->direction;
	packet_info->start_time = get_unix_systime();

	memcpy(&packet_info->l3, &l3_info, sizeof(packet_info->l3));
	memcpy(&packet_info->l4, &l4_info, sizeof(packet_info->l4));

	spin_lock_irqsave(&g_nvm_plugin.spin_untrack_lock, flags);
	retcode =
	    list_insert_tail(g_nvm_plugin.untracked_pkt_list, packet_info,
			     true);
	spin_unlock_irqrestore(&g_nvm_plugin.spin_untrack_lock, flags);

	if (!retcode) {
		TRACE(ERROR, LOG("Adding the packet failed"));
		KFREE(packet_info);
		return ERROR_ERROR;
	}

	schedule_work_on_queue(&g_nvm_plugin.track_work);
	return SUCCESS;
}

/*
*   \brief Helper method called by the sender work
*/
static void send_pending_flows(void *context)
{
	struct llist *iter = NULL;
	void *iter_data = NULL;
	error_code status;
	struct nvm_message_header *nvm_header = NULL;

	mutex_lock(&g_nvm_plugin.mutex_send_lock);
	while (true) {
		if (is_list_empty(g_nvm_plugin.send_list))
			break;	/* Done - for now. */
		iter = NULL;
		iter_data = NULL;
		list_get_next(g_nvm_plugin.send_list, &iter, &iter_data);

		if (!iter_data)
			break;

		nvm_header = (struct nvm_message_header *)iter_data;
		status =
			socket_sendto(g_nvm_plugin.pSocket,
					&g_nvm_plugin.exporter_address,
					(uint8_t *) iter_data, nvm_header->length);
		if (SUCCESS != status) {
			TRACE(ERROR,
					LOG("Failed to send flow. Error = %d", status));
		}
		/* Delete the flow */
		list_delete(g_nvm_plugin.send_list, iter);
		KFREE(iter_data);
	}
	mutex_unlock(&g_nvm_plugin.mutex_send_lock);
}

/*
 * Two flows are related if the transport protocol, the local port,
 * the remote port
 * and address are the same.
 */
static bool are_tcp_flows_similar(const struct app_flow *new_flow,
				  const struct app_flow *old_flow)
{
	/* IPv4 case */
	if (AF_INET == old_flow->local.Ipv4.sin_family) {
		return ((new_flow->local.Ipv4.sin_port == old_flow->local.Ipv4.sin_port)
		    && (new_flow->peer.Ipv4.sin_port == old_flow->peer.Ipv4.sin_port)
		    && (new_flow->peer.Ipv4.sin_family ==
			old_flow->peer.Ipv4.sin_family)
		    && (new_flow->local.Ipv4.sin_addr.s_addr ==
			old_flow->local.Ipv4.sin_addr.s_addr)
		    && (new_flow->peer.Ipv4.sin_addr.s_addr ==
			old_flow->peer.Ipv4.sin_addr.s_addr));
	}
	/* IPv6 case */
	else {
		return ((new_flow->local.Ipv6.sin6_port == old_flow->local.Ipv6.sin6_port)
		    && (new_flow->peer.Ipv6.sin6_port == old_flow->peer.Ipv6.sin6_port)
		    && (new_flow->peer.Ipv6.sin6_family ==
			old_flow->peer.Ipv6.sin6_family)
		    && (0 == memcmp(&new_flow->local.Ipv6.sin6_addr,
					&old_flow->local.Ipv6.sin6_addr,
						sizeof(struct in6_addr)))
		    && (0 == memcmp(&new_flow->peer.Ipv6.sin6_addr,
			 		&old_flow->peer.Ipv6.sin6_addr,
						sizeof(struct in6_addr))));
	}
}

/*
 * Two UDP flows are related when their protocol and
 * one of the address are same.
 * However, A UDP flow ends when
 * OUTBOUND case: when the local_addr remains same and the peer_addr changes
 */
static bool are_udp_flows_similar(const struct app_flow *new_flow,
				  const struct app_flow *old_flow,
				  bool *peers_matched)
{
	if (NULL == peers_matched)
		return false;

	*peers_matched = false;

	/* Ipv4 case */
	if (AF_INET == old_flow->local.Ipv4.sin_family) {
		/* If local matches */
		if ((new_flow->local.Ipv4.sin_port ==
			old_flow->local.Ipv4.sin_port)
		    && (new_flow->local.Ipv4.sin_addr.s_addr ==
			old_flow->local.Ipv4.sin_addr.s_addr)) {

			/* If peers also match, then its an existing flow */
			if ((new_flow->peer.Ipv4.sin_family ==
				old_flow->peer.Ipv4.sin_family)
			    && (new_flow->peer.Ipv4.sin_port ==
				old_flow->peer.Ipv4.sin_port)
			    && (new_flow->peer.Ipv4.sin_addr.s_addr ==
				old_flow->peer.Ipv4.sin_addr.s_addr)) {

				*peers_matched = true;
				return true;
			}
			else {
				return true;
			}
		}
	}
	/* Ipv6 case */
	else {
		/* If local ports match */
		if ((new_flow->local.Ipv6.sin6_port ==
			old_flow->local.Ipv6.sin6_port)
		    && (0 == memcmp(&new_flow->local.Ipv6.sin6_addr,
				&old_flow->local.Ipv6.sin6_addr,
				sizeof(struct in6_addr)))) {

			/* If peers also match, then its an existing flow */
			if ((new_flow->peer.Ipv6.sin6_family ==
				old_flow->peer.Ipv6.sin6_family)
			    && (new_flow->peer.Ipv6.sin6_port ==
				old_flow->peer.Ipv6.sin6_port)
			    && (0 == memcmp(&new_flow->peer.Ipv6.sin6_addr,
					&old_flow->peer.Ipv6.sin6_addr,
					sizeof(struct in6_addr)))) {

				*peers_matched = true;
				return true;
			}
			else {
				return true;
			}
		}
	}
	return false;
}

/**
 * \brief extract the base portion of a pathname
 * \description
 *
 * \param[in] pathname of the process
 *
 * \return base portion of the path
*/
static inline const char *file_name_from_path(const char *path)
{
	const char *p = strrchr (path, '/');
	return p ? p + 1 : path;
}

/*
*   \brief Method to get process information from the flow
*/
static void get_task_details(struct app_flow *flow)
{
	struct task_struct *curr = NULL;
	struct task_struct *parent = NULL;
	const char *process_name = NULL;
	const char *parent_process_name = NULL;

	if (NULL == flow)
		return;
	if (0 == flow->pid)
		return;

	curr = get_task_from_pid(flow->pid);
	if (NULL == curr)
		return;

	flow->file_path_len =
		get_exepath_from_task(curr, flow->file_path, ARRAY_SIZE(flow->file_path));

	process_name = file_name_from_path(flow->file_path);

	if (process_name && strcmp(process_name, default_name)) {
		strlcpy(flow->file_name, process_name, sizeof(flow->file_name));
		flow->file_name_len = strlen(flow->file_name);
	}
	else {
		flow->file_name_len =
			get_taskname(curr, flow->file_name, ARRAY_SIZE(flow->file_name));
	}

	parent = get_parent(curr);
	unref_task(curr);
	if (NULL == parent)
		return;

	flow->parent_pid = get_pid_of_task(parent);
	flow->parent_file_path_len =
		get_exepath_from_task(parent, flow->parent_file_path,
			ARRAY_SIZE(flow->parent_file_path));
	parent_process_name = file_name_from_path(flow->parent_file_path);

	if (parent_process_name && strcmp(parent_process_name, default_name)) {
		strlcpy(flow->parent_file_name, parent_process_name, sizeof(flow->parent_file_name));
		flow->parent_file_name_len = strlen(flow->parent_file_name);
	}
	else {
		flow->parent_file_name_len =
			get_taskname(parent, flow->parent_file_name,
				ARRAY_SIZE(flow->parent_file_name));
	}
	unref_task(parent);
}

/*
*   \brief Method to create a flow object from raw network data
*/
static bool create_flow_from_pkt(struct nwk_packet_info *packet_info,
				 struct TrackAppFlow **pFlowObj)
{
	struct TrackAppFlow *track = NULL;
	struct app_flow *flow = NULL;

	if (NULL == packet_info || NULL == pFlowObj)
		return false;

	*pFlowObj = NULL;
	track = KMALLOC(sizeof(struct TrackAppFlow));
	if (NULL == track) {
		TRACE(ERROR, LOG("Failed to allocate TrackAppFlow"));
		return false;
	}

	memset(track, 0, sizeof(struct TrackAppFlow));

	track->flow = KMALLOC(sizeof(struct app_flow));
	if (NULL == track->flow) {
		TRACE(ERROR, LOG("Failed to allocate app_flow"));
		KFREE(track);
		return false;
	}

	memset(track->flow, 0, sizeof(struct app_flow));

	flow = (track->flow);
	/* Set the header */
	flow->header.type = NVM_MESSAGE_APPFLOW_DATA;
	flow->header.version = NVM_APPFLOW_VERSION;
	flow->header.length = sizeof(struct app_flow);

	flow->proto = packet_info->l3.proto;

	flow->start_time = packet_info->start_time;
	track->connected = false;
	track->last_timestamp = flow->start_time;

	switch (packet_info->edirection) {
	case INBOUND:
		/* No need to get the processid for incoming packet,
		 * as that will be softIRQ calling the nf hook */
		flow->pid = 0;

		flow->direction = NVM_FLOW_DIRECTION_IN;
		if (AF_INET == packet_info->l3.daddr.family) {
			flow->family = AF_INET;
			flow->local.Ipv4.sin_family = AF_INET;
			flow->local.Ipv4.sin_addr.s_addr = packet_info->l3.daddr.ipv4.s_addr;
			flow->local.Ipv4.sin_port = packet_info->l4.dport;

			flow->peer.Ipv4.sin_family = AF_INET;
			flow->peer.Ipv4.sin_addr.s_addr = packet_info->l3.saddr.ipv4.s_addr;
			flow->peer.Ipv4.sin_port = packet_info->l4.sport;
		}
		else {
			flow->family = AF_INET6;
			flow->local.Ipv6.sin6_family = AF_INET6;
			flow->local.Ipv6.sin6_addr = packet_info->l3.daddr.ipv6;
			flow->local.Ipv6.sin6_port = packet_info->l4.dport;

			flow->peer.Ipv6.sin6_family = AF_INET6;
			flow->peer.Ipv6.sin6_addr = packet_info->l3.saddr.ipv6;
			flow->peer.Ipv6.sin6_port = packet_info->l4.sport;
		}
		track->recv_flags = packet_info->l4.flags;
		flow->in_bytes = packet_info->l4.len;
		break;
	case OUTBOUND:
		/* Get the current process id */
		flow->pid = packet_info->pid;

		flow->direction = NVM_FLOW_DIRECTION_OUT;
		if (AF_INET == packet_info->l3.saddr.family) {
			flow->family = AF_INET;
			flow->local.Ipv4.sin_family = AF_INET;
			flow->local.Ipv4.sin_addr.s_addr = packet_info->l3.saddr.ipv4.s_addr;
			flow->local.Ipv4.sin_port = packet_info->l4.sport;

			flow->peer.Ipv4.sin_family = AF_INET;
			flow->peer.Ipv4.sin_addr.s_addr = packet_info->l3.daddr.ipv4.s_addr;
			flow->peer.Ipv4.sin_port = packet_info->l4.dport;
		}
		else {
			flow->family = AF_INET6;
			flow->local.Ipv6.sin6_family = AF_INET6;
			flow->local.Ipv6.sin6_addr = packet_info->l3.saddr.ipv6;
			flow->local.Ipv6.sin6_port = packet_info->l4.sport;

			flow->peer.Ipv6.sin6_family = AF_INET6;
			flow->peer.Ipv6.sin6_addr = packet_info->l3.daddr.ipv6;
			flow->peer.Ipv6.sin6_port = packet_info->l4.dport;
		}
		track->sent_flags = packet_info->l4.flags;
		flow->out_bytes = packet_info->l4.len;
		break;
	default:
		TRACE(ERROR, LOG("Traffic direction unknown"));
		KFREE(track->flow);
		KFREE(track);
		return false;
	}

	*pFlowObj = track;
	return true;
}

/*
 * \brief private method to report flows triggered by period_flow interval
 */
static bool report_flow(struct app_flow *app_flow)
{
	struct app_flow *flow_copy = NULL;

	if (NULL == app_flow)
		return false;

	/* Make a copy of the flow */
	flow_copy = KMALLOC(sizeof(struct app_flow));
	if (NULL == flow_copy) {
		TRACE(ERROR, LOG("Failed to allocate copy of app_flow"));
		return false;
	}
	app_flow->end_time = get_unix_systime();
	memcpy(flow_copy, app_flow, sizeof(struct app_flow));
	/* Send the flow */
	mutex_lock(&g_nvm_plugin.mutex_send_lock);
	list_insert(g_nvm_plugin.send_list, flow_copy, false);
	schedule_work_on_queue(&g_nvm_plugin.send_work);
	mutex_unlock(&g_nvm_plugin.mutex_send_lock);

	return true;
}

/*
 * \brief private method to report pid_info
 */
static bool process_new_pid_info(struct app_flow *flow)
{
	struct nvm_pid_info *pid_info = NULL;

	if (NULL == flow)
		return false;

	if (0 == flow->pid)
		return false;

	pid_info = KMALLOC(sizeof(struct nvm_pid_info));
	if (NULL == pid_info) {
		TRACE(ERROR, LOG("Failed to allocate pid_info"));
		return false;
	}
	// Copy the appflow's process info into the pid_info
	pid_info->pid = flow->pid;
	pid_info->file_name_len = flow->file_name_len;
	memcpy( pid_info->file_name,flow->file_name, ARRAY_SIZE(pid_info->file_name) );

	pid_info->file_path_len = flow->file_path_len;
	memcpy( pid_info->file_path,flow->file_path, ARRAY_SIZE(pid_info->file_path) );

	pid_info->parent_pid = flow->parent_pid;
	pid_info->parent_file_name_len = flow->parent_file_name_len;
	memcpy( pid_info->parent_file_name,flow->parent_file_name, ARRAY_SIZE(pid_info->parent_file_name) );

	pid_info->parent_file_path_len = flow->parent_file_path_len;
	memcpy( pid_info->parent_file_path,flow->parent_file_path, ARRAY_SIZE(pid_info->parent_file_path) );
	pid_info->header.type = NVM_MESSAGE_PID_INFO;
	pid_info->header.version = NVM_APPFLOW_VERSION;
	pid_info->header.length = sizeof(struct nvm_pid_info);
	/* Send the pidinfo */
	mutex_lock(&g_nvm_plugin.mutex_send_lock);
	list_insert(g_nvm_plugin.send_list, pid_info, false);
	schedule_work_on_queue(&g_nvm_plugin.send_work);
	mutex_unlock(&g_nvm_plugin.mutex_send_lock);

	return true;
}

/*
*   \brief This method process an incoming tcp packet
*          and checks if its part of a flow.
*          It also sends out completed flows.
*/
static void process_tcp_flow(struct nwk_packet_info *untracked)
{
	/* Construct the TrackAppFlow structure */
	bool new_packet = true;
	struct TrackAppFlow *track = NULL;
	struct TrackAppFlow *track_old = NULL;
	struct hash_list *itr = NULL;
	HLIST_ITER;

	if (!create_flow_from_pkt(untracked, &track)) {
		TRACE(ERROR, LOG("Failure to create flow object"));
		return;
	}

	for_each_hlist_match(g_nvm_plugin.tcp_flows, itr, next,
			     track->flow->local.Ipv4.sin_port) {
		track_old = (struct TrackAppFlow *)itr->data;
		if (are_tcp_flows_similar(track->flow, track_old->flow)) {
			new_packet = false;
			/* Get the packet info in the flow */
			track_old->last_timestamp = get_unix_systime();
			track_old->flow->in_bytes += track->flow->in_bytes;
			track_old->flow->out_bytes += track->flow->out_bytes;
			track_old->sent_flags |= track->sent_flags;
			track_old->recv_flags |= track->recv_flags;
			if ((0 == track_old->flow->pid)
			    && (NVM_FLOW_DIRECTION_OUT ==
				track->flow->direction)) {
				track_old->flow->pid = track->flow->pid;
				get_task_details(track_old->flow);
			}
			/* KFREE the new flow*/
			KFREE(track->flow);
			KFREE(track);

			/* Check if TCP connection is established*/
			if (!track_old->connected
			    && IS_SET(track_old->sent_flags, FLAG_SYN)
			    && IS_SET(track_old->sent_flags, FLAG_ACK)
			    && IS_SET(track_old->recv_flags, FLAG_SYN)
			    && IS_SET(track_old->recv_flags, FLAG_ACK)) {
				track_old->connected = true;
				/* Send OnFlowStart for newly established tcp connections.*/
				process_new_pid_info(track_old->flow);
				/* Start of a new flow -
				 * if TCP connection is established and
				 * configured to report on flow start
				 * submit the flow data. */
				if (g_nvm_plugin.flow_report_interval >= 0) {
					track_old->flow->stage = e_FLOW_REPORT_STAGE_START;
					report_flow(track_old->flow);
				}
			}

			/*
			 * Both sides send a FIN, or either side sends a RST
			 */
			if ((IS_SET(track_old->sent_flags, FLAG_FIN)
			     && IS_SET(track_old->recv_flags, FLAG_FIN))
			    || IS_SET(track_old->sent_flags, FLAG_RST)
			    || IS_SET(track_old->recv_flags, FLAG_RST)) {

				/* TCP connection is established, send the flow.*/
				if (track_old->connected) {
					track_old->flow->end_time = get_unix_systime();
					track_old->flow->stage =
							e_FLOW_REPORT_STAGE_END;
					mutex_lock(&g_nvm_plugin.mutex_send_lock);
					list_insert(g_nvm_plugin.send_list,
							track_old->flow, false);
					schedule_work_on_queue(&g_nvm_plugin.send_work);
					mutex_unlock(&g_nvm_plugin.mutex_send_lock);
				} else {
					KFREE(track_old->flow);
				}
				/* Delete the track as it has been sent/cleaned now.
				 * don't KFREE the actuall flow here.
				 * The sender task will need it.
				 */
				hlist_del(itr);
				KFREE(track_old);
			}
			break;
		}

	}

	if (new_packet) {
		/* No related flows for this packet being tracked till now.
		   Hence add this packet only if direction is outbound and
		   sent flag has either SYN bit set or SYN & ACK bit set.
		   Reason for adding this check is to avoid incoming
		   SYN flood scenario. */
		if ((NVM_FLOW_DIRECTION_OUT == track->flow->direction)
		    && IS_SET(track->sent_flags, FLAG_SYN)) {

			if(IS_SET(track->sent_flags, FLAG_ACK)) {
				/* This is the response of incoming SYN.
				 * It is not the start of flow.
				 * Adding SYN flag & changing the direction
				 * to denote the actuall traffic which was inbound.*/
				track->recv_flags |= FLAG_SYN;
				track->flow->direction = NVM_FLOW_DIRECTION_IN;
			}
			get_task_details(track->flow);
			hlist_add(g_nvm_plugin.tcp_flows, track,
					track->flow->local.Ipv4.sin_port);
		} else {
			KFREE(track->flow);
			KFREE(track);
		}
	}
}

/*
*   \brief This method process an incoming udp packet
*          and checks if its part of a flow.
*          It also sends out completed flows.
*/
static void process_udp_flow(struct nwk_packet_info *untracked)
{
	struct TrackAppFlow *track = NULL;
	bool new_packet = true;
	struct TrackAppFlow *track_old = NULL;
	struct hash_list *itr = NULL;
	bool peers_matched = false;
	HLIST_ITER;

	if (!create_flow_from_pkt(untracked, &track)) {
		TRACE(ERROR, LOG("Failure"));
		return;
	}

	for_each_hlist_match(g_nvm_plugin.udp_flows, itr, next,
			     track->flow->local.Ipv4.sin_port) {
		track_old = (struct TrackAppFlow *)itr->data;
		peers_matched = false;
		if (are_udp_flows_similar
		    (track->flow, track_old->flow, &peers_matched)) {
			/* Remove it now to add it back later */
			/* Useful when queue is full using LRU replacement*/
			new_packet = false;
			/* Get the packet info in the flow */
			track_old->last_timestamp = get_unix_systime();
			track_old->flow->in_bytes += track->flow->in_bytes;
			track_old->flow->out_bytes += track->flow->out_bytes;

			if ((0 == track_old->flow->pid)
			    && (NVM_FLOW_DIRECTION_OUT ==
				track->flow->direction)) {
				track_old->flow->pid = track->flow->pid;
				get_task_details(track_old->flow);
				TRACE(ERROR,
				      LOG("Getting new name %d -  %s",
					  track_old->flow->pid,
					  track_old->flow->file_name));
			}

			if ((!peers_matched)
			    && (NVM_FLOW_DIRECTION_OUT ==
				track_old->flow->direction)) {
				/*
				 * UDP Client scenario -
				 * If this is new flow whose local addresses
				 * match the existing flow, peers dont match,
				 * then this is a new flow only when the old
				 * flow originated from the local machine.
				 */

				/* Send the flow */
				track_old->flow->end_time = get_unix_systime();
				track_old->flow->stage =
				    e_FLOW_REPORT_STAGE_END;
				mutex_lock(&g_nvm_plugin.mutex_send_lock);
				list_insert(g_nvm_plugin.send_list,
					    track_old->flow, false);
				schedule_work_on_queue(&g_nvm_plugin.send_work);
				mutex_unlock(&g_nvm_plugin.mutex_send_lock);

				/* don't KFREE the actual Flow.
				The sender task will need it */
				hlist_del(itr);
				KFREE(track_old);

				/* Add the new flow */
				new_packet = true;
			} else {
				/* Delete the new flow */
				KFREE(track->flow);
				KFREE(track);
			}
			break;
		}
	}

	if (new_packet) {
		/* this is a new flow */
		get_task_details(track->flow);
		process_new_pid_info(track->flow);
		hlist_add(g_nvm_plugin.udp_flows, track,
			  track->flow->local.Ipv4.sin_port);
		/* Start of a new flow -
		submit flow data if configured to report on flow start */
		if (g_nvm_plugin.flow_report_interval >= 0) {
			track->flow->stage = e_FLOW_REPORT_STAGE_START;
			report_flow(track->flow);
		}
	}
}

/*
*   \brief Helper method called by the processing worker
*/
static void track_pending_pkts(void *context)
{
	unsigned long flags = 0;
	struct llist *iter = NULL;
	void *iter_data = NULL;
	struct nwk_packet_info *untracked = NULL;

	while (true) {
		flags = 0;
		spin_lock_irqsave(&g_nvm_plugin.spin_untrack_lock, flags);
		if (!is_list_empty(g_nvm_plugin.untracked_pkt_list)) {
			iter = NULL;
			iter_data = NULL;
			list_get_next(g_nvm_plugin.untracked_pkt_list, &iter,
				      &iter_data);
			untracked = (struct nwk_packet_info *)iter_data;
			list_delete(g_nvm_plugin.untracked_pkt_list, iter);
			spin_unlock_irqrestore(&g_nvm_plugin.spin_untrack_lock,
					       flags);

			/* tracking TCP Flows */
			if (IPPROTO_TCP == untracked->l3.proto) {
				mutex_lock(&g_nvm_plugin.mutex_track_lock);
				process_tcp_flow(untracked);
				mutex_unlock(&g_nvm_plugin.mutex_track_lock);
			}
			/* track UDP flows */
			else if (IPPROTO_UDP == untracked->l3.proto) {
				mutex_lock(&g_nvm_plugin.mutex_track_lock);
				process_udp_flow(untracked);
				mutex_unlock(&g_nvm_plugin.mutex_track_lock);
			} else {
				/* Nothing to do - unknown protocol */
			}
			KFREE(untracked);
		} else {
			spin_unlock_irqrestore(&g_nvm_plugin.spin_untrack_lock,
					       flags);
			break;
		}
	}
}

/*
*   \brief Helper method called by the cleanup delayed worker
*/
static void cleanup(void *context)
{
	struct TrackAppFlow *track;
	struct task_struct *curr = NULL;
	struct hash_list *itr = NULL;
	struct hlist_node *tmp = NULL;
	int hash_bkt = 0;
	HLIST_ITER;

	mutex_lock(&g_nvm_plugin.mutex_track_lock);
	/*
	 * TCP case -
	 */
	for_each_hlist(g_nvm_plugin.tcp_flows, hash_bkt, tmp, itr, next) {
		track = (struct TrackAppFlow *)itr->data;
		curr = get_task_from_pid(track->flow->pid);
		if ((0 != track->flow->pid) && (NULL == curr)) {
			/* Send the flow only if TCP connection is established.*/
			if (track->connected) {
				track->flow->end_time = get_unix_systime();
				track->flow->stage = e_FLOW_REPORT_STAGE_END;
				mutex_lock(&g_nvm_plugin.mutex_send_lock);
				list_insert(g_nvm_plugin.send_list, track->flow, false);
				schedule_work_on_queue(&g_nvm_plugin.send_work);
				mutex_unlock(&g_nvm_plugin.mutex_send_lock);
			} else {
				KFREE(track->flow);
			}

			/* erase this entry */
			hlist_del(itr);
			/* Don't KFREE flow.
			It will be deleted by the sender task */
			KFREE(track);
		} else if ((get_unix_systime() - track->last_timestamp) >=
			   TCP_FLOW_TIMEOUT_SECS) {
			unref_task(curr);
			if(track->connected) {
				if (!(IS_SET(track->sent_flags, FLAG_FIN)
				     || IS_SET(track->recv_flags, FLAG_FIN)
				   || IS_SET(track->sent_flags, FLAG_RST)
				   || IS_SET(track->recv_flags, FLAG_RST))) {
					/* If the TCP flow is still active, skip*/
					continue;
				}
				track->flow->end_time = get_unix_systime();
				track->flow->stage = e_FLOW_REPORT_STAGE_END;
				/* Send the flow */
				mutex_lock(&g_nvm_plugin.mutex_send_lock);
				list_insert(g_nvm_plugin.send_list, track->flow, false);
				schedule_work_on_queue(&g_nvm_plugin.send_work);
				mutex_unlock(&g_nvm_plugin.mutex_send_lock);
			} else {
				KFREE(track->flow);
			}
			/* erase this entry */
			hlist_del(itr);

			/* Delete the track, as it has been sent/cleaned now.
			 * Don't KFREE flow here.
			 * It will be deleted by the sender task.
			 */
			KFREE(track);
		} else {
			unref_task(curr);
		}
	}

	/*
	 * UDP Case 1-
	 * Go through the list, the flow that received last packets more than
	 * UDP_FLOW_TIMEOUT_SECS back, send that flow out
	 */
	for_each_hlist(g_nvm_plugin.udp_flows, hash_bkt, tmp, itr, next) {
		track = (struct TrackAppFlow *)itr->data;
		curr = get_task_from_pid(track->flow->pid);
		if ((0 != track->flow->pid) && (NULL == curr)) {
			track->flow->end_time = get_unix_systime();
			track->flow->stage = e_FLOW_REPORT_STAGE_END;
			/* Send the flow */
			mutex_lock(&g_nvm_plugin.mutex_send_lock);
			list_insert(g_nvm_plugin.send_list, track->flow, false);
			schedule_work_on_queue(&g_nvm_plugin.send_work);
			mutex_unlock(&g_nvm_plugin.mutex_send_lock);

			/* erase this entry */
			hlist_del(itr);
			/* Don't KFREE flow.
			It will be deleted by the sender task */
			KFREE(track);
		} else if ((get_unix_systime() - track->last_timestamp) >=
			   UDP_FLOW_TIMEOUT_SECS) {
			unref_task(curr);
			track->flow->end_time = get_unix_systime();
			track->flow->stage = e_FLOW_REPORT_STAGE_END;
			/* Send the flow */
			mutex_lock(&g_nvm_plugin.mutex_send_lock);
			list_insert(g_nvm_plugin.send_list, track->flow, false);
			schedule_work_on_queue(&g_nvm_plugin.send_work);
			mutex_unlock(&g_nvm_plugin.mutex_send_lock);

			/* erase this entry */
			hlist_del(itr);
			/* Don't KFREE flow.
			It will be deleted by the sender task */
			KFREE(track);
		} else {
			unref_task(curr);
		}
	}

	/* Schedule again */
	schedule_delayed_work_on_queue(&g_nvm_plugin.cleanup_work,
				       CLEANUP_DELAY);
	mutex_unlock(&g_nvm_plugin.mutex_track_lock);
}

/*
*   \brief Helper method called by the periodic worker
*/
static void send_periodic_flows(void *context)
{
	struct TrackAppFlow *track = NULL;
	uint32_t curr_time = get_unix_systime();
	struct hash_list *itr = NULL;
	struct hlist_node *tmp = NULL;
	int hash_bkt = 0;
	HLIST_ITER;

	mutex_lock(&g_nvm_plugin.mutex_track_lock);

	for_each_hlist(g_nvm_plugin.tcp_flows, hash_bkt, tmp, itr, next) {
		track = (struct TrackAppFlow *)itr->data;
		/* Send the flow only if TCP connection is established.*/
		if (track->connected
		    && (curr_time - track->flow->end_time) >=
		    g_nvm_plugin.flow_report_interval) {
			track->flow->stage = e_FLOW_REPORT_STAGE_PERIODIC;
			report_flow(track->flow);
		}
	}
	for_each_hlist(g_nvm_plugin.udp_flows, hash_bkt, tmp, itr, next) {
		track = (struct TrackAppFlow *)itr->data;
		if ((curr_time - track->flow->end_time) >=
		    g_nvm_plugin.flow_report_interval) {
			track->flow->stage = e_FLOW_REPORT_STAGE_PERIODIC;
			report_flow(track->flow);
		}
	}

	mutex_unlock(&g_nvm_plugin.mutex_track_lock);
	schedule_delayed_work_on_queue(g_nvm_plugin.periodic_work,
				       g_nvm_plugin.flow_report_interval);
}

/*
*   \brief Method to start the plugin
*/
error_code nvm_plugin_start(void)
{
	if (g_nvm_plugin.started)
		return ERROR_ALREADY_INITIALIZED;

	/*Initialize the lists */
	if (true != list_init(&g_nvm_plugin.untracked_pkt_list))
		goto error_exit;

	if (true != list_init(&g_nvm_plugin.send_list))
		goto error_exit;

	hash_init(g_nvm_plugin.tcp_flows);
	hash_init(g_nvm_plugin.udp_flows);

	/*Initialize the locks */
	spin_lock_init(&g_nvm_plugin.spin_untrack_lock);
	mutex_init(&g_nvm_plugin.mutex_track_lock);
	mutex_init(&g_nvm_plugin.mutex_send_lock);

	g_nvm_plugin.flow_report_interval = -1; /*disable on start*/

	if (0 >
	    sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			&g_nvm_plugin.pSocket)) {
		TRACE(ERROR, LOG("Failed to create socket"));
		goto error_exit;
	}
	if (true !=
	    create_work_on_queue(&g_nvm_plugin.send_work, DEFERRED_SENDER_WQ,
				 send_pending_flows, NULL)) {
		TRACE(ERROR, LOG("Failed to create send_pending_flows"));
		goto error_exit;
	}

	if (true !=
	    create_work_on_queue(&g_nvm_plugin.track_work,
				 DEFERRED_PROCESSOR_WQ, track_pending_pkts,
				 NULL)) {
		TRACE(ERROR, LOG("Failed to create pendingPacketsTracker"));
		goto error_exit;
	}

	if (true !=
	    create_delayed_work_on_queue(&g_nvm_plugin.cleanup_work,
					 DEFERRED_CLEANUP_WQ, cleanup, NULL)) {
		TRACE(ERROR, LOG("Failed to create delayed cleanup work"));
		goto error_exit;
	}
	/* Schedule the cleanup task. It schedules itself subsequently */
	if (true !=
	    schedule_delayed_work_on_queue(&g_nvm_plugin.cleanup_work,
					   CLEANUP_DELAY)) {
		TRACE(WARNING, LOG("Failed to queue the clean-up work"));
		goto error_exit;
	}
	TRACE(DEBUG, LOG("NVM plugin started"));

	g_nvm_plugin.started = true;
	return SUCCESS;

 error_exit:
	nvm_plugin_stop();
	return ERROR_ERROR;
}

/*
*   \brief Method to stop the plugin
*/
error_code nvm_plugin_stop(void)
{
	int hash_bkt = 0;
	struct hash_list *itr = NULL;
	struct hlist_node *tmp = NULL;
	struct TrackAppFlow *app_flow = NULL;
	HLIST_ITER;

	if (!g_nvm_plugin.started)
		return ERROR_UNEXPECTED;

	nvm_plugin_list_clear();
	list_destroy(g_nvm_plugin.send_list);
	g_nvm_plugin.send_list = NULL;
	list_destroy(g_nvm_plugin.untracked_pkt_list);
	g_nvm_plugin.untracked_pkt_list = NULL;

	/*clear the hashtable */
	for_each_hlist(g_nvm_plugin.tcp_flows, hash_bkt, tmp, itr, next) {
		app_flow = (struct TrackAppFlow *)itr->data;
		KFREE(app_flow->flow);
		KFREE(app_flow);
		hlist_del(itr);
	}
	for_each_hlist(g_nvm_plugin.udp_flows, hash_bkt, tmp, itr, next) {
		app_flow = (struct TrackAppFlow *)itr->data;
		KFREE(app_flow->flow);
		KFREE(app_flow);
		hlist_del(itr);
	}

	destroy_work_on_queue(&g_nvm_plugin.send_work);
	destroy_work_on_queue(&g_nvm_plugin.track_work);
	destroy_delayed_work_on_queue(&g_nvm_plugin.cleanup_work);
	destroy_delayed_work_on_queue(g_nvm_plugin.periodic_work);
	KFREE(g_nvm_plugin.periodic_work);

	sock_release(g_nvm_plugin.pSocket);
	g_nvm_plugin.pSocket = NULL;

	TRACE(DEBUG, LOG("NVM plugin stopped"));

	g_nvm_plugin.started = false;
	return SUCCESS;
}

/*
 * \brief Method to update the periodic time interval for reporting flows
 */
error_code nvm_plugin_update_periodic_report_interval(uint32_t
							report_interval)
{
	/*
	 * Validate the interval.
	 * Acceptable are values within the range MIN MAX or 0
	 * ( 0 - means report on flow start and end).
	*/
	if (0 == report_interval
	    || (report_interval >= MIN_FLOW_REPORT_INTERVAL_SEC
		&& report_interval <= MAX_FLOW_REPORT_INTERVAL_SEC)) {
		TRACE(DEBUG,
		      LOG("Received flow report interval %u", report_interval));
		g_nvm_plugin.flow_report_interval = report_interval;
		/* Setting periodic interval work */
		if ((0 != g_nvm_plugin.flow_report_interval)
		    && (NULL == g_nvm_plugin.periodic_work)) {
			g_nvm_plugin.periodic_work =
			    KMALLOC(sizeof(struct delayed_work_on_q));
			if (true !=
			    create_delayed_work_on_queue(g_nvm_plugin.
							 periodic_work,
							 DEFERRED_PERIODIC_WQ,
							 send_periodic_flows,
							 NULL)) {
				TRACE(ERROR,
				      LOG
				      ("Failed to create periodic work"));
				g_nvm_plugin.flow_report_interval = -1;
				KFREE(g_nvm_plugin.periodic_work);
				return ERROR_ERROR;
			}
			/* Schedule the periodic task.
			 * It schedules itself subsequently */
			if (true !=
			    schedule_delayed_work_on_queue(g_nvm_plugin.
							   periodic_work,
							   g_nvm_plugin.
						   flow_report_interval)) {
				TRACE(WARNING,
				      LOG("Failed to queue the periodic work"));
				KFREE(g_nvm_plugin.periodic_work);
				g_nvm_plugin.flow_report_interval = -1;
				return ERROR_ERROR;
			}

		} else if ((0 == g_nvm_plugin.flow_report_interval)
			   && (NULL != g_nvm_plugin.periodic_work)) {
			destroy_delayed_work_on_queue(g_nvm_plugin.
						      periodic_work);
			KFREE(g_nvm_plugin.periodic_work);
		}

	} else {
		g_nvm_plugin.flow_report_interval = -1;
		TRACE(DEBUG,
		      LOG
		      ("Received flow report int %u, Disabling periodic flow",
		       report_interval));
		/* Removing the periodic interval work */
		if (NULL != g_nvm_plugin.periodic_work) {
			destroy_delayed_work_on_queue(g_nvm_plugin.
						      periodic_work);
			KFREE(g_nvm_plugin.periodic_work);
		}
	}
	return SUCCESS;
}
