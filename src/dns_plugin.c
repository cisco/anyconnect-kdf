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
 *  File:   dns_plugin.c
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 *****************************************************************************
 *
 *  This file contains the implementation of the DNS Plugin
 *  This plugin inspects the DNS packets and sends the
 *  DNS responses to a userspace DNS.
 *
 *******************************************************************************
 */

#include <linux/slab.h>
#include <linux/net.h>
#include "dbgout.h"
#include "dns_plugin.h"
#include "dns_user_kernel_types.h"

#define DNS_DEFERRED_PROCESSOR_WQ   "ACKDF_DNS"
#define DNS_PORT 53

struct dns_plugin g_dns_plugin;

/*
*   \brief Method to handle packets being delivered by the netfilter
*/
error_code dns_plugin_notify_network_packet(struct nw_pkt_meta *pNwPkt)
{
	struct ip_hdr *ip_header = NULL;
	struct udphdr *udp_header = NULL;
	struct dns_message *dns_msg = NULL;
	uint8_t *udp_payload = NULL;
	uint8_t protocol = 0;
	unsigned long flags = 0;
	bool ret_code = false;

	if (!g_dns_plugin.started)
		return SUCCESS;

	if (NULL == g_dns_plugin.pSocket) {
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
		protocol = ip_header->h_ip4.protocol;
	}
	else {
		/* IPv6 case*/
		protocol = ip_header->h_ip6.nexthdr;
	}

	if (IPPROTO_UDP == protocol) {
		udp_header = &(pNwPkt->l4_header->h_udp);
		/* check for DNS responses */
		if (!
		    ((DNS_PORT == NTOH16(udp_header->source))
		     && (INBOUND == pNwPkt->direction))) {
			/* Not a DNS response*/
			return SUCCESS;
		}
		if (NTOH16(udp_header->len) > DNS_UDP_PACKET_MAX_SIZE) {
			TRACE(ERROR,
			      LOG
			      ("DNS message payload(%d) exceeds max size(%d)",
			       NTOH16(udp_header->len),
			       DNS_UDP_PACKET_MAX_SIZE));
			return ERROR_BAD_PARAM;
		}

		dns_msg =
		    (struct dns_message *)
		    KMALLOC_ATOMIC(sizeof(struct dns_message));
		if (NULL == dns_msg) {
			TRACE(ERROR,
			      LOG("Failed to construct dns message object"));
			return ERROR_INSUFFICIENT_RESOURCES;
		}
		memset(dns_msg, 0, sizeof(struct dns_message));
		dns_msg->payload_len = NTOH16(udp_header->len);
		if (IS_IP_VERSION4(ip_header->h_ip4.version)) {
			dns_msg->dns_server.Ipv4.sin_family = AF_INET;
			dns_msg->dns_server.Ipv4.sin_addr.s_addr = ip_header->h_ip4.saddr;
			dns_msg->dns_server.Ipv4.sin_port = udp_header->source;
		}
		else {
			dns_msg->dns_server.Ipv6.sin6_family = AF_INET6;
			dns_msg->dns_server.Ipv6.sin6_addr = ip_header->h_ip6.saddr;
			dns_msg->dns_server.Ipv6.sin6_port = udp_header->source;
		}
		/* Copy the DNS payload */
		udp_payload =
		    ((uint8_t *) &(pNwPkt->l4_header->h_udp) +
		     sizeof(struct udphdr));
		memcpy(dns_msg->dns_payload, udp_payload, dns_msg->payload_len);

		spin_lock_irqsave(&g_dns_plugin.dnsmessagelist_lock, flags);
		ret_code =
		    list_insert_tail(g_dns_plugin.dns_msg_list, dns_msg, true);
		spin_unlock_irqrestore(&g_dns_plugin.dnsmessagelist_lock,
				       flags);

		if (!ret_code) {
			TRACE(ERROR, LOG("Adding the dnsMessage failed"));
			KFREE(dns_msg);
			return ERROR_ERROR;
		}

		schedule_work_on_queue(&g_dns_plugin.send_dns_message_wq);
	}

	return SUCCESS;
}

/*
*   \brief Helper method to send the DNS messages
*/
static void send_dns_messages(void *context)
{
	unsigned long flags = 0;
	struct llist *iter = NULL;
	void *iter_data = NULL;
	struct dns_message *dns_msg = NULL;
	error_code status = ERROR_ERROR;

	while (true) {
		flags = 0;
		spin_lock_irqsave(&g_dns_plugin.dnsmessagelist_lock, flags);
		if (!is_list_empty(g_dns_plugin.dns_msg_list)) {
			list_get_next(g_dns_plugin.dns_msg_list, &iter,
				      &iter_data);
			dns_msg = (struct dns_message *)iter_data;
			list_delete(g_dns_plugin.dns_msg_list, iter);
			spin_unlock_irqrestore(&g_dns_plugin.
					       dnsmessagelist_lock, flags);

			status =
			    socket_sendto(g_dns_plugin.pSocket,
					  &g_dns_plugin.exporter_address,
					  (uint8_t *) dns_msg,
					  sizeof(struct dns_message));
			if (SUCCESS != status) {
				TRACE(ERROR,
				      LOG("Failed to send flow. Error = %d",
					  status));
			}
			KFREE(dns_msg);
			iter = NULL;
			iter_data = NULL;
		} else {
			spin_unlock_irqrestore(&g_dns_plugin.
					       dnsmessagelist_lock, flags);
			break;
		}
	}
}

/*
*   \brief Method to clear all the various lists
*/
static void dns_plugin_list_clear(void)
{
	void *iter_data = NULL;
	struct llist *iter = NULL;
	struct dns_message *dns_msg = NULL;
	struct llist *tmp = NULL;

	list_get_next(g_dns_plugin.dns_msg_list, &iter, &iter_data);
	while ((iter) && iter != g_dns_plugin.dns_msg_list) {
		dns_msg = (struct dns_message *)iter_data;
		KFREE(dns_msg);
		tmp = iter;
		list_get_next(iter, &iter, &iter_data);
		list_delete(g_dns_plugin.dns_msg_list, tmp);
	}
}

/*
*   \brief Method to start the plugin
*/
error_code dns_plugin_start(void)
{
	if (g_dns_plugin.started)
		return ERROR_ALREADY_INITIALIZED;

	/*Initialize the lists */
	if (true != list_init(&g_dns_plugin.dns_msg_list))
		goto error_exit;


	/*Initialize the locks */
	spin_lock_init(&g_dns_plugin.dnsmessagelist_lock);

	if (0 >
	    sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			&g_dns_plugin.pSocket)) {
		TRACE(ERROR, LOG("Failed to create socket"));
		goto error_exit;
	}
	if (true !=
	    create_work_on_queue(&g_dns_plugin.send_dns_message_wq,
				 DNS_DEFERRED_PROCESSOR_WQ, send_dns_messages,
				 NULL)) {
		TRACE(ERROR, LOG("Failed to create sendPendingdns_msg_list"));
		goto error_exit;
	}

	TRACE(DEBUG, LOG("DNS plugin started"));
	g_dns_plugin.started = true;
	return SUCCESS;

 error_exit:
	dns_plugin_stop();
	return ERROR_ERROR;
}

/*
*   \brief Method to stop the plugin
*/
error_code dns_plugin_stop(void)
{
	if (!g_dns_plugin.started)
		return ERROR_UNEXPECTED;

	dns_plugin_list_clear();
	list_destroy(g_dns_plugin.dns_msg_list);
	g_dns_plugin.dns_msg_list = NULL;
	destroy_work_on_queue(&g_dns_plugin.send_dns_message_wq);

	sock_release(g_dns_plugin.pSocket);
	g_dns_plugin.pSocket = NULL;

	TRACE(DEBUG, LOG("DNS plugin stopped"));
	g_dns_plugin.started = false;
	return SUCCESS;
}
