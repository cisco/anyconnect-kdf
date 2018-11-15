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
 *  File:   netfilter_interface.c
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 **************************************************************************
 *
 *  This file contains the interface to the netfilter utility and
 *  handles the message delivery.
 *
 *************************************************************************
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4.h>
#include "defines.h"
#include "netfilter_interface.h"
#include "nvm_plugin.h"
#include "dns_plugin.h"
#include "dbgout.h"

const unsigned int g_nf_accept = NF_ACCEPT;
nf_hookfn hook_callback;	/* forward declaration of netfilter hook */

/* Hooks that need to be registered with netfilter*/
static struct nf_hook_ops ip_hooks[] = {
	{
	 .hooknum = NF_INET_LOCAL_IN,
	 .pf = NFPROTO_IPV4,
	 .priority = NF_IP_PRI_LAST,
	 },
	{
	 .hooknum = NF_INET_LOCAL_OUT,
	 .pf = NFPROTO_IPV4,
	 .priority = NF_IP_PRI_FIRST,
	 },
	{
	 .hooknum = NF_INET_LOCAL_IN,
	 .pf = NFPROTO_IPV6,
	 .priority = NF_IP_PRI_LAST,
	 },
	{
	 .hooknum = NF_INET_LOCAL_OUT,
	 .pf = NFPROTO_IPV6,
	 .priority = NF_IP_PRI_FIRST,
	 }
};

/*
*   \brief Register hooks to netfilter with given hook callback function
*/
error_code register_ip_hooks(void)
{
	error_code ret_code = SUCCESS;
	int hook_stat = 0;
	size_t counter = 0;
	const size_t total_hooks = ARRAY_SIZE(ip_hooks);

	for (counter = 0; counter < total_hooks; ++counter)
		ip_hooks[counter].hook = hook_callback;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0))
	hook_stat = nf_register_net_hooks(&init_net, ip_hooks, total_hooks);
#else
	hook_stat = nf_register_hooks(ip_hooks, total_hooks);
#endif
	if (0 != hook_stat) {
		TRACE(ERROR,
		      LOG("failed to register hooks error: %d", hook_stat));
		ret_code = ERROR_ERROR;
	}
	return ret_code;
}

/*
*   \brief DeRegister hooks to netfilter
*/
error_code deregister_ip_hooks(void)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0))
	nf_unregister_net_hooks(&init_net, ip_hooks, ARRAY_SIZE(ip_hooks));
#else
	nf_unregister_hooks(ip_hooks, ARRAY_SIZE(ip_hooks));
#endif
	return SUCCESS;
}

/*
 * Register the hooks
 */
bool load_ACKDF(void)
{
	TRACE(DEBUG, LOG("ACKDF starting"));
	if (SUCCESS != register_ip_hooks())
		TRACE(ERROR, LOG("Netfilter hook registration failed"));

	TRACE(DEBUG, LOG("ACKDF started"));

	return true;
}

/*
 * deregister the hooks
 */
bool unload_ACKDF(void)
{
	TRACE(DEBUG, LOG("ACKDF stopping"));
	deregister_ip_hooks();
	nvm_plugin_stop();
	dns_plugin_stop();
	TRACE(DEBUG, LOG("ACKDF stopped"));

	return true;
}

/*
 * get the l4 header
 */
struct l4_hdr *get_l4_header(struct sk_buff *pSKBuffer)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4, 1, 0))
	struct ip_hdr *ip_header = NULL;
#endif
	if (NULL == pSKBuffer)
		return NULL;

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4, 1, 0))
	ip_header = (struct ip_hdr *)ip_hdr(pSKBuffer);
	if (IS_IP_VERSION4(ip_header->h_ip4.version))
		return (struct l4_hdr *)((__u32 *) (ip_header) + ip_header->h_ip4.ihl);
	else
		return (struct l4_hdr *)skb_transport_header(pSKBuffer);
#else
	return (struct l4_hdr *)skb_transport_header(pSKBuffer);
#endif
}

enum direction_e convert_direction(const unsigned int hooknum)
{
	switch (hooknum) {
	case NF_INET_LOCAL_IN:
		return INBOUND;
	case NF_INET_LOCAL_OUT:
		return OUTBOUND;
	default:
		return UNKNOWN;
	};
}

/* This is invoked by the netfilter callback to
 * deliver packets to the plugins
 */
error_code notify_nw_packet(struct nw_pkt_meta *pkt)
{
	/* Delivery packets to nvm plugin and dns plugin */
	if (g_nvm_plugin.started)
		nvm_plugin_notify_network_packet(pkt);

	if (g_dns_plugin.started)
		dns_plugin_notify_network_packet(pkt);

	return SUCCESS;
}

/**
 * \function unsigned int hook_callback
 * \brief Hooking function interfacing with the netfilter hooks
 *
 * \return g_nf_accept (to make netfilter allow the packet to flow further)
 * note: The NF hook_callback has various definitions based on the
 *       kernel versions
 *       RHEL6.8 - 2.6 kernel
 *       RHEL7.2 - 3.10 kernel
 *       Ubuntu14/16 - 3.13 - 4.4 kernels
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))	/* RHEL6 case */
unsigned int
hook_callback(unsigned int hooknum,
	      struct sk_buff *pSKBuffer,
	      const struct net_device *in,
	      const struct net_device *out, int (*okfn) (struct sk_buff *))
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0))	/* RHEL7 case */
unsigned int
hook_callback(const struct nf_hook_ops *ops,
	      struct sk_buff *pSKBuffer,
	      const struct net_device *in,
	      const struct net_device *out, const struct nf_hook_state *pState)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0))
unsigned int
hook_callback(const struct nf_hook_ops *ops,
	      struct sk_buff *pSKBuffer,
	      const struct net_device *in,
	      const struct net_device *out, int (*okfn) (struct sk_buff *))
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) && \
	LINUX_VERSION_CODE <= KERNEL_VERSION(4, 3, 0))
unsigned int
hook_callback(const struct nf_hook_ops *ops,
	      struct sk_buff *pSKBuffer, const struct nf_hook_state *pState)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0))
unsigned int
hook_callback(void *pContext,
	      struct sk_buff *pSKBuffer, const struct nf_hook_state *pState)
#endif
{
	struct ip_hdr *ip_header = NULL;
	struct l4_hdr *l4_header = NULL;
	struct nw_pkt_meta pkt_meta;

	if (NULL == pSKBuffer) {
		TRACE(ERROR, LOG("sk_buff is null"));
		return g_nf_accept;
	}

	ip_header = (struct ip_hdr *)ip_hdr(pSKBuffer);
	if (NULL == ip_header) {
		TRACE(ERROR, LOG("Failed to extract IP header from sk_buff"));
		return g_nf_accept;
	}

	l4_header = get_l4_header(pSKBuffer);
	if (NULL == l4_header) {
		TRACE(ERROR, LOG("Failed to extract L4 header from sk_buff"));
		return g_nf_accept;
	}

	pkt_meta.ip_header = ip_header;
	pkt_meta.l4_header = l4_header;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
	pkt_meta.direction = convert_direction(hooknum);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0) && \
	LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0))
	pkt_meta.direction = convert_direction(ops->hooknum);
#else
	pkt_meta.direction = convert_direction(pState->hook);
#endif
	notify_nw_packet(&pkt_meta);

	return g_nf_accept;
}
