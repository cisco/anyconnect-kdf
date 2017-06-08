/*
 ****************************************************************************
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
 *  File:       dns_user_kernel_types.h
 *  Author:     Koushik Chakravarty <kouchakr@cisco.com>
 *
 *  Definitions of message structures used by the userspace to communicate
 *  messages to this module
 **************************************************************************
 */

#ifndef __DNS_USER_KERNEL_TYPES_H__
#define __DNS_USER_KERNEL_TYPES_H__

#include "nvm_user_kernel_types.h"

#define DNS_UDP_PACKET_MAX_SIZE 4096

/*
 * message structure for sharing dns messages between kdf and user space dns
 */
struct dns_message {
	struct ac_sockaddr_inet dns_server;
	uint32_t payload_len;
	uint8_t dns_payload[DNS_UDP_PACKET_MAX_SIZE];
};

/*
 * Defines for userspace to kdf communication message types
 */
#define DNS_PLUGIN_COMMAND_ENABLE                      10
#define DNS_PLUGIN_COMMAND_DISABLE                     20

/*
 * Userspace to KDF control message
 */
struct dns_io_ctrl {
	/* see DNS_PLUGIN_COMMAND_xxxxxxxxx above for valid commands */
	uint32_t command;
	uint32_t plugin_id;
};

/*
 * The following structure is used to pass information between the
 * userspace app and the DNS plugin.
 */
struct dns_info {
	struct ac_addr to_local;	/* ip of local user mode process */
	uint16_t to_local_port;	/* port number for local address */
};

#endif
