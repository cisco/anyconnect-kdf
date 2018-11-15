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
 *  File:   nvm_user_kernel_types.h
 *  Author: Koushik Chakravarty <kouchakr@cisco.com>
 *
 *  This file has the definitions for the messages that the userspace
 *  used to communicate
 *  to this driver via netlink
 *
 */

#ifndef __NVM_USER_KERNEL_TYPES_H__
#define __NVM_USER_KERNEL_TYPES_H__

struct ac_sockaddr_inet {
	union {
		struct sockaddr_in Ipv4;
		struct sockaddr_in6 Ipv6;
	};
};

struct ac_addr {
	uint8_t family;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	};
};

/*
 * Structure used to pass information between userspace app and the nvm plugin.
 */
struct nvm_info {
	struct ac_addr to_remote;	/* ip of appflow enabled collector*/
	struct ac_addr to_local;
	uint16_t to_remote_port;	/* port number for remote address*/
	uint16_t to_local_port;

	uint32_t reserved1;
	uint32_t reserved2;
	uint32_t reserved3;
	uint32_t reserved4;
};

/* Message command types */
#define NVM_PLUGIN_COMMAND_ENABLE_APPFLOW              1
#define NVM_PLUGIN_COMMAND_DISABLE_APPFLOW             2
#define NVM_PLUGIN_COMMAND_SET_FLOW_REPORT_INTERVAL    5

struct nvm_io_ctrl {
	uint32_t command;
	uint32_t plugin_id;
};

/* AppFlow structure -
 * data that is passed for each unique flow to the userspace application*/

#define APPFLOW_FILE_NAME_LEN           260
#define APPFLOW_FILE_PATH_LEN           2048
#define NVM_APPFLOW_VERSION             1
#define NVM_FLOW_DIRECTION_UNKNOWN      0
#define NVM_FLOW_DIRECTION_IN           1
#define NVM_FLOW_DIRECTION_OUT          2

/*The following enum indicates when the flow info was reported by module*/
enum flow_report_stage {
	e_FLOW_REPORT_STAGE_START,
	e_FLOW_REPORT_STAGE_PERIODIC,
	e_FLOW_REPORT_STAGE_END
};

/* NVM message types - messages sent to user space*/
#define NVM_MESSAGE_APPFLOW_DATA  1
#define NVM_MESSAGE_PID_INFO  2

struct nvm_message_header {
	uint16_t length;
	uint8_t version;
	uint8_t type;
};

struct app_flow {

	struct nvm_message_header header;

	struct ac_sockaddr_inet local;
	struct ac_sockaddr_inet peer;
	int family;		/* address family */
	int proto;		/* protocol */
	uint64_t in_bytes;
	uint64_t out_bytes;
	uint32_t pid;
	uint32_t parent_pid;

	uint32_t start_time;	/* time when socket was created */
	uint32_t end_time;	/* time when socket was closed */

	uint16_t file_name_len;
	uint16_t file_path_len;
	char file_name[APPFLOW_FILE_NAME_LEN];	/* null terminated image name*/
	char file_path[APPFLOW_FILE_PATH_LEN];	/* null terminated image path*/
	uint16_t parent_file_name_len;
	uint16_t parent_file_path_len;
	char parent_file_name[APPFLOW_FILE_NAME_LEN];
	char parent_file_path[APPFLOW_FILE_PATH_LEN];
	uint8_t direction;

	enum flow_report_stage stage;
};

struct nvm_pid_info {
    struct nvm_message_header header;
    uint32_t pid;
    uint32_t parent_pid;

    uint16_t file_name_len;
    uint16_t file_path_len;
    char file_name[APPFLOW_FILE_NAME_LEN];	/* null terminated image name*/
    char file_path[APPFLOW_FILE_PATH_LEN];	/* null terminated image path*/
    uint16_t parent_file_name_len;
    uint16_t parent_file_path_len;
    char parent_file_name[APPFLOW_FILE_NAME_LEN];
    char parent_file_path[APPFLOW_FILE_PATH_LEN];

};

#endif				/* __NVM_USER_KERNEL_TYPES_H__ */
