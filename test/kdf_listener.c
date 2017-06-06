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
 *  File:   kdf_listener.c
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 **********************************************************************
 * This example code serves as a guide to understand how to interact
 * with the Network Flow Interceptor.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <limits.h>
#include "dns_user_kernel_types.h"

#define FLOW_INTERCEPTOR_ID 30
int nmessages = 10;

static bool is_kdf_loaded()
{
	char buf[16] = {0};
	FILE *fp = NULL;
	size_t read_len = 0;

	fp = popen("lsmod | grep ac_kdf", "r");
	if (NULL == fp) {
		perror("Error in checking for module availability");
		return false;
	}
	read_len = fread(buf, 1, sizeof(buf), fp);
	pclose(fp);
	return read_len > 0;
}

static void usage()
{
	printf("USAGE: ./kdf_listener [OPTIONS]\n"
"\tOPTIONS: \n"
"\t\t-n <PORT> [-c <COUNT>] : enable NVM plugin, listen to udp PORT and print COUNT network flow reports\n"
"\t\t\t\t\t COUNT: default = 10, min = 5, max = 100\n"

"\t\t-d <PORT> [-c <COUNT>] : enable DNS plugin, listen to udp PORT and print COUNT dns messages\n"
"\t\t\t\t\t COUNT: default = 10, min = 5, max = 100\n"

"\t\t-p <INTERVAL> : set periodic interval, in seconds, for flow reporting. Possible values: 0, 60-360\n"

"\t\t-P : unset periodic reporting\n"

"\t\t-s : stop both plugins\n"

"\t\t-h : help\n"
);
}

static int netlink_write(const int sock, const char* buf, const size_t size)
{
	struct sockaddr_nl dest_addr = {0};
	struct iovec iov = {0};
	struct msghdr msg = {0};

	assert(NULL != buf);
	assert(0 != size);
	assert(-1 != sock);

	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;//for Linux Kernel
	dest_addr.nl_groups = 0;//unicast

	struct nlmsghdr *nlh = (struct nlmsghdr*)calloc(1, NLMSG_SPACE(size));
	assert(NULL != nlh);

	nlh->nlmsg_len = NLMSG_SPACE(size);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	//copy payload to be sent
	memcpy((char*)NLMSG_DATA(nlh), (char*)buf, size);

	//fill the iovec structure
	//netlink message header base address
	iov.iov_base = (void*)nlh;

	//netlink msg length
	iov.iov_len = nlh->nlmsg_len;

	//define the message header for message sending
	msg.msg_name = (void*)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	//send the msg
	ssize_t err = sendmsg(sock, &msg, 0);
	free (nlh);
	if (-1 == err) {
		perror("Sending the netlink message failed");
		return -1;
	}
	return 0;
}

static int bind_udp(const unsigned short port)
{
	int sock = -1;
	struct sockaddr_in in_addr = {0};

	/*Open socket to listen to incoming data*/
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		perror("Could not open listening socket");
		return -1;
	}
	in_addr.sin_family = AF_INET;
	in_addr.sin_port = htons(port);
	in_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(sock, (const struct sockaddr*)&in_addr, sizeof(in_addr)) < 0) {
		perror("Could not bind socket to port");
		close(sock);
		return -1;
	}
	return sock;
}

static void enable_nvm(const int sock, const unsigned short port)
{
	int in_sock = -1;
	struct app_flow flow;
	unsigned short msg_count = 0;
	struct {
		struct nvm_io_ctrl cmd;
		struct nvm_info info;
	} nlmsg = {{0}};

	/* Bind to UDP socket */
	in_sock = bind_udp(port);
	if (in_sock < 0) {
		return;
	}

	/*Start the NVM plugin*/
	nlmsg.info.to_local.ipv4.s_addr =  htonl(INADDR_LOOPBACK);
	nlmsg.info.to_local_port  = htons(port);

	nlmsg.cmd.command = NVM_PLUGIN_COMMAND_ENABLE_APPFLOW;
	netlink_write(sock, (char*)&nlmsg, sizeof(nlmsg));

	/*Listen for incoming flows*/
	printf ("Waiting for %d incoming flows\n", nmessages);
	while (msg_count < nmessages) {
		msg_count++;
		memset(&flow, 0, sizeof(flow));
		recv(in_sock, &flow, sizeof(flow), 0);
		printf("Flow no. %d -- Process(pid): %s(%u), parent(pid): %s(%u), protocol: %s , family IPv%d, bytes sent: %lu, bytes received: %lu, flow state = %s\n", msg_count, flow.file_name, flow.pid, flow.parent_file_name, flow.parent_pid, (IPPROTO_TCP == flow.proto ? "TCP" : "UDP"), (AF_INET6 == flow.family ? 6 : 4), flow.in_bytes, flow.out_bytes, (0 == flow.stage ? "Started" : (1 == flow.stage ? "Periodic report" : "Ended")));
	}
	close(in_sock);
}

static void enable_dns(const int sock, const unsigned short port)
{
	int in_sock = -1;
	struct dns_message dns;
	unsigned short msg_count = 0;
	struct {
		struct dns_io_ctrl cmd;
		struct dns_info dns_info;
	} nlmsg = {{0}};

	/* Bind to UDP socket */
	in_sock = bind_udp(port);
	if (in_sock < 0) {
		return;
	}

	/*Start the DNS plugin*/
	nlmsg.dns_info.to_local.ipv4.s_addr =  htonl(INADDR_LOOPBACK);
	nlmsg.dns_info.to_local_port  = htons(port);

	nlmsg.cmd.command = DNS_PLUGIN_COMMAND_ENABLE;
	netlink_write(sock, (char*)&nlmsg, sizeof(nlmsg));

	/*Listen for incoming dns payloads*/
	printf ("Waiting for %d incoming DNS payloads\n", nmessages);
	while (msg_count < nmessages) {
		msg_count++;
		memset(&dns, 0, sizeof(dns));
		recv(in_sock, &dns, sizeof(dns), 0);
		printf("DNS payload no. %d received\n", msg_count);
	}
	close(in_sock);
}

static void disable_plugins(const int sock)
{
	struct nvm_io_ctrl cmd = {0};

	cmd.command = NVM_PLUGIN_COMMAND_DISABLE_APPFLOW;
	netlink_write(sock, (char*)&cmd, sizeof(cmd));

	cmd.command = DNS_PLUGIN_COMMAND_DISABLE;
	netlink_write(sock, (char*)&cmd, sizeof(cmd));
}

static void set_interval(const int sock, const unsigned short interval)
{
	struct {
		struct nvm_io_ctrl cmd;
		unsigned short interval;
	} nlmsg = {{0}};

	nlmsg.cmd.command = NVM_PLUGIN_COMMAND_SET_FLOW_REPORT_INTERVAL;
	nlmsg.interval = interval;
	netlink_write(sock, (char*)&nlmsg, sizeof(nlmsg));
}

static void handle_cmd(const int opt, const char *value)
{
	int option = 0;
	int sock = -1;
	char *endp = NULL;

	sock = socket(PF_NETLINK, SOCK_RAW, FLOW_INTERCEPTOR_ID);
	if (sock < 0) {
		perror("Could not open netlink socket to establish channel");
		return;
	}
	switch (opt) {
	case 'n':
		option = atoi(value);
		if (option <= 0 || option >= USHRT_MAX) {
			printf("Invalid port number %s\n", value);
			break;
		}
		enable_nvm(sock, (unsigned short)option);
		break;
	case 'd':
		option = atoi(value);
		if (option <= 0 || option >= USHRT_MAX) {
			printf("Invalid port number %s\n", value);
			break;
		}
		enable_dns(sock, (unsigned short)option);
		break;
	case 's':
		disable_plugins(sock);
		printf("All plugins disabled\n");
		break;
	case 'p':
		option = strtol(value, &endp, 10);
		if (option < 0 || (option > 0 && option < 60) || option > 360 || *endp != '\0') {
			printf("Invalid time %s\n", value);
			break;
		}
		set_interval(sock, (unsigned short)option);
		printf("NVM plugin periodic reporting interval set to %u second(s)\n", option);
		break;
	case 'P':
		set_interval(sock, (unsigned short)999); /* disabling the periodic reporting */
		printf("NVM plugin periodic reporting interval disabled\n");
		break;
	}
	close(sock);
}

int main(int argc, char** argv)
{
	int opt = 0;
	int saved_opt = 0;
	const char* saved_optarg = NULL;

	if (!is_kdf_loaded()) {
		printf("Please load the ac_kdf.ko before running the kdf_listener\n");
		return 0;
	}
	while ((opt = getopt(argc, argv, "c:d:hn:p:Ps")) != -1) {
		switch (opt) {
		case 'n':
		case 'd':
		case 'p':
		case 's':
		case 'P':
			if (saved_opt != 0 && saved_opt != opt) {
				printf("Mutually incompatible options -%c and -%c provided\n", saved_opt, opt);
				return 1;
			}
			saved_opt = opt;
			saved_optarg = optarg;
			break;
		case 'c':
			nmessages = atoi(optarg);
			nmessages = nmessages < 5 ? 5 : (nmessages > 100 ? 100 : nmessages);
			break;
		case 'h':
		default:
			usage();
			return 0;
		}
	}
	if (saved_opt)
		handle_cmd(saved_opt, saved_optarg);
	else
		usage();

	return 0;
}
