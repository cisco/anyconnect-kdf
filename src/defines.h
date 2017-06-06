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
 *  File:    defines.h
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 ************************************************************************
 *
 *  This file contains part of the module wide definitions
 *
 ************************************************************************
 */
#ifndef __DEFINES_H__
#define __DEFINES_H__

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) \
	(sizeof(a)/sizeof(a[0]))
#endif

/*
 * per RFC 1034, the total number of octets that represent a domain name
 * (i.e., the sum of all label octets and label lengths) is limited to 255
 */
#define MAX_DOMAIN_NAME_SIZE    255

/* Memory allocation macros */
#define KMALLOC(nBytes) kmalloc(nBytes, GFP_KERNEL)
#define KMALLOC_ATOMIC(nBytes) kmalloc(nBytes, GFP_ATOMIC)
#define KFREE(pBlock) \
	{ \
		kfree(pBlock); \
		pBlock = NULL; \
	}

typedef enum _error_code {
	SUCCESS = 0,
	ERROR_ERROR = 1,
	ERROR_ALREADY_INITIALIZED = 2,
	ERROR_BAD_PARAM = 3,
	ERROR_INSUFFICIENT_RESOURCES = 4,
	ERROR_UNEXPECTED = 5,
	ERROR_NOT_INITIALIZED = 6,
} error_code;

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef SOCK_DGRAM
#define	SOCK_DGRAM 2
#endif

enum direction_e {
	UNKNOWN = -1,
	INBOUND = 0,
	OUTBOUND = 1
};

struct ip_hdr {
	union {
		struct iphdr h_ip4;
		struct ipv6hdr h_ip6;
	};
};

struct l4_hdr {
	union {
		struct udphdr h_udp;
		struct tcphdr h_tcp;
	};
};

struct nw_pkt_meta {
	struct ip_hdr *ip_header;
	struct l4_hdr *l4_header;
	enum direction_e direction;
};

#define HTON32(v) \
	(v>>24 | (v>>16 & 0xff) << 8 | (v>>8 & 0xff) << 16 | (v & 0xff) << 24)
#define NTOH32(v) HTON32(v)
#define HTON16(v) ((v >> 8) | ((v & 0xff) << 8))
#define NTOH16(v) HTON16(v)

#endif
