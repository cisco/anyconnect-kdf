/*
**************************************************************************
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
 **************************************************************************
 *
 *  File:   netfilter_interface.h
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 ***************************************************************************
 *
 *  This file contains the api declarations for using netfilter
 *
 ****************************************************************************
 */

#ifndef _NETFILTER_INTERFACE_H_
#define _NETFILTER_INTERFACE_H_

extern const unsigned int g_nf_accept;

error_code register_ipv4_hooks(void);
error_code deregister_ipv4_hooks(void);

bool load_ACKDF(void);
bool unload_ACKDF(void);

#endif
