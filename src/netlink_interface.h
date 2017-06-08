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
 *  File:   netlink_interface.h
 *  Author: Koushik Chakravarty <kouchakr@cisco.com>
 *
 *****************************************************************************
 *
 *  This file contains methods to work on netlink sockets.
 *
 ****************************************************************************
 */

#ifndef __NETLINK_INTERFACE_H__
#define __NETLINK_INTERFACE_H__

bool netlink_init(void);
void netlink_release(void);

#endif
