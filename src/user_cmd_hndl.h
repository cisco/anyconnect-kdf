/*
 *****************************************************************************
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
 *  File:   user_cmd_hndl.h
 *  Author:  Koushik Chakravarty <kouchakr@cisco.com>
 *
 *****************************************************************************
 *
 *  This file contains the handlers declaration for the userspace commands
 *
 ***************************************************************************
 */

#ifndef __USERSPACE_CMD_HNDL_H__
#define __USERSPACE_CMD_HNDL_H__

/**
 * \brief handle the userspace command
 */
void process_userspace_cmd(char *pData, size_t size);

#endif
