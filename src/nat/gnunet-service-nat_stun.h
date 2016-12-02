/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2015, 2016 GNUnet e.V.

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * This code provides some support for doing STUN transactions.  We
 * receive the simplest possible packet as the STUN server and try
 * to respond properly.
 *
 * All STUN packets start with a simple header made of a type,
 * length (excluding the header) and a 16-byte random transaction id.
 * Following the header we may have zero or more attributes, each
 * structured as a type, length and a value (whose format depends
 * on the type, but often contains addresses).
 * Of course all fields are in network format.
 *
 * This code was based on ministun.c.
 *
 * @file nat/gnunet-service-nat_stun.h
 * @brief Functions for STUN functionality
 * @author Bruno Souza Cabral
 */
#ifndef GNUNET_SERVICE_NAT_STUN_H
#define GNUNET_SERVICE_NAT_STUN_H

#include "platform.h"

/**
 * Handle an incoming STUN response.  Do some basic sanity checks on
 * packet size and content, try to extract information.
 * At the moment this only processes BIND requests,
 * and returns the externally visible address of the original
 * request.
 *
 * @param data the packet
 * @param len the length of the packet in @a data
 * @param[out] arg sockaddr_in where we will set our discovered address
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if the packet is invalid (not a stun packet)
 */
int
GNUNET_NAT_stun_handle_packet_ (const void *data,
				size_t len,
				struct sockaddr_in *arg);

#endif
