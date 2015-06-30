/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2012 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @file gns/w32resolver.h
 */
#ifndef W32RESOLVER_H
#define W32RESOLVER_H

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_common.h"

/**
 * Request DNS resolution.
 */
#define GNUNET_MESSAGE_TYPE_W32RESOLVER_REQUEST 4

/**
 * Response to a DNS resolution request.
 */
#define GNUNET_MESSAGE_TYPE_W32RESOLVER_RESPONSE 5

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Request for the resolver.  Followed by the 0-terminated hostname.
 *
 * The response will be one or more messages of type
 * W32RESOLVER_RESPONSE, each with the message header immediately
 * followed by the requested data (struct in[6]_addr).
 * The last W32RESOLVER_RESPONSE will just be a header without any data
 * (used to indicate the end of the list).
 */
struct GNUNET_W32RESOLVER_GetMessage
{
  /**
   * Type:  GNUNET_MESSAGE_TYPE_W32RESOLVER_REQUEST
   */
  struct GNUNET_MessageHeader header;

  uint32_t af GNUNET_PACKED;

  uint32_t sc_data1 GNUNET_PACKED;
  uint16_t sc_data2 GNUNET_PACKED;
  uint16_t sc_data3 GNUNET_PACKED;
  uint8_t sc_data4[8];
  /* followed by 0-terminated string for A/AAAA lookup */
};

GNUNET_NETWORK_STRUCT_END

#endif
