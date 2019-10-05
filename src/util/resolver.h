/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2012 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @author Christian Grothoff
 * @file util/resolver.h
 */
#ifndef RESOLVER_H
#define RESOLVER_H

#include "gnunet_common.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Request for the resolver.  Followed by either the "struct sockaddr"
 * or the 0-terminated hostname.
 *
 * The response will be one or more messages of type
 * RESOLVER_RESPONSE, each with the message header immediately
 * followed by the requested data (0-terminated hostname or struct
 * in[6]_addr, depending on direction).  The last RESOLVER_RESPONSE
 * will just be a header without any data (used to indicate the end of
 * the list).
 */
struct GNUNET_RESOLVER_GetMessage
{
  /**
   * Type:  #GNUNET_MESSAGE_TYPE_RESOLVER_REQUEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * GNUNET_YES to get hostname from IP,
   * GNUNET_NO to get IP from hostname.
   */
  int32_t direction GNUNET_PACKED;

  /**
   * Address family to use (AF_INET, AF_INET6 or AF_UNSPEC).
   */
  int32_t af GNUNET_PACKED;

  /**
   * identifies the request and is contained in the response message. The
   * client has to match response to request by this identifier.
   */
  uint32_t client_id GNUNET_PACKED;

  /* followed by 0-terminated string for A/AAAA-lookup or
     by 'struct in_addr' / 'struct in6_addr' for reverse lookup */
};


struct GNUNET_RESOLVER_ResponseMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * identifies the request this message responds to. The client
   * has to match response to request by this identifier.
   */
  uint32_t client_id GNUNET_PACKED;

  /* followed by 0-terminated string for response to a reverse lookup
   * or by 'struct in_addr' / 'struct in6_addr' for response to
   * A/AAAA-lookup
   */
};

GNUNET_NETWORK_STRUCT_END

#endif
