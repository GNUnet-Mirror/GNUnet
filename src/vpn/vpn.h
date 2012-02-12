/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file vpn/vpn.h
 * @brief IPC messages between VPN library and VPN service
 * @author Christian Grothoff
 */
#ifndef VPN_H
#define VPN_H

#include "gnunet_util_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message send by the VPN client to the VPN service requesting
 * the setup of a redirection from some IP via an exit node to
 * some global Internet address.
 */
struct RedirectToIpRequestMessage
{
  /**
   * Type is  GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_IP
   */
  struct GNUNET_MessageHeader header;

  /**
   * GNUNET_YES to notify only after completion of the mesh-level connection,
   * GNUNET_NO to notify as soon as an address was allocated (in nbo).
   */
  int32_t nac GNUNET_PACKED;
  
  /**
   * How long should the redirection be maintained at most?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * Address family desired for the result (AF_INET or AF_INET6 or AF_UNSPEC, in nbo)
   */
  int32_t result_af GNUNET_PACKED;

  /**
   * Address family used for the destination address (AF_INET or AF_INET6, in nbo)
   */
  int32_t addr_af GNUNET_PACKED;

  /**
   * Unique ID to match a future response to this request.
   * Picked by the client.
   */
  uint64_t request_id GNUNET_PACKED;

  /* followed by destination address ('struct in_addr' or 'struct in6_addr') */
  
};


/**
 * Message send by the VPN client to the VPN service requesting
 * the setup of a redirection from some IP to a service running
 * at a particular peer.
 */
struct RedirectToServiceRequestMessage
{
  /**
   * Type is  GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_IP
   */
  struct GNUNET_MessageHeader header;

  /**
   * GNUNET_YES to notify only after completion of the mesh-level connection,
   * GNUNET_NO to notify as soon as an address was allocated (in nbo).
   */
  int32_t nac GNUNET_PACKED;
  
  /**
   * How long should the redirection be maintained at most?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * Desired protocol (IPPROTO_UDP or IPPROTO_TCP)
   */
  int32_t protocol GNUNET_PACKED;
  
  /**
   * Address family desired for the result (AF_INET or AF_INET6 or AF_UNSPEC, in nbo)
   */
  int32_t result_af GNUNET_PACKED;

  /**
   * Target peer offering the service.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Service descriptor identifying the service.
   */
  GNUNET_HashCode service_descriptor GNUNET_PACKED;

  /**
   * Unique ID to match a future response to this request.
   * Picked by the client.
   */
  uint64_t request_id GNUNET_PACKED;

};


/**
 * Response from the VPN service to a VPN client informing about
 * the IP that was assigned for the requested redirection.
 */
struct RedirectToIpResponseMessage
{
  
  /**
   * Type is  GNUNET_MESSAGE_TYPE_VPN_CLIENT_USE_IP
   */
  struct GNUNET_MessageHeader header;

  /**
   * Address family of the allocated address that follows; will match
   * "result_af" from the request, of be "AF_UNSPEC" on errors.
   */
  int32_t result_af GNUNET_PACKED;

  /**
   * Unique ID to match the response to a request.
   */
  uint64_t request_id GNUNET_PACKED;

  /* followed by destination address ('struct in_addr' or 'struct in6_addr') */
  
};

GNUNET_NETWORK_STRUCT_END


#endif
