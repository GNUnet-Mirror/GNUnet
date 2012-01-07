/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
 * @file include/gnunet_vpn_service.h
 * @brief API to access the VPN service. 
 * @author Christian Grothoff
 */
#ifndef GNUNET_VPN_SERVICE_H
#define GNUNET_VPN_SERVICE_H

#include "gnunet_util_lib.h"


/**
 * Opaque VPN handle
 */
struct GNUNET_VPN_Handle;

/**
 * Opaque redirection request handle.
 */
struct GNUNET_VPN_RedirectionRequest;


/**
 * Callback invoked from the VPN service once a redirection is
 * available.  Provides the IP address that can now be used to
 * reach the requested destination.
 *
 * @param cls closure
 * @param af address family, AF_INET or AF_INET6; AF_UNSPEC on error;
 *                will match 'result_af' from the request
 * @param address IP address (struct in_addr or struct in_addr6, depending on 'af')
 *                that the VPN allocated for the redirection;
 *                traffic to this IP will now be redirected to the 
 *                specified target peer; NULL on error
 */
typedef void (*GNUNET_VPN_AllocationCallback)(void *cls,
					      int af,
					      const void *address);


/**
 * Cancel redirection request with the service.
 *
 * @param rr request to cancel
 */
void
GNUNET_VPN_cancel_request (struct GNUNET_VPN_RedirectionRequest *rr);


/**
 * Tell the VPN that a forwarding to a particular peer offering a
 * particular service is requested.  The VPN is to reserve a
 * particular IP for the redirection and return it.  The VPN will
 * begin the redirection as soon as possible and maintain it as long
 * as it is actively used and keeping it is feasible.  Given resource
 * limitations, the longest inactive mappings will be destroyed.
 *
 * @param vh VPN handle
 * @param result_af desired address family for the returned allocation
 *                  can also be AF_UNSPEC
 * @param protocol protocol, IPPROTO_UDP or IPPROTO_TCP
 * @param peer target peer for the redirection
 * @param serv service descriptor to give to the peer
 * @param nac GNUNET_YES to notify via callback only after completion of
 *            the MESH-level connection,
 *            GNUNET_NO to notify as soon as the IP has been reserved
 * @param expiration_time at what time should the redirection expire?
 *        (this should not impact connections that are active at that time)
 * @param cb function to call with the IP
 * @param cb_cls closure for cb
 * @return handle to cancel the request (means the callback won't be
 *         invoked anymore; the mapping may or may not be established
 *         anyway)
 */
struct GNUNET_VPN_RedirectionRequest *
GNUNET_VPN_redirect_to_peer (struct GNUNET_VPN_Handle *vh,
			     int result_af,
			     uint8_t protocol,
			     const struct GNUNET_PeerIdentity *peer,
			     const GNUNET_HashCode *serv,
			     int nac,
			     struct GNUNET_TIME_Absolute expiration_time,
			     GNUNET_VPN_AllocationCallback cb,
			     void *cb_cls);

		
/**
 * Tell the VPN that forwarding to the Internet via some exit node is
 * requested.  Note that both UDP and TCP traffic will be forwarded,
 * but possibly to different exit nodes.  The VPN is to reserve a
 * particular IP for the redirection and return it.  The VPN will
 * begin the redirection as soon as possible and maintain it as long
 * as it is actively used and keeping it is feasible.  Given resource
 * limitations, the longest inactive mappings will be destroyed.
 *
 * @param vh VPN handle
 * @param result_af desired address family for the returned allocation,
 *                  can also be AF_UNSPEC
 * @param addr_af address family for 'addr', AF_INET or AF_INET6
 * @param addr destination IP address on the Internet; destination
 *             port is to be taken from the VPN packet itself
 * @param nac GNUNET_YES to notify via callback only after completion of
 *            the MESH-level connection,
 *            GNUNET_NO to notify as soon as the IP has been reserved
 * @param expiration_time at what time should the redirection expire?
 *        (this should not impact connections that are active at that time)
 * @param cb function to call with the IP
 * @param cb_cls closure for cb
 * @return handle to cancel the request (means the callback won't be
 *         invoked anymore; the mapping may or may not be established
 *         anyway)
 */
struct GNUNET_VPN_RedirectionRequest *
GNUNET_VPN_redirect_to_ip (struct GNUNET_VPN_Handle *vh, 
			   int result_af,
			   int addr_af,
			   const void *addr,
			   int nac,
			   struct GNUNET_TIME_Absolute expiration_time,
			   GNUNET_VPN_AllocationCallback cb,
			   void *cb_cls);


/**
 * Connect to the VPN service
 *
 * @param cfg configuration to use
 * @return VPN handle 
 */
struct GNUNET_VPN_Handle *
GNUNET_VPN_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Disconnect from the VPN service.
 *
 * @param vh VPN handle
 */
void
GNUNET_VPN_disconnect (struct GNUNET_VPN_Handle *vh);

#endif
