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
 * @file vpn/vpn_api.c
 * @brief library to access the VPN service and tell it how to redirect traffic
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_vpn_service.h"
#include "vpn.h"


/**
 * Opaque VPN handle
 */
struct GNUNET_VPN_Handle
{
  /**
   * Configuration we use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Connection to VPN service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Head of list of active redirection requests.
   */
  struct GNUNET_VPN_RedirectionRequest *rr_head;

  /**
   * Tail of list of active redirection requests.
   */
  struct GNUNET_VPN_RedirectionRequest *rr_tail;
};


/**
 * Opaque redirection request handle.
 */
struct GNUNET_VPN_RedirectionRequest
{
  /**
   * Element in DLL.
   */
  struct GNUNET_VPN_RedirectionRequest *next;

  /**
   * Element in DLL.
   */
  struct GNUNET_VPN_RedirectionRequest *prev;

  /**
   * Pointer to the VPN struct.
   */
  struct GNUNET_VPN_Handle *vh;

  /**
   * Target IP address for the redirection, or NULL for
   * redirection to service.  Allocated after this struct.
   */
  const void *addr;

  /**
   * Function to call with the designated IP address.
   */
  GNUNET_VPN_AllocationCallback cb;
  
  /**
   * Closure for 'cb'.
   */
  void *cb_cls;

  /**
   * For service redirection, identity of the peer offering the service.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * For service redirection, service descriptor.
   */
  GNUNET_HashCode serv;		     

  /**
   * At what time should the created service mapping expire?
   */
  struct GNUNET_TIME_Absolute expiration_time;

  /**
   * Desired address family for the result.
   */
  int result_af;

  /**
   * Address family of 'addr'.  AF_INET or AF_INET6.
   */
  int addr_af;
  
  /**
   * GNUNET_YES if we are to call the callback only after successful
   * mesh tunnel creation.
   */
  int nac;
  
  /**
   * For service redirection, IPPROT_UDP or IPPROTO_TCP.
   */
  uint8_t protocol;

};


/**
 * Cancel redirection request with the service.
 *
 * @param rr request to cancel
 */
void
GNUNET_VPN_cancel_request (struct GNUNET_VPN_RedirectionRequest *rr)
{
  struct GNUNET_VPN_Handle *vh;

  vh = rr->vh;
  GNUNET_CONTAINER_DLL_remove (vh->rr_head,
			       vh->rr_tail,
			       rr);
  GNUNET_free (rr);
}


/**
 * Tell the VPN that a forwarding to a particular peer offering a
 * particular service is requested.  The VPN is to reserve a
 * particular IP for the redirection and return it.  The VPN will
 * begin the redirection as soon as possible and maintain it as long
 * as it is actively used and keeping it is feasible.  Given resource
 * limitations, the longest inactive mappings will be destroyed.
 *
 * @param vh VPN handle
 * @param af address family, AF_INET or AF_INET6
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
GNUNET_VPN_redirect_to_peer (struct GNUNET_VPN_Handle *rh,		   
			     int af,
			     uint8_t protocol,
			     const struct GNUNET_PeerIdentity *peer,
			     const GNUNET_HashCode *serv,
			     int nac,
			     struct GNUNET_TIME_Absolute expiration_time,
			     GNUNET_VPN_AllocationCallback cb,
			     void *cb_cls)
{
  return NULL; // FIXME
}

		
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
 * @param result_af desired address family for the returned allocation
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
GNUNET_VPN_redirect_to_ip (struct GNUNET_VPN_Handle *rh,		   
			   int result_af,
			   int addr_af,
			   const void *addr,
			   int nac,
			   struct GNUNET_TIME_Absolute expiration_time,
			   GNUNET_VPN_AllocationCallback cb,
			   void *cb_cls)
{
  return NULL; // FIXME
}


/**
 * Connect to the VPN service
 *
 * @param cfg configuration to use
 * @return VPN handle 
 */
struct GNUNET_VPN_Handle *
GNUNET_VPN_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_VPN_Handle *vh;

  vh = GNUNET_malloc (sizeof (struct GNUNET_VPN_Handle));
  vh->cfg = cfg;
  vh->client = GNUNET_CLIENT_connect ("vpn", cfg);
  return vh;
}


/**
 * Disconnect from the VPN service.
 *
 * @param vh VPN handle
 */
void
GNUNET_VPN_disconnect (struct GNUNET_VPN_Handle *vh)
{
  GNUNET_assert (NULL == vh->rr_head);
  GNUNET_CLIENT_disconnect (vh->client, GNUNET_NO);
  GNUNET_free (vh);
}

/* end of vpn_api.c */
