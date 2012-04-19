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
   * Active transmission request.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Head of list of active redirection requests.
   */
  struct GNUNET_VPN_RedirectionRequest *rr_head;

  /**
   * Tail of list of active redirection requests.
   */
  struct GNUNET_VPN_RedirectionRequest *rr_tail;

  /**
   * Identifier of a reconnect task.
   */
  GNUNET_SCHEDULER_TaskIdentifier rt;

  /**
   * How long do we wait until we try to reconnect?
   */
  struct GNUNET_TIME_Relative backoff;

  /**
   * ID of the last request that was submitted to the service.
   */
  uint64_t request_id_gen;

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
   * non-zero if this request has been sent to the service.
   */
  uint64_t request_id;

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
 * Disconnect from the service (communication error) and reconnect later.
 *
 * @param vh handle to reconnect.
 */
static void
reconnect (struct GNUNET_VPN_Handle *vh);


/**
 * Function called when we receive a message from the VPN service.
 *
 * @param cls the 'struct GNUNET_VPN_Handle'
 * @param msg message received, NULL on timeout or fatal error
 */
static void 
receive_response (void *cls,
		  const struct GNUNET_MessageHeader* msg)
{
  struct GNUNET_VPN_Handle *vh = cls;
  const struct RedirectToIpResponseMessage *rm;
  struct GNUNET_VPN_RedirectionRequest *rr;
  size_t msize;
  size_t alen;
  int af;

  if (NULL == msg) 
  {
    reconnect (vh);
    return;
  }
  if ( (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_VPN_CLIENT_USE_IP) ||
       (sizeof (struct RedirectToIpResponseMessage) > (msize = ntohs (msg->size))) )
  {
    GNUNET_break (0);
    reconnect (vh);
    return;
  }
  rm = (const struct RedirectToIpResponseMessage *) msg;
  af = (int) ntohl (rm->result_af);
  switch (af)
  {
  case AF_UNSPEC:
    alen = 0;
    break;
  case AF_INET:
    alen = sizeof (struct in_addr);
    break;
  case AF_INET6:
    alen = sizeof (struct in6_addr);
    break;
  default:
    GNUNET_break (0);
    reconnect (vh);
    return;
  }
  if ( (msize != alen + sizeof (struct RedirectToIpResponseMessage)) ||
       (0 == rm->request_id) )
  {
    GNUNET_break (0);
    reconnect (vh);
    return;
  }  
  GNUNET_CLIENT_receive (vh->client,
			 &receive_response, vh,
			 GNUNET_TIME_UNIT_FOREVER_REL);      
  for (rr = vh->rr_head; NULL != rr; rr = rr->next)
  {
    if (rr->request_id == rm->request_id)
    {
      GNUNET_CONTAINER_DLL_remove (vh->rr_head,
				   vh->rr_tail,
				   rr);
      rr->cb (rr->cb_cls,
	      af,
	      (af == AF_UNSPEC) ? NULL : &rm[1]);
      GNUNET_free (rr);
      break;
    }
  }
}


/**
 * We're ready to transmit a request to the VPN service. Do it.
 *
 * @param cls the 'struct GNUNET_VPN_Handle*'
 * @param size number of bytes available in buf
 * @param buf where to copy the request
 * @return number of bytes copied to 'buf'
 */
static size_t
transmit_request (void *cls,
		  size_t size,
		  void *buf)
{
  struct GNUNET_VPN_Handle *vh = cls;
  struct GNUNET_VPN_RedirectionRequest *rr;
  struct RedirectToIpRequestMessage rip;
  struct RedirectToServiceRequestMessage rs;
  char *cbuf;
  size_t alen;
  size_t ret;

  vh->th = NULL;
  /* find a pending request */
  rr = vh->rr_head;
  while ( (NULL != rr) &&
	  (0 != rr->request_id) )
    rr = rr->next;
  if (NULL == rr) 
    return 0;
  if (0 == size) 
  {
    reconnect (vh);
    return 0;
  }

  /* if first request, start receive loop */
  if (0 == vh->request_id_gen)
    GNUNET_CLIENT_receive (vh->client,
			   &receive_response, vh,
			   GNUNET_TIME_UNIT_FOREVER_REL); 
  if (NULL == rr->addr)
  {
    ret = sizeof (struct RedirectToServiceRequestMessage);
    GNUNET_assert (ret <= size);
    rs.header.size = htons ((uint16_t) ret);
    rs.header.type = htons (GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_SERVICE);
    rs.nac = htonl (rr->nac);
    rs.expiration_time = GNUNET_TIME_absolute_hton (rr->expiration_time);
    rs.protocol = htonl (rr->protocol);
    rs.result_af = htonl (rr->result_af);
    rs.target = rr->peer;
    rs.service_descriptor = rr->serv;
    rs.request_id = rr->request_id = ++vh->request_id_gen;    
    memcpy (buf, &rs, sizeof (struct RedirectToServiceRequestMessage));
  }
  else
  {
    switch (rr->addr_af)
    {
    case AF_INET:
      alen = sizeof (struct in_addr);
      break;
    case AF_INET6:
      alen = sizeof (struct in6_addr);
      break;
    default:
      GNUNET_assert (0);
      return 0;
    }
    ret = alen + sizeof (struct RedirectToIpRequestMessage);
    GNUNET_assert (ret <= size);
    rip.header.size = htons ((uint16_t) ret);
    rip.header.type = htons (GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_IP);
    rip.nac = htonl (rr->nac);
    rip.expiration_time = GNUNET_TIME_absolute_hton (rr->expiration_time);
    rip.result_af = htonl (rr->result_af);
    rip.addr_af = htonl (rr->addr_af);
    rip.request_id = rr->request_id = ++vh->request_id_gen;
    cbuf = buf;
    memcpy (cbuf, &rip, sizeof (struct RedirectToIpRequestMessage));
    memcpy (&cbuf[sizeof (struct RedirectToIpRequestMessage)], rr->addr, alen);
  }
  /* test if there are more pending requests */
  while ( (NULL != rr) &&
	  (0 != rr->request_id) )
    rr = rr->next;
  if (NULL != rr)
    vh->th = GNUNET_CLIENT_notify_transmit_ready (vh->client,
						  sizeof (struct RedirectToServiceRequestMessage),
						  GNUNET_TIME_UNIT_FOREVER_REL,
						  GNUNET_NO,
						  &transmit_request,
						  vh);
  return ret;
}


/**
 * Add a request to our request queue and transmit it.
 * 
 * @param rr request to queue and transmit.
 */
static void
queue_request (struct GNUNET_VPN_RedirectionRequest *rr)
{
  struct GNUNET_VPN_Handle *vh;

  vh = rr->vh;
  GNUNET_CONTAINER_DLL_insert_tail (vh->rr_head,
				    vh->rr_tail,
				    rr);
  if ( (NULL == vh->th) &&
       (NULL != vh->client) )
    vh->th = GNUNET_CLIENT_notify_transmit_ready (vh->client,
						  sizeof (struct RedirectToServiceRequestMessage),
						  GNUNET_TIME_UNIT_FOREVER_REL,
						  GNUNET_NO,
						  &transmit_request,
						  vh);
}


/**
 * Connect to the VPN service and start again to transmit our requests.
 *
 * @param cls the 'struct GNUNET_VPN_Handle *'
 * @param tc scheduler context
 */
static void
connect_task (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_VPN_Handle *vh = cls;
  
  vh->rt = GNUNET_SCHEDULER_NO_TASK;
  vh->client = GNUNET_CLIENT_connect ("vpn", vh->cfg);
  GNUNET_assert (NULL != vh->client);
  GNUNET_assert (NULL == vh->th);
  if (NULL != vh->rr_head) 
    vh->th = GNUNET_CLIENT_notify_transmit_ready (vh->client,
						  sizeof (struct RedirectToServiceRequestMessage),
						  GNUNET_TIME_UNIT_FOREVER_REL,
						  GNUNET_NO,
						  &transmit_request,
						  vh);
}


/**
 * Disconnect from the service (communication error) and reconnect later.
 *
 * @param vh handle to reconnect.
 */
static void
reconnect (struct GNUNET_VPN_Handle *vh)
{
  struct GNUNET_VPN_RedirectionRequest *rr;

  if (NULL != vh->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (vh->th);
    vh->th = NULL;
  }  
  GNUNET_CLIENT_disconnect (vh->client);
  vh->client = NULL;
  vh->request_id_gen = 0;
  for (rr = vh->rr_head; NULL != rr; rr = rr->next)
    rr->request_id = 0;
  vh->backoff = GNUNET_TIME_relative_max (GNUNET_TIME_UNIT_MILLISECONDS,
					  GNUNET_TIME_relative_min (GNUNET_TIME_relative_multiply (vh->backoff, 2),
								    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)));
  vh->rt = GNUNET_SCHEDULER_add_delayed (vh->backoff,
					 &connect_task, 
					 vh);
}


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
			     void *cb_cls)
{
  struct GNUNET_VPN_RedirectionRequest *rr;

  rr = GNUNET_malloc (sizeof (struct GNUNET_VPN_RedirectionRequest));
  rr->vh = vh;
  rr->cb = cb;
  rr->cb_cls = cb_cls;
  rr->peer = *peer;
  rr->serv = *serv;
  rr->expiration_time = expiration_time;
  rr->result_af = result_af;
  rr->nac = nac;
  rr->protocol = protocol;
  queue_request (rr);
  return rr;
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
GNUNET_VPN_redirect_to_ip (struct GNUNET_VPN_Handle *vh,
			   int result_af,
			   int addr_af,
			   const void *addr,
			   int nac,
			   struct GNUNET_TIME_Absolute expiration_time,
			   GNUNET_VPN_AllocationCallback cb,
			   void *cb_cls)
{
  struct GNUNET_VPN_RedirectionRequest *rr;
  size_t alen;

  switch (addr_af)
  {
  case AF_INET:
    alen = sizeof (struct in_addr);
    break;
  case AF_INET6:
    alen = sizeof (struct in6_addr);
    break;
  default:
    GNUNET_break (0);
    return NULL;
  }
  rr = GNUNET_malloc (sizeof (struct GNUNET_VPN_RedirectionRequest) + alen);
  rr->vh = vh;
  rr->addr = &rr[1];
  rr->cb = cb;
  rr->cb_cls = cb_cls;
  rr->expiration_time = expiration_time;
  rr->result_af = result_af;
  rr->addr_af = addr_af;
  rr->nac = nac;
  memcpy (&rr[1], addr, alen);
  queue_request (rr);
  return rr;
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
  if (NULL == vh->client)
  {
    GNUNET_free (vh);
    return NULL;
  }
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
  if (NULL != vh->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (vh->th);
    vh->th = NULL;
  }
  if (NULL != vh->client)
  {
    GNUNET_CLIENT_disconnect (vh->client);
    vh->client = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != vh->rt)
  {
    GNUNET_SCHEDULER_cancel (vh->rt);
    vh->rt = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (vh);
}

/* end of vpn_api.c */
