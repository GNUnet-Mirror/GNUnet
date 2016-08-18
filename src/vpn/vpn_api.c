/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2016 Christian Grothoff

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
  struct GNUNET_MQ_Handle *mq;

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
  struct GNUNET_SCHEDULER_Task *rt;

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
   * Closure for @e cb.
   */
  void *cb_cls;

  /**
   * For service redirection, identity of the peer offering the service.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * For service redirection, service descriptor.
   */
  struct GNUNET_HashCode serv;

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
   * Address family of @e addr.  AF_INET or AF_INET6.
   */
  int addr_af;

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
 * Check a #GNUNET_MESSAGE_TYPE_VPN_CLIENT_USE_IP message from the
 * VPN service.
 *
 * @param cls the `struct GNUNET_VPN_Handle`
 * @param rm message received
 * @return #GNUNET_OK if @a rm is well-formed
 */
static int
check_use_ip (void *cls,
              const struct RedirectToIpResponseMessage *rm)
{
  size_t alen;
  int af;

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
    return GNUNET_SYSERR;
  }
  if ( (ntohs (rm->header.size) != alen + sizeof (*rm)) ||
       (0 == rm->request_id) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a #GNUNET_MESSAGE_TYPE_VPN_CLIENT_USE_IP message from the
 * VPN service.
 *
 * @param cls the `struct GNUNET_VPN_Handle`
 * @param rm message received
 */
static void
handle_use_ip (void *cls,
               const struct RedirectToIpResponseMessage *rm)
{
  struct GNUNET_VPN_Handle *vh = cls;
  struct GNUNET_VPN_RedirectionRequest *rr;
  int af;

  af = (int) ntohl (rm->result_af);
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
 * Add a request to our request queue and transmit it.
 *
 * @param rr request to queue and transmit.
 */
static void
send_request (struct GNUNET_VPN_RedirectionRequest *rr)
{
  struct GNUNET_VPN_Handle *vh = rr->vh;
  struct RedirectToIpRequestMessage *rip;
  struct RedirectToServiceRequestMessage *rs;
  struct GNUNET_MQ_Envelope *env;
  size_t alen;

  if (NULL == vh->mq)
    return;
  if (NULL == rr->addr)
  {
    env = GNUNET_MQ_msg (rs,
                         GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_SERVICE);
    rs->reserved = htonl (0);
    rs->expiration_time = GNUNET_TIME_absolute_hton (rr->expiration_time);
    rs->protocol = htonl (rr->protocol);
    rs->result_af = htonl (rr->result_af);
    rs->target = rr->peer;
    rs->service_descriptor = rr->serv;
    rs->request_id = rr->request_id = ++vh->request_id_gen;
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
      return;
    }
    env = GNUNET_MQ_msg_extra (rip,
                               alen,
                               GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_IP);
    rip->reserved = htonl (0);
    rip->expiration_time = GNUNET_TIME_absolute_hton (rr->expiration_time);
    rip->result_af = htonl (rr->result_af);
    rip->addr_af = htonl (rr->addr_af);
    rip->request_id = rr->request_id = ++vh->request_id_gen;
    GNUNET_memcpy (&rip[1],
                   rr->addr,
                   alen);
  }
  GNUNET_MQ_send (vh->mq,
                  env);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_VPN_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_VPN_Handle *vh = cls;

  reconnect (vh);
}


/**
 * Connect to the VPN service and start again to transmit our requests.
 *
 * @param cls the `struct GNUNET_VPN_Handle *`
 */
static void
connect_task (void *cls)
{
  struct GNUNET_VPN_Handle *vh = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (use_ip,
                           GNUNET_MESSAGE_TYPE_VPN_CLIENT_USE_IP,
                           struct RedirectToIpResponseMessage,
                           cls),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_VPN_RedirectionRequest *rr;

  vh->rt = NULL;
  vh->mq = GNUNET_CLIENT_connecT (vh->cfg,
                                  "vpn",
                                  handlers,
                                  &mq_error_handler,
                                  vh);
  if (NULL == vh->mq)
    return;
  for (rr = vh->rr_head; NULL != rr; rr = rr->next)
    send_request (rr);
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

  GNUNET_MQ_destroy (vh->mq);
  vh->mq = NULL;
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
 * @param expiration_time at what time should the redirection expire?
 *        (this should not impact connections that are active at that time)
 * @param cb function to call with the IP
 * @param cb_cls closure for @a cb
 * @return handle to cancel the request (means the callback won't be
 *         invoked anymore; the mapping may or may not be established
 *         anyway)
 */
struct GNUNET_VPN_RedirectionRequest *
GNUNET_VPN_redirect_to_peer (struct GNUNET_VPN_Handle *vh,
			     int result_af,
			     uint8_t protocol,
			     const struct GNUNET_PeerIdentity *peer,
			     const struct GNUNET_HashCode *serv,
			     struct GNUNET_TIME_Absolute expiration_time,
			     GNUNET_VPN_AllocationCallback cb,
			     void *cb_cls)
{
  struct GNUNET_VPN_RedirectionRequest *rr;

  rr = GNUNET_new (struct GNUNET_VPN_RedirectionRequest);
  rr->vh = vh;
  rr->cb = cb;
  rr->cb_cls = cb_cls;
  rr->peer = *peer;
  rr->serv = *serv;
  rr->expiration_time = expiration_time;
  rr->result_af = result_af;
  rr->protocol = protocol;
  GNUNET_CONTAINER_DLL_insert_tail (vh->rr_head,
				    vh->rr_tail,
				    rr);
  send_request (rr);
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
 * @param addr_af address family for @a addr, AF_INET or AF_INET6
 * @param addr destination IP address on the Internet; destination
 *             port is to be taken from the VPN packet itself
 * @param expiration_time at what time should the redirection expire?
 *        (this should not impact connections that are active at that time)
 * @param cb function to call with the IP
 * @param cb_cls closure for @a cb
 * @return handle to cancel the request (means the callback won't be
 *         invoked anymore; the mapping may or may not be established
 *         anyway)
 */
struct GNUNET_VPN_RedirectionRequest *
GNUNET_VPN_redirect_to_ip (struct GNUNET_VPN_Handle *vh,
			   int result_af,
			   int addr_af,
			   const void *addr,
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
  GNUNET_memcpy (&rr[1],
          addr,
          alen);
  GNUNET_CONTAINER_DLL_insert_tail (vh->rr_head,
				    vh->rr_tail,
				    rr);
  send_request (rr);
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
  struct GNUNET_VPN_Handle *vh
    = GNUNET_new (struct GNUNET_VPN_Handle);

  vh->cfg = cfg;
  connect_task (vh);
  if (NULL == vh->mq)
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
  if (NULL != vh->mq)
  {
    GNUNET_MQ_destroy (vh->mq);
    vh->mq = NULL;
  }
  if (NULL != vh->rt)
  {
    GNUNET_SCHEDULER_cancel (vh->rt);
    vh->rt = NULL;
  }
  GNUNET_free (vh);
}

/* end of vpn_api.c */
