/*
     This file is part of GNUnet.
     (C) 2010, 2012 Christian Grothoff

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
 * @file pt/gnunet-daemon-pt.c
 * @brief tool to manipulate DNS and VPN services to perform protocol translation (IPvX over GNUnet)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dns_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_mesh_service.h"
#include "gnunet_tun_lib.h"
#include "gnunet_vpn_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_applications.h"


/**
 * After how long do we time out if we could not get an IP from VPN or MESH?
 */
#define TIMEOUT GNUNET_TIME_UNIT_MINUTES


/**
 * How many bytes of payload do we allow at most for a DNS reply?
 * Given that this is pretty much limited to loopback, we can be
 * pretty high (Linux loopback defaults to 16k, most local UDP packets
 * should survive up to 9k (NFS), so 8k should be pretty safe in
 * general).
 */
#define MAX_DNS_SIZE (8 * 1024)


/**
 * Which group of DNS records are we currently processing?
 */
enum RequestGroup
  {
    /**
     * DNS answers
     */
    ANSWERS = 0, 

    /**
     * DNS authority records
     */
    AUTHORITY_RECORDS = 1,

    /**
     * DNS additional records
     */
    ADDITIONAL_RECORDS = 2,

    /**
     * We're done processing.
     */
    END = 3
  };


/**
 * Information tracked per DNS reply that we are processing.
 */
struct ReplyContext
{
  /**
   * Handle to submit the final result.
   */
  struct GNUNET_DNS_RequestHandle *rh;
  
  /**
   * DNS packet that is being modified.
   */
  struct GNUNET_DNSPARSER_Packet *dns;

  /**
   * Active redirection request with the VPN.
   */
  struct GNUNET_VPN_RedirectionRequest *rr;

  /**
   * Record for which we have an active redirection request.
   */
  struct GNUNET_DNSPARSER_Record *rec;

  /**
   * Offset in the current record group that is being modified.
   */
  unsigned int offset;

  /**
   * Group that is being modified
   */
  enum RequestGroup group;
  
};


/**
 * State we keep for a request that is going out via MESH.
 */
struct RequestContext
{
  /**
   * We keep these in a DLL.
   */
  struct RequestContext *next;

  /**
   * We keep these in a DLL.
   */
  struct RequestContext *prev;

  /**
   * Handle for interaction with DNS service.
   */
  struct GNUNET_DNS_RequestHandle *rh;
  
  /**
   * Message we're sending out via MESH, allocated at the
   * end of this struct.
   */
  const struct GNUNET_MessageHeader *mesh_message;

  /**
   * Task used to abort this operation with timeout.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * ID of the original DNS request (used to match the reply).
   */
  uint16_t dns_id;

  /**
   * GNUNET_NO if this request is still in the transmit_queue,
   * GNUNET_YES if we are in the receive_queue.
   */ 
  int16_t was_transmitted;

};


/**
 * The handle to the configuration used throughout the process
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * The handle to the VPN
 */
static struct GNUNET_VPN_Handle *vpn_handle;

/**
 * The handle to the MESH service
 */
static struct GNUNET_MESH_Handle *mesh_handle;

/**
 * Tunnel we use for DNS requests over MESH.
 */
static struct GNUNET_MESH_Tunnel *mesh_tunnel;

/**
 * Active transmission request with MESH (or NULL).
 */
static struct GNUNET_MESH_TransmitHandle *mesh_th;

/**
 * Head of DLL of requests to be transmitted to mesh_tunnel.
 */
static struct RequestContext *transmit_queue_head;

/**
 * Tail of DLL of requests to be transmitted to mesh_tunnel.
 */
static struct RequestContext *transmit_queue_tail;

/**
 * Head of DLL of requests waiting for a response.
 */
static struct RequestContext *receive_queue_head;

/**
 * Tail of DLL of requests waiting for a response.
 */
static struct RequestContext *receive_queue_tail;

/**
 * Statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * The handle to DNS post-resolution modifications.
 */
static struct GNUNET_DNS_Handle *dns_post_handle;

/**
 * The handle to DNS pre-resolution modifications.
 */
static struct GNUNET_DNS_Handle *dns_pre_handle;

/**
 * Are we doing IPv4-pt?
 */
static int ipv4_pt;

/**
 * Are we doing IPv6-pt?
 */
static int ipv6_pt;

/**
 * Are we tunneling DNS queries?
 */
static int dns_tunnel;

/**
 * Number of DNS exit peers we currently have in the mesh tunnel.
 * Used to see if using the mesh tunnel makes any sense right now.
 */
static unsigned int dns_exit_available;


/**
 * We're done modifying all records in the response.  Submit the reply
 * and free the resources of the rc.
 *
 * @param rc context to process
 */
static void
finish_request (struct ReplyContext *rc)
{
  char *buf;
  size_t buf_len;

  if (GNUNET_SYSERR ==
      GNUNET_DNSPARSER_pack (rc->dns,
			     MAX_DNS_SIZE,
			     &buf,
			     &buf_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to pack DNS request.  Dropping.\n"));
    GNUNET_DNS_request_drop (rc->rh);
  }
  else
  {
    GNUNET_STATISTICS_update (stats,
			      gettext_noop ("# DNS requests mapped to VPN"),
			      1, GNUNET_NO);
    GNUNET_DNS_request_answer (rc->rh,
			       buf_len, buf);
    GNUNET_free (buf);
  }
  GNUNET_DNSPARSER_free_packet (rc->dns);
  GNUNET_free (rc);
}


/**
 * Process the next record of the given request context.
 * When done, submit the reply and free the resources of
 * the rc.
 *
 * @param rc context to process
 */
static void
submit_request (struct ReplyContext *rc);


/**
 * Callback invoked from the VPN service once a redirection is
 * available.  Provides the IP address that can now be used to
 * reach the requested destination.  We substitute the active
 * record and then continue with 'submit_request' to look at
 * the other records.
 *
 * @param cls our 'struct ReplyContext'
 * @param af address family, AF_INET or AF_INET6; AF_UNSPEC on error;
 *                will match 'result_af' from the request
 * @param address IP address (struct in_addr or struct in_addr6, depending on 'af')
 *                that the VPN allocated for the redirection;
 *                traffic to this IP will now be redirected to the 
 *                specified target peer; NULL on error
 */
static void
vpn_allocation_callback (void *cls,
			 int af,
			 const void *address)
{
  struct ReplyContext *rc = cls;

  rc->rr = NULL;
  if (af == AF_UNSPEC)
  {
    GNUNET_DNS_request_drop (rc->rh);
    GNUNET_DNSPARSER_free_packet (rc->dns);
    GNUNET_free (rc);
    return;
  }
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# DNS records modified"),
			    1, GNUNET_NO);
  switch (rc->rec->type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    GNUNET_assert (AF_INET == af);
    memcpy (rc->rec->data.raw.data, address, sizeof (struct in_addr));
    break;
  case GNUNET_DNSPARSER_TYPE_AAAA:
    GNUNET_assert (AF_INET6 == af);
    memcpy (rc->rec->data.raw.data, address, sizeof (struct in6_addr));
    break;
  default:
    GNUNET_assert (0);
    return;
  }
  rc->rec = NULL;
  submit_request (rc);
}


/**
 * Modify the given DNS record by asking VPN to create a tunnel
 * to the given address.  When done, continue with submitting
 * other records from the request context ('submit_request' is
 * our continuation).
 *
 * @param rc context to process
 * @param rec record to modify
 */
static void
modify_address (struct ReplyContext *rc,
		struct GNUNET_DNSPARSER_Record *rec)
{
  int af;

  switch (rec->type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    af = AF_INET;
    GNUNET_assert (rec->data.raw.data_len == sizeof (struct in_addr));
    break;
  case GNUNET_DNSPARSER_TYPE_AAAA:
    af = AF_INET6;
    GNUNET_assert (rec->data.raw.data_len == sizeof (struct in6_addr));
    break;
  default:
    GNUNET_assert (0);
    return;
  }
  rc->rec = rec;
  rc->rr = GNUNET_VPN_redirect_to_ip (vpn_handle,
				      af, af,
				      rec->data.raw.data,
				      GNUNET_NO /* nac */,
				      GNUNET_TIME_relative_to_absolute (TIMEOUT),
				      &vpn_allocation_callback,
				      rc);
}


/**
 * Process the next record of the given request context.
 * When done, submit the reply and free the resources of
 * the rc.
 *
 * @param rc context to process
 */
static void
submit_request (struct ReplyContext *rc)
{
  struct GNUNET_DNSPARSER_Record *ra;
  unsigned int ra_len;
  unsigned int i;

  while (1)
  {
    switch (rc->group)
    {
    case ANSWERS:
      ra = rc->dns->answers;
      ra_len = rc->dns->num_answers;
      break;
    case AUTHORITY_RECORDS:
      ra = rc->dns->authority_records;
      ra_len = rc->dns->num_authority_records;
      break;
    case ADDITIONAL_RECORDS:
      ra = rc->dns->additional_records;
      ra_len = rc->dns->num_additional_records;
      break;
    case END:
      finish_request (rc);
      return;
    default:
      GNUNET_assert (0);      
    }
    for (i=rc->offset;i<ra_len;i++)
    {
      switch (ra[i].type)
      {
      case GNUNET_DNSPARSER_TYPE_A:
	if (ipv4_pt)
	{
	  rc->offset = i + 1;
	  modify_address (rc, &ra[i]);
	  return;
	}
	break;
      case GNUNET_DNSPARSER_TYPE_AAAA:
	if (ipv6_pt)
	{
	  rc->offset = i + 1;
	  modify_address (rc, &ra[i]);
	  return;
	}
	break;
      }
    }
    rc->group++;
  }
}


/**
 * Test if any of the given records need protocol-translation work.
 *
 * @param ra array of records
 * @param ra_len number of entries in ra
 * @return GNUNET_YES if any of the given records require protocol-translation
 */
static int
work_test (const struct GNUNET_DNSPARSER_Record *ra,
	   unsigned int ra_len)
{
  unsigned int i;

  for (i=0;i<ra_len;i++)
  {
    switch (ra[i].type)
    {
    case GNUNET_DNSPARSER_TYPE_A:
      if (ipv4_pt)
	return GNUNET_YES;
      break;
    case GNUNET_DNSPARSER_TYPE_AAAA:
      if (ipv6_pt)
	return GNUNET_YES;
      break;
    }
  }
  return GNUNET_NO;
}


/**
 * This function is called AFTER we got an IP address for a 
 * DNS request.  Now, the PT daemon has the chance to substitute
 * the IP address with one from the VPN range to tunnel requests
 * destined for this IP address via VPN and MESH.
 *
 * @param cls closure
 * @param rh request handle to user for reply
 * @param request_length number of bytes in request
 * @param request udp payload of the DNS request
 */
static void 
dns_post_request_handler (void *cls,
			  struct GNUNET_DNS_RequestHandle *rh,
			  size_t request_length,
			  const char *request)
{
  struct GNUNET_DNSPARSER_Packet *dns;
  struct ReplyContext *rc;
  int work;

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# DNS replies intercepted"),
			    1, GNUNET_NO);
  dns = GNUNET_DNSPARSER_parse (request, request_length);
  if (NULL == dns)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to parse DNS request.  Dropping.\n"));
    GNUNET_DNS_request_drop (rh);
    return;
  }
  work = GNUNET_NO;
  work |= work_test (dns->answers, dns->num_answers);
  work |= work_test (dns->authority_records, dns->num_authority_records);
  work |= work_test (dns->additional_records, dns->num_additional_records);
  if (! work)
  {
    GNUNET_DNS_request_forward (rh);
    GNUNET_DNSPARSER_free_packet (dns);
    return;
  }
  rc = GNUNET_malloc (sizeof (struct ReplyContext));
  rc->rh = rh;
  rc->dns = dns;
  rc->offset = 0;
  rc->group = ANSWERS;
  submit_request (rc);
}


/**
 * Transmit a DNS request via MESH and move the request
 * handle to the receive queue.
 *
 * @param cls NULL
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes written to buf
 */
static size_t
transmit_dns_request_to_mesh (void *cls,
			      size_t size,
			      void *buf)
{
  struct RequestContext *rc;
  size_t mlen;

  mesh_th = NULL;
  if (NULL == (rc = transmit_queue_head))
    return 0;
  mlen = ntohs (rc->mesh_message->size);
  if (mlen > size)
  {    
    mesh_th = GNUNET_MESH_notify_transmit_ready (mesh_tunnel,
						 GNUNET_NO, 0,
						 TIMEOUT,
						 NULL, mlen,
						 &transmit_dns_request_to_mesh,
						 NULL);
    return 0;
  }
  GNUNET_assert (GNUNET_NO == rc->was_transmitted);
  memcpy (buf, rc->mesh_message, mlen);
  GNUNET_CONTAINER_DLL_remove (transmit_queue_head,
			       transmit_queue_tail,
			       rc);
  rc->was_transmitted = GNUNET_YES;
  GNUNET_CONTAINER_DLL_insert (receive_queue_head,
			       receive_queue_tail,
			       rc);
  rc = transmit_queue_head;
  if (NULL != rc)
    mesh_th = GNUNET_MESH_notify_transmit_ready (mesh_tunnel,
						 GNUNET_NO, 0,
						 TIMEOUT,
						 NULL, ntohs (rc->mesh_message->size),
						 &transmit_dns_request_to_mesh,
						 NULL);
  return mlen;
}


/**
 * Task run if the time to answer a DNS request via MESH is over.
 *
 * @param cls the 'struct RequestContext' to abort
 * @param tc scheduler context
 */
static void
timeout_request (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RequestContext *rc = cls;
  
  if (rc->was_transmitted)
    GNUNET_CONTAINER_DLL_remove (receive_queue_head,
				 receive_queue_tail,
				 rc);
  else
    GNUNET_CONTAINER_DLL_remove (transmit_queue_head,
				 transmit_queue_tail,
				 rc);
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# DNS requests dropped (timeout)"),
			    1, GNUNET_NO);
  GNUNET_DNS_request_drop (rc->rh);
  GNUNET_free (rc);
}


/**
 * This function is called *before* the DNS request has been 
 * given to a "local" DNS resolver.  Tunneling for DNS requests
 * was enabled, so we now need to send the request via some MESH
 * tunnel to a DNS EXIT for resolution.
 *
 * @param cls closure
 * @param rh request handle to user for reply
 * @param request_length number of bytes in request
 * @param request udp payload of the DNS request
 */
static void 
dns_pre_request_handler (void *cls,
			 struct GNUNET_DNS_RequestHandle *rh,
			 size_t request_length,
			 const char *request)
{
  struct RequestContext *rc;
  size_t mlen;
  struct GNUNET_MessageHeader hdr;
  struct GNUNET_TUN_DnsHeader dns;

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# DNS requests intercepted"),
			    1, GNUNET_NO);
  if (0 == dns_exit_available)
  {
    GNUNET_STATISTICS_update (stats,
			      gettext_noop ("# DNS requests dropped (DNS mesh tunnel down)"),
			      1, GNUNET_NO);
    GNUNET_DNS_request_drop (rh);
    return;
  }
  if (request_length < sizeof (dns))
  {
    GNUNET_STATISTICS_update (stats,
			      gettext_noop ("# DNS requests dropped (malformed)"),
			      1, GNUNET_NO);
    GNUNET_DNS_request_drop (rh);
    return;
  }
  memcpy (&dns, request, sizeof (dns));
  GNUNET_assert (NULL != mesh_tunnel);
  mlen = sizeof (struct GNUNET_MessageHeader) + request_length;
  rc = GNUNET_malloc (sizeof (struct RequestContext) + mlen);
  rc->rh = rh;
  rc->mesh_message = (const struct GNUNET_MessageHeader*) &rc[1];
  rc->timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
						   &timeout_request,
						   rc);
  rc->dns_id = dns.id;
  hdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_DNS_TO_INTERNET);
  hdr.size = htons (mlen);
  memcpy (&rc[1], &hdr, sizeof (struct GNUNET_MessageHeader));
  memcpy (&(((char*)&rc[1])[sizeof (struct GNUNET_MessageHeader)]),
	  request,
	  request_length);
  GNUNET_CONTAINER_DLL_insert_tail (transmit_queue_head,
				    transmit_queue_tail,
				    rc);
  if (NULL == mesh_th)
    mesh_th = GNUNET_MESH_notify_transmit_ready (mesh_tunnel,
						 GNUNET_NO, 0,
						 TIMEOUT,
						 NULL, mlen,
						 &transmit_dns_request_to_mesh,
						 NULL);
}


/**
 * Process a request via mesh to perform a DNS query.
 *
 * @param cls closure, NULL
 * @param tunnel connection to the other end
 * @param tunnel_ctx pointer to our 'struct TunnelState *'
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
receive_dns_response (void *cls GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
		      void **tunnel_ctx,
		      const struct GNUNET_PeerIdentity *sender GNUNET_UNUSED,
		      const struct GNUNET_MessageHeader *message,
		      const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
  struct GNUNET_TUN_DnsHeader dns;
  size_t mlen;
  struct RequestContext *rc;

  mlen = ntohs (message->size);
  mlen -= sizeof (struct GNUNET_MessageHeader);
  if (mlen < sizeof (struct GNUNET_TUN_DnsHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  memcpy (&dns, &message[1], sizeof (dns));
  for (rc = receive_queue_head; NULL != rc; rc = rc->next)
  {
    GNUNET_assert (GNUNET_YES == rc->was_transmitted);
    if (dns.id == rc->dns_id)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# DNS replies received"),
				1, GNUNET_NO);
      GNUNET_DNS_request_answer (rc->rh,
				 mlen,
				 (const void*) &message[1]);
      GNUNET_CONTAINER_DLL_remove (receive_queue_head,
				   receive_queue_tail,
				   rc);
      GNUNET_SCHEDULER_cancel (rc->timeout_task);
      GNUNET_free (rc);
      return GNUNET_OK;      
    }
  }
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# DNS replies dropped (too late?)"),
			    1, GNUNET_NO);
  return GNUNET_OK;
}


/**
 * The MESH DNS tunnel went down.  Abort all pending DNS
 * requests (we're unlikely to get an answer in time).
 */ 
static void
abort_all_requests ()
{
  struct RequestContext *rc;

  while (NULL != (rc = receive_queue_head))
  {
    GNUNET_STATISTICS_update (stats,
			      gettext_noop ("# DNS requests aborted (tunnel down)"),
			      1, GNUNET_NO);
    GNUNET_CONTAINER_DLL_remove (receive_queue_head,
				 receive_queue_tail,
				 rc);
    GNUNET_DNS_request_drop (rc->rh);
    GNUNET_SCHEDULER_cancel (rc->timeout_task);
    GNUNET_free (rc);    
  }
  while (NULL != (rc = transmit_queue_head))
  {
    GNUNET_STATISTICS_update (stats,
			      gettext_noop ("# DNS requests aborted (tunnel down)"),
			      1, GNUNET_NO);
    GNUNET_CONTAINER_DLL_remove (transmit_queue_head,
				 transmit_queue_tail,
				 rc);
    GNUNET_DNS_request_drop (rc->rh);
    GNUNET_SCHEDULER_cancel (rc->timeout_task);
    GNUNET_free (rc);    
  }
}


/**
 * Method called whenever a peer has disconnected from the tunnel.
 *
 * @param cls closure
 * @param peer peer identity the tunnel stopped working with
 */
static void
mesh_disconnect_handler (void *cls,
			 const struct
			 GNUNET_PeerIdentity * peer)
{
  GNUNET_assert (dns_exit_available > 0);
  dns_exit_available--;
  if (0 == dns_exit_available)
  {
    if (NULL != mesh_th)
    {
      GNUNET_MESH_notify_transmit_ready_cancel (mesh_th);
      mesh_th = NULL;
    }
    abort_all_requests ();
  }
}


/**
 * Method called whenever a peer has connected to the tunnel.
 *
 * @param cls closure
 * @param peer peer identity the tunnel was created to, NULL on timeout
 * @param atsi performance data for the connection
 */
static void
mesh_connect_handler (void *cls,
		      const struct GNUNET_PeerIdentity
		      * peer,
		      const struct
		      GNUNET_ATS_Information * atsi)
{
  dns_exit_available++;
}


/**
 * Function scheduled as very last function, cleans up after us
 */
static void
cleanup (void *cls GNUNET_UNUSED,
         const struct GNUNET_SCHEDULER_TaskContext *tskctx)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Protocol translation daemon is shutting down now\n");
  if (vpn_handle != NULL)
  {
    GNUNET_VPN_disconnect (vpn_handle);
    vpn_handle = NULL;
  }
  if (NULL != mesh_th)
  {
    GNUNET_MESH_notify_transmit_ready_cancel (mesh_th);
    mesh_th = NULL;
  }
  if (NULL != mesh_tunnel)
  {
    GNUNET_MESH_tunnel_destroy (mesh_tunnel);
    mesh_tunnel = NULL;
  }
  if (mesh_handle != NULL)
  {
    GNUNET_MESH_disconnect (mesh_handle);
    mesh_handle = NULL;
  }
  abort_all_requests ();
  if (dns_post_handle != NULL)
  {
    GNUNET_DNS_disconnect (dns_post_handle);
    dns_post_handle = NULL;
  }
  if (dns_pre_handle != NULL)
  {
    GNUNET_DNS_disconnect (dns_pre_handle);
    dns_pre_handle = NULL;
  }
  if (stats != NULL)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_YES);
    stats = NULL;
  }
}


/**
 * @brief Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg_ configuration
 */
static void
run (void *cls, char *const *args GNUNET_UNUSED,
     const char *cfgfile GNUNET_UNUSED,
     const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
  cfg = cfg_;
  stats = GNUNET_STATISTICS_create ("pt", cfg);
  ipv4_pt = GNUNET_CONFIGURATION_get_value_yesno (cfg, "pt", "TUNNEL_IPV4");
  ipv6_pt = GNUNET_CONFIGURATION_get_value_yesno (cfg, "pt", "TUNNEL_IPV6"); 
  dns_tunnel = GNUNET_CONFIGURATION_get_value_yesno (cfg, "pt", "TUNNEL_DNS"); 
  if (! (ipv4_pt || ipv6_pt || dns_tunnel))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("No useful service enabled.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;    
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, cls);
  if (ipv4_pt || ipv6_pt)
  {
    dns_post_handle 
      = GNUNET_DNS_connect (cfg, 
			    GNUNET_DNS_FLAG_POST_RESOLUTION,
			    &dns_post_request_handler, NULL);
    if (NULL == dns_post_handle)       
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to %s service.  Exiting.\n"),
		  "DNS");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    vpn_handle = GNUNET_VPN_connect (cfg);
    if (NULL == vpn_handle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to %s service.  Exiting.\n"),
		  "VPN");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
  if (dns_tunnel)
  {
    static struct GNUNET_MESH_MessageHandler mesh_handlers[] = {
      {&receive_dns_response, GNUNET_MESSAGE_TYPE_VPN_DNS_FROM_INTERNET, 0},
      {NULL, 0, 0}
    };
    static GNUNET_MESH_ApplicationType mesh_types[] = {
      GNUNET_APPLICATION_TYPE_END
    };

    dns_pre_handle 
      = GNUNET_DNS_connect (cfg, 
			    GNUNET_DNS_FLAG_PRE_RESOLUTION,
			    &dns_pre_request_handler, NULL);
    if (NULL == dns_pre_handle)       
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to %s service.  Exiting.\n"),
		  "DNS");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    mesh_handle = GNUNET_MESH_connect (cfg, 1, NULL, NULL, NULL,
				       mesh_handlers, mesh_types);
    if (NULL == mesh_handle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to %s service.  Exiting.\n"),
		  "MESH");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    mesh_tunnel = GNUNET_MESH_tunnel_create (mesh_handle,
					     NULL,
					     &mesh_connect_handler,
					     &mesh_disconnect_handler,
					     NULL);
    GNUNET_MESH_peer_request_connect_by_type (mesh_tunnel,
					      GNUNET_APPLICATION_TYPE_INTERNET_RESOLVER); 
  }
}


/**
 * The main function
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-daemon-pt",
                              gettext_noop
                              ("Daemon to run to perform IP protocol translation to GNUnet"),
                              options, &run, NULL)) ? 0 : 1;
}


/* end of gnunet-daemon-pt.c */
