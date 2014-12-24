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
#include "gnunet_cadet_service.h"
#include "gnunet_tun_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_vpn_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_applications.h"
#include "block_dns.h"


/**
 * After how long do we time out if we could not get an IP from VPN or CADET?
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
 * How many channels do we open at most at the same time?
 */
#define MAX_OPEN_TUNNELS 4


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
 * Handle to a peer that advertised that it is willing to serve
 * as a DNS exit.  We try to keep a few channels open and a few
 * peers in reserve.
 */
struct CadetExit
{

  /**
   * Kept in a DLL.
   */
  struct CadetExit *next;

  /**
   * Kept in a DLL.
   */
  struct CadetExit *prev;

  /**
   * Channel we use for DNS requests over CADET, NULL if we did
   * not initialze a channel to this peer yet.
   */
  struct GNUNET_CADET_Channel *cadet_channel;

  /**
   * At what time did the peer's advertisement expire?
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Head of DLL of requests waiting for a response.
   */
  struct RequestContext *receive_queue_head;

  /**
   * Tail of DLL of requests waiting for a response.
   */
  struct RequestContext *receive_queue_tail;

  /**
   * Head of DLL of requests to be transmitted to a cadet_channel.
   */
  struct RequestContext *transmit_queue_head;

  /**
   * Tail of DLL of requests to be transmitted to a cadet_channel.
   */
  struct RequestContext *transmit_queue_tail;

  /**
   * Active transmission request for this channel (or NULL).
   */
  struct GNUNET_CADET_TransmitHandle *cadet_th;

  /**
   * Identity of the peer that is providing the exit for us.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * How many DNS requests did we transmit via this channel?
   */
  unsigned int num_transmitted;

  /**
   * How many DNS requests were answered via this channel?
   */
  unsigned int num_answered;

};



/**
 * State we keep for a request that is going out via CADET.
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
   * Exit that was chosen for this request.
   */
  struct CadetExit *exit;

  /**
   * Handle for interaction with DNS service.
   */
  struct GNUNET_DNS_RequestHandle *rh;

  /**
   * Message we're sending out via CADET, allocated at the
   * end of this struct.
   */
  const struct GNUNET_MessageHeader *cadet_message;

  /**
   * Task used to abort this operation with timeout.
   */
  struct GNUNET_SCHEDULER_Task * timeout_task;

  /**
   * Length of the request message that follows this struct.
   */
  uint16_t mlen;

  /**
   * ID of the original DNS request (used to match the reply).
   */
  uint16_t dns_id;

  /**
   * #GNUNET_NO if this request is still in the transmit_queue,
   * #GNUNET_YES if we are in the receive_queue.
   */
  int16_t was_transmitted;

};


/**
 * Head of DLL of cadet exits.  Cadet exits with an open channel are
 * always at the beginning (so we do not have to traverse the entire
 * list to find them).
 */
static struct CadetExit *exit_head;

/**
 * Tail of DLL of cadet exits.
 */
static struct CadetExit *exit_tail;

/**
 * The handle to the configuration used throughout the process
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * The handle to the VPN
 */
static struct GNUNET_VPN_Handle *vpn_handle;

/**
 * The handle to the CADET service
 */
static struct GNUNET_CADET_Handle *cadet_handle;

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
 * Handle to access the DHT.
 */
static struct GNUNET_DHT_Handle *dht;

/**
 * Our DHT GET operation to find DNS exits.
 */
static struct GNUNET_DHT_GetHandle *dht_get;

/**
 * Are we doing IPv4-pt?
 */
static int ipv4_pt;

/**
 * Are we doing IPv6-pt?
 */
static int ipv6_pt;

/**
 * Are we channeling DNS queries?
 */
static int dns_channel;

/**
 * Number of DNS exit peers we currently have in the cadet channel.
 * Used to see if using the cadet channel makes any sense right now,
 * as well as to decide if we should open new channels.
 */
static unsigned int dns_exit_available;


/**
 * We are short on cadet exits, try to open another one.
 */
static void
try_open_exit ()
{
  struct CadetExit *pos;
  uint32_t candidate_count;
  uint32_t candidate_selected;

  candidate_count = 0;
  for (pos = exit_head; NULL != pos; pos = pos->next)
    if (NULL == pos->cadet_channel)
      candidate_count++;
  candidate_selected = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
						 candidate_count);
  candidate_count = 0;
  for (pos = exit_head; NULL != pos; pos = pos->next)
    if (NULL == pos->cadet_channel)
    {
      candidate_count++;
      if (candidate_selected < candidate_count)
      {
	/* move to the head of the DLL */
	pos->cadet_channel = GNUNET_CADET_channel_create (cadet_handle,
						      pos,
						      &pos->peer,
						      GNUNET_APPLICATION_TYPE_INTERNET_RESOLVER,
						      GNUNET_CADET_OPTION_DEFAULT);
	if (NULL == pos->cadet_channel)
	{
	  GNUNET_break (0);
	  continue;
	}
	GNUNET_CONTAINER_DLL_remove (exit_head,
				     exit_tail,
				     pos);
	GNUNET_CONTAINER_DLL_insert (exit_head,
				     exit_tail,
				     pos);
	dns_exit_available++;
	return;
      }
    }
  GNUNET_assert (NULL == exit_head);
}


/**
 * Compute the weight of the given exit.  The higher the weight,
 * the more likely it will be that the channel will be chosen.
 * A weigt of zero means that we should close the channel as it
 * is so bad, that we should not use it.
 *
 * @param exit exit to calculate the weight for
 * @return weight of the channel
 */
static uint32_t
get_channel_weight (struct CadetExit *exit)
{
  uint32_t dropped;
  uint32_t drop_percent;
  uint32_t good_percent;

  GNUNET_assert (exit->num_transmitted >= exit->num_answered);
  dropped = exit->num_transmitted - exit->num_answered;
  if (exit->num_transmitted > 0)
    drop_percent = (uint32_t) ((100LL * dropped) / exit->num_transmitted);
  else
    drop_percent = 50; /* no data */
  if ( (exit->num_transmitted > 20) &&
       (drop_percent > 25) )
    return 0; /* statistically significant, and > 25% loss, die */
  good_percent = 100 - drop_percent;
  GNUNET_assert (0 != good_percent);
  if ( UINT32_MAX / good_percent / good_percent < exit->num_transmitted)
    return UINT32_MAX; /* formula below would overflow */
  return 1 + good_percent * good_percent * exit->num_transmitted;
}


/**
 * Choose a cadet exit for a DNS request.  We try to use a channel
 * that is reliable and currently available.  All existing
 * channels are given a base weight of 1, plus a score relating
 * to the total number of queries answered in relation to the
 * total number of queries we sent to that channel.  That
 * score is doubled if the channel is currently idle.
 *
 * @return NULL if no exit is known, otherwise the
 *         exit that we should use to queue a message with
 */
static struct CadetExit *
choose_exit ()
{
  struct CadetExit *pos;
  uint64_t total_transmitted;
  uint64_t selected_offset;
  uint32_t channel_weight;

  total_transmitted = 0;
  for (pos = exit_head; NULL != pos; pos = pos->next)
  {
    if (NULL == pos->cadet_channel)
      break;
    channel_weight = get_channel_weight (pos);
    total_transmitted += channel_weight;
    /* double weight for idle channels */
    if (NULL == pos->cadet_th)
      total_transmitted += channel_weight;
  }
  if (0 == total_transmitted)
  {
    /* no channels available, or only a very bad one... */
    return exit_head;
  }
  selected_offset = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
					      total_transmitted);
  total_transmitted = 0;
  for (pos = exit_head; NULL != pos; pos = pos->next)
  {
    if (NULL == pos->cadet_channel)
      break;
    channel_weight = get_channel_weight (pos);
    total_transmitted += channel_weight;
    /* double weight for idle channels */
    if (NULL == pos->cadet_th)
      total_transmitted += channel_weight;
    if (total_transmitted > selected_offset)
      return pos;
  }
  GNUNET_break (0);
  return NULL;
}


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
 * @param cls our `struct ReplyContext`
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
 * Modify the given DNS record by asking VPN to create a channel
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
 * @param ra_len number of entries in @a ra
 * @return #GNUNET_YES if any of the given records require protocol-translation
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
 * the IP address with one from the VPN range to channel requests
 * destined for this IP address via VPN and CADET.
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
  rc = GNUNET_new (struct ReplyContext);
  rc->rh = rh;
  rc->dns = dns;
  rc->offset = 0;
  rc->group = ANSWERS;
  submit_request (rc);
}


/**
 * Transmit a DNS request via CADET and move the request
 * handle to the receive queue.
 *
 * @param cls the `struct CadetExit`
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes written to buf
 */
static size_t
transmit_dns_request_to_cadet (void *cls,
			      size_t size,
			      void *buf)
{
  struct CadetExit *exit = cls;
  struct RequestContext *rc;
  size_t mlen;

  exit->cadet_th = NULL;
  if (NULL == (rc = exit->transmit_queue_head))
    return 0;
  mlen = rc->mlen;
  if (mlen > size)
  {
    exit->cadet_th = GNUNET_CADET_notify_transmit_ready (exit->cadet_channel,
						       GNUNET_NO,
						       TIMEOUT,
						       mlen,
						       &transmit_dns_request_to_cadet,
						       exit);
    return 0;
  }
  GNUNET_assert (GNUNET_NO == rc->was_transmitted);
  memcpy (buf, rc->cadet_message, mlen);
  GNUNET_CONTAINER_DLL_remove (exit->transmit_queue_head,
			       exit->transmit_queue_tail,
			       rc);
  rc->was_transmitted = GNUNET_YES;
  GNUNET_CONTAINER_DLL_insert (exit->receive_queue_head,
			       exit->receive_queue_tail,
			       rc);
  rc = exit->transmit_queue_head;
  if (NULL != rc)
    exit->cadet_th = GNUNET_CADET_notify_transmit_ready (exit->cadet_channel,
						       GNUNET_NO,
						       TIMEOUT,
						       rc->mlen,
						       &transmit_dns_request_to_cadet,
						       exit);
  return mlen;
}


/**
 * Task run if the time to answer a DNS request via CADET is over.
 *
 * @param cls the `struct RequestContext` to abort
 * @param tc scheduler context
 */
static void
timeout_request (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RequestContext *rc = cls;
  struct CadetExit *exit = rc->exit;

  if (rc->was_transmitted)
  {
    exit->num_transmitted++;
    GNUNET_CONTAINER_DLL_remove (exit->receive_queue_head,
				 exit->receive_queue_tail,
				 rc);
  }
  else
  {
    GNUNET_CONTAINER_DLL_remove (exit->transmit_queue_head,
				 exit->transmit_queue_tail,
				 rc);
  }
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# DNS requests dropped (timeout)"),
			    1, GNUNET_NO);
  GNUNET_DNS_request_drop (rc->rh);
  GNUNET_free (rc);
  if ( (0 == get_channel_weight (exit)) &&
       (NULL == exit->receive_queue_head) &&
       (NULL == exit->transmit_queue_head) )
  {
    /* this straw broke the camel's back: this channel now has
       such a low score that it will not be used; close it! */
    GNUNET_assert (NULL == exit->cadet_th);
    GNUNET_CADET_channel_destroy (exit->cadet_channel);
    exit->cadet_channel = NULL;
    GNUNET_CONTAINER_DLL_remove (exit_head,
				 exit_tail,
				 exit);
    GNUNET_CONTAINER_DLL_insert_tail (exit_head,
				      exit_tail,
				      exit);
    /* go back to semi-innocent: mark as not great, but
       avoid a prohibitively negative score (see
       #get_channel_weight, which checks for a certain
       minimum number of transmissions before making
       up an opinion) */
    exit->num_transmitted = 5;
    exit->num_answered = 0;
    dns_exit_available--;
    /* now try to open an alternative exit */
    try_open_exit ();
  }
}


/**
 * This function is called *before* the DNS request has been
 * given to a "local" DNS resolver.  Channeling for DNS requests
 * was enabled, so we now need to send the request via some CADET
 * channel to a DNS EXIT for resolution.
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
  struct CadetExit *exit;

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# DNS requests intercepted"),
			    1, GNUNET_NO);
  if (0 == dns_exit_available)
  {
    GNUNET_STATISTICS_update (stats,
			      gettext_noop ("# DNS requests dropped (DNS cadet channel down)"),
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
  mlen = sizeof (struct GNUNET_MessageHeader) + request_length;
  exit = choose_exit ();
  GNUNET_assert (NULL != exit);
  GNUNET_assert (NULL != exit->cadet_channel);
  rc = GNUNET_malloc (sizeof (struct RequestContext) + mlen);
  rc->exit = exit;
  rc->rh = rh;
  rc->cadet_message = (const struct GNUNET_MessageHeader*) &rc[1];
  rc->timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
						   &timeout_request,
						   rc);
  rc->dns_id = dns.id;
  rc->mlen = mlen;
  hdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_DNS_TO_INTERNET);
  hdr.size = htons (mlen);
  memcpy (&rc[1], &hdr, sizeof (struct GNUNET_MessageHeader));
  memcpy (&(((char*)&rc[1])[sizeof (struct GNUNET_MessageHeader)]),
	  request,
	  request_length);
  GNUNET_CONTAINER_DLL_insert_tail (exit->transmit_queue_head,
				    exit->transmit_queue_tail,
				    rc);
  if (NULL == exit->cadet_th)
    exit->cadet_th = GNUNET_CADET_notify_transmit_ready (exit->cadet_channel,
						       GNUNET_NO,
						       TIMEOUT,
						       mlen,
						       &transmit_dns_request_to_cadet,
						       exit);
}


/**
 * Process a request via cadet to perform a DNS query.
 *
 * @param cls NULL
 * @param channel connection to the other end
 * @param channel_ctx pointer to our `struct CadetExit`
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
receive_dns_response (void *cls,
		      struct GNUNET_CADET_Channel *channel,
		      void **channel_ctx,
		      const struct GNUNET_MessageHeader *message)
{
  struct CadetExit *exit = *channel_ctx;
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
  for (rc = exit->receive_queue_head; NULL != rc; rc = rc->next)
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
      GNUNET_CONTAINER_DLL_remove (exit->receive_queue_head,
				   exit->receive_queue_tail,
				   rc);
      GNUNET_SCHEDULER_cancel (rc->timeout_task);
      GNUNET_free (rc);
      exit->num_answered++;
      exit->num_transmitted++;
      return GNUNET_OK;
    }
  }
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# DNS replies dropped (too late?)"),
			    1, GNUNET_NO);
  return GNUNET_OK;
}


/**
 * Abort all pending DNS requests with the given cadet exit.
 *
 * @param exit cadet exit to abort requests for
 */
static void
abort_all_requests (struct CadetExit *exit)
{
  struct RequestContext *rc;

  while (NULL != (rc = exit->receive_queue_head))
  {
    GNUNET_CONTAINER_DLL_remove (exit->receive_queue_head,
				 exit->receive_queue_tail,
				 rc);
    GNUNET_DNS_request_drop (rc->rh);
    GNUNET_SCHEDULER_cancel (rc->timeout_task);
    GNUNET_free (rc);
  }
  while (NULL != (rc = exit->transmit_queue_head))
  {
    GNUNET_CONTAINER_DLL_remove (exit->transmit_queue_head,
				 exit->transmit_queue_tail,
				 rc);
    GNUNET_DNS_request_drop (rc->rh);
    GNUNET_SCHEDULER_cancel (rc->timeout_task);
    GNUNET_free (rc);
  }
}


/**
 * Function scheduled as very last function, cleans up after us
 *
 * @param cls closure, NULL
 * @param tskctx scheduler context, unused
 */
static void
cleanup (void *cls,
         const struct GNUNET_SCHEDULER_TaskContext *tskctx)
{
  struct CadetExit *exit;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Protocol translation daemon is shutting down now\n");
  if (NULL != vpn_handle)
  {
    GNUNET_VPN_disconnect (vpn_handle);
    vpn_handle = NULL;
  }
  while (NULL != (exit = exit_head))
  {
    GNUNET_CONTAINER_DLL_remove (exit_head,
				 exit_tail,
				 exit);
    if (NULL != exit->cadet_th)
    {
      GNUNET_CADET_notify_transmit_ready_cancel (exit->cadet_th);
      exit->cadet_th = NULL;
    }
    if (NULL != exit->cadet_channel)
    {
      GNUNET_CADET_channel_destroy (exit->cadet_channel);
      exit->cadet_channel = NULL;
    }
    abort_all_requests (exit);
    GNUNET_free (exit);
  }
  if (NULL != cadet_handle)
  {
    GNUNET_CADET_disconnect (cadet_handle);
    cadet_handle = NULL;
  }
  if (NULL != dns_post_handle)
  {
    GNUNET_DNS_disconnect (dns_post_handle);
    dns_post_handle = NULL;
  }
  if (NULL != dns_pre_handle)
  {
    GNUNET_DNS_disconnect (dns_pre_handle);
    dns_pre_handle = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_YES);
    stats = NULL;
  }
  if (NULL != dht_get)
  {
    GNUNET_DHT_get_stop (dht_get);
    dht_get = NULL;
  }
  if (NULL != dht)
  {
    GNUNET_DHT_disconnect (dht);
    dht = NULL;
  }
}


/**
 * Function called whenever a channel is destroyed.  Should clean up
 * the associated state and attempt to build a new one.
 *
 * It must NOT call #GNUNET_CADET_channel_destroy on the channel.
 *
 * @param cls closure (the `struct CadetExit` set from #GNUNET_CADET_connect)
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 */
static void
cadet_channel_end_cb (void *cls,
		    const struct GNUNET_CADET_Channel *channel,
		    void *channel_ctx)
{
  struct CadetExit *exit = channel_ctx;
  struct CadetExit *alt;
  struct RequestContext *rc;

  if (NULL != exit->cadet_th)
  {
    GNUNET_CADET_notify_transmit_ready_cancel (exit->cadet_th);
    exit->cadet_th = NULL;
  }
  exit->cadet_channel = NULL;
  dns_exit_available--;
  /* open alternative channels */
  try_open_exit ();
  if (NULL == exit->cadet_channel)
  {
    /* our channel is now closed, move our requests to an alternative
       channel */
    alt = choose_exit ();
    while (NULL != (rc = exit->transmit_queue_head))
    {
      GNUNET_CONTAINER_DLL_remove (exit->transmit_queue_head,
				   exit->transmit_queue_tail,
				   rc);
      rc->exit = alt;
      GNUNET_CONTAINER_DLL_insert (alt->transmit_queue_head,
				   alt->transmit_queue_tail,
				   rc);
    }
    while (NULL != (rc = exit->receive_queue_head))
    {
      GNUNET_CONTAINER_DLL_remove (exit->receive_queue_head,
				   exit->receive_queue_tail,
				   rc);
      rc->was_transmitted = GNUNET_NO;
      rc->exit = alt;
      GNUNET_CONTAINER_DLL_insert (alt->transmit_queue_head,
				   alt->transmit_queue_tail,
				   rc);
    }
  }
  else
  {
    /* the same peer was chosen, just make sure the queue processing is restarted */
    alt = exit;
  }
  if ( (NULL == alt->cadet_th) &&
       (NULL != (rc = alt->transmit_queue_head)) )
    alt->cadet_th = GNUNET_CADET_notify_transmit_ready (alt->cadet_channel,
						      GNUNET_NO,
						      TIMEOUT,
						      rc->mlen,
						      &transmit_dns_request_to_cadet,
						      alt);
}


/**
 * Function called whenever we find an advertisement for a
 * DNS exit in the DHT.  If we don't have a cadet channel,
 * we should build one; otherwise, we should save the
 * advertisement for later use.
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path peers on reply path (or NULL if not recorded)
 *                 [0] = datastore's first neighbor, [length - 1] = local peer
 * @param get_path_length number of entries in @a get_path
 * @param put_path peers on the PUT path (or NULL if not recorded)
 *                 [0] = origin, [length - 1] = datastore
 * @param put_path_length number of entries in @a put_path
 * @param type type of the result
 * @param size number of bytes in @a data
 * @param data pointer to the result data
 */
static void
handle_dht_result (void *cls,
		   struct GNUNET_TIME_Absolute exp,
		   const struct GNUNET_HashCode *key,
		   const struct GNUNET_PeerIdentity *get_path,
		   unsigned int get_path_length,
		   const struct GNUNET_PeerIdentity *put_path,
		   unsigned int put_path_length,
		   enum GNUNET_BLOCK_Type type,
		   size_t size, const void *data)
{
  const struct GNUNET_DNS_Advertisement *ad;
  struct CadetExit *exit;

  if (sizeof (struct GNUNET_DNS_Advertisement) != size)
  {
    GNUNET_break (0);
    return;
  }
  ad = data;
  for (exit = exit_head; NULL != exit; exit = exit->next)
    if (0 == memcmp (&ad->peer,
		     &exit->peer,
		     sizeof (struct GNUNET_PeerIdentity)))
      break;
  if (NULL == exit)
  {
    exit = GNUNET_new (struct CadetExit);
    exit->peer = ad->peer;
    /* channel is closed, so insert at the end */
    GNUNET_CONTAINER_DLL_insert_tail (exit_head,
				      exit_tail,
				      exit);
  }
  exit->expiration = GNUNET_TIME_absolute_max (exit->expiration,
					       GNUNET_TIME_absolute_ntoh (ad->expiration_time));
  if (dns_exit_available < MAX_OPEN_TUNNELS)
    try_open_exit ();
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
  struct GNUNET_HashCode dns_key;

  cfg = cfg_;
  stats = GNUNET_STATISTICS_create ("pt", cfg);
  ipv4_pt = GNUNET_CONFIGURATION_get_value_yesno (cfg, "pt", "TUNNEL_IPV4");
  ipv6_pt = GNUNET_CONFIGURATION_get_value_yesno (cfg, "pt", "TUNNEL_IPV6");
  dns_channel = GNUNET_CONFIGURATION_get_value_yesno (cfg, "pt", "TUNNEL_DNS");
  if (! (ipv4_pt || ipv6_pt || dns_channel))
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
  if (dns_channel)
  {
    static struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
      {&receive_dns_response, GNUNET_MESSAGE_TYPE_VPN_DNS_FROM_INTERNET, 0},
      {NULL, 0, 0}
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
    cadet_handle = GNUNET_CADET_connect (cfg, NULL, NULL,
				       &cadet_channel_end_cb,
				       cadet_handlers, NULL);
    if (NULL == cadet_handle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to %s service.  Exiting.\n"),
		  "CADET");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    dht = GNUNET_DHT_connect (cfg, 1);
    if (NULL == dht)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to %s service.  Exiting.\n"),
		  "DHT");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    GNUNET_CRYPTO_hash ("dns", strlen ("dns"), &dns_key);
    dht_get = GNUNET_DHT_get_start (dht,
				    GNUNET_BLOCK_TYPE_DNS,
				    &dns_key,
				    1,
				    GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
				    NULL, 0,
				    &handle_dht_result, NULL);
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
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  ret = (GNUNET_OK ==
	 GNUNET_PROGRAM_run (argc, argv, "gnunet-daemon-pt",
			     gettext_noop
			     ("Daemon to run to perform IP protocol translation to GNUnet"),
			     options, &run, NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}


/* end of gnunet-daemon-pt.c */
