/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff

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
 * @file vpn/gnunet-daemon-vpn-dns.c
 * @brief
 * @author Philipp Toelke
 */
#include <platform.h>
#include <gnunet_common.h>
#include <gnunet_client_lib.h>
#include <gnunet_os_lib.h>
#include <gnunet_mesh_service.h>
#include <gnunet_protocols.h>
#include <gnunet_server_lib.h>
#include <gnunet_container_lib.h>
#include <block_dns.h>

#include "gnunet_dns_service.h"
#include "dns.h"

struct query_packet_list
{
  struct query_packet_list *next GNUNET_PACKED;
  struct query_packet_list *prev GNUNET_PACKED;
  struct query_packet pkt;
};



struct GNUNET_DNS_Handle
{
  struct query_packet_list *head;
  struct query_packet_list *tail;
  struct GNUNET_CLIENT_Connection *dns_connection;
  unsigned char restart_hijack;

  struct GNUNET_CLIENT_TransmitHandle *dns_transmit_handle;

  const struct GNUNET_CONFIGURATION_Handle *cfg;

  GNUNET_SCHEDULER_Task process_answer_cb;
  
  void *process_answer_cb_cls;
};


/**
 * Callback called by notify_transmit_ready; sends dns-queries or rehijack-messages
 * to the service-dns
 * {{{
 */
size_t
send_query (void *cls GNUNET_UNUSED, size_t size, void *buf)
{
  struct GNUNET_DNS_Handle *h = cls;

  size_t len;

  h->dns_transmit_handle = NULL;

  /*
   * Send the rehijack-message
   */
  if (h->restart_hijack == 1)
  {
    h->restart_hijack = 0;
    /*
     * The message is just a header
     */
    GNUNET_assert (sizeof (struct GNUNET_MessageHeader) <= size);
    struct GNUNET_MessageHeader *hdr = buf;

    len = sizeof (struct GNUNET_MessageHeader);
    hdr->size = htons (len);
    hdr->type = htons (GNUNET_MESSAGE_TYPE_REHIJACK);
  }
  else if (h->head != NULL)
  {
    struct query_packet_list *query = h->head;

    len = ntohs (query->pkt.hdr.size);

    GNUNET_assert (len <= size);

    memcpy (buf, &query->pkt.hdr, len);

    GNUNET_CONTAINER_DLL_remove (h->head, h->tail, query);

    GNUNET_free (query);
  }
  else
  {
    GNUNET_break (0);
    len = 0;
  }

  /*
   * Check whether more data is to be sent
   */
  if (h->head != NULL)
  {
    h->dns_transmit_handle =
      GNUNET_CLIENT_notify_transmit_ready (h->dns_connection,
					   ntohs (h->head->pkt.hdr.size),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             GNUNET_YES, &send_query, h);
  }
  else if (h->restart_hijack == 1)
  {
    h->dns_transmit_handle =
      GNUNET_CLIENT_notify_transmit_ready (h->dns_connection,
					   sizeof (struct
                                                     GNUNET_MessageHeader),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             GNUNET_YES, &send_query, h);
  }

  return len;
}

/* }}} */



/**
 * This receives packets from the service-dns and schedules process_answer to
 * handle it
 */
static void
dns_answer_handler (void *cls,
                    const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_DNS_Handle *h = cls;

  /* the service disconnected, reconnect after short wait */
  if (msg == NULL)
  {
    if (h->dns_transmit_handle != NULL)
      GNUNET_CLIENT_notify_transmit_ready_cancel (h->dns_transmit_handle);
    h->dns_transmit_handle = NULL;
    GNUNET_CLIENT_disconnect (h->dns_connection, GNUNET_NO);
    h->dns_connection = NULL;
#if 0
    h->conn_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                      &connect_to_service_dns, h);
#endif
    return;
  }

  /* the service did something strange, reconnect immediately */
  if (msg->type != htons (GNUNET_MESSAGE_TYPE_VPN_DNS_LOCAL_RESPONSE_DNS))
  {
    GNUNET_break (0);
    GNUNET_CLIENT_disconnect (h->dns_connection, GNUNET_NO);
    h->dns_connection = NULL;
#if 0
    conn_task = GNUNET_SCHEDULER_add_now (&connect_to_service_dns, NULL);
#endif
    return;
  }
  void *pkt = GNUNET_malloc (ntohs (msg->size));

  memcpy (pkt, msg, ntohs (msg->size));

  GNUNET_SCHEDULER_add_now (h->process_answer_cb, pkt);
  GNUNET_CLIENT_receive (h->dns_connection, &dns_answer_handler, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Connect to the service-dns
 */
struct GNUNET_DNS_Handle *
GNUNET_DNS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
		    GNUNET_SCHEDULER_Task cb,
		    void *cb_cls)
{
  struct GNUNET_DNS_Handle *h;

  h = GNUNET_malloc (sizeof (struct GNUNET_DNS_Handle));
  h->cfg = cfg;
  h->process_answer_cb = cb;
  h->process_answer_cb_cls = cb_cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting to service-dns\n");
  h->dns_connection = GNUNET_CLIENT_connect ("dns", h->cfg);
  /* This would most likely be a misconfiguration */
  GNUNET_assert (NULL != h->dns_connection);
  GNUNET_CLIENT_receive (h->dns_connection, 
			 &dns_answer_handler, NULL,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  /* If a packet is already in the list, schedule to send it */
  if (h->dns_transmit_handle == NULL && h->head != NULL)
    h->dns_transmit_handle =
        GNUNET_CLIENT_notify_transmit_ready (h->dns_connection,
                                             ntohs (h->head->pkt.hdr.size),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             GNUNET_YES, &send_query, h);
  else if (h->dns_transmit_handle == NULL && h->restart_hijack == 1)
  {
    h->dns_transmit_handle =
      GNUNET_CLIENT_notify_transmit_ready (h->dns_connection,
					   sizeof (struct
                                                     GNUNET_MessageHeader),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             GNUNET_YES, &send_query, NULL);
  }
  return h;
}


void
GNUNET_DNS_restart_hijack (struct GNUNET_DNS_Handle *h)
{
  h->restart_hijack = 1;
  if (NULL != h->dns_connection && h->dns_transmit_handle == NULL)
    h->dns_transmit_handle =
      GNUNET_CLIENT_notify_transmit_ready (h->dns_connection,
                                             sizeof (struct
                                                     GNUNET_MessageHeader),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             GNUNET_YES, &send_query, h);
}


/**
 * FIXME: we should not expost our internal structures like this.
 * Just a quick initial hack.
 */
static void
queue_request (struct GNUNET_DNS_Handle *h,
	       struct query_packet_list *q)
{
  GNUNET_CONTAINER_DLL_insert_tail (h->head, h->tail, q);
  if (h->dns_connection != NULL && h->dns_transmit_handle == NULL)
    h->dns_transmit_handle =
      GNUNET_CLIENT_notify_transmit_ready (h->dns_connection, ntohs(q->pkt.hdr.size),
					   GNUNET_TIME_UNIT_FOREVER_REL,
					   GNUNET_YES, &send_query,
					   h);
}



/**
 * Process a DNS request sent to an IPv4 resolver.  Pass it
 * to the DNS service for resolution.
 *
 * @param h DNS handle
 * @param dst_ip destination IPv4 address
 * @param src_ip source IPv4 address (usually local machine)
 * @param src_port source port (to be used for reply)
 * @param udp_packet_len length of the UDP payload in bytes
 * @param udp_packet UDP payload
 */
void
GNUNET_DNS_queue_request_v4 (struct GNUNET_DNS_Handle *h,
			     const struct in_addr *dst_ip,
			     const struct in_addr *src_ip,
			     uint16_t src_port,
			     size_t udp_packet_len,
			     const char *udp_packet)
{
  size_t len = sizeof (struct query_packet) + udp_packet_len - 1;
  struct query_packet_list *query =
    GNUNET_malloc (len + sizeof (struct answer_packet_list) -
		   sizeof (struct answer_packet));
  query->pkt.hdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_DNS_LOCAL_QUERY_DNS);
  query->pkt.hdr.size = htons (len);
  memcpy (query->pkt.orig_to, dst_ip, 4);
  memcpy (query->pkt.orig_from, src_ip, 4);
  query->pkt.addrlen = 4;
  query->pkt.src_port = htons (src_port);
  memcpy (query->pkt.data, udp_packet, udp_packet_len);  
  queue_request (h, query);
}


/**
 * Process a DNS request sent to an IPv6 resolver.  Pass it
 * to the DNS service for resolution.
 *
 * @param h DNS handle
 * @param dst_ip destination IPv6 address
 * @param src_ip source IPv6 address (usually local machine)
 * @param src_port source port (to be used for reply)
 * @param udp_packet_len length of the UDP payload in bytes
 * @param udp_packet UDP payload
 */
void
GNUNET_DNS_queue_request_v6 (struct GNUNET_DNS_Handle *h,
			     const struct in6_addr *dst_ip,
			     const struct in6_addr *src_ip,
			     uint16_t src_port,
			     size_t udp_packet_len,
			     const char *udp_packet)
{
  size_t len =
    sizeof (struct query_packet) + udp_packet_len - 1;
  struct query_packet_list *query =
    GNUNET_malloc (len + sizeof (struct answer_packet_list) -
		   sizeof (struct answer_packet));
  query->pkt.hdr.type =
    htons (GNUNET_MESSAGE_TYPE_VPN_DNS_LOCAL_QUERY_DNS);
  query->pkt.hdr.size = htons (len);
  memcpy (query->pkt.orig_to, dst_ip, 16);
  memcpy (query->pkt.orig_from, src_ip, 16);
  query->pkt.addrlen = 16;
  query->pkt.src_port = htons (src_port);
  memcpy (query->pkt.data, udp_packet,
	  udp_packet_len);
  queue_request (h, query);
}


void
GNUNET_DNS_disconnect (struct GNUNET_DNS_Handle *h)
{
  if (h->dns_connection != NULL)
  {
    GNUNET_CLIENT_disconnect (h->dns_connection, GNUNET_NO);
    h->dns_connection = NULL;
  }
  GNUNET_free (h);
}

/* end of dns_api.c */
