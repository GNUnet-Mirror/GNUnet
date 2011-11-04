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

#include "gnunet-daemon-vpn-dns.h"
#include "gnunet-daemon-vpn.h"
#include "gnunet-daemon-vpn-helper.h"
#include "gnunet-service-dns-p.h"
#include "gnunet-vpn-packet.h"

struct query_packet_list *head;
struct query_packet_list *tail;
struct GNUNET_CLIENT_Connection *dns_connection;
unsigned char restart_hijack;
struct answer_packet_list *answer_proc_head;
struct answer_packet_list *answer_proc_tail;

struct GNUNET_CLIENT_TransmitHandle *dns_transmit_handle;

/**
 * Callback called by notify_transmit_ready; sends dns-queries or rehijack-messages
 * to the service-dns
 * {{{
 */
size_t
send_query (void *cls __attribute__ ((unused)), size_t size, void *buf)
{
  size_t len;

  dns_transmit_handle = NULL;

  /*
   * Send the rehijack-message
   */
  if (restart_hijack == 1)
  {
    restart_hijack = 0;
    /*
     * The message is just a header
     */
    GNUNET_assert (sizeof (struct GNUNET_MessageHeader) <= size);
    struct GNUNET_MessageHeader *hdr = buf;

    len = sizeof (struct GNUNET_MessageHeader);
    hdr->size = htons (len);
    hdr->type = htons (GNUNET_MESSAGE_TYPE_REHIJACK);
  }
  else if (head != NULL)
  {
    struct query_packet_list *query = head;

    len = ntohs (query->pkt.hdr.size);

    GNUNET_assert (len <= size);

    memcpy (buf, &query->pkt.hdr, len);

    GNUNET_CONTAINER_DLL_remove (head, tail, query);

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
  if (head != NULL)
  {
    dns_transmit_handle =
        GNUNET_CLIENT_notify_transmit_ready (dns_connection,
                                             ntohs (head->pkt.hdr.size),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             GNUNET_YES, &send_query, NULL);
  }
  else if (restart_hijack == 1)
  {
    dns_transmit_handle =
        GNUNET_CLIENT_notify_transmit_ready (dns_connection,
                                             sizeof (struct
                                                     GNUNET_MessageHeader),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             GNUNET_YES, &send_query, NULL);
  }

  return len;
}

/* }}} */


/**
 * Connect to the service-dns
 */
void
connect_to_service_dns (void *cls
                        __attribute__ ((unused)),
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  conn_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting to service-dns\n");
  GNUNET_assert (dns_connection == NULL);
  dns_connection = GNUNET_CLIENT_connect ("dns", cfg);
  /* This would most likely be a misconfiguration */
  GNUNET_assert (NULL != dns_connection);
  GNUNET_CLIENT_receive (dns_connection, &dns_answer_handler, NULL,
                         GNUNET_TIME_UNIT_FOREVER_REL);

  /* We might not yet be connected. Yay, mps. */
  if (NULL == dns_connection)
    return;

  /* If a packet is already in the list, schedule to send it */
  if (dns_transmit_handle == NULL && head != NULL)
    dns_transmit_handle =
        GNUNET_CLIENT_notify_transmit_ready (dns_connection,
                                             ntohs (head->pkt.hdr.size),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             GNUNET_YES, &send_query, NULL);
  else if (dns_transmit_handle == NULL && restart_hijack == 1)
  {
    dns_transmit_handle =
        GNUNET_CLIENT_notify_transmit_ready (dns_connection,
                                             sizeof (struct
                                                     GNUNET_MessageHeader),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             GNUNET_YES, &send_query, NULL);
  }
}

/**
 * This receives packets from the service-dns and schedules process_answer to
 * handle it
 */
void
dns_answer_handler (void *cls
                    __attribute__ ((unused)),
                    const struct GNUNET_MessageHeader *msg)
{
  /* the service disconnected, reconnect after short wait */
  if (msg == NULL)
  {
    if (dns_transmit_handle != NULL)
      GNUNET_CLIENT_notify_transmit_ready_cancel (dns_transmit_handle);
    dns_transmit_handle = NULL;
    GNUNET_CLIENT_disconnect (dns_connection, GNUNET_NO);
    dns_connection = NULL;
    conn_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                      &connect_to_service_dns, NULL);
    return;
  }

  /* the service did something strange, reconnect immediately */
  if (msg->type != htons (GNUNET_MESSAGE_TYPE_VPN_DNS_LOCAL_RESPONSE_DNS))
  {
    GNUNET_break (0);
    GNUNET_CLIENT_disconnect (dns_connection, GNUNET_NO);
    dns_connection = NULL;
    conn_task = GNUNET_SCHEDULER_add_now (&connect_to_service_dns, NULL);
    return;
  }
  void *pkt = GNUNET_malloc (ntohs (msg->size));

  memcpy (pkt, msg, ntohs (msg->size));

  GNUNET_SCHEDULER_add_now (process_answer, pkt);
  GNUNET_CLIENT_receive (dns_connection, &dns_answer_handler, NULL,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}
