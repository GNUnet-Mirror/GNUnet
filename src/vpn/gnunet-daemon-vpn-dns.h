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
 * @file vpn/gnunet-daemon-vpn-dns.h
 * @brief
 * @author Philipp Toelke
 */
#ifndef GNUNET_DAEMON_VPN_DNS_H
#define GNUNET_DAEMON_VPN_DNS_H

/**
 * a list of outgoing dns-query-packets
 */
extern struct query_packet_list *head;

/**
 * The last element of the list of outgoing dns-query-packets
 */
extern struct query_packet_list *tail;

/**
 * Callback called by notify_transmit_ready; sends dns-queries or rehijack-messages
 * to the service-dns
 */
size_t
send_query (void *cls, size_t size, void *buf);

/**
 * Connect to the service-dns
 */
void
connect_to_service_dns (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * This receives packets from the service-dns and schedules process_answer to
 * handle it
 */
void
dns_answer_handler (void *cls, const struct GNUNET_MessageHeader *msg);

/**
 * The connection to the service-dns
 */
extern struct GNUNET_CLIENT_Connection *dns_connection;

/**
 * A flag to show that the service-dns has to rehijack the outbound dns-packets
 *
 * This gets set when the helper restarts as the routing-tables are flushed when
 * the interface vanishes.
 */
extern unsigned char restart_hijack;

/**
 * A list of processed dns-responses.
 *
 * "processed" means that the packet is complete and can be sent out via udp
 * directly
 */
extern struct answer_packet_list *answer_proc_head;

/**
 * The last element of the list of processed dns-responses.
 */
extern struct answer_packet_list *answer_proc_tail;

extern GNUNET_SCHEDULER_TaskIdentifier conn_task;

#endif /* end of include guard: GNUNET-DAEMON-VPN-DNS_H */
