/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_performance.h
 * @brief ats service, interaction with 'performance' API
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_ATS_PERFORMANCE_H
#define GNUNET_SERVICE_ATS_PERFORMANCE_H

#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "ats.h"

/**
 * Register a new performance client.
 *
 * @param client handle of the new client
 * @param flag flag specifying the type of the client
 */
void
GAS_performance_add_client (struct GNUNET_SERVER_Client *client,
                            enum StartFlag flag);


/**
 * Unregister a client (which may have been a performance client,
 * but this is not assured).
 *
 * @param client handle of the (now dead) client
 */
void
GAS_performance_remove_client (struct GNUNET_SERVER_Client *client);


/**
 * Transmit the given performance information to all performance
 * clients.
 *
 * @param peer peer for which this is an address suggestion
 * @param plugin_name 0-termintated string specifying the transport plugin
 * @param plugin_addr binary address for the plugin to use
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param atsi performance data for the address
 * @param atsi_count number of performance records in 'ats'
 * @param bandwidth_out assigned outbound bandwidth
 * @param bandwidth_in assigned inbound bandwidth
 */
void
GAS_performance_notify_clients (const struct GNUNET_PeerIdentity *peer,
                                const char *plugin_name,
                                const void *plugin_addr, size_t plugin_addr_len,
                                const struct GNUNET_ATS_Information *atsi,
                                uint32_t atsi_count,
                                struct GNUNET_BANDWIDTH_Value32NBO
                                bandwidth_out,
                                struct GNUNET_BANDWIDTH_Value32NBO
                                bandwidth_in);


/**
 * Handle 'reservation request' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_reservation_request (void *cls, struct GNUNET_SERVER_Client *client,
                                const struct GNUNET_MessageHeader *message);


/**
 * Handle 'preference change' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_preference_change (void *cls, struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message);


/**
 * Initialize performance subsystem.
 *
 * @param server handle to our server
 */
void
GAS_performance_init (struct GNUNET_SERVER_Handle *server);


/**
 * Shutdown performance subsystem.
 */
void
GAS_performance_done (void);


/* FIXME: add API to broadcast performance updates! */

#endif
/* end of gnunet-service-ats_performance.h */
