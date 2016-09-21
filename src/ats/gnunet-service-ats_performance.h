/*
     This file is part of GNUnet.
     Copyright (C) 2011-2015 GNUnet e.V.

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
 * Transmit the given performance information to all performance
 * clients.
 *
 * @param peer peer for which this is an address suggestion
 * @param plugin_name 0-termintated string specifying the transport plugin
 * @param plugin_addr binary address for the plugin to use
 * @param plugin_addr_len number of bytes in @a plugin_addr
 * @param active #GNUNET_YES if this address is actively used
 *        to maintain a connection to a peer;
 *        #GNUNET_NO if the address is not actively used;
 *        #GNUNET_SYSERR if this address is no longer available for ATS
 * @param prop performance data for the address
 * @param local_address_info information about the local flags for the address
 * @param bandwidth_out assigned outbound bandwidth
 * @param bandwidth_in assigned inbound bandwidth
 */
void
GAS_performance_notify_all_clients (const struct GNUNET_PeerIdentity *peer,
                                    const char *plugin_name,
                                    const void *plugin_addr,
                                    size_t plugin_addr_len,
                                    int active,
                                    const struct GNUNET_ATS_Properties *prop,
                                    enum GNUNET_HELLO_AddressInfo local_address_info,
                                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                                    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in);


/**
 * Register a new performance client.
 *
 * @param client handle of the new client
 * @param flag flag specifying the type of the client
 */
void
GAS_performance_add_client (struct GNUNET_SERVICE_Client *client,
                            enum StartFlag flag);


/**
 * Initialize performance subsystem.
 *
 * @param server handle to our server
 * @param addresses the address handle to use
 */
void
GAS_performance_init (void);


/**
 * Shutdown performance subsystem.
 */
void
GAS_performance_done (void);


#endif
/* end of gnunet-service-ats_performance.h */
