/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file nat/gnunet-service-nat_helper.h
 * @brief runs the gnunet-helper-nat-server
 * @author Milan Bouchet-Valat
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"


/**
 * Information we keep per NAT helper process.
 */
struct HelperContext;


/**
 * Function called whenever we get a connection reversal
 * request from another peer.
 *
 * @param cls closure
 * @param ra IP address of the peer who wants us to connect to it
 */
typedef void
(*GN_ReversalCallback) (void *cls,
                        const struct sockaddr_in *ra);


/**
 * Start the gnunet-helper-nat-server and process incoming
 * requests.
 *
 * @param internal_address
 * @param cb function to call if we receive a request
 * @param cb_cls closure for @a cb
 * @param cfg handle to the GNUnet configuration
 * @return NULL on error
 */
struct HelperContext *
GN_start_gnunet_nat_server_ (const struct in_addr *internal_address,
                             GN_ReversalCallback cb,
                             void *cb_cls,
                             const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Start the gnunet-helper-nat-server and process incoming
 * requests.
 *
 * @param h helper context to stop
 */
void
GN_stop_gnunet_nat_server_ (struct HelperContext *h);


/**
 * We want to connect to a peer that is behind NAT.  Run the
 * gnunet-helper-nat-client to send dummy ICMP responses to cause
 * that peer to connect to us (connection reversal).
 *
 * @param internal_address out internal address to use
 * @param internal_port internal port to use
 * @param remote_v4 the address of the peer (IPv4-only)
 * @param cfg handle to the GNUnet configuration
 * @return #GNUNET_SYSERR on error,
 *         #GNUNET_OK otherwise
 */
int
GN_request_connection_reversal (const struct in_addr *internal_address,
                                uint16_t internal_port,
                                const struct in_addr *remote_v4,
                                const struct GNUNET_CONFIGURATION_Handle *cfg);


/* end of gnunet-service-nat_helper.h */
