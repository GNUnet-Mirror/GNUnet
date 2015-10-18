/*
     This file is part of GNUnet.
     Copyright (C) 2010-2015 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_neighbours.h
 * @brief neighbour manipulation API, allows manipulation of
 *        performance metrics (delay and towards ATS)
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_MANIPULATION_H
#define GNUNET_SERVICE_TRANSPORT_MANIPULATION_H

#include "platform.h"
#include "gnunet-service-transport_blacklist.h"
#include "gnunet-service-transport_clients.h"
#include "gnunet-service-transport_hello.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport_plugins.h"
#include "gnunet-service-transport_validation.h"
#include "gnunet-service-transport.h"
#include "transport.h"


/**
 * Set traffic metric to manipulate
 *
 * @param cls closure
 * @param client client sending message
 * @param message containing information
 */
void
GST_manipulation_set_metric (void *cls,
                             struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message);


/**
 * Adapter function between transport's send function and transport plugins
 *
 * @param target the peer the message to send to
 * @param msg the message received
 * @param msg_size message size
 * @param timeout timeout
 * @param cont the continuation to call after sending
 * @param cont_cls cls for continuation
 */
void
GST_manipulation_send (const struct GNUNET_PeerIdentity *target,
                       const void *msg,
                       size_t msg_size,
                       struct GNUNET_TIME_Relative timeout,
                       GST_NeighbourSendContinuation cont,
                       void *cont_cls);


/**
 * Adapter function between transport plugins and transport receive function
 * manipulation delays for next send.
 *
 * @param cls the closure for transport
 * @param address the address and the peer the message was received from
 * @param message the message received
 * @param session the session the message was received on
 * @return manipulated delay for next receive
 */
struct GNUNET_TIME_Relative
GST_manipulation_recv (void *cls,
                       const struct GNUNET_HELLO_Address *address,
                       struct GNUNET_ATS_Session *session,
                       const struct GNUNET_MessageHeader *message);


/**
 * Function that will be called to manipulate ATS information according to
 * current manipulation settings
 *
 * @param address binary address
 * @param session the session
 * @param prop[IN|OUT] metrics to modify
 */
void
GST_manipulation_manipulate_metrics (const struct GNUNET_HELLO_Address *address,
                                     struct GNUNET_ATS_Session *session,
                                     struct GNUNET_ATS_Properties *prop);


/**
 * Notify manipulation about disconnect so it can discard queued messages
 *
 * @param peer the disconnecting peer
 */
void
GST_manipulation_peer_disconnect (const struct GNUNET_PeerIdentity *peer);


/**
 * Initialize traffic manipulation
 */
void
GST_manipulation_init (void);


/**
 * Stop traffic manipulation
 */
void
GST_manipulation_stop (void);

#endif
/* end of file gnunet-service-transport_neighbours.h */
