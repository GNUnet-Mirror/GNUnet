/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_neighbours.h
 * @brief neighbour management API
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

void
GST_manipulation_set_metric (void *cls, struct GNUNET_SERVER_Client *client,
    const struct GNUNET_MessageHeader *message);

void
GST_manipulation_send (const struct GNUNET_PeerIdentity *target, const void *msg,
    size_t msg_size, struct GNUNET_TIME_Relative timeout,
    GST_NeighbourSendContinuation cont, void *cont_cls);

struct GNUNET_TIME_Relative
GST_manipulation_recv (void *cls, const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_MessageHeader *message,
    const struct GNUNET_ATS_Information *ats,
    uint32_t ats_count, struct Session *session,
    const char *sender_address,
    uint16_t sender_address_len);

void
GST_manipulation_init ();

void
GST_manipulation_stop ();

#endif
/* end of file gnunet-service-transport_neighbours.h */
