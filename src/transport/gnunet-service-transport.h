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
 * @file transport/gnunet-service-transport.h
 * @brief globals
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_H
#define GNUNET_SERVICE_TRANSPORT_H

#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_transport_service.h"

#define VERBOSE_VALIDATION GNUNET_YES

/**
 * Statistics handle.
 */
extern struct GNUNET_STATISTICS_Handle *GST_stats;

/**
 * Configuration handle.
 */
extern const struct GNUNET_CONFIGURATION_Handle *GST_cfg;

/**
 * Configuration handle.
 */
extern struct GNUNET_PeerIdentity GST_my_identity;

/**
 * Handle to peerinfo service.
 */
extern struct GNUNET_PEERINFO_Handle *GST_peerinfo;

/**
 * Our private key.
 */
extern struct GNUNET_CRYPTO_EddsaPrivateKey *GST_my_private_key;

/**
 * ATS handle.
 */
extern struct GNUNET_ATS_SchedulingHandle *GST_ats;


/**
 * Function to call when a peer's address has changed
 *
 * @param cls closure
 * @param peer peer this update is about,
 * @param address address, NULL for disconnect notification
 */
typedef void
(*GNUNET_TRANSPORT_NeighbourChangeCallback) (void *cls,
    const struct GNUNET_PeerIdentity *peer,
    const struct GNUNET_HELLO_Address *address,
    enum GNUNET_TRANSPORT_PeerState state,
    struct GNUNET_TIME_Absolute state_timeout,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
    struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out);


/**
 * Function called by the transport for each received message.
 *
 * @param cls closure, const char* with the name of the plugin we received the message from
 * @param address address and (claimed) identity of the other peer
 * @param session identifier used for this session (NULL for plugins
 *                that do not offer bi-directional communication to the sender
 *                using the same "connection")
 * @param message the message, NULL if we only care about
 *                learning about the delay until we should receive again
 * @return how long the plugin should wait until receiving more data
 *         (plugins that do not support this, can ignore the return value)
 */
struct GNUNET_TIME_Relative
GST_receive_callback (void *cls,
                      const struct GNUNET_HELLO_Address *address,
                      struct Session *session,
                      const struct GNUNET_MessageHeader *message);


#endif
/* end of file gnunet-service-transport_plugins.h */
