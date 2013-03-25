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

#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_util_lib.h"

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
 * Our public key.
 */
extern struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded GST_my_public_key;

/**
 * Our private key.
 */
extern struct GNUNET_CRYPTO_EccPrivateKey *GST_my_private_key;

/**
 * ATS handle.
 */
extern struct GNUNET_ATS_SchedulingHandle *GST_ats;

/**
 * Function called by the transport for each received message.
 * This function should also be called with "NULL" for the
 * message to signal that the other peer disconnected.
 *
 * @param cls closure, const char* with the name of the plugin we received the message from
 * @param peer (claimed) identity of the other peer
 * @param message the message, NULL if we only care about
 *                learning about the delay until we should receive again -- FIXME!
 * @param session identifier used for this session (NULL for plugins
 *                that do not offer bi-directional communication to the sender
 *                using the same "connection")
 * @param sender_address binary address of the sender (if we established the
 *                connection or are otherwise sure of it; should be NULL
 *                for inbound TCP/UDP connections since it it not clear
 *                that we could establish ourselves a connection to that
 *                IP address and get the same system)
 * @param sender_address_len number of bytes in sender_address
 * @return how long the plugin should wait until receiving more data
 *         (plugins that do not support this, can ignore the return value)
 */
struct GNUNET_TIME_Relative
GST_receive_callback (void *cls,
		      const struct GNUNET_PeerIdentity *peer,
		      const struct GNUNET_MessageHeader *message,
		      struct Session *session,
		      const char *sender_address,
		      uint16_t sender_address_len);


void
GST_update_ats_metrics (const struct GNUNET_PeerIdentity *peer,
			const struct GNUNET_HELLO_Address *address,
			struct Session *session,
			const struct GNUNET_ATS_Information *ats,
			uint32_t ats_count);

#endif
/* end of file gnunet-service-transport_plugins.h */
