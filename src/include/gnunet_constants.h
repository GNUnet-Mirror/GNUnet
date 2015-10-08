/*
     This file is part of GNUnet.
     Copyright (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_constants.h
 * @brief "global" constants for performance tuning
 * @author Christian Grothoff
 */

#ifndef GNUNET_CONSTANTS_H
#define GNUNET_CONSTANTS_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Last resort choice for configuration file name.
 */
#define GNUNET_DEFAULT_USER_CONFIG_FILE "~/.config/gnunet.conf"

/**
 * Bandwidth (in/out) to assume initially (before either peer has
 * communicated any particular preference).  Should be rather low; set
 * so that at least one maximum-size message can be send roughly once
 * per minute.
 */
#define GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT GNUNET_BANDWIDTH_value_init (1024)

/**
 * After how long do we consider a connection to a peer dead
 * if we don't receive messages from the peer?
 */
#define GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * How long do we delay reading more from a peer after a quota violation?
 */
#define GNUNET_CONSTANTS_QUOTA_VIOLATION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2)

/**
 * After how long do we consider a service unresponsive
 * even if we assume that the service commonly does not
 * respond instantly (DNS, Database, etc.).
 */
#define GNUNET_CONSTANTS_SERVICE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 10)

/**
 * How long do we delay messages to get larger packet sizes (CORKing)?
 */
#define GNUNET_CONSTANTS_MAX_CORK_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * After what amount of latency for a message do we print a warning?
 */
#define GNUNET_CONSTANTS_LATENCY_WARN GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * Until which load do we consider the peer overly idle
 * (which means that we would like to use more resources).<p>
 *
 * Note that we use 70 to leave some room for applications
 * to consume resources "idly" (i.e. up to 85%) and then
 * still have some room for "paid for" resource consumption.
 */
#define GNUNET_CONSTANTS_IDLE_LOAD_THRESHOLD 70

/**
 * For how long do we allow unused bandwidth
 * from the past to carry over into the future? (in seconds)
 */
#define GNUNET_CONSTANTS_MAX_BANDWIDTH_CARRY_S 5


/**
 * After how long do we expire an address in a HELLO that we just
 * validated?  This value is also used for our own addresses when we
 * create a HELLO.
 */
#define GNUNET_CONSTANTS_HELLO_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 12)


/**
 * How long do we cache records at most in the DHT?
 */
#define GNUNET_CONSTANTS_DHT_MAX_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 24)


/**
 * Size of the `struct EncryptedMessage` of the core (which
 * is the per-message overhead of the core).
 */
#define GNUNET_CONSTANTS_CORE_SIZE_ENCRYPTED_MESSAGE (24 + sizeof (struct GNUNET_HashCode))

/**
 * What is the maximum size for encrypted messages?  Note that this
 * number imposes a clear limit on the maximum size of any message.
 * Set to a value close to 64k but not so close that transports will
 * have trouble with their headers.
 *
 * Could theoretically be 64k minus (#GNUNET_CONSTANTS_CORE_SIZE_ENCRYPTED_MESSAGE +
 * #GNUNET_CONSTANTS_TRANSPORT_SIZE_OUTBOUND_MESSAGE), but we're going
 * to be more conservative for now.
 */
#define GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE (63 * 1024)

/**
 * Size of the CADET message overhead:
 * + sizeof (struct GNUNET_CADET_Encrypted)
 * + sizeof (struct GNUNET_CADET_Data)
 * + sizeof (struct GNUNET_CADET_ACK))
 *
 * Checked for correcteness in gnunet-service-cadet_tunnel.c: GCT_init().
 */
#define GNUNET_CONSTANTS_CADET_P2P_OVERHEAD 132

/**
 * Maximum message size that can be sent on CADET.
 */
#define GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE \
(GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE - GNUNET_CONSTANTS_CADET_P2P_OVERHEAD)

/**
 * Largest block that can be stored in the DHT.
 */
#define GNUNET_CONSTANTS_MAX_BLOCK_SIZE (62 * 1024)


/**
 * K-value that must be used for the bloom filters in 'GET'
 * queries.
 */
#define GNUNET_CONSTANTS_BLOOMFILTER_K 16




#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
