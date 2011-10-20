/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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

#include "gnunet_bandwidth_lib.h"

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
 * After how long do we consider a connection to a peer dead
 * if we got an explicit disconnect and were unable to reconnect?
 */
#define GNUNET_CONSTANTS_DISCONNECT_SESSION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)

/**
 * How long do we delay reading more from a peer after a quota violation?
 */
#define GNUNET_CONSTANTS_QUOTA_VIOLATION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2)

/**
 * How long do we wait after a FORK+EXEC before testing for the
 * resulting process to be up (port open, waitpid, etc.)?
 */
#define GNUNET_CONSTANTS_EXEC_WAIT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 200)

/**
 * After how long do we retry a service connection that was
 * unavailable?  Used in cases where an exponential back-off
 * seems inappropriate.
 */
#define GNUNET_CONSTANTS_SERVICE_RETRY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 500)

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
 * Size of the 'struct EncryptedMessage' of the core (which
 * is the per-message overhead of the core).
 */
#define GNUNET_CONSTANTS_CORE_SIZE_ENCRYPTED_MESSAGE (24 + sizeof (GNUNET_HashCode))

/**
 * Size of the 'struct OutboundMessage' of the transport
 * (which, in combination with the
 * GNUNET_CONSTANTS_CORE_SIZE_ENCRYPTED_MESSAGE) defines
 * the headers that must be pre-pendable to all GNUnet
 * messages.  Taking GNUNET_SERVER_MAX_MESSAGE_SIZE
 * and subtracting these two constants defines the largest
 * message core can handle.
 */
#define GNUNET_CONSTANTS_TRANSPORT_SIZE_OUTBOUND_MESSAGE (16 + sizeof (struct GNUNET_PeerIdentity))


/**
 * What is the maximum size for encrypted messages?  Note that this
 * number imposes a clear limit on the maximum size of any message.
 * Set to a value close to 64k but not so close that transports will
 * have trouble with their headers.
 *
 * Could theoretically be 64k minus (GNUNET_CONSTANTS_CORE_SIZE_ENCRYPTED_MESSAGE +
 * GNUNET_CONSTANTS_TRANSPORT_SIZE_OUTBOUND_MESSAGE), but we're going
 * to be more conservative for now.
 */
#define GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE (63 * 1024)


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
