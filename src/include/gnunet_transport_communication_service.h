/*
     This file is part of GNUnet.
     Copyright (C) 2009-2016 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * API of the transport service towards the communicator processes.
 *
 * @defgroup transport TRANSPORT service
 * Low-level communication with other peers
 *
 * @see [Documentation](https://gnunet.org/transport-service)
 *
 * @{
 */

#ifndef GNUNET_TRANSPORT_COMMUNICATION_SERVICE_H
#define GNUNET_TRANSPORT_COMMUNICATION_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"

/**
 * Version number of the transport communication API.
 */
#define GNUNET_TRANSPORT_COMMUNICATION_VERSION 0x00000000


/**
 * Function called by the transport service to initialize a
 * message queue given address information about another peer.
 *
 * @param cls closure
 * @param peer identity of the other peer
 * @param address where to send the message, human-readable
 *        communicator-specific format, 0-terminated, UTF-8
 * @return NULL if the provided address is invalid, otherwise an MQ to
 *         send messages to that peer
 */
typedef struct GNUNET_MQ_Handle *
(*GNUNET_TRANSPORT_CommunicatorMqInit) (void *cls,
                                        const struct GNUNET_PeerIdentity *peer,
                                        const void *address);


/**
 * Opaque handle to the transport service for communicators.
 */
struct GNUNET_TRANSPORT_CommunicatorHandle;


/**
 * Connect to the transport service.
 *
 * @param cfg configuration to use
 * @param name name of the communicator that is connecting
 * @param mtu maximum message size supported by communicator, 0 if
 *            sending is not supported
 * @param mq_init function to call to initialize a message queue given
 *                the address of another peer, can be NULL if the
 *                communicator only supports receiving messages
 * @param mq_init_cls closure for @a mq_init
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_CommunicatorHandle *
GNUNET_TRANSPORT_communicator_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *name,
                                       size_t mtu,
                                       GNUNET_TRANSPORT_CommunicatorMqInit mq_init,
                                       void *mq_init_cls);


/**
 * Disconnect from the transport service.
 *
 * @param ch handle returned from connect
 */
void
GNUNET_TRANSPORT_communicator_disconnect (struct GNUNET_TRANSPORT_CommunicatorHandle *ch);


/* ************************* Receiving *************************** */

/**
 * Function called to notify communicator that we have received
 * and processed the message.
 *
 * @param cls closure
 * @param success #GNUNET_SYSERR on failure (try to disconnect/reset connection)
 *                #GNUNET_OK on success
 */
typedef void
(*GNUNET_TRANSPORT_MessageCompletedCallback) (void *cls,
                                              int success);


/**
 * Notify transport service that the communicator has received
 * a message.
 *
 * @param handle connection to transport service
 * @param sender presumed sender of the message (details to be checked
 *        by higher layers)
 * @param msg the message
 * @param cb function to call once handling the message is done, NULL if
 *         flow control is not supported by this communicator
 * @param cb_cls closure for @a cb
 * @return #GNUNET_OK if all is well, #GNUNET_NO if the message was
 *         immediately dropped due to memory limitations (communicator
 *         should try to apply back pressure),
 *         #GNUNET_SYSERR if the message is ill formed and communicator
 *         should try to reset stream
 */
int
GNUNET_TRANSPORT_communicator_receive (struct GNUNET_TRANSPORT_CommunicatorHandle *handle,
                                       const struct GNUNET_PeerIdentity *sender,
                                       const struct GNUNET_MessageHeader *msg,
                                       GNUNET_TRANSPORT_MessageCompletedCallback cb,
                                       void *cb_cls);


/* ************************* Discovery *************************** */


/**
 * Notify transport service that an MQ became available due to an
 * "inbound" connection or because the communicator discovered the
 * presence of another peer.
 *
 * @param handle connection to transport service
 * @param peer peer with which we can now communicate
 * @param address address in human-readable format, 0-terminated, UTF-8
 * @param nt which network type does the @a address belong to?
 * @param mq message queue of the @a peer
 */
void
GNUNET_TRANSPORT_communicator_mq_add (struct GNUNET_TRANSPORT_CommunicatorHandle *handle,
                                      const struct GNUNET_PeerIdentity *peer,
                                      const char *address,
                                      enum GNUNET_ATS_Network_Type nt,
                                      struct GNUNET_MQ_Handle *mq);


/**
 * Notify transport service that an MQ became unavailable due to a
 * disconnect or timeout.
 *
 * @param handle connection to transport service
 * @param peer peer with which we can no longer communicate via the given mq
 * @param address address in human-readable format, 0-terminated, UTF-8
 * @param nt which network type does the @a address belong to?
 * @param mq message queue of the @a peer
 */
void
GNUNET_TRANSPORT_communicator_mq_remove (struct GNUNET_TRANSPORT_CommunicatorHandle *handle,
                                         const struct GNUNET_PeerIdentity *peer,
                                         const char *address,
                                         enum GNUNET_ATS_Network_Type nt,
                                         struct GNUNET_MQ_Handle *mq);


/**
 * Notify transport service about an address that this communicator
 * provides for this peer.
 *
 * @param handle connection to transport service
 * @param address our address in human-readable format, 0-terminated, UTF-8
 * @param nt which network type does the address belong to?
 * @param expiration when does the communicator forsee this address expiring?
 */
void
GNUNET_TRANSPORT_communicator_address_add (struct GNUNET_TRANSPORT_CommunicatorHandle *handle,
                                           const char *address,
                                           enum GNUNET_ATS_Network_Type nt,
                                           struct GNUNET_TIME_Absolute expiration);


/**
 * Notify transport service about an address that this communicator
 * no longer provides for this peer.
 *
 * @param handle connection to transport service
 * @param address our former address in human-readable format,
 *        0-terminated, in UTF-8
 */
void
GNUNET_TRANSPORT_communicator_address_remove (struct GNUNET_TRANSPORT_CommunicatorHandle *handle,
                                              const char *address);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TRANSPORT_COMMUNICATOR_SERVICE_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_transport_communicator_service.h */
