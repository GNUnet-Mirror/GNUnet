/*
     This file is part of GNUnet.
     Copyright (C) 2009-2019 GNUnet e.V.

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
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_nt_lib.h"

/**
 * Version number of the transport communication API.
 */
#define GNUNET_TRANSPORT_COMMUNICATION_VERSION 0x00000000

/**
 * Queue length
 */
#define GNUNET_TRANSPORT_QUEUE_LENGTH_UNLIMITED UINT64_MAX

/**
 * Function called by the transport service to initialize a
 * message queue given address information about another peer.
 * If and when the communication channel is established, the
 * communicator must call #GNUNET_TRANSPORT_communicator_mq_add()
 * to notify the service that the channel is now up.  It is
 * the responsibility of the communicator to manage sane
 * retries and timeouts for any @a peer/@a address combination
 * provided by the transport service.  Timeouts and retries
 * do not need to be signalled to the transport service.
 *
 * @param cls closure
 * @param peer identity of the other peer
 * @param address where to send the message, human-readable
 *        communicator-specific format, 0-terminated, UTF-8
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the provided address is
 * invalid
 */
typedef int (*GNUNET_TRANSPORT_CommunicatorMqInit) (
  void *cls,
  const struct GNUNET_PeerIdentity *peer,
  const char *address);


/**
 * Opaque handle to the transport service for communicators.
 */
struct GNUNET_TRANSPORT_CommunicatorHandle;


/**
 * What characteristics does this communicator have?
 *
 * FIXME: may want to distinguish bi-directional as well,
 * should we define a bit for that? Needed in DV logic (handle_dv_learn)!
 */
enum GNUNET_TRANSPORT_CommunicatorCharacteristics
{
  /**
   * Characteristics are unknown (i.e. DV).
   */
  GNUNET_TRANSPORT_CC_UNKNOWN = 0,

  /**
   * Transmission is reliabile (with ACKs), i.e. TCP/HTTP/HTTPS.
   */
  GNUNET_TRANSPORT_CC_RELIABLE = 1,

  /**
   * Transmission is unreliable (i.e. UDP)
   */
  GNUNET_TRANSPORT_CC_UNRELIABLE = 2
};


/**
 * Function called when the transport service has received a
 * backchannel message for this communicator (!) via a different
 * return path.
 *
 * Typically used to receive messages of type
 * #GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_FC_LIMITS or
 * #GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_KX_CONFIRMATION
 * as well as communicator-specific messages to assist with
 * NAT traversal.
 *
 * @param cls closure
 * @param sender which peer sent the notification
 * @param msg payload
 */
typedef void (*GNUNET_TRANSPORT_CommunicatorNotify) (
  void *cls,
  const struct GNUNET_PeerIdentity *sender,
  const struct GNUNET_MessageHeader *msg);


/**
 * Connect to the transport service.
 *
 * @param cfg configuration to use
 * @param config_section section of the configuration to use for options
 * @param addr_prefix address prefix for addresses supported by this
 *        communicator, could be NULL for incoming-only communicators
 * @param cc what characteristics does the communicator have?
 * @param mq_init function to call to initialize a message queue given
 *                the address of another peer, can be NULL if the
 *                communicator only supports receiving messages
 * @param mq_init_cls closure for @a mq_init
 * @param notify_cb function to pass backchannel messages to communicator
 * @param notify_cb_cls closure for @a notify_cb
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_CommunicatorHandle *
GNUNET_TRANSPORT_communicator_connect (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *config_section_name,
  const char *addr_prefix,
  enum GNUNET_TRANSPORT_CommunicatorCharacteristics cc,
  GNUNET_TRANSPORT_CommunicatorMqInit mq_init,
  void *mq_init_cls,
  GNUNET_TRANSPORT_CommunicatorNotify notify_cb,
  void *notify_cb_cls);


/**
 * Disconnect from the transport service.
 *
 * @param ch handle returned from connect
 */
void
GNUNET_TRANSPORT_communicator_disconnect (
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch);


/* ************************* Receiving *************************** */

/**
 * Function called to notify communicator that we have received
 * and processed the message.  Used for flow control (if supported
 * by the communicator).
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
 * @param expected_addr_validity how long does the communicator believe it
 *        will continue to be able to receive messages from the same address
 *        on which it received this message?
 * @param cb function to call once handling the message is done, NULL if
 *         flow control is not supported by this communicator
 * @param cb_cls closure for @a cb
 * @return #GNUNET_OK if all is well, #GNUNET_NO if the message was
 *         immediately dropped due to memory limitations (communicator
 *         should try to apply back pressure),
 *         #GNUNET_SYSERR if the message could not be delivered because
 *         the tranport service is not yet up
 */
int
GNUNET_TRANSPORT_communicator_receive (
  struct GNUNET_TRANSPORT_CommunicatorHandle *handle,
  const struct GNUNET_PeerIdentity *sender,
  const struct GNUNET_MessageHeader *msg,
  struct GNUNET_TIME_Relative expected_addr_validity,
  GNUNET_TRANSPORT_MessageCompletedCallback cb,
  void *cb_cls);


/* ************************* Discovery *************************** */

/**
 * Handle returned to identify the internal data structure the transport
 * API has created to manage a message queue to a particular peer.
 */
struct GNUNET_TRANSPORT_QueueHandle;


/**
 * Possible states of a connection.
 */
enum GNUNET_TRANSPORT_ConnectionStatus
{
  /**
   * Connection is down.
   */
  GNUNET_TRANSPORT_CS_DOWN = -1,

  /**
   * this is an outbound connection (transport initiated)
   */
  GNUNET_TRANSPORT_CS_OUTBOUND = 0,

  /**
   * this is an inbound connection (communicator initiated)
   */
  GNUNET_TRANSPORT_CS_INBOUND = 1
};


/**
 * Notify transport service that a MQ became available due to an
 * "inbound" connection or because the communicator discovered the
 * presence of another peer.
 *
 * @param ch connection to transport service
 * @param peer peer with which we can now communicate
 * @param address address in human-readable format, 0-terminated, UTF-8
 * @param mtu maximum message size supported by queue, 0 if
 *            sending is not supported, SIZE_MAX for no MTU
 * @param q_len number of messages that can be send through this queue
 * @param priority queue priority. Queues with highest priority should be
 *                 used
 * @param nt which network type does the @a address belong to?
 * @param cs what is the connection status of the queue?
 * @param mq message queue of the @a peer
 * @return API handle identifying the new MQ
 */
struct GNUNET_TRANSPORT_QueueHandle *
GNUNET_TRANSPORT_communicator_mq_add (
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch,
  const struct GNUNET_PeerIdentity *peer,
  const char *address,
  uint32_t mtu,
  uint64_t q_len,
  uint32_t priority,
  enum GNUNET_NetworkType nt,
  enum GNUNET_TRANSPORT_ConnectionStatus cs,
  struct GNUNET_MQ_Handle *mq);

/**
 * Notify transport service that an MQ was updated
 *
 * @param ch connection to transport service
 * @param qh the queue to update
 * @param q_len number of messages that can be send through this queue
 * @param priority queue priority. Queues with highest priority should be
 *                 used
 */
void
GNUNET_TRANSPORT_communicator_mq_update (
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch,
  const struct GNUNET_TRANSPORT_QueueHandle *u_qh,
  uint64_t q_len,
  uint32_t priority);

/**
 * Notify transport service that an MQ became unavailable due to a
 * disconnect or timeout.
 *
 * @param qh handle for the queue that must be invalidated
 */
void
GNUNET_TRANSPORT_communicator_mq_del (struct GNUNET_TRANSPORT_QueueHandle *qh);


/**
 * Internal representation of an address a communicator is
 * currently providing for the transport service.
 */
struct GNUNET_TRANSPORT_AddressIdentifier;


/**
 * Notify transport service about an address that this communicator
 * provides for this peer.
 *
 * @param ch connection to transport service
 * @param address our address in human-readable format, 0-terminated, UTF-8
 * @param nt which network type does the address belong to?
 * @param expiration when does the communicator forsee this address expiring?
 */
struct GNUNET_TRANSPORT_AddressIdentifier *
GNUNET_TRANSPORT_communicator_address_add (
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch,
  const char *address,
  enum GNUNET_NetworkType nt,
  struct GNUNET_TIME_Relative expiration);


/**
 * Notify transport service about an address that this communicator
 * no longer provides for this peer.
 *
 * @param ai address that is no longer provided
 */
void
GNUNET_TRANSPORT_communicator_address_remove (
  struct GNUNET_TRANSPORT_AddressIdentifier *ai);


/**
 * The communicator asks the transport service to route a message via
 * a different path to another communicator service at another peer.
 * This must only be done for special control traffic (as there is no
 * flow control for this API), such as acknowledgements, and generally
 * only be done if the communicator is uni-directional (i.e. cannot
 * send the message back itself).
 *
 * While backchannel messages are signed and encrypted, communicators
 * must protect against replay attacks when using this backchannel
 * communication!
 *
 * @param ch handle of this communicator
 * @param pid peer to send the message to
 * @param comm name of the communicator to send the message to
 * @param header header of the message to transmit and pass via the
 *        notify-API to @a pid's communicator @a comm
 */
void
GNUNET_TRANSPORT_communicator_notify (
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch,
  const struct GNUNET_PeerIdentity *pid,
  const char *comm,
  const struct GNUNET_MessageHeader *header);


#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TRANSPORT_COMMUNICATOR_SERVICE_H */
#endif

/** @} */ /* end of group */

/* end of gnunet_transport_communicator_service.h */
