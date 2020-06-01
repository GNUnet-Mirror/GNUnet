/*
     This file is part of GNUnet.
     Copyright (C) 2019 GNUnet e.V.

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
 * @file transport/transport-testing2.h
 * @brief functions and structures related to testing-tng
 * @author Christian Grothoff
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_transport_service.h"
#include "transport.h"


/**
 * @brief Handle to a transport communicator
 */
struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle;


/**
 * @brief Queue of a communicator and some context
 */
struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue;


/**
 * @brief Handle/Context to a single transmission
 */
struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorTransmission;

/**
 * @brief Function signature for callbacks that are called when new
 * backchannel message arrived
 *
 * @param cls Closure
 * @param msg Backchannel message
 * @param pid Target peer
 */
typedef struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *
(*GNUNET_TRANSPORT_TESTING_BackchannelCallback)(void *cls,
                                                struct GNUNET_MessageHeader *msg,
                                                struct GNUNET_PeerIdentity *pid);


/**
 * @brief Function signature for callbacks that are called when new
 * communicators become available
 *
 * @param cls Closure
 * @param tc_h Communicator handle
 * @param cc Characteristics of communicator
 * @param address_prefix Prefix of the address
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_CommunicatorAvailableCallback)(void *cls,
                                                          struct
                                                          GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle
                                                          *tc_h,
                                                          enum
                                                          GNUNET_TRANSPORT_CommunicatorCharacteristics
                                                          cc,
                                                          char *address_prefix);


/**
 * @brief Receive information about the address of a communicator.
 *
 * @param cls Closure
 * @param tc_h Communicator handle
 * @param address Address represented as string
 * @param expiration Expiration
 * @param aid Aid
 * @param nt Network Type
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_AddAddressCallback)(void *cls,
                                               struct
                                               GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle
                                               *tc_h,
                                               const char *address,
                                               struct GNUNET_TIME_Relative
                                               expiration,
                                               uint32_t aid,
                                               enum GNUNET_NetworkType nt);


/**
 * @brief Get informed about the success of a queue request.
 *
 * @param cls Closure
 * @param tc_h Communicator handle
 * @param will_try #GNUNET_YES if communicator will try to create queue
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_QueueCreateReplyCallback)(void *cls,
                                                     struct
                                                     GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle
                                                     *tc_h,
                                                     int will_try);


/**
 * @brief Handle opening of queue
 *
 * @param cls Closure
 * @param tc_h Communicator handle
 * @param tc_queue Handle to newly opened queue
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_AddQueueCallback)(void *cls,
                                             struct
                                             GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle
                                             *tc_h,
                                             struct
                                             GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue
                                             *tc_queue,
                                             size_t mtu);


/**
 * @brief Handle an incoming message
 *
 * @param cls Closure
 * @param tc_h Handle to the receiving communicator
 * @param msg Received message
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_IncomingMessageCallback)(void *cls,
                                                    struct
                                                    GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle
                                                    *tc_h,
                                                    const char*payload,
                                                    size_t payload_len);


/**
 * @brief Start communicator part of transport service and communicator
 *
 * @param service_name Name of the service
 * @param cfg Configuration handle
 * @param communicator_available Callback that is called when a new
 * communicator becomes available
 * @param add_address_cb Callback handling new addresses
 * @param queue_create_reply_cb Callback handling success of queue requests
 * @param add_queue_cb Callback handling freshly created queues
 * @param incoming_message_cb Callback handling incoming messages
 * @param cb_cls Closure to @p communicator_available
 *
 * @return Handle to the communicator duo
 */
struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *
GNUNET_TRANSPORT_TESTING_transport_communicator_service_start (
  const char *service_name,
  const char *binary_name,
  const char *cfg_filename,
  const struct GNUNET_PeerIdentity *peer_id,
  GNUNET_TRANSPORT_TESTING_CommunicatorAvailableCallback
  communicator_available_cb,
  GNUNET_TRANSPORT_TESTING_AddAddressCallback add_address_cb,
  GNUNET_TRANSPORT_TESTING_QueueCreateReplyCallback queue_create_reply_cb,
  GNUNET_TRANSPORT_TESTING_AddQueueCallback add_queue_cb,
  GNUNET_TRANSPORT_TESTING_IncomingMessageCallback incoming_message_cb,
  GNUNET_TRANSPORT_TESTING_BackchannelCallback bc_cb,
  void *cb_cls);


void
GNUNET_TRANSPORT_TESTING_transport_communicator_service_stop (
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h);


/**
 * @brief Instruct communicator to open a queue
 *
 * @param tc_h Handle to communicator which shall open queue
 * @param peer_id Towards which peer
 * @param address For which address
 */
void
GNUNET_TRANSPORT_TESTING_transport_communicator_open_queue (struct
                                                            GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle
                                                            *tc_h,
                                                            const struct
                                                            GNUNET_PeerIdentity
                                                            *peer_id,
                                                            const char *address);


/**
 * @brief Instruct communicator to send data
 *
 * @param tc_queue The queue to use for sending
 * @param cont function to call when done sending
 * @param cont_cls closure for @a cont
 * @param payload Data to send
 * @param payload_size Size of the @a payload
 */
void
GNUNET_TRANSPORT_TESTING_transport_communicator_send (struct
                                                      GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle
                                                      *tc_h,
                                                      GNUNET_SCHEDULER_TaskCallback
                                                      cont,
                                                      void *cont_cls,
                                                      const void *payload,
                                                      size_t payload_size);
