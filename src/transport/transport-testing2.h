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
 * @brief functions related to testing-tng
 * @author Christian Grothoff
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_transport_service.h"
#include "transport.h"


struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle;

struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue;

struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorTransmission;

/**
 * @brief Function signature for callbacks that are called when new communicators become available
 *
 * @param Closure
 * @param msg Message
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_CommunicatorAvailableCallback)(void *cls,
      struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
      enum GNUNET_TRANSPORT_CommunicatorCharacteristics cc,
      char *address_prefix);


typedef void
(*GNUNET_TRANSPORT_TESTING_AddAddressCallback)(void *cls,
      struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
      const char *address,
      struct GNUNET_TIME_Relative expiration,
      uint32_t aid,
      enum GNUNET_NetworkType nt);


typedef void
(*GNUNET_TRANSPORT_TESTING_QueueCreateReplyCallback)(void *cls,
    struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
    int will_try);


typedef void
(*GNUNET_TRANSPORT_TESTING_AddQueueCallback)(void *cls,
    struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
    struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *tc_queue);


/**
 * @brief Start communicator part of transport service and communicator
 *
 * @param service_name Name of the service
 * @param cfg Configuration handle
 * @param communicator_available Callback that is called when a new
 * communicator becomes available
 * @param cb_cls Closure to @p communicator_available
 *
 * @return Handle to the communicator duo
 */
struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *
GNUNET_TRANSPORT_TESTING_transport_communicator_service_start
  (const char *service_name,
   const char *cfg_filename,
   GNUNET_TRANSPORT_TESTING_CommunicatorAvailableCallback communicator_available_cb,
   GNUNET_TRANSPORT_TESTING_AddAddressCallback add_address_cb,
   GNUNET_TRANSPORT_TESTING_QueueCreateReplyCallback queue_create_reply_cb,
   GNUNET_TRANSPORT_TESTING_AddQueueCallback add_queue_cb,
   void *cb_cls);

void
GNUNET_TRANSPORT_TESTING_transport_communicator_open_queue
  (struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
   const struct GNUNET_PeerIdentity *peer_id,
   const char *address);

struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorTransmission *
GNUNET_TRANSPORT_TESTING_transport_communicator_send
  (struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *tc_queue,
   const void *payload,
   size_t payload_size/*,
   GNUNET_TRANSPORT_TESTING_SuccessStatus cb,
   void *cb_cls*/);

