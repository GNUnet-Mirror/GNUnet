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

/**
 * @brief Function signature for callbacks that are called when new communicators become available
 *
 * @param Closure
 * @param msg Message
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_CommunicatorAvailableCallback)(void *cls,
						   const struct GNUNET_TRANSPORT_CommunicatorAvailableMessage *msg);


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
   GNUNET_TRANSPORT_TESTING_CommunicatorAvailableCallback communicator_available,
   //GNUNET_TRANSPORT_TESTING_Callback2 cb2,
   //GNUNET_TRANSPORT_TESTING_Callback3 cb3,
   //GNUNET_TRANSPORT_TESTING_Callback4 cb4,
   void *cb_cls);

//void
//GNUNET_TRANSPORT_TESTING_transport_communicator_open_queue
//  (struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tch,
//   const char *address);
//
//struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorTransmission *
//GNUNET_TRANSPORT_TESTING_transport_communicator_send
//  (struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *tcq,
//   const struct GNUNET_MessageHeader *hdr,
//   GNUNET_TRANSPORT_TESTING_SuccessStatus cb, void *cb_cls);

