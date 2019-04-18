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
 * @file transport/transport-testing2.c
 * @brief functions related to testing-tng
 * @author Christian Grothoff
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_constants.h"
#include "transport-testing2.h"
#include "gnunet_ats_transport_service.h"
#include "gnunet_signatures.h"
#include "transport.h"


#define LOG(kind,...) GNUNET_log_from (kind, "transport-testing2", __VA_ARGS__)


/**
 * @brief Check whether incoming msg indicating available communicator is
 * correct
 *
 * @param cls Closure
 * @param msg Message struct
 *
 * @return GNUNET_YES in case message is correct
 */
static int
check_communicator_available (void *cls,
    const struct GNUNET_TRANSPORT_CommunicatorAvailableMessage *msg)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "check_communicator_available()\n");
  return GNUNET_YES;
}


/**
 * @brief Handle new communicator
 *
 * @param cls Closure
 * @param msg Message struct
 */
static void
handle_communicator_available (void *cls,
    const struct GNUNET_TRANSPORT_CommunicatorAvailableMessage *msg)
{
  GNUNET_TRANSPORT_TESTING_CommunicatorAvailableCallback communicator_available = cls;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "handle_communicator_available()\n");
  if (NULL != communicator_available)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "calling communicator_available()\n");
    communicator_available (NULL, msg);
  }
  //GNUNET_SERVICE_client_continue (client);
}


/**
 * @brief Shut down the service
 *
 * @param cls Closure - Handle to the service
 */
static void
shutdown_service (void *cls)
{
  struct GNUNET_SERVICE_Handle *h = cls;

  GNUNET_SERVICE_stop (h);
}


/**
 * @brief Start the communicator part of the transport service
 *
 * @param communicator_available Callback to be called when a new communicator
 * becomes available
 * @param cfg Configuration
 */
static void
transport_communicator_start (GNUNET_TRANSPORT_TESTING_CommunicatorAvailableCallback communicator_available,
                              struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_MQ_MessageHandler mh[] = {
    GNUNET_MQ_hd_var_size (communicator_available,
        GNUNET_MESSAGE_TYPE_TRANSPORT_NEW_COMMUNICATOR,
        struct GNUNET_TRANSPORT_CommunicatorAvailableMessage,
        &communicator_available),
    //GNUNET_MQ_hd_var_size (communicator_backchannel,
    //    GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL,
    //    struct GNUNET_TRANSPORT_CommunicatorBackchannel,
    //    NULL),
    //GNUNET_MQ_hd_var_size (add_address,
    //    GNUNET_MESSAGE_TYPE_TRANSPORT_ADD_ADDRESS,
    //    struct GNUNET_TRANSPORT_AddAddressMessage,
    //    NULL),
    //GNUNET_MQ_hd_fixed_size (del_address,
    //                         GNUNET_MESSAGE_TYPE_TRANSPORT_DEL_ADDRESS,
    //                         struct GNUNET_TRANSPORT_DelAddressMessage,
    //                         NULL),
    //GNUNET_MQ_hd_var_size (incoming_msg,
    //    GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG,
    //    struct GNUNET_TRANSPORT_IncomingMessage,
    //    NULL),
    //GNUNET_MQ_hd_fixed_size (queue_create_ok,
    //      GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_OK,
    //      struct GNUNET_TRANSPORT_CreateQueueResponse,
    //      NULL),
    //GNUNET_MQ_hd_fixed_size (queue_create_fail,
    //      GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_FAIL,
    //      struct GNUNET_TRANSPORT_CreateQueueResponse,
    //      NULL),
    //GNUNET_MQ_hd_var_size (add_queue_message,
    //    GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_SETUP,
    //    struct GNUNET_TRANSPORT_AddQueueMessage,
    //    NULL),
    //GNUNET_MQ_hd_fixed_size (del_queue_message,
    //                         GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_TEARDOWN,
    //                         struct GNUNET_TRANSPORT_DelQueueMessage,
    //                         NULL),
    //GNUNET_MQ_hd_fixed_size (send_message_ack,
    //                         GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG_ACK,
    //                         struct GNUNET_TRANSPORT_SendMessageToAck,
    //                         NULL),
  };
  struct GNUNET_SERVICE_Handle *h;

  h = GNUNET_SERVICE_start ("transport",
                            cfg,
                            NULL,
                            NULL,
                            NULL,
                            mh);
  if (NULL == h)
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed starting service!\n");
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Started service\n");
    GNUNET_SCHEDULER_add_shutdown (&shutdown_service, h);
  }
}


/**
 * @brief Start the communicator
 *
 * @param cfgname Name of the communicator
 */
static void
communicator_start (const char *cfgname)
{
  char *binary;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_OS_Process *proc;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "communicator_start\n");
  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-communicator-unix");
  cfg = GNUNET_CONFIGURATION_create ();
  proc =
    GNUNET_OS_start_process (GNUNET_YES,
                             GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                             NULL, NULL, NULL,
                             binary,
                             "./gnunet-communicator-unix",
                             "-c",
                             cfgname,
                             NULL);
  if (NULL == proc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to start communicator!");
    return;
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_load (cfg,
                                            cfgname));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "started communicator\n");
  GNUNET_free (binary);
}


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
   void *cb_cls)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;

  cfg = GNUNET_CONFIGURATION_create ();
  if ( (GNUNET_SYSERR ==
        GNUNET_CONFIGURATION_load (cfg,
                                   cfg_filename)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Malformed configuration file `%s', exit ...\n"),
                  cfg_filename);
    return NULL;
  }
  /* Start communicator part of service */
  transport_communicator_start (communicator_available, cfg);

  /* Schedule start communicator */
  communicator_start ("test_communicator_1.conf");
}

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

