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


struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle
{
  /**
   * @brief Handle to the configuration
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * @brief File name of configuration file
   */
  char *cfg_filename;

  /**
   * @brief Handle to the transport service
   */
  struct GNUNET_SERVICE_Handle *tsh;

  /**
   * @brief Task that will be run on shutdown to stop and clean transport
   * service
   */
  struct GNUNET_SCHEDULER_Task *ts_shutdown_task;

  /**
   * @brief Handle to the client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * @brief Process of the communicator
   */
  struct GNUNET_OS_Process *c_proc;

  /**
   * @brief Task that will be run on shutdown to stop and clean communicator
   */
  struct GNUNET_SCHEDULER_Task *c_shutdown_task;

  /* Callbacks + Closures */
  /**
   * @brief Callback called when a new communicator connects
   */
  GNUNET_TRANSPORT_TESTING_CommunicatorAvailableCallback communicator_available;

  /**
   * @brief Closure to the callback
   */
  void *communicator_available_cls;
};


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
  uint16_t size;

  size = ntohs (msg->header.size) - sizeof (*msg);
  if (0 == size)
    return GNUNET_OK; /* receive-only communicator */
  GNUNET_MQ_check_zero_termination (msg);
  return GNUNET_OK;
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
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h = cls;
  uint16_t size;

  size = ntohs (msg->header.size) - sizeof (*msg);
  if (0 == size)
    return; /* receive-only communicator */
  if (NULL != tc_h->communicator_available)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "calling communicator_available()\n");
    tc_h->communicator_available (tc_h->communicator_available_cls, msg);
  }
  GNUNET_SERVICE_client_continue (tc_h->client);
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
 * @brief Callback called when new Client (Communicator) connects
 *
 * @param cls Closure - TransporCommmunicator Handle
 * @param client Client
 * @param mq Messagequeue
 *
 * @return TransportCommunicator Handle
 */
static void *
connect_cb (void *cls,
            struct GNUNET_SERVICE_Client *client,
            struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Client connected.\n");
  tc_h->client = client;
  return tc_h;
}


/**
 * @brief Callback called when Client disconnects
 *
 * @param cls Closure - TransportCommunicator Handle
 * @param client Client
 * @param internal_cls TransporCommmunicator Handle
 */
static void
disconnect_cb (void *cls,
               struct GNUNET_SERVICE_Client *client,
               void *internal_cls)
{
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Client disconnected.\n");
  tc_h->client = NULL;
}


/**
 * @brief Start the communicator part of the transport service
 *
 * @param communicator_available Callback to be called when a new communicator
 * becomes available
 * @param cfg Configuration
 */
static void
transport_communicator_start (struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h)
{
  struct GNUNET_MQ_MessageHandler mh[] = {
    GNUNET_MQ_hd_var_size (communicator_available,
        GNUNET_MESSAGE_TYPE_TRANSPORT_NEW_COMMUNICATOR,
        struct GNUNET_TRANSPORT_CommunicatorAvailableMessage,
        &tc_h),
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
                            tc_h->cfg,
                            &connect_cb,
                            &disconnect_cb,
                            tc_h,
                            mh);
  if (NULL == h)
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed starting service!\n");
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Started service\n");
    /* TODO */ GNUNET_SCHEDULER_add_shutdown (&shutdown_service, h);
  }
}


/**
 * @brief Task run at shutdown to kill communicator and clean up
 *
 * @param cls Closure - Process of communicator
 */
static void
shutdown_communicator (void *cls)
{
  struct GNUNET_OS_Process *proc = cls;

  if (GNUNET_OK != GNUNET_OS_process_kill (proc,
                                           SIGTERM))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "Error shutting down communicator with SIGERM, trying SIGKILL\n");
    if (GNUNET_OK != GNUNET_OS_process_kill (proc,
                                             SIGKILL))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
          "Error shutting down communicator with SIGERM and SIGKILL\n");
    }
  }
  GNUNET_OS_process_destroy (proc);
}


/**
 * @brief Start the communicator
 *
 * @param cfgname Name of the communicator
 */
static void
communicator_start (struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h)
{
  char *binary;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "communicator_start\n");
  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-communicator-unix");
  tc_h->c_proc =
    GNUNET_OS_start_process (GNUNET_YES,
                             GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                             NULL, NULL, NULL,
                             binary,
                             "./gnunet-communicator-unix",
                             "-c",
                             tc_h->cfg_filename,
                             NULL);
  if (NULL == tc_h->c_proc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to start communicator!");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "started communicator\n");
  GNUNET_free (binary);
  /* TODO */ GNUNET_SCHEDULER_add_shutdown (&shutdown_communicator,
                                            tc_h->c_proc);
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
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h;

  tc_h = GNUNET_new (struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle);
  tc_h->cfg_filename = GNUNET_strdup (cfg_filename);
  tc_h->cfg = GNUNET_CONFIGURATION_create ();
  if ( (GNUNET_SYSERR ==
        GNUNET_CONFIGURATION_load (tc_h->cfg,
                                   cfg_filename)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Malformed configuration file `%s', exit ...\n"),
                  cfg_filename);
    return NULL;
  }
  tc_h->communicator_available = communicator_available;
  tc_h->communicator_available_cls = cb_cls;

  /* Start communicator part of service */
  transport_communicator_start (tc_h);

  /* Schedule start communicator */
  communicator_start (tc_h);
  return tc_h;
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

