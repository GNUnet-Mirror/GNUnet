/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api.c
 * @brief API for accessing the GNUnet testing service.
 *        This library is supposed to make it easier to write
 *        testcases and script large-scale benchmarks.
 * @author Christian Grothoff
 * @author Sree Harsha Totakura
 */


#include "platform.h"
#include "gnunet_testbed_service.h"
#include "gnunet_core_service.h"
#include "gnunet_constants.h"
#include "gnunet_transport_service.h"
#include "gnunet_hello_lib.h"
#include <zlib.h>

#include "testbed.h"
#include "testbed_api.h"
#include "testbed_api_hosts.h"
#include "testbed_api_peers.h"

/**
 * Generic logging shorthand
 */
#define LOG(kind, ...)                          \
  GNUNET_log_from (kind, "testbed-api", __VA_ARGS__);

/**
 * Debug logging
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__);

/**
 * Relative time seconds shorthand
 */
#define TIME_REL_SECS(sec) \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, sec)


/**
 * Default server message sending retry timeout
 */
#define TIMEOUT_REL TIME_REL_SECS(1)


/**
 * The message queue for sending messages to the controller service
 */
struct MessageQueue
{
  /**
   * The message to be sent
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * next pointer for DLL
   */
  struct MessageQueue *next;
  
  /**
   * prev pointer for DLL
   */
  struct MessageQueue *prev;
};


/**
 * Structure for a controller link
 */
struct ControllerLink
{
  /**
   * The next ptr for DLL
   */
  struct ControllerLink *next;

  /**
   * The prev ptr for DLL
   */
  struct ControllerLink *prev;

  /**
   * The host which will be referred in the peer start request. This is the
   * host where the peer should be started
   */
  struct GNUNET_TESTBED_Host *delegated_host;

  /**
   * The host which will contacted to delegate the peer start request
   */
  struct GNUNET_TESTBED_Host *slave_host;

  /**
   * The configuration to be used to connect to slave host
   */
  const struct GNUNET_CONFIGURATION_Handle *slave_cfg;

  /**
   * GNUNET_YES if the slave should be started (and stopped) by us; GNUNET_NO
   * if we are just allowed to use the slave via TCP/IP
   */
  int is_subordinate;
};


/**
 * handle for host registration
 */
struct GNUNET_TESTBED_HostRegistrationHandle
{
  /**
   * The host being registered
   */
  struct GNUNET_TESTBED_Host *host;

  /**
   * The controller at which this host is being registered
   */
  struct GNUNET_TESTBED_Controller *c;

  /**
   * The Registartion completion callback
   */
  GNUNET_TESTBED_HostRegistrationCompletion cc;

  /**
   * The closure for above callback
   */
  void *cc_cls;
};


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_ADDHOSTCONFIRM message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 * @return GNUNET_YES if we can continue receiving from service; GNUNET_NO if
 *           not
 */
static int
handle_addhostconfirm (struct GNUNET_TESTBED_Controller *c,
                       const struct GNUNET_TESTBED_HostConfirmedMessage *msg)
{
  struct GNUNET_TESTBED_HostRegistrationHandle *rh;
  char *emsg;
  uint16_t msg_size;

  rh = c->rh;
  if (NULL == rh)
  {  
    return GNUNET_OK;    
  }
  if (GNUNET_TESTBED_host_get_id_ (rh->host) != ntohl (msg->host_id))
  {
    LOG_DEBUG ("Mismatch in host id's %u, %u of host confirm msg\n",
               GNUNET_TESTBED_host_get_id_ (rh->host), ntohl (msg->host_id));
    return GNUNET_OK;
  }
  c->rh = NULL;
  msg_size = ntohs (msg->header.size);
  if (sizeof (struct GNUNET_TESTBED_HostConfirmedMessage) == msg_size)
  {
    LOG_DEBUG ("Host %u successfully registered\n", ntohl (msg->host_id));
    GNUNET_TESTBED_mark_host_registered_at_  (rh->host, c);
    rh->cc (rh->cc_cls, NULL);
    GNUNET_free (rh);
    return GNUNET_OK;
  } 
  /* We have an error message */
  emsg = (char *) &msg[1];
  if ('\0' != emsg[msg_size - 
                   sizeof (struct GNUNET_TESTBED_HostConfirmedMessage)])
  {
    GNUNET_break (0);
    GNUNET_free (rh);
    return GNUNET_NO;
  }  
  LOG (GNUNET_ERROR_TYPE_ERROR, _("Adding host %u failed with error: %s\n"),
       ntohl (msg->host_id), emsg);
  rh->cc (rh->cc_cls, emsg);
  GNUNET_free (rh);
  return GNUNET_OK;
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_ADDHOSTCONFIRM message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 * @return GNUNET_YES if we can continue receiving from service; GNUNET_NO if
 *           not
 */
static int
handle_opsuccess (struct GNUNET_TESTBED_Controller *c,
                  const struct
                  GNUNET_TESTBED_GenericOperationSuccessEventMessage *msg)
{
  struct GNUNET_TESTBED_Operation *op;
  struct GNUNET_TESTBED_EventInformation *event;
  uint64_t op_id;
  
  op_id = GNUNET_ntohll (msg->operation_id);
  LOG_DEBUG ("Operation %ul successful\n", op_id);
  for (op = c->op_head; NULL != op; op = op->next)
  {
    if (op->operation_id == op_id)
      break;
  }
  if (NULL == op)
  {
    LOG_DEBUG ("Operation not found\n");
    return GNUNET_YES;
  }
  event = NULL;
  if (0 != (c->event_mask & (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED)))
    event = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_EventInformation));
  if (NULL != event)
    event->type = GNUNET_TESTBED_ET_OPERATION_FINISHED; 
  switch (op->type)
  {
  case OP_PEER_DESTROY:
    {
      struct PeerDestroyData *data;
      
      if (NULL != event)
      {
        event->details.operation_finished.operation = op;
        event->details.operation_finished.op_cls = NULL;
        event->details.operation_finished.emsg = NULL;
        event->details.operation_finished.pit = GNUNET_TESTBED_PIT_GENERIC;
        event->details.operation_finished.op_result.generic = NULL;
      }
      data = (struct PeerDestroyData *) op->data;
      if (NULL != data->peer->details)
      {
        if (NULL != data->peer->details->cfg)
          GNUNET_CONFIGURATION_destroy (data->peer->details->cfg);
        //PEER_DETAILS
      }
      GNUNET_free (data->peer);
      GNUNET_free (data);
      //PEERDESTROYDATA
    }
    break;
  default:
    GNUNET_break (0);
  }
  if (NULL != event)
  {
    if (NULL != c->cc)
      c->cc (c->cc_cls, event);
    GNUNET_free (event);
  }
  GNUNET_CONTAINER_DLL_remove (c->op_head, c->op_tail, op);
  GNUNET_free (op);
  return GNUNET_YES;  
}


/**
 * Handler for messages from controller (testbed service)
 *
 * @param cls the controller handler
 * @param msg message received, NULL on timeout or fatal error
 */
static void 
message_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TESTBED_Controller *c = cls;  
  int status;

  c->in_receive = GNUNET_NO;
  /* FIXME: Add checks for message integrity */
  if (NULL == msg)
  {
    LOG_DEBUG ("Receive timed out or connection to service dropped\n");
    return;
  }
  status = GNUNET_OK;
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_TESTBED_ADDHOSTCONFIRM:
    status =
      handle_addhostconfirm (c, (const struct
                                 GNUNET_TESTBED_HostConfirmedMessage *) msg);
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_GENERICOPSUCCESS:
    status =
      handle_opsuccess (c, (const struct
                            GNUNET_TESTBED_GenericOperationSuccessEventMessage
                            *) msg);
    break;
  default:
    GNUNET_break (0);
  }
  if ((GNUNET_OK == status) && (GNUNET_NO == c->in_receive))
  {
    c->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (c->client, &message_handler, c,
                           GNUNET_TIME_UNIT_FOREVER_REL);    
  }
}


/**
 * Function called to notify a client about the connection begin ready to queue
 * more data.  "buf" will be NULL and "size" zero if the connection was closed
 * for writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_ready_notify (void *cls, size_t size, void *buf)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  struct MessageQueue *mq_entry;

  c->th = NULL;
  mq_entry = c->mq_head;
  GNUNET_assert (NULL != mq_entry);
  if ((0 == size) && (NULL == buf)) /* Timeout */
  {
    LOG_DEBUG ("Message sending timed out -- retrying\n");
    c->th =
      GNUNET_CLIENT_notify_transmit_ready (c->client,
                                           ntohs (mq_entry->msg->size),
                                           TIMEOUT_REL,
                                           GNUNET_YES, &transmit_ready_notify,
                                           c);
    return 0;
  }
  GNUNET_assert (ntohs (mq_entry->msg->size) <= size);
  size = ntohs (mq_entry->msg->size);  
  memcpy (buf, mq_entry->msg, size);
  LOG_DEBUG ("Message of type: %u and size: %u sent\n",
	     ntohs (mq_entry->msg->type), size);
  GNUNET_free (mq_entry->msg);
  GNUNET_CONTAINER_DLL_remove (c->mq_head, c->mq_tail, mq_entry);
  GNUNET_free (mq_entry);
  mq_entry = c->mq_head;
  if (NULL != mq_entry)
    c->th = 
      GNUNET_CLIENT_notify_transmit_ready (c->client,
                                           ntohs (mq_entry->msg->size),
                                           TIMEOUT_REL,
                                           GNUNET_YES, &transmit_ready_notify,
                                           c);
  if (GNUNET_NO == c->in_receive)
  {
    c->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (c->client, &message_handler, c,
			   GNUNET_TIME_UNIT_FOREVER_REL);
  }
  return size;
}


/**
 * Queues a message in send queue for sending to the service
 *
 * @param controller the handle to the controller
 * @param msg the message to queue
 */
void
GNUNET_TESTBED_queue_message (struct GNUNET_TESTBED_Controller *controller,
                              struct GNUNET_MessageHeader *msg)
{
  struct MessageQueue *mq_entry;
  uint16_t type;
  uint16_t size;

  type = ntohs (msg->type);
  size = ntohs (msg->size);
  GNUNET_assert ((GNUNET_MESSAGE_TYPE_TESTBED_INIT <= type) &&
                 (GNUNET_MESSAGE_TYPE_TESTBED_MAX > type));                 
  mq_entry = GNUNET_malloc (sizeof (struct MessageQueue));
  mq_entry->msg = msg;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queueing message of type %u, size %u for sending\n", type,
       ntohs (msg->size));
  GNUNET_CONTAINER_DLL_insert_tail (controller->mq_head, controller->mq_tail,
                                    mq_entry);
  if (NULL == controller->th)
    controller->th = 
      GNUNET_CLIENT_notify_transmit_ready (controller->client, size,
                                           TIMEOUT_REL,
                                           GNUNET_YES, &transmit_ready_notify,
                                           controller);
}


/**
 * Handle for controller process
 */
struct GNUNET_TESTBED_ControllerProc
{
  /**
   * The helper handle
   */
  struct GNUNET_TESTBED_HelperHandle *helper;

  /**
   * The controller error callback
   */
  GNUNET_TESTBED_ControllerErrorCallback cec;

  /**
   * The closure for the above callback
   */
  void *cec_cls;
};


/**
 * Callback that will be called when the helper process dies. This is not called
 * when the helper process is stoped using GNUNET_HELPER_stop()
 *
 * @param cls the closure from GNUNET_HELPER_start()
 */
static void 
controller_exp_cb (void *cls)
{
  struct GNUNET_TESTBED_ControllerProc *cproc = cls;

  if (NULL != cproc->cec)
    cproc->cec (cproc->cec_cls, NULL); /* FIXME: How to get the error message? */
}


/**
 * Starts a controller process at the host
 *
 * @param controller_ip the ip address of the controller. Will be set as TRUSTED
 *          host when starting testbed controller at host
 * @param host the host where the controller has to be started; NULL for localhost
 * @param cfg template configuration to use for the remote controller; the
 *          remote controller will be started with a slightly modified
 *          configuration (port numbers, unix domain sockets and service home
 *          values are changed as per TESTING library on the remote host)
 * @param cec function called if the contoller dies unexpectedly; will not be 
 *            invoked after GNUNET_TESTBED_controller_stop, if 'cec' was called,
 *            GNUNET_TESTBED_controller_stop must no longer be called; will
 *            never be called in the same task as 'GNUNET_TESTBED_controller_start'
 *            (synchronous errors will be signalled by returning NULL)
 * @param cec_cls closure for 'cec'
 * @return the controller process handle, NULL on errors
 */
struct GNUNET_TESTBED_ControllerProc *
GNUNET_TESTBED_controller_start (const char *controller_ip,
				 struct GNUNET_TESTBED_Host *host,
				 const struct GNUNET_CONFIGURATION_Handle *cfg,
				 GNUNET_TESTBED_ControllerErrorCallback cec,
				 void *cec_cls)
{
  struct GNUNET_TESTBED_ControllerProc *cproc;
  
  cproc = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_ControllerProc));
  cproc->helper = GNUNET_TESTBED_host_run_ (controller_ip, host, cfg,
					    &controller_exp_cb, cproc);
  if (NULL == cproc->helper)
  {
    GNUNET_free (cproc);
    return NULL;
  }
  cproc->cec = cec;
  cproc->cec_cls = cec_cls;
  return cproc;
}


/**
 * Stop the controller process (also will terminate all peers and controllers
 * dependent on this controller).  This function blocks until the testbed has
 * been fully terminated (!).
 *
 * @param cproc the controller process handle
 */
void
GNUNET_TESTBED_controller_stop (struct GNUNET_TESTBED_ControllerProc *cproc)
{
  GNUNET_TESTBED_host_stop_ (cproc->helper);
  GNUNET_free (cproc);
}


/**
 * Start a controller process using the given configuration at the
 * given host.
 *
 * @param cfg configuration to use
 * @param host host to run the controller on; This should be the same host if
 *          the controller was previously started with
 *          GNUNET_TESTBED_controller_start; NULL for localhost
 * @param event_mask bit mask with set of events to call 'cc' for;
 *                   or-ed values of "1LL" shifted by the
 *                   respective 'enum GNUNET_TESTBED_EventType'
 *                   (i.e.  "(1LL << GNUNET_TESTBED_ET_CONNECT) | ...")
 * @param cc controller callback to invoke on events
 * @param cc_cls closure for cc
 * @return handle to the controller
 */
struct GNUNET_TESTBED_Controller *
GNUNET_TESTBED_controller_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
				   struct GNUNET_TESTBED_Host *host,
				   uint64_t event_mask,
				   GNUNET_TESTBED_ControllerCallback cc,
				   void *cc_cls)
{
  struct GNUNET_TESTBED_Controller *controller;
  struct GNUNET_TESTBED_InitMessage *msg;

  controller = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Controller));
  controller->cc = cc;
  controller->cc_cls = cc_cls;
  controller->event_mask = event_mask;
  controller->cfg = GNUNET_CONFIGURATION_dup (cfg);
  controller->client = GNUNET_CLIENT_connect ("testbed", controller->cfg);  
  if (NULL == controller->client)
  {
    GNUNET_TESTBED_controller_disconnect (controller);
    return NULL;
  }
  if (NULL == host)
  {
    host = GNUNET_TESTBED_host_create_by_id_ (0);
    if (NULL == host)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
	   "Treating NULL host as localhost. Multiple references to localhost. "
	   " May break when localhost freed before calling disconnect \n");
      host = GNUNET_TESTBED_host_lookup_by_id_ (0);
    }
    else
    {
      controller->aux_host = GNUNET_YES;
    }
  }
  GNUNET_assert (NULL != host);
  msg = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_InitMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_INIT);
  msg->header.size = htons (sizeof (struct GNUNET_TESTBED_InitMessage));
  msg->host_id = htonl (GNUNET_TESTBED_host_get_id_ (host));
  msg->event_mask = GNUNET_htonll (controller->event_mask);
  GNUNET_TESTBED_queue_message (controller, (struct GNUNET_MessageHeader *) msg);
  return controller;
}


/**
 * Configure shared services at a controller.  Using this function,
 * you can specify that certain services (such as "resolver")
 * should not be run for each peer but instead be shared
 * across N peers on the specified host.  This function
 * must be called before any peers are created at the host.
 * 
 * @param controller controller to configure
 * @param service_name name of the service to share
 * @param num_peers number of peers that should share one instance
 *        of the specified service (1 for no sharing is the default),
 *        use 0 to disable the service
 */
void
GNUNET_TESTBED_controller_configure_sharing (struct GNUNET_TESTBED_Controller *controller,
					     const char *service_name,
					     uint32_t num_peers)
{
  struct GNUNET_TESTBED_ConfigureSharedServiceMessage *msg;
  uint16_t service_name_size;
  uint16_t msg_size;
  
  service_name_size = strlen (service_name) + 1;
  msg_size = sizeof (struct GNUNET_TESTBED_ConfigureSharedServiceMessage)
    + service_name_size;
  msg = GNUNET_malloc (msg_size);
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_SERVICESHARE);
  msg->host_id = htonl (GNUNET_TESTBED_host_get_id_ (controller->host));
  msg->num_peers = htonl (num_peers);
  memcpy (&msg[1], service_name, service_name_size);
  GNUNET_TESTBED_queue_message (controller, (struct GNUNET_MessageHeader *) msg);
}


/**
 * disconnects from the controller.
 *
 * @param controller handle to controller to stop
 */
void
GNUNET_TESTBED_controller_disconnect (struct GNUNET_TESTBED_Controller *controller)
{
  struct MessageQueue *mq_entry;

  if (NULL != controller->th)
    GNUNET_CLIENT_notify_transmit_ready_cancel (controller->th);
 /* Clear the message queue */
  while (NULL != (mq_entry = controller->mq_head))
  {
    GNUNET_CONTAINER_DLL_remove (controller->mq_head,
				 controller->mq_tail,
				 mq_entry);
    GNUNET_free (mq_entry->msg);
    GNUNET_free (mq_entry);
  }
  if (NULL != controller->client)
    GNUNET_CLIENT_disconnect (controller->client);
  GNUNET_CONFIGURATION_destroy (controller->cfg);
  if (GNUNET_YES == controller->aux_host)
    GNUNET_TESTBED_host_destroy (controller->host);
  GNUNET_free (controller);
}


/**
 * Register a host with the controller
 *
 * @param controller the controller handle
 * @param host the host to register
 * @param cc the completion callback to call to inform the status of
 *          registration. After calling this callback the registration handle
 *          will be invalid. Cannot be NULL.
 * @param cc_cls the closure for the cc
 * @return handle to the host registration which can be used to cancel the
 *           registration 
 */
struct GNUNET_TESTBED_HostRegistrationHandle *
GNUNET_TESTBED_register_host (struct GNUNET_TESTBED_Controller *controller,
                              struct GNUNET_TESTBED_Host *host,
                              GNUNET_TESTBED_HostRegistrationCompletion cc,
                              void *cc_cls)
{
  struct GNUNET_TESTBED_HostRegistrationHandle *rh;
  struct GNUNET_TESTBED_AddHostMessage *msg;
  const char *username;
  const char *hostname;
  uint16_t msg_size;
  uint16_t user_name_length;

  if (NULL != controller->rh)
    return NULL;
  hostname = GNUNET_TESTBED_host_get_hostname_ (host);
  if (GNUNET_YES == GNUNET_TESTBED_is_host_registered_ (host, controller))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Host hostname: %s already registered\n",
         (NULL == hostname) ? "localhost" : hostname);
    return NULL;
  }  
  rh = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_HostRegistrationHandle));
  rh->host = host;
  rh->c = controller;
  GNUNET_assert (NULL != cc);
  rh->cc = cc;
  rh->cc_cls = cc_cls;
  controller->rh = rh;
  username = GNUNET_TESTBED_host_get_username_ (host);
  msg_size = (sizeof (struct GNUNET_TESTBED_AddHostMessage));
  user_name_length = 0;
  if (NULL != username)
  {
    user_name_length = strlen (username) + 1;
    msg_size += user_name_length;
  }
  /* FIXME: what happens when hostname is NULL? localhost */
  GNUNET_assert (NULL != hostname);
  msg_size += strlen (hostname) + 1;
  msg = GNUNET_malloc (msg_size);
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_ADDHOST);
  msg->host_id = htonl (GNUNET_TESTBED_host_get_id_ (host));
  msg->ssh_port = htons (GNUNET_TESTBED_host_get_ssh_port_ (host));
  msg->user_name_length = htons (user_name_length);
  if (NULL != username)
    memcpy (&msg[1], username, user_name_length);
  strcpy (((void *) &msg[1]) + user_name_length, hostname);
  GNUNET_TESTBED_queue_message (controller, (struct GNUNET_MessageHeader *) msg);
  return rh;
}


/**
 * Cancel the pending registration. Note that if the registration message is
 * already sent to the service the cancellation has only the effect that the
 * registration completion callback for the registration is never called.
 *
 * @param handle the registration handle to cancel
 */
void
GNUNET_TESTBED_cancel_registration (struct GNUNET_TESTBED_HostRegistrationHandle
                                    *handle)
{
  if (handle != handle->c->rh)
  {
    GNUNET_break (0);
    return;
  }
  handle->c->rh = NULL;
  GNUNET_free (handle);  
}


/**
 * Same as the GNUNET_TESTBED_controller_link, however expects configuration in
 * serialized and compressed
 *
 * @param master handle to the master controller who creates the association
 * @param delegated_host requests to which host should be delegated; cannot be NULL
 * @param slave_host which host is used to run the slave controller; use NULL to
 *          make the master controller connect to the delegated host
 * @param sxcfg serialized and compressed configuration
 * @param sxcfg_size the size scfg
 * @param scfg_size the size of uncompressed serialized configuration
 * @param is_subordinate GNUNET_YES if the controller at delegated_host should
 *          be started by the master controller; GNUNET_NO if we are just
 *          allowed to use the slave via TCP/IP
 */
void
GNUNET_TESTBED_controller_link_2 (struct GNUNET_TESTBED_Controller *master,
				  struct GNUNET_TESTBED_Host *delegated_host,
				  struct GNUNET_TESTBED_Host *slave_host,
				  const char *sxcfg,
				  size_t sxcfg_size,
				  size_t scfg_size,
				  int is_subordinate)
{
  struct GNUNET_TESTBED_ControllerLinkMessage *msg;
  uint16_t msg_size;

  GNUNET_assert (GNUNET_YES == 
		 GNUNET_TESTBED_is_host_registered_ (delegated_host, master));
  if ((NULL != slave_host) && (0 != GNUNET_TESTBED_host_get_id_ (slave_host)))
    GNUNET_assert (GNUNET_YES == 
		   GNUNET_TESTBED_is_host_registered_ (slave_host, master));
  msg_size = sxcfg_size + sizeof (struct GNUNET_TESTBED_ControllerLinkMessage);
  msg = GNUNET_malloc (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_LCONTROLLERS);  
  msg->header.size = htons (msg_size);
  msg->delegated_host_id = htonl (GNUNET_TESTBED_host_get_id_ (delegated_host));
  msg->slave_host_id = htonl (GNUNET_TESTBED_host_get_id_ 
			      ((NULL != slave_host) ? slave_host : master->host));
  msg->config_size = htons ((uint16_t) scfg_size);
  msg->is_subordinate = (GNUNET_YES == is_subordinate) ? 1 : 0;
  memcpy (&msg[1], sxcfg, sxcfg_size);
  GNUNET_TESTBED_queue_message (master, (struct GNUNET_MessageHeader *) msg);
}


/**
 * Compresses given configuration using zlib compress
 *
 * @param config the serialized configuration
 * @param size the size of config
 * @param xconfig will be set to the compressed configuration (memory is fresly
 *          allocated) 
 * @return the size of the xconfig
 */
size_t
GNUNET_TESTBED_compress_config (const char *config, size_t size,
                                char **xconfig)
{
  size_t xsize;
  
  xsize = compressBound ((uLong) size);
  *xconfig = GNUNET_malloc (xsize);
  GNUNET_assert (Z_OK ==
		 compress2 ((Bytef *)* xconfig, (uLongf *) &xsize,
                            (const Bytef *) config, (uLongf) size, 
                            Z_BEST_SPEED));
  return xsize;
}
                                

/**
 * Create a link from slave controller to delegated controller. Whenever the
 * master controller is asked to start a peer at the delegated controller the
 * request will be routed towards slave controller (if a route exists). The
 * slave controller will then route it to the delegated controller. The
 * configuration of the slave controller is given and to be used to either
 * create the slave controller or to connect to an existing slave controller
 * process.  'is_subordinate' specifies if the given slave controller should be
 * started and managed by the master controller, or if the slave already has a
 * master and this is just a secondary master that is also allowed to use the
 * existing slave.
 *
 * @param master handle to the master controller who creates the association
 * @param delegated_host requests to which host should be delegated
 * @param slave_host which host is used to run the slave controller 
 * @param slave_cfg configuration to use for the slave controller
 * @param is_subordinate GNUNET_YES if the slave should be started (and stopped)
 *                       by the master controller; GNUNET_NO if we are just
 *                       allowed to use the slave via TCP/IP
 */
void
GNUNET_TESTBED_controller_link (struct GNUNET_TESTBED_Controller *master,
				struct GNUNET_TESTBED_Host *delegated_host,
				struct GNUNET_TESTBED_Host *slave_host,
				const struct GNUNET_CONFIGURATION_Handle *slave_cfg,
				int is_subordinate)
{
  char *config;
  char *cconfig;
  size_t cc_size;
  size_t config_size;  
  
  GNUNET_assert (GNUNET_YES == 
		 GNUNET_TESTBED_is_host_registered_ (delegated_host, master));
  if ((NULL != slave_host) && (0 != GNUNET_TESTBED_host_get_id_ (slave_host)))
    GNUNET_assert (GNUNET_YES == 
		   GNUNET_TESTBED_is_host_registered_ (slave_host, master));
  config = GNUNET_CONFIGURATION_serialize (slave_cfg, &config_size);
  cc_size = GNUNET_TESTBED_compress_config (config, config_size, &cconfig);
  GNUNET_free (config);
  GNUNET_assert ((UINT16_MAX -
		  sizeof (struct GNUNET_TESTBED_ControllerLinkMessage))
		  >= cc_size); /* Configuration doesn't fit in 1 message */
  GNUNET_TESTBED_controller_link_2 (master, delegated_host, slave_host,
				    (const char *) cconfig,
				    cc_size, config_size, is_subordinate);
  GNUNET_free (cconfig);
}


/**
 * Ask the testbed controller to write the current overlay topology to
 * a file.  Naturally, the file will only contain a snapshot as the
 * topology may evolve all the time.
 *
 * @param controller overlay controller to inspect
 * @param filename name of the file the topology should
 *        be written to.
 */
void
GNUNET_TESTBED_overlay_write_topology_to_file (struct GNUNET_TESTBED_Controller *controller,
					       const char *filename)
{
  GNUNET_break (0);
}



/* end of testbed_api.c */
