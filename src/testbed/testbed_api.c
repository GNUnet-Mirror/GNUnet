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
 */
#include "platform.h"
#include "gnunet_testbed_service.h"
#include "gnunet_core_service.h"
#include "gnunet_constants.h"
#include "gnunet_transport_service.h"
#include "gnunet_hello_lib.h"

#include "testbed.h"
#include "testbed_api_hosts.h"


#define LOG(kind, ...)                          \
  GNUNET_log_from (kind, "testbed-api", __VA_ARGS__);


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
 * Handle to interact with a GNUnet testbed controller.  Each
 * controller has at least one master handle which is created when the
 * controller is created; this master handle interacts with the
 * controller process, destroying it destroys the controller (by
 * closing stdin of the controller process).  Additionally,
 * controllers can interact with each other (in a P2P fashion); those
 * links are established via TCP/IP on the controller's service port.
 */
struct GNUNET_TESTBED_Controller
{

  /**
   * The host where the controller is running
   */
  const struct GNUNET_TESTBED_Host *host;

  /**
   * The helper handle
   */
  struct GNUNET_TESTBED_HelperHandle *helper;

  /**
   * The controller callback
   */
  GNUNET_TESTBED_ControllerCallback cc;

  /**
   * The closure for controller callback
   */
  void *cc_cls;

  /**
   * The configuration to use while connecting to controller
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The client connection handle to the controller service
   */
  struct GNUNET_CLIENT_Connection *client;
  
  /**
   * The head of the message queue
   */
  struct MessageQueue *mq_head;

  /**
   * The tail of the message queue
   */
  struct MessageQueue *mq_tail;

  /**
   * The client transmit handle
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * The controller event mask
   */
  uint64_t event_mask;

  /**
   * Did we start the receive loop yet?
   */
  int in_receive;
};



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

  /* FIXME: Add checks for message integrity */
  switch (ntohs (msg->type))
  {
  default:
    GNUNET_break (0);
  }
  GNUNET_CLIENT_receive (c->client, &message_handler, c,
                         GNUNET_TIME_UNIT_FOREVER_REL);
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
  GNUNET_assert (ntohs (mq_entry->msg->size) <= size);
  size = ntohs (mq_entry->msg->size);
  memcpy (buf, mq_entry->msg, size);
  GNUNET_free (mq_entry->msg);
  GNUNET_CONTAINER_DLL_remove (c->mq_head, c->mq_tail, mq_entry);
  GNUNET_free (mq_entry);
  mq_entry = c->mq_head;
  if (NULL != mq_entry)
    c->th = 
      GNUNET_CLIENT_notify_transmit_ready (c->client,
                                           ntohs (mq_entry->msg->size),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO, &transmit_ready_notify,
                                           c);
  if ( (GNUNET_NO == c->in_receive) &&
       (size > 0) )
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
static void
queue_message (struct GNUNET_TESTBED_Controller *controller,
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
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO, &transmit_ready_notify,
                                           controller);
}


/**
 * Start a controller process using the given configuration at the
 * given host.
 *
 * @param cfg configuration to use
 * @param host host to run the controller on, NULL for 'localhost'
 * @param event_mask bit mask with set of events to call 'cc' for;
 *                   or-ed values of "1LL" shifted by the
 *                   respective 'enum GNUNET_TESTBED_EventType'
 *                   (i.e.  "(1LL << GNUNET_TESTBED_ET_CONNECT) | ...")
 * @param cc controller callback to invoke on events
 * @param cc_cls closure for cc
 * @return handle to the controller
 */
struct GNUNET_TESTBED_Controller *
GNUNET_TESTBED_controller_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
				 struct GNUNET_TESTBED_Host *host,
				 uint64_t event_mask,
				 GNUNET_TESTBED_ControllerCallback cc,
				 void *cc_cls)
{
  struct GNUNET_TESTBED_Controller *controller;
  char * const binary_argv[] = {
    "gnunet-service-testbed",
    "gnunet-service-testbed",
    NULL
  };
  struct GNUNET_TESTBED_InitMessage *msg;

  controller = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Controller));
  controller->helper = GNUNET_TESTBED_host_run_ (host, binary_argv);
  if (NULL == controller->helper)
  {
    GNUNET_free (controller);
    return NULL;
  }
  controller->host = host;
  controller->cc = cc;
  controller->cc_cls = cc_cls;
  controller->event_mask = event_mask;
  controller->cfg = GNUNET_CONFIGURATION_dup (cfg);
  controller->client = GNUNET_CLIENT_connect ("testbed", controller->cfg);
  if (NULL == controller->client)
  {
    GNUNET_TESTBED_controller_stop (controller);
    return NULL;
  }  
  msg = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_InitMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_INIT);
  msg->header.size = htons (sizeof (struct GNUNET_TESTBED_InitMessage));
  msg->host_id = htonl (GNUNET_TESTBED_host_get_id_ (controller->host));
  msg->event_mask = GNUNET_htonll (controller->event_mask);
  queue_message (controller, (struct GNUNET_MessageHeader *) msg);
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
  GNUNET_break (0);
}


/**
 * Stop the given controller (also will terminate all peers and
 * controllers dependent on this controller).  This function 
 * blocks until the testbed has been fully terminated (!).
 *
 * @param controller handle to controller to stop
 */
void
GNUNET_TESTBED_controller_stop (struct GNUNET_TESTBED_Controller *controller)
{
  struct MessageQueue *mq_entry;

  if (NULL != controller->th)
    GNUNET_CLIENT_notify_transmit_ready_cancel (controller->th);
  for (mq_entry = controller->mq_head; /* Clear the message queue */
       NULL != mq_entry; mq_entry = controller->mq_head)
  {
    GNUNET_free (mq_entry->msg);
    GNUNET_free (mq_entry);
  }
  if (NULL != controller->client)
    GNUNET_CLIENT_disconnect (controller->client);
  GNUNET_TESTBED_host_stop_ (controller->helper);
  GNUNET_CONFIGURATION_destroy (controller->cfg);
  GNUNET_free (controller);
}


/**
 * Create a link from a 'master' controller to a slave controller.
 * Whenever the master controller is asked to start a peer at the
 * given 'delegated_host', it will delegate the request to the
 * specified slave controller.  Note that the slave controller runs at
 * the 'slave_host', which may or may not be the same host as the
 * 'delegated_host' (for hierarchical delegations).  The configuration
 * of the slave controller is given and to be used to either create
 * the slave controller or to connect to an existing slave controller
 * process.  'is_subordinate' specifies if the given slave controller
 * should be started and managed by the master controller, or if the
 * slave already has a master and this is just a secondary master that
 * is also allowed to use the existing slave.
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
  GNUNET_break (0);
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
