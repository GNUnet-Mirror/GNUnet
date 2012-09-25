/*
  This file is part of GNUnet.
  (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-service-testbed.c
 * @brief implementation of the TESTBED service
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_service_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_core_service.h"
#include "gnunet_hello_lib.h"
#include <zlib.h>

#include "gnunet_testbed_service.h"
#include "testbed.h"
#include "testbed_api.h"
#include "testbed_api_hosts.h"
#include "gnunet_testing_lib-new.h"

/**
 * Generic logging
 */
#define LOG(kind,...)                           \
  GNUNET_log (kind, __VA_ARGS__)

/**
 * Debug logging
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

/**
 * By how much should the arrays lists grow
 */
#define LIST_GROW_STEP 10

/**
 * Default timeout for operations which may take some time
 */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * Timeout of Transport try_connect requests
 */
#define TRANSPORT_TRY_CONNECT_TIMEOUT                                   \
  GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 100)

/**
 * The main context information associated with the client which started us
 */
struct Context
{
  /**
   * The client handle associated with this context
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * The network address of the master controller
   */
  char *master_ip;

  /**
   * The TESTING system handle for starting peers locally
   */
  struct GNUNET_TESTING_System *system;

  /**
   * Event mask of event to be responded in this context
   */
  uint64_t event_mask;

  /**
   * Our host id according to this context
   */
  uint32_t host_id;
};


/**
 * The message queue for sending messages to clients
 */
struct MessageQueue
{
  /**
   * The message to be sent
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * The client to send the message to
   */
  struct GNUNET_SERVER_Client *client;

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
 * The structure for identifying a shared service
 */
struct SharedService
{
  /**
   * The name of the shared service
   */
  char *name;

  /**
   * Number of shared peers per instance of the shared service
   */
  uint32_t num_shared;

  /**
   * Number of peers currently sharing the service
   */
  uint32_t num_sharing;
};


/**
 * A routing entry
 */
struct Route
{
  /**
   * destination host
   */
  uint32_t dest;

  /**
   * The host destination is reachable thru
   */
  uint32_t thru;
};


/**
 * Structure representing a connected(directly-linked) controller
 */
struct Slave
{
  /**
   * The controller process handle if we had started the controller
   */
  struct GNUNET_TESTBED_ControllerProc *controller_proc;

  /**
   * The controller handle
   */
  struct GNUNET_TESTBED_Controller *controller;

  /**
   * The id of the host this controller is running on
   */
  uint32_t host_id;
};


/**
 * States of LCFContext
 */
enum LCFContextState
{
  /**
   * The Context has been initialized; Nothing has been done on it
   */
  INIT,

  /**
   * Delegated host has been registered at the forwarding controller
   */
  DELEGATED_HOST_REGISTERED,
  
  /**
   * The slave host has been registred at the forwarding controller
   */
  SLAVE_HOST_REGISTERED,
  
  /**
   * The context has been finished (may have error)
   */
  FINISHED
};


/**
 * Link controllers request forwarding context
 */
struct LCFContext
{
  /**
   * The gateway which will pass the link message to delegated host
   */
  struct Slave *gateway;

  /**
   * The controller link message that has to be forwarded to
   */
  struct GNUNET_TESTBED_ControllerLinkMessage *msg;

  /**
   * The client which has asked to perform this operation
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * The host registration handle while registered hosts in this context
   */
  struct GNUNET_TESTBED_HostRegistrationHandle *rhandle;

  /**
   * The id of the operation which created this context
   */
  uint64_t operation_id;

  /**
   * The state of this context
   */
  enum LCFContextState state;

  /**
   * The delegated host
   */
  uint32_t delegated_host_id;

  /**
   * The slave host
   */
  uint32_t slave_host_id;

};


/**
 * Structure of a queue entry in LCFContext request queue
 */
struct LCFContextQueue
{
  /**
   * The LCFContext
   */
  struct LCFContext *lcf;

  /**
   * Head prt for DLL
   */
  struct LCFContextQueue *next;

  /**
   * Tail ptr for DLL
   */
  struct LCFContextQueue *prev;
};


/**
 * A locally started peer
 */
struct Peer
{
  union
  {
    struct
    {
      /**
       * The peer handle from testing API
       */
      struct GNUNET_TESTING_Peer *peer;

      /**
       * The modified (by GNUNET_TESTING_peer_configure) configuration this
       * peer is configured with
       */
      struct GNUNET_CONFIGURATION_Handle *cfg;
      
      /**
       * Is the peer running
       */
      int is_running;

    } local;

    struct
    {
      /**
       * The controller this peer is started through
       */
      struct GNUNET_TESTBED_Controller *controller;

    } remote;

  } details;

  /**
   * Is this peer locally created?
   */
  int is_remote;

  /**
   * Our local reference id for this peer
   */
  uint32_t id;

};


/**
 * Context information for connecting 2 peers in overlay
 */
struct OverlayConnectContext
{
  /**
   * The client which has requested for overlay connection
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * the peer which has to connect to the other peer
   */
  struct Peer *peer;

  /**
   * The other peer
   */
  struct Peer *other_peer;

  /**
   * Transport handle of the first peer to get its HELLO
   */
  struct GNUNET_TRANSPORT_Handle *p1th;

  /**
   * Transport handle of other peer to offer first peer's HELLO
   */
  struct GNUNET_TRANSPORT_Handle *p2th;

  /**
   * Core handles of the first peer; used to notify when second peer connects to it
   */
  struct GNUNET_CORE_Handle *ch;

  /**
   * HELLO of the other peer
   */
  struct GNUNET_MessageHeader *hello;

  /**
   * Get hello handle to acquire HELLO of first peer
   */
  struct GNUNET_TRANSPORT_GetHelloHandle *ghh;

  /**
   * The error message we send if this overlay connect operation has timed out
   */
  char *emsg;

  /**
   * Operation context for suboperations
   */
  struct OperationContext *opc;

  /**
   * The peer identity of the first peer
   */
  struct GNUNET_PeerIdentity peer_identity;

  /**
   * The peer identity of the other peer
   */
  struct GNUNET_PeerIdentity other_peer_identity;

  /**
   * The id of the operation responsible for creating this context
   */
  uint64_t op_id;

  /**
   * The id of the task for sending HELLO of peer 2 to peer 1 and ask peer 1 to
   * connect to peer 2
   */
  GNUNET_SCHEDULER_TaskIdentifier send_hello_task;

  /**
   * The id of the overlay connect timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

};


/**
 * Context information for RequestOverlayConnect
 * operations. RequestOverlayConnect is used when peers A, B reside on different
 * hosts and the host controller for peer B is asked by the host controller of
 * peer A to make peer B connect to peer A
 */
struct RequestOverlayConnectContext
{
  /**
   * The transport handle of peer B
   */
  struct GNUNET_TRANSPORT_Handle *th;
  
  /**
   * Peer A's HELLO
   */
  struct GNUNET_MessageHeader *hello;

  /**
   * The peer identity of peer A
   */
  struct GNUNET_PeerIdentity a_id;

  /**
   * Task for offering HELLO of A to B and doing try_connect
   */
  GNUNET_SCHEDULER_TaskIdentifier attempt_connect_task_id;
  
  /**
   * Task to timeout RequestOverlayConnect
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_rocc_task_id;
  
};


/**
 * Context information for operations forwarded to subcontrollers
 */
struct ForwardedOperationContext
{
  /**
   * The generated operation context
   */
  struct OperationContext *opc;

  /**
   * The client to which we have to reply
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Closure pointer
   */
  void *cls;

  /**
   * Task ID for the timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * The id of the operation that has been forwarded
   */
  uint64_t operation_id;

};


/**
 * Context information used while linking controllers
 */
struct LinkControllersContext
{
  /**
   * The client which initiated the link controller operation
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * The ID of the operation
   */
  uint64_t operation_id;

  /**
   * Pointer to the slave handle if we are directly starting/connecting to the controller
   */
  struct Slave *slave;
};



/**
 * The master context; generated with the first INIT message
 */
static struct Context *master_context;

/***********/
/* Handles */
/***********/

/**
 * Current Transmit Handle; NULL if no notify transmit exists currently
 */
static struct GNUNET_SERVER_TransmitHandle *transmit_handle;

/****************/
/* Lists & Maps */
/****************/

/**
 * The head for the LCF queue
 */
static struct LCFContextQueue *lcfq_head;

/**
 * The tail for the LCF queue
 */
static struct LCFContextQueue *lcfq_tail;

/**
 * The message queue head
 */
static struct MessageQueue *mq_head;

/**
 * The message queue tail
 */
static struct MessageQueue *mq_tail;

/**
 * Array of host list
 */
static struct GNUNET_TESTBED_Host **host_list;

/**
 * A list of routes
 */
static struct Route **route_list;

/**
 * A list of directly linked neighbours
 */
static struct Slave **slave_list;

/**
 * A list of peers we own locally
 */
static struct Peer **peer_list;

/**
 * The hashmap of shared services
 */
static struct GNUNET_CONTAINER_MultiHashMap *ss_map;

/**
 * The size of the host list
 */
static uint32_t host_list_size;

/**
 * The size of the route list
 */
static uint32_t route_list_size;

/**
 * The size of directly linked neighbours list
 */
static uint32_t slave_list_size;

/**
 * The size of the peer list
 */
static uint32_t peer_list_size;

/*********/
/* Tasks */
/*********/

/**
 * The lcf_task handle
 */
static GNUNET_SCHEDULER_TaskIdentifier lcf_proc_task_id;

/**
 * The shutdown task handle
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task_id;


/**
 * Function called to notify a client about the connection begin ready to queue
 * more data.  "buf" will be NULL and "size" zero if the connection was closed
 * for writing in the meantime.
 *
 * @param cls NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_ready_notify (void *cls, size_t size, void *buf)
{
  struct MessageQueue *mq_entry;

  transmit_handle = NULL;
  mq_entry = mq_head;
  GNUNET_assert (NULL != mq_entry);
  if (0 == size)
    return 0;
  GNUNET_assert (ntohs (mq_entry->msg->size) <= size);
  size = ntohs (mq_entry->msg->size);
  memcpy (buf, mq_entry->msg, size);
  GNUNET_free (mq_entry->msg);
  GNUNET_CONTAINER_DLL_remove (mq_head, mq_tail, mq_entry);
  GNUNET_free (mq_entry);
  mq_entry = mq_head;
  if (NULL != mq_entry)
    transmit_handle =
        GNUNET_SERVER_notify_transmit_ready (mq_entry->client,
                                             ntohs (mq_entry->msg->size),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             &transmit_ready_notify, NULL);
  return size;
}


/**
 * Queues a message in send queue for sending to the service
 *
 * @param client the client to whom the queued message has to be sent
 * @param msg the message to queue
 */
static void
queue_message (struct GNUNET_SERVER_Client *client,
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
  mq_entry->client = client;
  LOG_DEBUG ("Queueing message of type %u, size %u for sending\n", type,
             ntohs (msg->size));
  GNUNET_CONTAINER_DLL_insert_tail (mq_head, mq_tail, mq_entry);
  if (NULL == transmit_handle)
    transmit_handle =
        GNUNET_SERVER_notify_transmit_ready (client, size,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             &transmit_ready_notify, NULL);
}


/**
 * Similar to GNUNET_realloc; however clears tail part of newly allocated memory
 *
 * @param ptr the memory block to realloc
 * @param size the size of ptr
 * @param new_size the size to which ptr has to be realloc'ed
 * @return the newly reallocated memory block
 */
static void *
TESTBED_realloc (void *ptr, size_t size, size_t new_size)
{
  ptr = GNUNET_realloc (ptr, new_size);
  if (new_size > size)
    ptr = memset (ptr + size, 0, new_size - size);
  return ptr;
}


/**
 * Function to add a host to the current list of known hosts
 *
 * @param host the host to add
 * @return GNUNET_OK on success; GNUNET_SYSERR on failure due to host-id
 *           already in use
 */
static int
host_list_add (struct GNUNET_TESTBED_Host *host)
{
  uint32_t host_id;

  host_id = GNUNET_TESTBED_host_get_id_ (host);
  if (host_list_size <= host_id)
  {
    host_list =
        TESTBED_realloc (host_list,
                         sizeof (struct GNUNET_TESTBED_Host *) * host_list_size,
                         sizeof (struct GNUNET_TESTBED_Host *) *
                         (host_list_size + LIST_GROW_STEP));
    host_list_size += LIST_GROW_STEP;
  }
  if (NULL != host_list[host_id])
  {
    LOG_DEBUG ("A host with id: %u already exists\n", host_id);
    return GNUNET_SYSERR;
  }
  host_list[host_id] = host;
  return GNUNET_OK;
}


/**
 * Adds a route to the route list
 *
 * @param route the route to add
 */
static void
route_list_add (struct Route *route)
{
  if (route->dest >= route_list_size)
  {
    route_list =
        TESTBED_realloc (route_list, sizeof (struct Route *) * route_list_size,
                         sizeof (struct Route *) * (route_list_size +
                                                    LIST_GROW_STEP));
    route_list_size += LIST_GROW_STEP;
  }
  GNUNET_assert (NULL == route_list[route->dest]);
  route_list[route->dest] = route;
}


/**
 * Adds a slave to the slave array
 *
 * @param slave the slave controller to add
 */
static void
slave_list_add (struct Slave *slave)
{
  if (slave->host_id >= slave_list_size)
  {
    slave_list =
        TESTBED_realloc (slave_list, sizeof (struct Slave *) * slave_list_size,
                         sizeof (struct Slave *) * (slave_list_size +
                                                    LIST_GROW_STEP));
    slave_list_size += LIST_GROW_STEP;
  }
  GNUNET_assert (NULL == slave_list[slave->host_id]);
  slave_list[slave->host_id] = slave;
}


/**
 * Adds a peer to the peer array
 *
 * @param peer the peer to add
 */
static void
peer_list_add (struct Peer *peer)
{
  uint32_t orig_size;

  orig_size = peer_list_size;
  if (peer->id >= peer_list_size)
  {
    while (peer->id >= peer_list_size)
      peer_list_size += LIST_GROW_STEP;
    peer_list =
        TESTBED_realloc (peer_list, sizeof (struct Peer *) * orig_size,
                         sizeof (struct Peer *) * peer_list_size);
  }
  GNUNET_assert (NULL == peer_list[peer->id]);
  peer_list[peer->id] = peer;
}


/**
 * Removes a the give peer from the peer array
 *
 * @param peer the peer to be removed
 */
static void
peer_list_remove (struct Peer *peer)
{
  uint32_t id;
  uint32_t orig_size;

  peer_list[peer->id] = NULL;
  orig_size = peer_list_size;
  while (peer_list_size >= LIST_GROW_STEP)
  {
    for (id = peer_list_size - 1;
         (id >= peer_list_size - LIST_GROW_STEP) && (id != UINT32_MAX); id--)
      if (NULL != peer_list[id])
        break;
    if (id != ((peer_list_size - LIST_GROW_STEP) - 1))
      break;
    peer_list_size -= LIST_GROW_STEP;
  }
  if (orig_size == peer_list_size)
    return;
  peer_list =
      GNUNET_realloc (peer_list, sizeof (struct Peer *) * peer_list_size);
}


/**
 * Finds the route with directly connected host as destination through which
 * the destination host can be reached
 *
 * @param host_id the id of the destination host
 * @return the route with directly connected destination host; NULL if no route
 *           is found
 */
static struct Route *
find_dest_route (uint32_t host_id)
{
  struct Route *route;

  while (NULL != (route = route_list[host_id]))
  {
    if (route->thru == master_context->host_id)
      break;
    host_id = route->thru;
  }
  return route;
}


/**
 * Routes message to a host given its host_id
 *
 * @param host_id the id of the destination host
 * @param msg the message to be routed
 */
static void
route_message (uint32_t host_id, const struct GNUNET_MessageHeader *msg)
{
  GNUNET_break (0);
}


/**
 * Send operation failure message to client
 *
 * @param client the client to which the failure message has to be sent to
 * @param operation_id the id of the failed operation
 * @param emsg the error message; can be NULL
 */
static void
send_operation_fail_msg (struct GNUNET_SERVER_Client *client,
                         uint64_t operation_id, const char *emsg)
{
  struct GNUNET_TESTBED_OperationFailureEventMessage *msg;
  uint16_t msize;
  uint16_t emsg_len;

  msize = sizeof (struct GNUNET_TESTBED_OperationFailureEventMessage);
  emsg_len = (NULL == emsg) ? 0 : strlen (emsg) + 1;
  msize += emsg_len;
  msg = GNUNET_malloc (msize);
  msg->header.size = htons (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_OPERATIONFAILEVENT);
  msg->event_type = htonl (GNUNET_TESTBED_ET_OPERATION_FINISHED);
  msg->operation_id = GNUNET_htonll (operation_id);
  if (0 != emsg_len)
    memcpy (&msg[1], emsg, emsg_len);
  queue_message (client, &msg->header);
}


/**
 * Function to send generic operation success message to given client
 *
 * @param client the client to send the message to
 * @param operation_id the id of the operation which was successful
 */
static void
send_operation_success_msg (struct GNUNET_SERVER_Client *client,
                            uint64_t operation_id)
{
  struct GNUNET_TESTBED_GenericOperationSuccessEventMessage *msg;
  uint16_t msize;

  msize = sizeof (struct GNUNET_TESTBED_GenericOperationSuccessEventMessage);
  msg = GNUNET_malloc (msize);
  msg->header.size = htons (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_GENERICOPSUCCESS);
  msg->operation_id = GNUNET_htonll (operation_id);
  msg->event_type = htonl (GNUNET_TESTBED_ET_OPERATION_FINISHED);
  queue_message (client, &msg->header);
}


/**
 * The  Link Controller forwarding task
 *
 * @param cls the LCFContext
 * @param tc the Task context from scheduler
 */
static void
lcf_proc_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Completion callback for host registrations while forwarding Link Controller messages
 *
 * @param cls the LCFContext
 * @param emsg the error message; NULL if host registration is successful
 */
static void
lcf_proc_cc (void *cls, const char *emsg)
{
  struct LCFContext *lcf = cls;

  lcf->rhandle = NULL;
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == lcf_proc_task_id);
  switch (lcf->state)
  {
  case INIT:
    if (NULL != emsg)
      goto registration_error;
    lcf->state = DELEGATED_HOST_REGISTERED;
    lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    break;
  case DELEGATED_HOST_REGISTERED:
    if (NULL != emsg)
      goto registration_error;
    lcf->state = SLAVE_HOST_REGISTERED;
    lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    break;
  default:
    GNUNET_assert (0);          /* Shouldn't reach here */
  }
  return;

 registration_error:
  LOG (GNUNET_ERROR_TYPE_WARNING, "Host registration failed with message: %s\n",
       emsg);
  lcf->state = FINISHED;
  lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
}


/**
 * Callback to be called when forwarded link controllers operation is
 * successfull. We have to relay the reply msg back to the client
 *
 * @param cls ForwardedOperationContext
 * @param msg the peer create success message
 */
static void
forwarded_operation_reply_relay (void *cls,
                                 const struct GNUNET_MessageHeader *msg)
{
  struct ForwardedOperationContext *fopc = cls;
  struct GNUNET_MessageHeader *dup_msg;
  uint16_t msize;

  msize = ntohs (msg->size);
  LOG_DEBUG ("Relaying message with type: %u, size: %u\n", ntohs (msg->type),
             msize);
  dup_msg = GNUNET_malloc (msize);
  (void) memcpy (dup_msg, msg, msize);
  queue_message (fopc->client, dup_msg);
  GNUNET_SERVER_client_drop (fopc->client);
  GNUNET_SCHEDULER_cancel (fopc->timeout_task);
  GNUNET_free (fopc);
}


/**
 * Task to free resources when forwarded link controllers has been timedout
 *
 * @param cls the ForwardedOperationContext
 * @param tc the task context from scheduler
 */
static void
forwarded_operation_timeout (void *cls,
                             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedOperationContext *fopc = cls;

  GNUNET_TESTBED_forward_operation_msg_cancel_ (fopc->opc);
  send_operation_fail_msg (fopc->client, fopc->operation_id, "Timeout");
  GNUNET_SERVER_client_drop (fopc->client);
  GNUNET_free (fopc);
}


/**
 * The  Link Controller forwarding task
 *
 * @param cls the LCFContext
 * @param tc the Task context from scheduler
 */
static void
lcf_proc_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct LCFContext *lcf = cls;
  struct LCFContextQueue *lcfq;
  struct ForwardedOperationContext *fopc;

  lcf_proc_task_id = GNUNET_SCHEDULER_NO_TASK;
  switch (lcf->state)
  {
  case INIT:
    if (GNUNET_NO ==
        GNUNET_TESTBED_is_host_registered_ (host_list[lcf->delegated_host_id],
                                            lcf->gateway->controller))
    {
      lcf->rhandle =
          GNUNET_TESTBED_register_host (lcf->gateway->controller,
                                        host_list[lcf->delegated_host_id],
                                        lcf_proc_cc, lcf);
    }
    else
    {
      lcf->state = DELEGATED_HOST_REGISTERED;
      lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    }
    break;
  case DELEGATED_HOST_REGISTERED:
    if (GNUNET_NO ==
        GNUNET_TESTBED_is_host_registered_ (host_list[lcf->slave_host_id],
                                            lcf->gateway->controller))
    {
      lcf->rhandle =
          GNUNET_TESTBED_register_host (lcf->gateway->controller,
                                        host_list[lcf->slave_host_id],
                                        lcf_proc_cc, lcf);
    }
    else
    {
      lcf->state = SLAVE_HOST_REGISTERED;
      lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    }
    break;
  case SLAVE_HOST_REGISTERED:
    fopc = GNUNET_malloc (sizeof (struct ForwardedOperationContext));
    fopc->client = lcf->client;
    fopc->operation_id = lcf->operation_id;
    fopc->opc =
        GNUNET_TESTBED_forward_operation_msg_ (lcf->gateway->controller,
                                               lcf->operation_id,
                                               &lcf->msg->header,
                                               &forwarded_operation_reply_relay,
                                               fopc);
    fopc->timeout_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT, &forwarded_operation_timeout,
                                      fopc);
    lcf->state = FINISHED;
    lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    break;
  case FINISHED:
    lcfq = lcfq_head;
    GNUNET_assert (lcfq->lcf == lcf);
    GNUNET_free (lcf->msg);
    GNUNET_free (lcf);
    GNUNET_CONTAINER_DLL_remove (lcfq_head, lcfq_tail, lcfq);
    GNUNET_free (lcfq);
    if (NULL != lcfq_head)
      lcf_proc_task_id =
          GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcfq_head->lcf);
  }
}


/**
 * Callback for event from slave controllers
 *
 * @param cls struct Slave *
 * @param event information about the event
 */
static void
slave_event_callback (void *cls,
                      const struct GNUNET_TESTBED_EventInformation *event)
{
  GNUNET_break (0);
}


/**
 * Callback to signal successfull startup of the controller process
 *
 * @param cls the closure from GNUNET_TESTBED_controller_start()
 * @param cfg the configuration with which the controller has been started;
 *          NULL if status is not GNUNET_OK
 * @param status GNUNET_OK if the startup is successfull; GNUNET_SYSERR if not,
 *          GNUNET_TESTBED_controller_stop() shouldn't be called in this case
 */
static void
slave_status_callback (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
                       int status)
{
  struct LinkControllersContext *lcc = cls;

  if (GNUNET_SYSERR == status)
  {
    lcc->slave->controller_proc = NULL;
    LOG (GNUNET_ERROR_TYPE_WARNING, "Unexpected slave shutdown\n");
    GNUNET_SCHEDULER_shutdown ();       /* We too shutdown */
    return;
  }
  lcc->slave->controller =
      GNUNET_TESTBED_controller_connect (cfg, host_list[lcc->slave->host_id],
                                         master_context->event_mask,
                                         &slave_event_callback, lcc->slave);
  if (NULL != lcc->slave->controller)
    send_operation_success_msg (lcc->client, lcc->operation_id);
  else
    send_operation_fail_msg (lcc->client, lcc->operation_id,
                             "Could not connect to delegated controller");
  GNUNET_SERVER_client_drop (lcc->client);
  GNUNET_free (lcc);
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_INIT messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_init (void *cls, struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_InitMessage *msg;
  struct GNUNET_TESTBED_Host *host;
  const char *controller_hostname;
  uint16_t msize;

  if (NULL != master_context)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GNUNET_TESTBED_InitMessage *) message;
  msize = ntohs (message->size);
  if (msize <= sizeof (struct GNUNET_TESTBED_InitMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msize -= sizeof (struct GNUNET_TESTBED_InitMessage);
  controller_hostname = (const char *) &msg[1];
  if ('\0' != controller_hostname[msize - 1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  master_context = GNUNET_malloc (sizeof (struct Context));
  master_context->client = client;
  master_context->host_id = ntohl (msg->host_id);
  master_context->master_ip = GNUNET_strdup (controller_hostname);
  LOG_DEBUG ("Master Controller IP: %s\n", master_context->master_ip);
  master_context->system =
      GNUNET_TESTING_system_create ("testbed", master_context->master_ip);
  host =
      GNUNET_TESTBED_host_create_with_id (master_context->host_id, NULL, NULL,
                                          0);
  host_list_add (host);
  master_context->event_mask = GNUNET_ntohll (msg->event_mask);
  GNUNET_SERVER_client_keep (client);
  LOG_DEBUG ("Created master context with host ID: %u\n",
             master_context->host_id);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_ADDHOST messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_add_host (void *cls, struct GNUNET_SERVER_Client *client,
                 const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_TESTBED_Host *host;
  const struct GNUNET_TESTBED_AddHostMessage *msg;
  struct GNUNET_TESTBED_HostConfirmedMessage *reply;
  char *username;
  char *hostname;
  char *emsg;
  uint32_t host_id;
  uint16_t username_length;
  uint16_t hostname_length;
  uint16_t reply_size;
  uint16_t msize;

  msg = (const struct GNUNET_TESTBED_AddHostMessage *) message;
  msize = ntohs (msg->header.size);
  username = (char *) &(msg[1]);
  username_length = ntohs (msg->user_name_length);
  GNUNET_assert (msize > (sizeof (struct GNUNET_TESTBED_AddHostMessage) + username_length + 1));        /* msg must contain hostname */
  if (0 != username_length)
    GNUNET_assert ('\0' == username[username_length]);
  username_length = (0 == username_length) ? 0 : username_length + 1;
  hostname = username + username_length;
  hostname_length =
      msize - (sizeof (struct GNUNET_TESTBED_AddHostMessage) + username_length);
  GNUNET_assert ('\0' == hostname[hostname_length - 1]);
  GNUNET_assert (strlen (hostname) == hostname_length - 1);
  host_id = ntohl (msg->host_id);
  LOG_DEBUG ("Received ADDHOST message\n");
  LOG_DEBUG ("-------host id: %u\n", host_id);
  LOG_DEBUG ("-------hostname: %s\n", hostname);
  if (0 != username_length)
    LOG_DEBUG ("-------username: %s\n", username);
  else
  {
    LOG_DEBUG ("-------username: NULL\n");
    username = NULL;
  }
  LOG_DEBUG ("-------ssh port: %u\n", ntohs (msg->ssh_port));
  host =
      GNUNET_TESTBED_host_create_with_id (host_id, hostname, username,
                                          ntohs (msg->ssh_port));
  GNUNET_assert (NULL != host);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  reply_size = sizeof (struct GNUNET_TESTBED_HostConfirmedMessage);
  if (GNUNET_OK != host_list_add (host))
  {
    /* We are unable to add a host */
    emsg = "A host exists with given host-id";
    LOG_DEBUG ("%s: %u", emsg, host_id);
    GNUNET_TESTBED_host_destroy (host);
    reply_size += strlen (emsg) + 1;
    reply = GNUNET_malloc (reply_size);
    memcpy (&reply[1], emsg, strlen (emsg) + 1);
  }
  else
    reply = GNUNET_malloc (reply_size);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_ADDHOSTCONFIRM);
  reply->header.size = htons (reply_size);
  reply->host_id = htonl (host_id);
  queue_message (client, &reply->header);
}


/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
int
ss_exists_iterator (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct SharedService *queried_ss = cls;
  struct SharedService *ss = value;

  if (0 == strcmp (ss->name, queried_ss->name))
    return GNUNET_NO;
  else
    return GNUNET_YES;
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_ADDHOST messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_configure_shared_service (void *cls, struct GNUNET_SERVER_Client *client,
                                 const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_ConfigureSharedServiceMessage *msg;
  struct SharedService *ss;
  char *service_name;
  struct GNUNET_HashCode hash;
  uint16_t msg_size;
  uint16_t service_name_size;

  msg = (const struct GNUNET_TESTBED_ConfigureSharedServiceMessage *) message;
  msg_size = ntohs (message->size);
  if (msg_size <= sizeof (struct GNUNET_TESTBED_ConfigureSharedServiceMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  service_name_size =
      msg_size - sizeof (struct GNUNET_TESTBED_ConfigureSharedServiceMessage);
  service_name = (char *) &msg[1];
  if ('\0' != service_name[service_name_size - 1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  LOG_DEBUG ("Received service sharing request for %s, with %d peers\n",
             service_name, ntohl (msg->num_peers));
  if (ntohl (msg->host_id) != master_context->host_id)
  {
    route_message (ntohl (msg->host_id), message);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  ss = GNUNET_malloc (sizeof (struct SharedService));
  ss->name = strdup (service_name);
  ss->num_shared = ntohl (msg->num_peers);
  GNUNET_CRYPTO_hash (ss->name, service_name_size, &hash);
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_get_multiple (ss_map, &hash,
                                                  &ss_exists_iterator, ss))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Service %s already configured as a shared service. "
         "Ignoring service sharing request \n", ss->name);
    GNUNET_free (ss->name);
    GNUNET_free (ss);
    return;
  }
  GNUNET_CONTAINER_multihashmap_put (ss_map, &hash, ss,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_LCONTROLLERS message
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_link_controllers (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_ControllerLinkMessage *msg;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct LCFContextQueue *lcfq;
  struct Route *route;
  struct Route *new_route;
  char *config;
  uLongf dest_size;
  size_t config_size;
  uint32_t delegated_host_id;
  uint32_t slave_host_id;
  uint16_t msize;

  if (NULL == master_context)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msize = ntohs (message->size);
  if (sizeof (struct GNUNET_TESTBED_ControllerLinkMessage) >= msize)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GNUNET_TESTBED_ControllerLinkMessage *) message;
  delegated_host_id = ntohl (msg->delegated_host_id);
  if (delegated_host_id == master_context->host_id)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_WARNING, "Trying to link ourselves\n");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if ((delegated_host_id >= host_list_size) ||
      (NULL == host_list[delegated_host_id]))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Delegated host not registered with us\n");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  slave_host_id = ntohl (msg->slave_host_id);
  if ((slave_host_id >= host_list_size) || (NULL == host_list[slave_host_id]))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Slave host not registered with us\n");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (slave_host_id == delegated_host_id)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Slave and delegated host are same\n");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  if (slave_host_id == master_context->host_id) /* Link from us */
  {
    struct Slave *slave;
    struct LinkControllersContext *lcc;

    msize -= sizeof (struct GNUNET_TESTBED_ControllerLinkMessage);
    config_size = ntohs (msg->config_size);
    if ((delegated_host_id < slave_list_size) && (NULL != slave_list[delegated_host_id]))       /* We have already added */
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Host %u already connected\n",
           delegated_host_id);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    config = GNUNET_malloc (config_size);
    dest_size = (uLongf) config_size;
    if (Z_OK !=
        uncompress ((Bytef *) config, &dest_size, (const Bytef *) &msg[1],
                    (uLong) msize))
    {
      GNUNET_break (0);         /* Compression error */
      GNUNET_free (config);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    if (config_size != dest_size)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Uncompressed config size mismatch\n");
      GNUNET_free (config);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    cfg = GNUNET_CONFIGURATION_create ();       /* Free here or in lcfcontext */
    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_deserialize (cfg, config, config_size, GNUNET_NO))
    {
      GNUNET_break (0);         /* Configuration parsing error */
      GNUNET_free (config);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    GNUNET_free (config);
    if ((delegated_host_id < slave_list_size) &&
        (NULL != slave_list[delegated_host_id]))
    {
      GNUNET_break (0);         /* Configuration parsing error */
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    slave = GNUNET_malloc (sizeof (struct Slave));
    slave->host_id = delegated_host_id;
    slave_list_add (slave);
    if (1 != msg->is_subordinate)
    {
      slave->controller =
          GNUNET_TESTBED_controller_connect (cfg, host_list[slave->host_id],
                                             master_context->event_mask,
                                             &slave_event_callback, slave);
      GNUNET_CONFIGURATION_destroy (cfg);
      if (NULL != slave->controller)
        send_operation_success_msg (client, GNUNET_ntohll (msg->operation_id));
      else
        send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                                 "Could not connect to delegated controller");
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
    lcc = GNUNET_malloc (sizeof (struct LinkControllersContext));
    lcc->operation_id = GNUNET_ntohll (msg->operation_id);
    GNUNET_SERVER_client_keep (client);
    lcc->client = client;
    lcc->slave = slave;
    slave->controller_proc =
	GNUNET_TESTBED_controller_start (master_context->master_ip,
					 host_list[slave->host_id], cfg,
					 &slave_status_callback, lcc);
    GNUNET_CONFIGURATION_destroy (cfg);
    new_route = GNUNET_malloc (sizeof (struct Route));
    new_route->dest = delegated_host_id;
    new_route->thru = master_context->host_id;
    route_list_add (new_route);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  /* Route the request */
  if (slave_host_id >= route_list_size)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "No route towards slave host");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  lcfq = GNUNET_malloc (sizeof (struct LCFContextQueue));
  lcfq->lcf = GNUNET_malloc (sizeof (struct LCFContext));
  lcfq->lcf->delegated_host_id = delegated_host_id;
  lcfq->lcf->slave_host_id = slave_host_id;
  route = find_dest_route (slave_host_id);
  GNUNET_assert (NULL != route);        /* because we add routes carefully */
  GNUNET_assert (route->dest < slave_list_size);
  GNUNET_assert (NULL != slave_list[route->dest]);
  lcfq->lcf->state = INIT;
  lcfq->lcf->operation_id = GNUNET_ntohll (msg->operation_id);
  lcfq->lcf->gateway = slave_list[route->dest];
  lcfq->lcf->msg = GNUNET_malloc (msize);
  (void) memcpy (lcfq->lcf->msg, msg, msize);
  GNUNET_SERVER_client_keep (client);
  lcfq->lcf->client = client;
  if (NULL == lcfq_head)
  {
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == lcf_proc_task_id);
    GNUNET_CONTAINER_DLL_insert_tail (lcfq_head, lcfq_tail, lcfq);
    lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcfq->lcf);
  }
  else
    GNUNET_CONTAINER_DLL_insert_tail (lcfq_head, lcfq_tail, lcfq);
  /* FIXME: Adding a new route should happen after the controllers are linked
   * successfully */
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  new_route = GNUNET_malloc (sizeof (struct Route));
  new_route->dest = delegated_host_id;
  new_route->thru = route->dest;
  route_list_add (new_route);
}


/**
 * The task to be executed if the forwarded peer create operation has been
 * timed out
 *
 * @param cls the FowardedOperationContext
 * @param tc the TaskContext from the scheduler
 */
static void
peer_create_forward_timeout (void *cls,
                             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedOperationContext *fo_ctxt = cls;

  /* send error msg to client */
  send_operation_fail_msg (fo_ctxt->client, fo_ctxt->operation_id, "Timedout");
  GNUNET_SERVER_client_drop (fo_ctxt->client);
  GNUNET_TESTBED_forward_operation_msg_cancel_ (fo_ctxt->opc);
  GNUNET_free (fo_ctxt);
}


/**
 * Callback to be called when forwarded peer create operation is
 * successfull. We have to relay the reply msg back to the client
 *
 * @param cls ForwardedOperationContext
 * @param msg the peer create success message
 */
static void
peer_create_success_cb (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct ForwardedOperationContext *fo_ctxt = cls;
  const struct GNUNET_TESTBED_PeerCreateSuccessEventMessage *success_msg;
  struct GNUNET_MessageHeader *dup_msg;
  struct Peer *peer;
  uint16_t msize;

  GNUNET_SCHEDULER_cancel (fo_ctxt->timeout_task);
  if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_TESTBED_PEERCREATESUCCESS)
  {
    success_msg =
        (const struct GNUNET_TESTBED_PeerCreateSuccessEventMessage *) msg;
    peer = GNUNET_malloc (sizeof (struct Peer));
    peer->is_remote = GNUNET_YES;
    peer->id = ntohl (success_msg->peer_id);
    GNUNET_assert (NULL != fo_ctxt->cls);
    peer->details.remote.controller = fo_ctxt->cls;
    peer_list_add (peer);
  }
  msize = ntohs (msg->size);
  dup_msg = GNUNET_malloc (msize);
  (void) memcpy (dup_msg, msg, msize);
  queue_message (fo_ctxt->client, dup_msg);
  GNUNET_SERVER_client_drop (fo_ctxt->client);
  GNUNET_free (fo_ctxt);
}



/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_CREATEPEER messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_peer_create (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerCreateMessage *msg;
  struct GNUNET_TESTBED_PeerCreateSuccessEventMessage *reply;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct ForwardedOperationContext *fo_ctxt;
  struct Route *route;
  struct Peer *peer;
  char *config;
  size_t dest_size;
  int ret;
  uint32_t config_size;
  uint32_t host_id;
  uint32_t peer_id;
  uint16_t msize;


  msize = ntohs (message->size);
  if (msize <= sizeof (struct GNUNET_TESTBED_PeerCreateMessage))
  {
    GNUNET_break (0);           /* We need configuration */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  msg = (const struct GNUNET_TESTBED_PeerCreateMessage *) message;
  host_id = ntohl (msg->host_id);
  peer_id = ntohl (msg->peer_id);
  if (UINT32_MAX == peer_id)
  {
    send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                             "Cannot create peer with given ID");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (host_id == master_context->host_id)
  {
    char *emsg;

    /* We are responsible for this peer */
    msize -= sizeof (struct GNUNET_TESTBED_PeerCreateMessage);
    config_size = ntohl (msg->config_size);
    config = GNUNET_malloc (config_size);
    dest_size = config_size;
    if (Z_OK !=
        (ret =
         uncompress ((Bytef *) config, (uLongf *) & dest_size,
                     (const Bytef *) &msg[1], (uLong) msize)))
    {
      GNUNET_break (0);         /* uncompression error */
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    if (config_size != dest_size)
    {
      GNUNET_break (0);         /* Uncompressed config size mismatch */
      GNUNET_free (config);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    cfg = GNUNET_CONFIGURATION_create ();
    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_deserialize (cfg, config, config_size, GNUNET_NO))
    {
      GNUNET_break (0);         /* Configuration parsing error */
      GNUNET_free (config);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    GNUNET_free (config);
    peer = GNUNET_malloc (sizeof (struct Peer));
    peer->is_remote = GNUNET_NO;
    peer->details.local.cfg = cfg;
    peer->id = peer_id;
    LOG_DEBUG ("Creating peer with id: %u\n", peer->id);
    peer->details.local.peer =
        GNUNET_TESTING_peer_configure (master_context->system,
                                       peer->details.local.cfg, peer->id,
                                       NULL /* Peer id */ ,
                                       &emsg);
    if (NULL == peer->details.local.peer)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Configuring peer failed: %s\n", emsg);
      GNUNET_free (emsg);
      GNUNET_free (peer);
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    peer->details.local.is_running = GNUNET_NO;
    peer_list_add (peer);
    reply =
        GNUNET_malloc (sizeof
                       (struct GNUNET_TESTBED_PeerCreateSuccessEventMessage));
    reply->header.size =
        htons (sizeof (struct GNUNET_TESTBED_PeerCreateSuccessEventMessage));
    reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_PEERCREATESUCCESS);
    reply->peer_id = msg->peer_id;
    reply->operation_id = msg->operation_id;
    queue_message (client, &reply->header);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  /* Forward peer create request */
  route = find_dest_route (host_id);
  if (NULL == route)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  fo_ctxt = GNUNET_malloc (sizeof (struct ForwardedOperationContext));
  GNUNET_SERVER_client_keep (client);
  fo_ctxt->client = client;
  fo_ctxt->operation_id = GNUNET_ntohll (msg->operation_id);
  fo_ctxt->cls = slave_list[route->dest]->controller;
  fo_ctxt->opc =
      GNUNET_TESTBED_forward_operation_msg_ (slave_list
                                             [route->dest]->controller,
                                             fo_ctxt->operation_id,
                                             &msg->header,
                                             peer_create_success_cb, fo_ctxt);
  fo_ctxt->timeout_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &peer_create_forward_timeout,
                                    fo_ctxt);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_DESTROYPEER messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_peer_destroy (void *cls, struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerDestroyMessage *msg;
  struct ForwardedOperationContext *fopc;
  struct Peer *peer;
  uint32_t peer_id;

  msg = (const struct GNUNET_TESTBED_PeerDestroyMessage *) message;
  peer_id = ntohl (msg->peer_id);
  LOG_DEBUG ("Received peer destory on peer: %u and operation id: %ul\n",
             peer_id, GNUNET_ntohll (msg->operation_id));
  if ((peer_list_size <= peer_id) || (NULL == peer_list[peer_id]))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Asked to destroy a non existent peer with id: %u\n", peer_id);
    send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                             "Peer doesn't exist");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  peer = peer_list[peer_id];
  if (GNUNET_YES == peer->is_remote)
  {
    /* Forward the destory message to sub controller */
    fopc = GNUNET_malloc (sizeof (struct ForwardedOperationContext));
    GNUNET_SERVER_client_keep (client);
    fopc->client = client;
    fopc->operation_id = GNUNET_ntohll (msg->operation_id);
    fopc->opc =
        GNUNET_TESTBED_forward_operation_msg_ (peer->details.remote.controller,
                                               fopc->operation_id, &msg->header,
                                               &forwarded_operation_reply_relay,
                                               fopc);
    fopc->timeout_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT, &forwarded_operation_timeout,
                                      fopc);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  GNUNET_TESTING_peer_destroy (peer->details.local.peer);
  GNUNET_CONFIGURATION_destroy (peer->details.local.cfg);
  peer_list_remove (peer);
  GNUNET_free (peer);
  send_operation_success_msg (client, GNUNET_ntohll (msg->operation_id));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_DESTROYPEER messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_peer_start (void *cls, struct GNUNET_SERVER_Client *client,
                   const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerStartMessage *msg;
  struct GNUNET_TESTBED_PeerEventMessage *reply;
  struct ForwardedOperationContext *fopc;
  struct Peer *peer;
  uint32_t peer_id;

  msg = (const struct GNUNET_TESTBED_PeerStartMessage *) message;
  peer_id = ntohl (msg->peer_id);
  if ((peer_id >= peer_list_size) || (NULL == peer_list[peer_id]))
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Asked to start a non existent peer with id: %u\n", peer_id);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  peer = peer_list[peer_id];
  if (GNUNET_YES == peer->is_remote)
  {
    fopc = GNUNET_malloc (sizeof (struct ForwardedOperationContext));
    GNUNET_SERVER_client_keep (client);
    fopc->client = client;
    fopc->operation_id = GNUNET_ntohll (msg->operation_id);
    fopc->opc =
        GNUNET_TESTBED_forward_operation_msg_ (peer->details.remote.controller,
                                               fopc->operation_id, &msg->header,
                                               &forwarded_operation_reply_relay,
                                               fopc);
    fopc->timeout_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT, &forwarded_operation_timeout,
                                      fopc);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (GNUNET_OK != GNUNET_TESTING_peer_start (peer->details.local.peer))
  {
    send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                             "Failed to start");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  peer->details.local.is_running = GNUNET_YES;
  reply = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_PeerEventMessage));
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_PEEREVENT);
  reply->header.size = htons (sizeof (struct GNUNET_TESTBED_PeerEventMessage));
  reply->event_type = htonl (GNUNET_TESTBED_ET_PEER_START);
  reply->host_id = htonl (master_context->host_id);
  reply->peer_id = msg->peer_id;
  reply->operation_id = msg->operation_id;
  queue_message (client, &reply->header);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_DESTROYPEER messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_peer_stop (void *cls, struct GNUNET_SERVER_Client *client,
                  const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerStopMessage *msg;
  struct GNUNET_TESTBED_PeerEventMessage *reply;
  struct ForwardedOperationContext *fopc;
  struct Peer *peer;
  uint32_t peer_id;

  msg = (const struct GNUNET_TESTBED_PeerStopMessage *) message;
  peer_id = ntohl (msg->peer_id);
  if ((peer_id >= peer_list_size) || (NULL == peer_list[peer_id]))
  {
    send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                             "Peer not found");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  peer = peer_list[peer_id];
  if (GNUNET_YES == peer->is_remote)
  {
    fopc = GNUNET_malloc (sizeof (struct ForwardedOperationContext));
    GNUNET_SERVER_client_keep (client);
    fopc->client = client;
    fopc->operation_id = GNUNET_ntohll (msg->operation_id);
    fopc->opc =
        GNUNET_TESTBED_forward_operation_msg_ (peer->details.remote.controller,
                                               fopc->operation_id, &msg->header,
                                               &forwarded_operation_reply_relay,
                                               fopc);
    fopc->timeout_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT, &forwarded_operation_timeout,
                                      fopc);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (GNUNET_OK != GNUNET_TESTING_peer_stop (peer->details.local.peer))
  {
    send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                             "Peer not running");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  peer->details.local.is_running = GNUNET_NO;
  reply = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_PeerEventMessage));
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_PEEREVENT);
  reply->header.size = htons (sizeof (struct GNUNET_TESTBED_PeerEventMessage));
  reply->event_type = htonl (GNUNET_TESTBED_ET_PEER_STOP);
  reply->host_id = htonl (master_context->host_id);
  reply->peer_id = msg->peer_id;
  reply->operation_id = msg->operation_id;
  queue_message (client, &reply->header);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_GETPEERCONFIG messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_peer_get_config (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerGetConfigurationMessage *msg;
  struct GNUNET_TESTBED_PeerConfigurationInformationMessage *reply;
  struct Peer *peer;
  char *config;
  char *xconfig;
  size_t c_size;
  size_t xc_size;
  uint32_t peer_id;
  uint16_t msize;

  msg = (const struct GNUNET_TESTBED_PeerGetConfigurationMessage *) message;
  peer_id = ntohl (msg->peer_id);
  if ((peer_id >= peer_list_size) || (NULL == peer_list[peer_id]))
  {
    send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                             "Peer not found");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  peer = peer_list[peer_id];
  if (GNUNET_YES == peer->is_remote)
  {
    /* FIXME: forward to sub controller */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  config =
      GNUNET_CONFIGURATION_serialize (peer_list[peer_id]->details.local.cfg,
                                      &c_size);
  xc_size = GNUNET_TESTBED_compress_config_ (config, c_size, &xconfig);
  GNUNET_free (config);
  msize =
      xc_size +
      sizeof (struct GNUNET_TESTBED_PeerConfigurationInformationMessage);
  reply = GNUNET_realloc (xconfig, msize);
  (void) memmove (&reply[1], reply, xc_size);
  reply->header.size = htons (msize);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_PEERCONFIG);
  reply->peer_id = msg->peer_id;
  reply->operation_id = msg->operation_id;
  GNUNET_TESTING_peer_get_identity (peer_list[peer_id]->details.local.peer,
                                    &reply->peer_identity);
  reply->config_size = htons ((uint16_t) c_size);
  queue_message (client, &reply->header);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Task for cleaing up overlay connect context structure
 *
 * @param cls the overlay connect context
 * @param tc the task context
 */
static void
occ_cleanup (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct OverlayConnectContext *occ = cls;

  LOG_DEBUG ("Cleaning up occ\n");
  GNUNET_free_non_null (occ->emsg);
  GNUNET_free_non_null (occ->hello);
  GNUNET_SERVER_client_drop (occ->client);
  if (NULL != occ->opc)
    GNUNET_TESTBED_forward_operation_msg_cancel_ (occ->opc);
  if (GNUNET_SCHEDULER_NO_TASK != occ->send_hello_task)
    GNUNET_SCHEDULER_cancel (occ->send_hello_task);
  if (NULL != occ->ch)
    GNUNET_CORE_disconnect (occ->ch);
  if (NULL != occ->ghh)
    GNUNET_TRANSPORT_get_hello_cancel (occ->ghh);
  if (NULL != occ->p1th)
    GNUNET_TRANSPORT_disconnect (occ->p1th);
  if (NULL != occ->p2th)
    GNUNET_TRANSPORT_disconnect (occ->p2th);
  GNUNET_free (occ);
}


/**
 * Task which will be run when overlay connect request has been timed out
 *
 * @param cls the OverlayConnectContext
 * @param tc the TaskContext
 */
static void
timeout_overlay_connect (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct OverlayConnectContext *occ = cls;

  occ->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  send_operation_fail_msg (occ->client, occ->op_id, occ->emsg);
  occ_cleanup (occ, tc);
}



/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param new_peer the peer that connected
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
overlay_connect_notify (void *cls, const struct GNUNET_PeerIdentity *new_peer,
                        const struct GNUNET_ATS_Information *ats,
                        unsigned int ats_count)
{
  struct OverlayConnectContext *occ = cls;
  struct GNUNET_TESTBED_ConnectionEventMessage *msg;
  char *new_peer_str;
  char *other_peer_str;

  LOG_DEBUG ("Overlay connect notify\n");
  if (0 ==
      memcmp (new_peer, &occ->peer_identity,
              sizeof (struct GNUNET_PeerIdentity)))
    return;
  new_peer_str = GNUNET_strdup (GNUNET_i2s (new_peer));
  other_peer_str = GNUNET_strdup (GNUNET_i2s (&occ->other_peer_identity));
  if (0 !=
      memcmp (new_peer, &occ->other_peer_identity,
              sizeof (struct GNUNET_PeerIdentity)))
  {
    LOG_DEBUG ("Unexpected peer %4s connected when expecting peer %4s\n",
	       new_peer_str, other_peer_str);
    GNUNET_free (new_peer_str);
    GNUNET_free (other_peer_str);
    return;
  }
  GNUNET_free (new_peer_str);
  LOG_DEBUG ("Peer %4s connected to peer %4s\n", other_peer_str, 
             GNUNET_i2s (&occ->peer_identity));
  GNUNET_free (other_peer_str);
  if (GNUNET_SCHEDULER_NO_TASK != occ->send_hello_task)
  {
    GNUNET_SCHEDULER_cancel (occ->send_hello_task);
    occ->send_hello_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != occ->timeout_task);
  GNUNET_SCHEDULER_cancel (occ->timeout_task);
  occ->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_free_non_null (occ->emsg);
  occ->emsg = NULL;
  if (NULL != occ->p2th)
    GNUNET_TRANSPORT_disconnect (occ->p2th);
  occ->p2th = NULL;
  LOG_DEBUG ("Peers connected - Sending overlay connect success\n");
  msg = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_ConnectionEventMessage));
  msg->header.size =
      htons (sizeof (struct GNUNET_TESTBED_ConnectionEventMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_PEERCONEVENT);
  msg->event_type = htonl (GNUNET_TESTBED_ET_CONNECT);
  msg->peer1 = htonl (occ->peer->id);
  msg->peer2 = htonl (occ->other_peer->id);
  msg->operation_id = GNUNET_htonll (occ->op_id);
  queue_message (occ->client, &msg->header);
  GNUNET_SCHEDULER_add_now (&occ_cleanup, occ);
}


/**
 * Task to offer HELLO of peer 1 to peer 2 and try to make peer 2 to connect to
 * peer 1.
 *
 * @param cls the OverlayConnectContext
 * @param tc the TaskContext from scheduler
 */
static void
send_hello (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct OverlayConnectContext *occ = cls;
  char *other_peer_str;

  occ->send_hello_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_assert (NULL != occ->hello);
  other_peer_str = GNUNET_strdup (GNUNET_i2s (&occ->other_peer_identity));
  if (GNUNET_YES == occ->other_peer->is_remote)
  {
    struct GNUNET_TESTBED_RequestConnectMessage *msg;
    uint16_t msize;
    uint16_t hello_size;

    LOG_DEBUG ("Offering HELLO of %s to %s via Remote Overlay Request\n", 
	       GNUNET_i2s (&occ->peer_identity), other_peer_str);
    hello_size = ntohs (occ->hello->size);
    msize = sizeof (struct GNUNET_TESTBED_RequestConnectMessage) + hello_size;
    msg = GNUNET_malloc (msize);
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_REQUESTCONNECT);
    msg->header.size = htons (msize);
    msg->peer = htonl (occ->other_peer->id);
    msg->operation_id = GNUNET_htonll (occ->op_id);
    (void) memcpy (&msg->peer_identity, &occ->peer_identity,
		   sizeof (struct GNUNET_PeerIdentity));
    memcpy (msg->hello, occ->hello, hello_size);
    GNUNET_TESTBED_queue_message_ (occ->other_peer->details.remote.controller,
				   &msg->header);
  }
  else
  {
    LOG_DEBUG ("Offering HELLO of %s to %s\n", 
	       GNUNET_i2s (&occ->peer_identity), other_peer_str);
    GNUNET_TRANSPORT_offer_hello (occ->p2th, occ->hello, NULL, NULL);
    GNUNET_TRANSPORT_try_connect (occ->p2th, &occ->peer_identity);
    occ->send_hello_task =
        GNUNET_SCHEDULER_add_delayed (TRANSPORT_TRY_CONNECT_TIMEOUT,
                                      &send_hello, occ);
  }
  GNUNET_free (other_peer_str);  
}

/**
 * Test for checking whether HELLO message is empty
 *
 * @param cls empty flag to set
 * @param address the HELLO
 * @param expiration expiration of the HELLO
 * @return
 */
static int
test_address (void *cls, const struct GNUNET_HELLO_Address *address,
              struct GNUNET_TIME_Absolute expiration)
{
  int *empty = cls;

  *empty = GNUNET_NO;
  return GNUNET_OK;
}


/**
 * Function called whenever there is an update to the HELLO of peers in the
 * OverlayConnectClosure. If we have a valid HELLO, we connect to the peer 2's
 * transport and offer peer 1's HELLO and ask peer 2 to connect to peer 1
 *
 * @param cls closure
 * @param hello our updated HELLO
 */
static void
hello_update_cb (void *cls, const struct GNUNET_MessageHeader *hello)
{
  struct OverlayConnectContext *occ = cls;
  int empty;
  uint16_t msize;

  msize = ntohs (hello->size);
  empty = GNUNET_YES;
  (void) GNUNET_HELLO_iterate_addresses ((const struct GNUNET_HELLO_Message *)
                                         hello, GNUNET_NO, &test_address,
                                         &empty);
  if (GNUNET_YES == empty)
  {
    LOG_DEBUG ("HELLO of %s is empty\n", GNUNET_i2s (&occ->peer_identity));
    return;
  }
  LOG_DEBUG ("Received HELLO of %s\n", GNUNET_i2s (&occ->peer_identity));
  occ->hello = GNUNET_malloc (msize);
  memcpy (occ->hello, hello, msize);
  GNUNET_TRANSPORT_get_hello_cancel (occ->ghh);
  occ->ghh = NULL;
  GNUNET_TRANSPORT_disconnect (occ->p1th);
  occ->p1th = NULL;
  GNUNET_free_non_null (occ->emsg);
  if (GNUNET_NO == occ->other_peer->is_remote)
  {   
    occ->p2th =
	GNUNET_TRANSPORT_connect (occ->other_peer->details.local.cfg,
				  &occ->other_peer_identity, NULL, NULL, NULL,
				  NULL);
    if (NULL == occ->p2th)
    {
      GNUNET_asprintf (&occ->emsg, "Cannot connect to TRANSPORT of %s\n",
		       GNUNET_i2s (&occ->other_peer_identity));
      GNUNET_SCHEDULER_cancel (occ->timeout_task);
      occ->timeout_task = GNUNET_SCHEDULER_add_now (&timeout_overlay_connect, occ);
      return;
    }
  }
  occ->emsg = GNUNET_strdup ("Timeout while offering HELLO to other peer");
  occ->send_hello_task = GNUNET_SCHEDULER_add_now (&send_hello, occ);
}


/**
 * Function called after GNUNET_CORE_connect has succeeded (or failed
 * for good).  Note that the private key of the peer is intentionally
 * not exposed here; if you need it, your process should try to read
 * the private key file directly (which should work if you are
 * authorized...).
 *
 * @param cls closure
 * @param server handle to the server, NULL if we failed
 * @param my_identity ID of this peer, NULL if we failed
 */
static void
core_startup_cb (void *cls, struct GNUNET_CORE_Handle *server,
                 const struct GNUNET_PeerIdentity *my_identity)
{
  struct OverlayConnectContext *occ = cls;

  GNUNET_free_non_null (occ->emsg);
  occ->emsg = GNUNET_strdup ("Failed to connect to CORE\n");
  if ((NULL == server) || (NULL == my_identity))
    goto error_return;
  GNUNET_free (occ->emsg);
  occ->ch = server;
  occ->emsg = NULL;
  memcpy (&occ->peer_identity, my_identity,
          sizeof (struct GNUNET_PeerIdentity));
  occ->p1th =
      GNUNET_TRANSPORT_connect (occ->peer->details.local.cfg,
                                &occ->peer_identity, NULL, NULL, NULL, NULL);
  if (NULL == occ->p1th)
  {
    GNUNET_asprintf (&occ->emsg, "Cannot connect to TRANSPORT of peers %4s",
		    GNUNET_i2s (&occ->peer_identity));
    goto error_return;
  }
  LOG_DEBUG ("Acquiring HELLO of peer %s\n", GNUNET_i2s (&occ->peer_identity));
  occ->emsg = GNUNET_strdup ("Timeout while acquiring HELLO message");
  occ->ghh = GNUNET_TRANSPORT_get_hello (occ->p1th, &hello_update_cb, occ);
  return;
  
 error_return:
  GNUNET_SCHEDULER_cancel (occ->timeout_task);
  occ->timeout_task = GNUNET_SCHEDULER_add_now (&timeout_overlay_connect, occ);
  return;
}


/**
 * Callback to be called when forwarded get peer config operation as part of
 * overlay connect is successfull. Connection to Peer 1's core is made and is
 * checked for new connection from peer 2
 *
 * @param cls ForwardedOperationContext
 * @param msg the peer create success message
 */
static void
overlay_connect_get_config (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct OverlayConnectContext *occ = cls;
  const struct GNUNET_TESTBED_PeerConfigurationInformationMessage *cmsg;
  const struct GNUNET_CORE_MessageHandler no_handlers[] = {
    {NULL, 0, 0}
  };

  occ->opc = NULL;
  if (GNUNET_MESSAGE_TYPE_TESTBED_PEERCONFIG != ntohs (msg->type))
    goto error_return;
  cmsg = (const struct GNUNET_TESTBED_PeerConfigurationInformationMessage *)
      msg;
  memcpy (&occ->other_peer_identity, &cmsg->peer_identity,
	  sizeof (struct GNUNET_PeerIdentity));
  GNUNET_free_non_null (occ->emsg);
  occ->emsg = GNUNET_strdup ("Timeout while connecting to CORE");
  occ->ch =
      GNUNET_CORE_connect (occ->peer->details.local.cfg, occ, &core_startup_cb,
                           &overlay_connect_notify, NULL, NULL, GNUNET_NO, NULL,
                           GNUNET_NO, no_handlers);
  if (NULL == occ->ch)
    goto error_return;
  return;

 error_return:
  GNUNET_SCHEDULER_cancel (occ->timeout_task);
  occ->timeout_task = 
      GNUNET_SCHEDULER_add_now (&timeout_overlay_connect, occ);
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_OLCONNECT messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_overlay_connect (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_OverlayConnectMessage *msg;
  struct OverlayConnectContext *occ;
  const struct GNUNET_CORE_MessageHandler no_handlers[] = {
    {NULL, 0, 0}
  };
  struct Peer *peer;
  uint64_t operation_id;
  uint32_t p1;
  uint32_t p2;

  msg = (const struct GNUNET_TESTBED_OverlayConnectMessage *) message;
  p1 = ntohl (msg->peer1);
  p2 = ntohl (msg->peer2);
  GNUNET_assert (p1 < peer_list_size);
  GNUNET_assert (NULL != peer_list[p1]);
  peer = peer_list[p1];
  operation_id = GNUNET_ntohll (msg->operation_id);
  if (GNUNET_YES == peer->is_remote)
  {
    struct ForwardedOperationContext *fopc;

    fopc = GNUNET_malloc (sizeof (struct ForwardedOperationContext));
    GNUNET_SERVER_client_keep (client);
    fopc->client = client;
    fopc->operation_id = operation_id;
    fopc->opc = 
	GNUNET_TESTBED_forward_operation_msg_ (peer->details.remote.controller,
					       operation_id, message,
					       &forwarded_operation_reply_relay,
					       fopc);
    fopc->timeout_task =
	GNUNET_SCHEDULER_add_delayed (TIMEOUT, &forwarded_operation_timeout,
				      fopc);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  occ = GNUNET_malloc (sizeof (struct OverlayConnectContext));
  GNUNET_SERVER_client_keep (client);
  occ->client = client;
  occ->peer = peer_list[p1];
  occ->other_peer = peer_list[p2];
  occ->op_id = GNUNET_ntohll (msg->operation_id);
  /* Get the identity of the second peer */
  if (GNUNET_YES == occ->other_peer->is_remote)
  {
    struct GNUNET_TESTBED_PeerGetConfigurationMessage cmsg;

    cmsg.header.size = 
	htons (sizeof (struct GNUNET_TESTBED_PeerGetConfigurationMessage));
    cmsg.header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_GETPEERCONFIG);
    cmsg.peer_id = msg->peer2;
    cmsg.operation_id = msg->operation_id;
    occ->opc = 
	GNUNET_TESTBED_forward_operation_msg_ (occ->other_peer->details.remote.controller,
					       occ->op_id, &cmsg.header,
					       &overlay_connect_get_config,
					       occ);
    occ->emsg = 
	GNUNET_strdup ("Timeout while getting peer identity of peer B\n");
    occ->timeout_task =
	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
				      (GNUNET_TIME_UNIT_SECONDS, 30),
				      &timeout_overlay_connect, occ);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  GNUNET_TESTING_peer_get_identity (occ->other_peer->details.local.peer,
				    &occ->other_peer_identity);
  /* Connect to the core of 1st peer and wait for the 2nd peer to connect */
  occ->emsg = GNUNET_strdup ("Timeout while connecting to CORE");
  occ->ch =
      GNUNET_CORE_connect (occ->peer->details.local.cfg, occ, &core_startup_cb,
                           &overlay_connect_notify, NULL, NULL, GNUNET_NO, NULL,
                           GNUNET_NO, no_handlers);
  if (NULL == occ->ch)
    occ->timeout_task = 
	GNUNET_SCHEDULER_add_now (&timeout_overlay_connect, occ);
  else
    occ->timeout_task =
	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
				      (GNUNET_TIME_UNIT_SECONDS, 30),
				      &timeout_overlay_connect, occ);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Function to cleanup RequestOverlayConnectContext and any associated tasks
 * with it
 *
 * @param rocc the RequestOverlayConnectContext
 */
static void
cleanup_rocc (struct RequestOverlayConnectContext *rocc)
{
  if (GNUNET_SCHEDULER_NO_TASK != rocc->attempt_connect_task_id)
    GNUNET_SCHEDULER_cancel (rocc->attempt_connect_task_id);
  if (GNUNET_SCHEDULER_NO_TASK != rocc->timeout_rocc_task_id)
    GNUNET_SCHEDULER_cancel (rocc->timeout_rocc_task_id);
  GNUNET_TRANSPORT_disconnect (rocc->th);
  GNUNET_free_non_null (rocc->hello);
  GNUNET_free (rocc);
}


/**
 * Task to timeout rocc and cleanit up
 *
 * @param cls the RequestOverlayConnectContext
 * @param tc the TaskContext from scheduler
 */
static void
timeout_rocc_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RequestOverlayConnectContext *rocc = cls;
  
  rocc->timeout_rocc_task_id = GNUNET_SCHEDULER_NO_TASK;
  cleanup_rocc (rocc);
}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param new_peer the peer that connected
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void 
transport_connect_notify (void *cls, const struct GNUNET_PeerIdentity *new_peer,
                          const struct GNUNET_ATS_Information * ats,
                          uint32_t ats_count)
{
  struct RequestOverlayConnectContext *rocc = cls;

  LOG_DEBUG ("Request Overlay connect notify\n");
  if (0 != memcmp (new_peer, &rocc->a_id, sizeof (struct GNUNET_PeerIdentity)))
  {
    return;
  }
  LOG_DEBUG ("Peer %4s connected\n", GNUNET_i2s (&rocc->a_id));
  cleanup_rocc (rocc);
}


/**
 * Task to offer the HELLO message to the peer and ask it to connect to the peer
 * whose identity is in RequestOverlayConnectContext
 *
 * @param cls the RequestOverlayConnectContext
 * @param tc the TaskContext from scheduler
 */
static void
attempt_connect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RequestOverlayConnectContext *rocc = cls;

  rocc->attempt_connect_task_id = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_TRANSPORT_offer_hello (rocc->th, rocc->hello, NULL, NULL);
  GNUNET_TRANSPORT_try_connect (rocc->th, &rocc->a_id);
  rocc->attempt_connect_task_id = 
      GNUNET_SCHEDULER_add_delayed (TRANSPORT_TRY_CONNECT_TIMEOUT,
                                    &attempt_connect_task, rocc);
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_REQUESTCONNECT messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_overlay_request_connect (void *cls, struct GNUNET_SERVER_Client *client,
				const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_RequestConnectMessage *msg;
  struct RequestOverlayConnectContext *rocc;
  struct Peer *peer;
  uint32_t peer_id;
  uint16_t msize;
  uint16_t hsize;
  
  msize = ntohs (message->size);
  if (sizeof (struct GNUNET_TESTBED_RequestConnectMessage) >= msize)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }  
  msg = (const struct GNUNET_TESTBED_RequestConnectMessage *) message;
  if ((NULL == msg->hello) || 
      (GNUNET_MESSAGE_TYPE_HELLO != ntohs (msg->hello->type)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  hsize = ntohs (msg->hello->size);
  if ((sizeof (struct GNUNET_TESTBED_RequestConnectMessage) + hsize) != msize)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  peer_id = ntohl (msg->peer);
  if ((peer_id >= peer_list_size) || (NULL == (peer = peer_list[peer_id])))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (GNUNET_NO != peer->is_remote)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  rocc = GNUNET_malloc (sizeof (struct RequestOverlayConnectContext));
  rocc->th = GNUNET_TRANSPORT_connect (peer->details.local.cfg, NULL, rocc, 
                                       NULL, &transport_connect_notify, NULL);
  if (NULL == rocc->th)
  {
    GNUNET_break (0);
    GNUNET_free (rocc);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  memcpy (&rocc->a_id, &msg->peer_identity,
          sizeof (struct GNUNET_PeerIdentity));
  rocc->hello = GNUNET_malloc (hsize);
  memcpy (rocc->hello, msg->hello, hsize);
  /* GNUNET_TRANSPORT_offer_hello (th, msg->hello, NULL, NULL); */
  /* GNUNET_TRANSPORT_try_connect (th, &msg->peer_identity); */
  rocc->attempt_connect_task_id =
      GNUNET_SCHEDULER_add_now (&attempt_connect_task, rocc);
  rocc->timeout_rocc_task_id =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &timeout_rocc_task, rocc);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
ss_map_free_iterator (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct SharedService *ss = value;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (ss_map, key, value));
  GNUNET_free (ss->name);
  GNUNET_free (ss);
  return GNUNET_YES;
}


/**
 * Task to clean up and shutdown nicely
 *
 * @param cls NULL
 * @param tc the TaskContext from scheduler
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct LCFContextQueue *lcfq;
  uint32_t id;

  shutdown_task_id = GNUNET_SCHEDULER_NO_TASK;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down testbed service\n");
  (void) GNUNET_CONTAINER_multihashmap_iterate (ss_map, &ss_map_free_iterator,
                                                NULL);
  GNUNET_CONTAINER_multihashmap_destroy (ss_map);
  if (NULL != lcfq_head)
  {
    if (GNUNET_SCHEDULER_NO_TASK != lcf_proc_task_id)
    {
      GNUNET_SCHEDULER_cancel (lcf_proc_task_id);
      lcf_proc_task_id = GNUNET_SCHEDULER_NO_TASK;
    }
    if (NULL != lcfq_head->lcf->rhandle)
      GNUNET_TESTBED_cancel_registration (lcfq_head->lcf->rhandle);
  }
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == lcf_proc_task_id);
  for (lcfq = lcfq_head; NULL != lcfq; lcfq = lcfq_head)
  {
    GNUNET_free (lcfq->lcf->msg);
    GNUNET_free (lcfq->lcf);
    GNUNET_CONTAINER_DLL_remove (lcfq_head, lcfq_tail, lcfq);
    GNUNET_free (lcfq);
  }
  /* Clear peer list */
  for (id = 0; id < peer_list_size; id++)
    if (NULL != peer_list[id])
    {
      if (GNUNET_NO == peer_list[id]->is_remote)
      {
	if (GNUNET_YES == peer_list[id]->details.local.is_running)
	  GNUNET_TESTING_peer_stop (peer_list[id]->details.local.peer);
        GNUNET_TESTING_peer_destroy (peer_list[id]->details.local.peer);
        GNUNET_CONFIGURATION_destroy (peer_list[id]->details.local.cfg);
      }
      GNUNET_free (peer_list[id]);
    }
  GNUNET_free_non_null (peer_list);
  /* Clear host list */
  for (id = 0; id < host_list_size; id++)
    if (NULL != host_list[id])
      GNUNET_TESTBED_host_destroy (host_list[id]);
  GNUNET_free_non_null (host_list);
  /* Clear route list */
  for (id = 0; id < route_list_size; id++)
    if (NULL != route_list[id])
      GNUNET_free (route_list[id]);
  GNUNET_free_non_null (route_list);
  /* Clear slave_list */
  for (id = 0; id < slave_list_size; id++)
    if (NULL != slave_list[id])
    {
      if (NULL != slave_list[id]->controller)
        GNUNET_TESTBED_controller_disconnect (slave_list[id]->controller);
      if (NULL != slave_list[id]->controller_proc)
        GNUNET_TESTBED_controller_stop (slave_list[id]->controller_proc);
    }
  if (NULL != master_context)
  {
    GNUNET_free_non_null (master_context->master_ip);
    if (NULL != master_context->system)
      GNUNET_TESTING_system_destroy (master_context->system, GNUNET_YES);
    GNUNET_free (master_context);
    master_context = NULL;
  }
}


/**
 * Callback for client disconnect
 *
 * @param cls NULL
 * @param client the client which has disconnected
 */
static void
client_disconnect_cb (void *cls, struct GNUNET_SERVER_Client *client)
{
  if (NULL == master_context)
    return;
  if (client == master_context->client)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Master client disconnected\n");
    GNUNET_SERVER_client_drop (client);
    /* should not be needed as we're terminated by failure to read
     * from stdin, but if stdin fails for some reason, this shouldn't
     * hurt for now --- might need to revise this later if we ever
     * decide that master connections might be temporarily down
     * for some reason */
    //GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * Testbed setup
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
testbed_run (void *cls, struct GNUNET_SERVER_Handle *server,
             const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler message_handlers[] = {
    {&handle_init, NULL, GNUNET_MESSAGE_TYPE_TESTBED_INIT, 0},
    {&handle_add_host, NULL, GNUNET_MESSAGE_TYPE_TESTBED_ADDHOST, 0},
    {&handle_configure_shared_service, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_SERVICESHARE, 0},
    {&handle_link_controllers, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_LCONTROLLERS, 0},
    {&handle_peer_create, NULL, GNUNET_MESSAGE_TYPE_TESTBED_CREATEPEER, 0},
    {&handle_peer_destroy, NULL, GNUNET_MESSAGE_TYPE_TESTBED_DESTROYPEER,
     sizeof (struct GNUNET_TESTBED_PeerDestroyMessage)},
    {&handle_peer_start, NULL, GNUNET_MESSAGE_TYPE_TESTBED_STARTPEER,
     sizeof (struct GNUNET_TESTBED_PeerStartMessage)},
    {&handle_peer_stop, NULL, GNUNET_MESSAGE_TYPE_TESTBED_STOPPEER,
     sizeof (struct GNUNET_TESTBED_PeerStopMessage)},
    {&handle_peer_get_config, NULL, GNUNET_MESSAGE_TYPE_TESTBED_GETPEERCONFIG,
     sizeof (struct GNUNET_TESTBED_PeerGetConfigurationMessage)},
    {&handle_overlay_connect, NULL, GNUNET_MESSAGE_TYPE_TESTBED_OLCONNECT,
     sizeof (struct GNUNET_TESTBED_OverlayConnectMessage)},
    {&handle_overlay_request_connect, NULL, GNUNET_MESSAGE_TYPE_TESTBED_REQUESTCONNECT,
     0},
    {NULL}
  };

  GNUNET_SERVER_add_handlers (server, message_handlers);
  GNUNET_SERVER_disconnect_notify (server, &client_disconnect_cb, NULL);
  ss_map = GNUNET_CONTAINER_multihashmap_create (5);
  shutdown_task_id =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                    &shutdown_task, NULL);
  LOG_DEBUG ("Testbed startup complete\n");
}


/**
 * The starting point of execution
 */
int
main (int argc, char *const *argv)
{
  //sleep (15);                 /* Debugging */
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "testbed", GNUNET_SERVICE_OPTION_NONE,
                              &testbed_run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-testbed.c */
