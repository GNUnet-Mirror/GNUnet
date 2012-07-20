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
#include <zlib.h>

#include "testbed.h"
#include "gnunet_testbed_service.h"
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


#define LIST_GROW_STEP 10

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
 * Slave startup context
 */
struct SlaveContext
{
  /**
   * The slave corresponding to this context
   */
  struct Slave *slave;

  /**
   * The configuration used as a template while startup
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;
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
   * The serialized and compressed configuration
   */
  char *sxcfg;

  /**
   * The gateway which will pass the link message to delegated host
   */
  struct Slave *gateway;

  /**
   * The host registration handle while registered hosts in this context
   */
  struct GNUNET_TESTBED_HostRegistrationHandle *rhandle;

  /**
   * The size of the compressed serialized configuration
   */
  size_t sxcfg_size;

  /**
   * The size of the uncompressed configuration
   */
  size_t scfg_size;

  /**
   * Should the delegated host be started by the slave host?
   */
  int is_subordinate;

  /**
   * The state of this context
   */
  enum LCFContextState state;

  /**
   * The delegated host
   */
  uint32_t delegated_host_id;
  

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
  /**
   * The peer handle from testing API
   */
  struct GNUNET_TESTING_Peer *peer;

  /**
   * The modified (by GNUNET_TESTING_peer_configure) configuration this peer is
   * configured with
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Our local reference id for this peer
   */
  uint32_t id;

};


/**
 * The master context; generated with the first INIT message
 */
static struct Context *master_context;

/***********/
/* Handles */
/***********/

/**
 * Wrapped stdin.
 */
static struct GNUNET_DISK_FileHandle *fh;

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

/******************/
/* Testing System */
/******************/

/**
 * Our configuration; we also use this as template for starting other controllers
 */
static struct GNUNET_CONFIGURATION_Handle *config;


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
  LOG_DEBUG ( "Queueing message of type %u, size %u for sending\n", type,
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
      TESTBED_realloc (route_list, 
                       sizeof (struct Route *) * route_list_size,
                       sizeof (struct Route *) * 
                       (route_list_size + LIST_GROW_STEP));
    route_list_size += LIST_GROW_STEP;
  }
  GNUNET_assert (NULL == route_list[route->dest]);
  route_list[route->dest] = route;
}


/**
 * Adds a slave to the slave array
 *
 * @param route the route to add
 */
static void
slave_list_add (struct Slave *slave)
{
  if (slave->host_id  >= slave_list_size)
  {
    slave_list = TESTBED_realloc (slave_list, 
                                  sizeof (struct Slave *) *slave_list_size,
                                  sizeof (struct Slave *) *
                                  (slave_list_size + LIST_GROW_STEP));
    slave_list_size += LIST_GROW_STEP;
  }
  GNUNET_assert (NULL == slave_list[slave->host_id]);
  slave_list[slave->host_id] = slave;
}


/**
 * Adds a peer to the peer array
 *
 * @param route the route to add
 */
static void
peer_list_add (struct Peer *peer)
{
  if (peer->id  >= peer_list_size)
  {
    peer_list = TESTBED_realloc (peer_list, 
                                 sizeof (struct Peer *) * peer_list_size,
                                 sizeof (struct Peer *) *
                                 (peer_list_size + LIST_GROW_STEP));
    peer_list_size += LIST_GROW_STEP;
  }
  GNUNET_assert (NULL == peer_list[peer->id]);
  peer_list[peer->id] = peer;
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
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, 
           "Host registration failed with message: %s\n", emsg);
      lcf->state = FINISHED;
      lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
      return;
    }
    lcf->state = DELEGATED_HOST_REGISTERED;
    lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    break;
  default:
    GNUNET_assert (0); 		/* Shouldn't reach here */
  }  
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
    GNUNET_TESTBED_controller_link_2 (lcf->gateway->controller,
                                      host_list[lcf->delegated_host_id],
                                      host_list[lcf->gateway->host_id],
                                      lcf->sxcfg, lcf->sxcfg_size,
                                      lcf->scfg_size,
                                      lcf->is_subordinate);
    lcf->state = FINISHED;
  case FINISHED:   
    lcfq = lcfq_head;
    GNUNET_assert (lcfq->lcf == lcf);
    GNUNET_free (lcf->sxcfg);
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
slave_event_callback(void *cls,
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
slave_status_callback (void *cls, 
                       const struct GNUNET_CONFIGURATION_Handle *cfg,
                       int status)
{
  struct SlaveContext *sc = cls;

  if (GNUNET_SYSERR == status)
  {
    sc->slave->controller_proc = NULL;
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unexpected slave shutdown\n");
    GNUNET_SCHEDULER_shutdown ();	/* We too shutdown */
    return;
  }
  GNUNET_CONFIGURATION_destroy (sc->cfg);
  sc->slave->controller =
    GNUNET_TESTBED_controller_connect (cfg, host_list[sc->slave->host_id],
                                       master_context->event_mask,
                                       &slave_event_callback, sc->slave);
  GNUNET_free (sc);
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_INIT messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void 
handle_init (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_InitMessage *msg;
  struct GNUNET_TESTBED_Host *host;
  void *addr;
  size_t addrlen;

  if (NULL != master_context)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GNUNET_TESTBED_InitMessage *) message;  
  master_context = GNUNET_malloc (sizeof (struct Context));
  master_context->client = client;
  master_context->host_id = ntohl (msg->host_id);
  GNUNET_assert (GNUNET_OK == 
		 GNUNET_SERVER_client_get_address (client, &addr, &addrlen));
  master_context->master_ip = GNUNET_malloc (NI_MAXHOST);
  if (0 != getnameinfo (addr, addrlen, master_context->master_ip, NI_MAXHOST,
			NULL, 0, NI_NUMERICHOST))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 "Cannot determine the ip of master controller: %s\n", STRERROR (errno));
    GNUNET_free (addr);
    GNUNET_assert (0);
  }
  GNUNET_free (addr);
  LOG_DEBUG ("Master Controller IP: %s\n", master_context->master_ip);
  master_context->system = 
    GNUNET_TESTING_system_create ("testbed", master_context->master_ip);
  host = GNUNET_TESTBED_host_create_with_id (master_context->host_id,
                                             NULL, NULL, 0);
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
handle_add_host (void *cls,
                 struct GNUNET_SERVER_Client *client,
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
  
  msg = (const struct GNUNET_TESTBED_AddHostMessage *) message;
  username_length = ntohs (msg->user_name_length);
  username_length = (0 == username_length) ? 0 : username_length + 1;
  username = (char *) &(msg[1]);
  hostname = username + username_length;
  if (ntohs (message->size) <=
      (sizeof (struct GNUNET_TESTBED_AddHostMessage) + username_length))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  hostname_length = ntohs (message->size)
    - (sizeof (struct GNUNET_TESTBED_AddHostMessage) + username_length);
  if (strlen (hostname) != hostname_length - 1)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  host_id = ntohl (msg->host_id);
  LOG_DEBUG ("Received ADDHOST message\n");
  LOG_DEBUG ("-------host id: %u\n", host_id);
  if (NULL != hostname) LOG_DEBUG ("-------hostname: %s\n", hostname);
  if (0 != username_length) LOG_DEBUG ("-------username: %s\n", username);
  else LOG_DEBUG ("-------username: NULL\n");
  LOG_DEBUG ("-------ssh port: %u\n", ntohs (msg->ssh_port));
  host = GNUNET_TESTBED_host_create_with_id (host_id, hostname, username,
                                             ntohs (msg->ssh_port));
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
  queue_message (client, (struct GNUNET_MessageHeader *) reply);
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
int ss_exists_iterator (void *cls,
                        const struct GNUNET_HashCode * key,
                        void *value)
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
handle_configure_shared_service (void *cls,
                                 struct GNUNET_SERVER_Client *client,
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
  service_name_size = msg_size - 
    sizeof (struct GNUNET_TESTBED_ConfigureSharedServiceMessage);
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
handle_link_controllers (void *cls,
                         struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_ControllerLinkMessage *msg;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct SlaveContext *sc;
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
  msize -= sizeof (struct GNUNET_TESTBED_ControllerLinkMessage);
  config_size = ntohs (msg->config_size);
  
  if (slave_host_id == master_context->host_id) /* Link from us */
  {
    struct Slave *slave;

    if ((delegated_host_id < slave_list_size) && 
        (NULL != slave_list[delegated_host_id])) /* We have already added */
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Host %u already connected\n",
           delegated_host_id);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }    
    config = GNUNET_malloc (config_size);
    dest_size = (uLongf) config_size;    
    if (Z_OK != uncompress ((Bytef *) config, &dest_size,
                            (const Bytef *) &msg[1], (uLong) msize))
    {
      GNUNET_break (0);           /* Compression error */
      GNUNET_free (config);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    if (config_size == dest_size)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Uncompressed config size mismatch\n");
      GNUNET_free (config);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    }
    cfg = GNUNET_CONFIGURATION_create (); /* Free here or in lcfcontext */
    if (GNUNET_OK != GNUNET_CONFIGURATION_deserialize (cfg, config, config_size,
                                                       GNUNET_NO))
    {
      GNUNET_break (0);           /* Configuration parsing error */
      GNUNET_free (config);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    GNUNET_free (config);
    if ((delegated_host_id < slave_list_size) &&
	(NULL != slave_list[delegated_host_id]))
    {
      GNUNET_break (0);           /* Configuration parsing error */
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    slave = GNUNET_malloc (sizeof (struct Slave));
    slave->host_id = delegated_host_id;
    slave_list_add (slave);
    sc = GNUNET_malloc (sizeof (struct SlaveContext));
    sc->slave = slave;
    sc->cfg = cfg;
    if (1 == msg->is_subordinate)
    {
      slave->controller_proc =
        GNUNET_TESTBED_controller_start (master_context->master_ip,
					 host_list[slave->host_id],
					 cfg, &slave_status_callback,
					 sc);
    }    
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
  while (NULL != (route = route_list[slave_host_id]))
  {
    if (route->thru == master_context->host_id)
      break;
    slave_host_id = route->thru;
  }
  GNUNET_assert (NULL != route); /* because we add routes carefully */
  GNUNET_assert (route->dest < slave_list_size);
  GNUNET_assert (NULL != slave_list[route->dest]);  
  lcfq = GNUNET_malloc (sizeof (struct LCFContextQueue));
  lcfq->lcf = GNUNET_malloc (sizeof (struct LCFContext));
  lcfq->lcf->delegated_host_id = delegated_host_id;
  lcfq->lcf->is_subordinate =
    (1 == msg->is_subordinate) ? GNUNET_YES : GNUNET_NO;
  lcfq->lcf->state = INIT;
  lcfq->lcf->gateway = slave_list[route->dest];
  lcfq->lcf->sxcfg_size = msize;
  lcfq->lcf->sxcfg = GNUNET_malloc (msize);
  lcfq->lcf->scfg_size = config_size;
  (void) memcpy (lcfq->lcf->sxcfg, &msg[1], msize);
  if (NULL == lcfq_head)
  {
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == lcf_proc_task_id);
    GNUNET_CONTAINER_DLL_insert_tail (lcfq_head, lcfq_tail, lcfq);
    lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcfq);
  }
  else
    GNUNET_CONTAINER_DLL_insert_tail (lcfq_head, lcfq_tail, lcfq);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  new_route = GNUNET_malloc (sizeof (struct Route));
  new_route->dest = delegated_host_id;
  new_route->thru = route->dest;
  route_list_add (new_route);
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_CREATEPEER messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void 
handle_peer_create (void *cls,
                    struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerCreateMessage *msg;
  struct GNUNET_TESTBED_PeerCreateSuccessEventMessage *reply;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  char *config;
  size_t dest_size;
  int ret;
  uint32_t config_size;
  uint16_t msize;
  

  msize = ntohs (message->size);
  if (msize <= sizeof (struct GNUNET_TESTBED_PeerCreateMessage))
  {
    GNUNET_break (0);           /* We need configuration */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  msg = (const struct GNUNET_TESTBED_PeerCreateMessage *) message;
  if (ntohl (msg->host_id) == master_context->host_id)
  {
    struct Peer *peer;
    char *emsg;
    
    /* We are responsible for this peer */
    msize -= sizeof (struct GNUNET_TESTBED_PeerCreateMessage);
    config_size = ntohl (msg->config_size);    
    config = GNUNET_malloc (config_size);
    dest_size = config_size;
    if (Z_OK != (ret = uncompress ((Bytef *) config, (uLongf *) &dest_size,
                                   (const Bytef *) &msg[1], (uLong) msize)))
    {
      GNUNET_break (0);           /* uncompression error */
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    if (config_size != dest_size)
    {
      GNUNET_break (0);/* Uncompressed config size mismatch */
      GNUNET_free (config);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    cfg = GNUNET_CONFIGURATION_create ();
    if (GNUNET_OK != GNUNET_CONFIGURATION_deserialize (cfg, config, config_size,
                                                       GNUNET_NO))
    {
      GNUNET_break (0);           /* Configuration parsing error */
      GNUNET_free (config);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    GNUNET_free (config);
    peer = GNUNET_malloc (sizeof (struct Peer));
    peer->cfg = cfg;
    peer->id = ntohl (msg->peer_id);
    LOG_DEBUG ("Creating peer with id: %u\n", peer->id);
    peer->peer = GNUNET_TESTING_peer_configure (master_context->system, peer->cfg,
                                                peer->id,
                                                NULL /* Peer id */,
                                                &emsg);
    if (NULL == peer->peer)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Configuring peer failed: %s\n", emsg);
      GNUNET_free (emsg);
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    peer_list_add (peer);
    reply = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_PeerCreateSuccessEventMessage));
    reply->header.size = htons (sizeof (struct GNUNET_TESTBED_PeerCreateSuccessEventMessage));
    reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_PEERCREATESUCCESS);
    reply->peer_id = msg->peer_id;
    reply->operation_id = msg->operation_id;
    queue_message (client, &reply->header);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  /* FIXME: Forward the peer to other host */
  GNUNET_break (0);
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
handle_peer_destroy (void *cls,
                     struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerDestroyMessage *msg;
  struct GNUNET_TESTBED_GenericOperationSuccessEventMessage *reply;
  uint32_t peer_id;
  uint32_t id;
  uint16_t reply_size;
  
  msg = (const struct GNUNET_TESTBED_PeerDestroyMessage *) message;
  peer_id = ntohl (msg->peer_id);
  LOG_DEBUG ("Received peer destory on peer: %u and operation id: %ul\n",
             peer_id, GNUNET_ntohll (msg->operation_id));
  if ((peer_list_size <= peer_id) || (NULL == peer_list[peer_id]))
  {
    GNUNET_break (0);
    /* FIXME: Reply with failure event message or forward to slave controller */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }  
  GNUNET_TESTING_peer_destroy (peer_list[peer_id]->peer);
  GNUNET_CONFIGURATION_destroy (peer_list[peer_id]->cfg);
  GNUNET_free (peer_list[peer_id]);
  peer_list[peer_id] = NULL;
  for (id = 0; id < LIST_GROW_STEP; id++)
  {
    if (((peer_id + id >= peer_list_size) ||
         (NULL != peer_list[peer_id])))
      break;
  }
  if (LIST_GROW_STEP == id)
  {
    peer_list_size -= LIST_GROW_STEP;
    peer_list = GNUNET_realloc (peer_list, peer_list_size);
  }
  reply_size = 
    sizeof (struct GNUNET_TESTBED_GenericOperationSuccessEventMessage);
  reply = GNUNET_malloc (reply_size);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_GENERICOPSUCCESS);
  reply->header.size = htons (reply_size);
  reply->operation_id = msg->operation_id;
  reply->event_type = htonl (GNUNET_TESTBED_ET_OPERATION_FINISHED);
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
handle_peer_start (void *cls,
		   struct GNUNET_SERVER_Client *client,
		   const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerStartMessage *msg;
  struct GNUNET_TESTBED_PeerEventMessage *reply;
  uint32_t peer_id;

  msg = (const struct GNUNET_TESTBED_PeerStartMessage *) message;
  peer_id = ntohl (msg->peer_id);
  if ((peer_id >= peer_list_size) 
      || (NULL == peer_list[peer_id]))
  {
    GNUNET_break (0);
    /* FIXME: reply with failure message or forward to slave controller */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (GNUNET_OK != GNUNET_TESTING_peer_start (peer_list[peer_id]->peer))
  {
    /* FIXME: return FAILURE message */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
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
handle_peer_stop (void *cls,
		  struct GNUNET_SERVER_Client *client,
		  const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerStopMessage *msg;
  struct GNUNET_TESTBED_PeerEventMessage *reply;
  uint32_t peer_id;

  msg = (const struct GNUNET_TESTBED_PeerStopMessage *) message;
  peer_id = ntohl (msg->peer_id);
  if ((peer_id >= peer_list_size) || (NULL == peer_list[peer_id]))
  {
    GNUNET_break (0);		/* FIXME: route to slave? */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (GNUNET_OK != GNUNET_TESTING_peer_stop (peer_list[peer_id]->peer))
  {
    /* FIXME: return FAILURE message */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
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
ss_map_free_iterator (void *cls,
                      const struct GNUNET_HashCode * key, void *value)
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
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct LCFContextQueue *lcfq;
  uint32_t id;

  shutdown_task_id = GNUNET_SCHEDULER_NO_TASK;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down testbed service\n");
  (void) GNUNET_CONTAINER_multihashmap_iterate (ss_map, &ss_map_free_iterator,
                                                NULL);
  GNUNET_CONTAINER_multihashmap_destroy (ss_map);  
  if (NULL != fh)
  {
    GNUNET_DISK_file_close (fh);
    fh = NULL;
  }
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
    GNUNET_free (lcfq->lcf->sxcfg);
    GNUNET_free (lcfq->lcf);
    GNUNET_CONTAINER_DLL_remove (lcfq_head, lcfq_tail, lcfq);
    GNUNET_free (lcfq);
  }
  /* Clear peer list */
  for (id = 0; id < peer_list_size; id++)
    if (NULL != peer_list[id])
    {
      GNUNET_TESTING_peer_destroy (peer_list[id]->peer);
      GNUNET_CONFIGURATION_destroy (peer_list[id]->cfg);
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
      GNUNET_assert (NULL != slave_list[id]->controller);
      GNUNET_TESTBED_controller_disconnect (slave_list[id]->controller);
      if (NULL != slave_list[id]->controller_proc)
        GNUNET_TESTBED_controller_stop (slave_list[id]->controller_proc);
    }
  GNUNET_free_non_null (master_context->master_ip);
  if (NULL != master_context->system)
    GNUNET_TESTING_system_destroy (master_context->system, GNUNET_YES);
  GNUNET_free_non_null (master_context);
}


/**
 * Debug shutdown task in case of stdin getting closed
 *
 * @param cls NULL
 * @param tc the TaskContext from scheduler
 */
static void
shutdown_task_ (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "STDIN closed ...\n");
  shutdown_task (cls, tc);
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
       from stdin, but if stdin fails for some reason, this shouldn't 
       hurt for now --- might need to revise this later if we ever
       decide that master connections might be temporarily down 
       for some reason */
    GNUNET_SCHEDULER_shutdown ();
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
testbed_run (void *cls,
             struct GNUNET_SERVER_Handle *server,
             const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler message_handlers[] =
    {
      {&handle_init, NULL, GNUNET_MESSAGE_TYPE_TESTBED_INIT,
       sizeof (struct GNUNET_TESTBED_InitMessage)},
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
      {NULL}
    };

  config = GNUNET_CONFIGURATION_dup (cfg);
  GNUNET_SERVER_add_handlers (server,
                              message_handlers);
  GNUNET_SERVER_disconnect_notify (server,
                                   &client_disconnect_cb,
                                   NULL);
  ss_map = GNUNET_CONTAINER_multihashmap_create (5);
  fh = GNUNET_DISK_get_handle_from_native (stdin);
  if (NULL == fh)
    shutdown_task_id = 
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				    &shutdown_task,
				    NULL);
  else
    shutdown_task_id = 
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
				      fh,
				      &shutdown_task_,
				      NULL);
  LOG_DEBUG ("Testbed startup complete\n");
}


/**
 * The starting point of execution
 */
int main (int argc, char *const *argv)
{
  return
    (GNUNET_OK ==
     GNUNET_SERVICE_run (argc,
                         argv,
                         "testbed",
                         GNUNET_SERVICE_OPTION_NONE,
                         &testbed_run,
                         NULL)) ? 0 : 1;
}
