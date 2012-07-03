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

struct Context
{
  /**
   * The client handle associated with this context
   */
  struct GNUNET_SERVER_Client *client;
  
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
   * The forwarding (next hop) host id
   */
  uint32_t next_hop;

  /**
   * The controller handle if we have started the controller at the next hop
   * host 
   */
  struct GNUNET_TESTBED_Controller *fcontroller;
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
   * The configuration
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The handle of the controller this request has to be forwarded to
   */
  struct GNUNET_TESTBED_Controller *fcontroller;

  /**
   * The host registration handle while registered hosts in this context
   */
  struct GNUNET_TESTBED_HostRegistrationHandle *rhandle;

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
 * Wrapped stdin.
 */
static struct GNUNET_DISK_FileHandle *fh;

/**
 * The master context; generated with the first INIT message
 */
static struct Context *master_context;

/**
 * The shutdown task handle
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task_id;

/**
 * Array of host list
 */
static struct GNUNET_TESTBED_Host **host_list;

/**
 * The size of the host list
 */
static uint32_t host_list_size;

/**
 * A list of routes
 */
static struct Route **route_list;

/**
 * The size of the route list
 */
static uint32_t route_list_size;

/**
 * The message queue head
 */
static struct MessageQueue *mq_head;

/**
 * The message queue tail
 */
static struct MessageQueue *mq_tail;

/**
 * The head for the LCF queue
 */
static struct LCFContextQueue *lcfq_head;

/**
 * The tail for the LCF queue
 */
static struct LCFContextQueue *lcfq_tail;

/**
 * Current Transmit Handle; NULL if no notify transmit exists currently
 */
struct GNUNET_SERVER_TransmitHandle *transmit_handle;

/**
 * The hashmap of shared services
 */
struct GNUNET_CONTAINER_MultiHashMap *ss_map;


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
    host_list = GNUNET_realloc (host_list, 
                                sizeof (struct GNUNET_TESTBED_Host *)
                                * (host_id + 10));
    host_list_size += (host_id + 10);
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
  switch (lcf->state)
  {
  case INIT:
    if (NULL != emsg)
      goto registration_error;
    lcf->state = DELEGATED_HOST_REGISTERED;
    (void) GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    break;
  case DELEGATED_HOST_REGISTERED:
     if (NULL != emsg)
      goto registration_error;
     lcf->state = SLAVE_HOST_REGISTERED;
     (void) GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
     break;
  default:
    GNUNET_assert (0); 		/* Shouldn't reach here */
  }  
  return;

 registration_error:
  LOG (GNUNET_ERROR_TYPE_WARNING, 
       "Host registration failed with message: %s\n", emsg);
  lcf->state = FINISHED;
  (void) GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
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

  switch (lcf->state)
  {
  case INIT:
    if (GNUNET_NO ==
	GNUNET_TESTBED_is_host_registered_ (host_list[lcf->delegated_host_id],
					    lcf->fcontroller))
    {
      lcf->rhandle =
	GNUNET_TESTBED_register_host (lcf->fcontroller,
				      host_list[lcf->delegated_host_id],
				      lcf_proc_cc, lcf);						   
    }
    else
    {
      lcf->state = DELEGATED_HOST_REGISTERED;
      (void) GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    }
    break;
  case DELEGATED_HOST_REGISTERED:
    if (GNUNET_NO ==
	GNUNET_TESTBED_is_host_registered_ (host_list[lcf->slave_host_id],
					    lcf->fcontroller))
    {
      lcf->rhandle =
	GNUNET_TESTBED_register_host (lcf->fcontroller,
				      host_list[lcf->slave_host_id],
				      lcf_proc_cc, lcf);						   
    }
    else
    {
      lcf->state = SLAVE_HOST_REGISTERED;
      (void) GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    }
    break;
  case SLAVE_HOST_REGISTERED:
    GNUNET_TESTBED_controller_link (lcf->fcontroller,
				    host_list[lcf->delegated_host_id],
				    host_list[lcf->slave_host_id],
				    lcf->cfg, lcf->is_subordinate);
    lcf->state = FINISHED;
    break;
  case FINISHED:
    lcfq = lcfq_head;
    GNUNET_CONFIGURATION_destroy (lcfq->lcf->cfg);
    GNUNET_free (lcfq->lcf);
    GNUNET_CONTAINER_DLL_remove (lcfq_head, lcfq_tail, lcfq);
    GNUNET_free (lcfq);
    if (NULL != lcfq_head)
      (void) GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcfq_head->lcf);
  }
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
  if (strlen (hostname) != hostname_length)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  host_id = ntohl (msg->host_id);
  LOG_DEBUG ("Received ADDHOST message\n");
  LOG_DEBUG ("-------host id: %u\n", host_id);
  if (NULL != hostname) LOG_DEBUG ("-------hostname: %s\n", hostname);
  if (NULL != username) LOG_DEBUG ("-------username: %s\n", username);
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
  struct LCFContextQueue *lcfq;
  struct Route *route;
  char *config;  
  uLongf dest_size;
  size_t config_size;
  uint32_t delegated_host_id;
  uint32_t slave_host_id;
  uint16_t msize;
   
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

  config_size = ntohs (msg->config_size);
  config = GNUNET_malloc (config_size);
  dest_size = (uLongf) config_size;
  msize -= sizeof (struct GNUNET_TESTBED_ControllerLinkMessage);
  if (Z_OK != uncompress ((Bytef *) config, &dest_size,
                          (const Bytef *) &msg[1], (uLong) msize))
  {
    GNUNET_break (0);           /* Compression error */
    GNUNET_free (config);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_assert (config_size == dest_size);
  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK != GNUNET_CONFIGURATION_deserialize (cfg, config, config_size,
                                                     GNUNET_NO))
  {
    GNUNET_break (0);           /* Configuration parsing error */
    GNUNET_break (config);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_free (config);

  /* If delegated host and slave host are not same we have to forward
     towards delegated host */
  if (slave_host_id != delegated_host_id)
  {
    if ((slave_host_id >= route_list_size) ||
	(NULL == (route = route_list[slave_host_id])) ||
	(NULL == route->fcontroller))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Not route towards slave host");
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    if (slave_host_id == route->next_hop) /* Slave directly connected */
    {
      /* Then make slave host and delegated host same so that slave
	 will startup directly link to the delegated host */
      slave_host_id = delegated_host_id;
    }
    lcfq = GNUNET_malloc (sizeof (struct LCFContextQueue));
    lcfq->lcf = GNUNET_malloc (sizeof (struct LCFContext));
    lcfq->lcf->delegated_host_id = delegated_host_id;
    lcfq->lcf->slave_host_id = slave_host_id;
    lcfq->lcf->is_subordinate =
      (1 == msg->is_subordinate) ? GNUNET_YES : GNUNET_NO;
    lcfq->lcf->state = INIT;
    lcfq->lcf->fcontroller = route->fcontroller;
    lcfq->lcf->cfg = cfg;
    if (NULL == lcfq_head)
    {
      GNUNET_CONTAINER_DLL_insert_tail (lcfq_head, lcfq_tail, lcfq);
      (void) GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcfq);
    }
    else
      GNUNET_CONTAINER_DLL_insert_tail (lcfq_head, lcfq_tail, lcfq);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  /* If we are not the slave controller then we have to route the request
     towards the slave controller */
  if (1 == msg->is_subordinate)
  {
    GNUNET_break (0);           /* FIXME: Implement the slave controller
                                   startup */ 
  }  
  GNUNET_CONFIGURATION_destroy (cfg);
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
  uint32_t host_id;
  uint32_t route_id;

  shutdown_task_id = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_SCHEDULER_shutdown ();
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down testbed service\n");
  (void) GNUNET_CONTAINER_multihashmap_iterate (ss_map, &ss_map_free_iterator,
                                                NULL);
  GNUNET_CONTAINER_multihashmap_destroy (ss_map);
  if (NULL != fh)
  {
    GNUNET_DISK_file_close (fh);
    fh = NULL;
  }
  /* Clear host list */
  for (host_id = 0; host_id < host_list_size; host_id++)
    if (NULL != host_list[host_id])
      GNUNET_TESTBED_host_destroy (host_list[host_id]);
  GNUNET_free_non_null (host_list);
  /* Clear route list */
  for (route_id = 0; route_id < route_list_size; route_id++)
    if (NULL != route_list[route_id])
    {
      if (NULL != route_list[route_id]->fcontroller)
        GNUNET_TESTBED_controller_stop (route_list[route_id]->fcontroller);
      GNUNET_free (route_list[route_id]);
    }
  GNUNET_free_non_null (route_list);
  GNUNET_free_non_null (master_context);
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
      {NULL}
    };

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
				      &shutdown_task,
				      NULL);
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
