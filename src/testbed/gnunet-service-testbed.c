/*
  This file is part of GNUnet.
  (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-service-testbed.c
 * @brief implementation of the TESTBED service
 * @author Sree Harsha Totakura
 */

#include "gnunet-service-testbed.h"
#include "gnunet-service-testbed_barriers.h"
#include "gnunet-service-testbed_connectionpool.h"

/***********/
/* Globals */
/***********/

/**
 * Our configuration
 */
struct GNUNET_CONFIGURATION_Handle *GST_config;

/**
 * The master context; generated with the first INIT message
 */
struct Context *GST_context;

/**
 * Array of hosts
 */
struct GNUNET_TESTBED_Host **GST_host_list;

/**
 * DLL head for forwarded operation contexts
 */
struct ForwardedOperationContext *fopcq_head;

/**
 * DLL tail for forwarded operation contexts
 */
struct ForwardedOperationContext *fopcq_tail;

/**
 * Operation queue for open file descriptors
 */
struct OperationQueue *GST_opq_openfds;

/**
 * Timeout for operations which may take some time
 */
const struct GNUNET_TIME_Relative GST_timeout;

/**
 * The size of the host list
 */
unsigned int GST_host_list_size;

/**
 * The size of the peer list
 */
unsigned int GST_peer_list_size;


/***********************************/
/* Local definitions and variables */
/***********************************/

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
 * Our hostname; we give this to all the peers we start
 */
static char *hostname;

/**
 * Current Transmit Handle; NULL if no notify transmit exists currently
 */
static struct GNUNET_SERVER_TransmitHandle *transmit_handle;

/**
 * The message queue head
 */
static struct MessageQueue *mq_head;

/**
 * The message queue tail
 */
static struct MessageQueue *mq_tail;


/**
 * The shutdown task handle
 */
static struct GNUNET_SCHEDULER_Task * shutdown_task_id;


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
  GNUNET_SERVER_client_drop (mq_entry->client);
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
void
GST_queue_message (struct GNUNET_SERVER_Client *client,
                   struct GNUNET_MessageHeader *msg)
{
  struct MessageQueue *mq_entry;
  uint16_t type;
  uint16_t size;

  type = ntohs (msg->type);
  size = ntohs (msg->size);
  GNUNET_assert ((GNUNET_MESSAGE_TYPE_TESTBED_INIT <= type) &&
                 (GNUNET_MESSAGE_TYPE_TESTBED_MAX > type));
  mq_entry = GNUNET_new (struct MessageQueue);
  mq_entry->msg = msg;
  mq_entry->client = client;
  GNUNET_SERVER_client_keep (client);
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
  if (GST_host_list_size <= host_id)
    GST_array_grow_large_enough (GST_host_list, GST_host_list_size, host_id);
  if (NULL != GST_host_list[host_id])
  {
    LOG_DEBUG ("A host with id: %u already exists\n", host_id);
    return GNUNET_SYSERR;
  }
  GST_host_list[host_id] = host;
  return GNUNET_OK;
}


/**
 * Send operation failure message to client
 *
 * @param client the client to which the failure message has to be sent to
 * @param operation_id the id of the failed operation
 * @param emsg the error message; can be NULL
 */
void
GST_send_operation_fail_msg (struct GNUNET_SERVER_Client *client,
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
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_OPERATION_FAIL_EVENT);
  msg->event_type = htonl (GNUNET_TESTBED_ET_OPERATION_FINISHED);
  msg->operation_id = GNUNET_htonll (operation_id);
  if (0 != emsg_len)
    memcpy (&msg[1], emsg, emsg_len);
  GST_queue_message (client, &msg->header);
}


/**
 * Function to send generic operation success message to given client
 *
 * @param client the client to send the message to
 * @param operation_id the id of the operation which was successful
 */
void
GST_send_operation_success_msg (struct GNUNET_SERVER_Client *client,
                                uint64_t operation_id)
{
  struct GNUNET_TESTBED_GenericOperationSuccessEventMessage *msg;
  uint16_t msize;

  msize = sizeof (struct GNUNET_TESTBED_GenericOperationSuccessEventMessage);
  msg = GNUNET_malloc (msize);
  msg->header.size = htons (msize);
  msg->header.type =
      htons (GNUNET_MESSAGE_TYPE_TESTBED_GENERIC_OPERATION_SUCCESS);
  msg->operation_id = GNUNET_htonll (operation_id);
  msg->event_type = htonl (GNUNET_TESTBED_ET_OPERATION_FINISHED);
  GST_queue_message (client, &msg->header);
}

/**
 * Callback which will be called after a host registration succeeded or failed
 *
 * @param cls the handle to the slave at which the registration is completed
 * @param emsg the error message; NULL if host registration is successful
 */
static void
hr_completion (void *cls, const char *emsg);


/**
 * Attempts to register the next host in the host registration queue
 *
 * @param slave the slave controller whose host registration queue is checked
 *          for host registrations
 */
static void
register_next_host (struct Slave *slave)
{
  struct HostRegistration *hr;

  hr = slave->hr_dll_head;
  GNUNET_assert (NULL != hr);
  GNUNET_assert (NULL == slave->rhandle);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Registering host %u at %u\n",
       GNUNET_TESTBED_host_get_id_ (hr->host),
       GNUNET_TESTBED_host_get_id_ (GST_host_list[slave->host_id]));
  slave->rhandle =
      GNUNET_TESTBED_register_host (slave->controller, hr->host, hr_completion,
                                    slave);
}


/**
 * Callback which will be called to after a host registration succeeded or failed
 *
 * @param cls the handle to the slave at which the registration is completed
 * @param emsg the error message; NULL if host registration is successful
 */
static void
hr_completion (void *cls, const char *emsg)
{
  struct Slave *slave = cls;
  struct HostRegistration *hr;

  slave->rhandle = NULL;
  hr = slave->hr_dll_head;
  GNUNET_assert (NULL != hr);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Registering host %u at %u successful\n",
       GNUNET_TESTBED_host_get_id_ (hr->host),
       GNUNET_TESTBED_host_get_id_ (GST_host_list[slave->host_id]));
  GNUNET_CONTAINER_DLL_remove (slave->hr_dll_head, slave->hr_dll_tail, hr);
  if (NULL != hr->cb)
    hr->cb (hr->cb_cls, emsg);
  GNUNET_free (hr);
  if (NULL != slave->hr_dll_head)
    register_next_host (slave);
}


/**
 * Adds a host registration's request to a slave's registration queue
 *
 * @param slave the slave controller at which the given host has to be
 *          registered
 * @param cb the host registration completion callback
 * @param cb_cls the closure for the host registration completion callback
 * @param host the host which has to be registered
 */
void
GST_queue_host_registration (struct Slave *slave,
                             GNUNET_TESTBED_HostRegistrationCompletion cb,
                             void *cb_cls, struct GNUNET_TESTBED_Host *host)
{
  struct HostRegistration *hr;
  int call_register;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queueing host registration for host %u at %u\n",
       GNUNET_TESTBED_host_get_id_ (host),
       GNUNET_TESTBED_host_get_id_ (GST_host_list[slave->host_id]));
  hr = GNUNET_new (struct HostRegistration);
  hr->cb = cb;
  hr->cb_cls = cb_cls;
  hr->host = host;
  call_register = (NULL == slave->hr_dll_head) ? GNUNET_YES : GNUNET_NO;
  GNUNET_CONTAINER_DLL_insert_tail (slave->hr_dll_head, slave->hr_dll_tail, hr);
  if (GNUNET_YES == call_register)
    register_next_host (slave);
}


/**
 * Callback to relay the reply msg of a forwarded operation back to the client
 *
 * @param cls ForwardedOperationContext
 * @param msg the message to relay
 */
void
GST_forwarded_operation_reply_relay (void *cls,
                                     const struct GNUNET_MessageHeader *msg)
{
  struct ForwardedOperationContext *fopc = cls;
  struct GNUNET_MessageHeader *dup_msg;
  uint16_t msize;

  msize = ntohs (msg->size);
  LOG_DEBUG ("Relaying message with type: %u, size: %u\n", ntohs (msg->type),
             msize);
  dup_msg = GNUNET_copy_message (msg);
  GST_queue_message (fopc->client, dup_msg);
  GNUNET_SERVER_client_drop (fopc->client);
  GNUNET_SCHEDULER_cancel (fopc->timeout_task);
  GNUNET_CONTAINER_DLL_remove (fopcq_head, fopcq_tail, fopc);
  GNUNET_free (fopc);
}


/**
 * Task to free resources when forwarded operation has been timedout
 *
 * @param cls the ForwardedOperationContext
 * @param tc the task context from scheduler
 */
void
GST_forwarded_operation_timeout (void *cls,
                                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedOperationContext *fopc = cls;

  GNUNET_TESTBED_forward_operation_msg_cancel_ (fopc->opc);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "A forwarded operation has timed out\n");
  GST_send_operation_fail_msg (fopc->client, fopc->operation_id,
                               "A forwarded operation has timed out");
  GNUNET_SERVER_client_drop (fopc->client);
  GNUNET_CONTAINER_DLL_remove (fopcq_head, fopcq_tail, fopc);
  GNUNET_free (fopc);
}


/**
 * Parse service sharing specification line.
 * Format is "[<service:share>] [<service:share>] ..."
 *
 * @param ss_str the spec string to be parsed
 * @param cfg the configuration to use for shared services
 * @return an array suitable to pass to GNUNET_TESTING_system_create().  NULL
 *           upon empty service sharing specification.
 */
static struct GNUNET_TESTING_SharedService *
parse_shared_services (char *ss_str, struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_TESTING_SharedService ss;
  struct GNUNET_TESTING_SharedService *slist;
  char service[256];
  char *arg;
  unsigned int n;
#define GROW_SS                                 \
  do {                                          \
    GNUNET_array_grow (slist, n, n+1);                                  \
    (void) memcpy (&slist[n - 1], &ss,                                  \
                   sizeof (struct GNUNET_TESTING_SharedService));       \
  } while (0)

  slist = NULL;
  n = 0;
  ss.cfg = cfg;
  for (; NULL != (arg = strtok (ss_str, " ")); ss_str = NULL)
  {
    ss.service = NULL;
    ss.share = 0;
    if (2 != sscanf (arg, "%255[^:]:%u", service, &ss.share))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Ignoring shared service spec: %s", arg);
      continue;
    }
    LOG_DEBUG ("Will be sharing %s service among %u peers\n", service, ss.share);
    ss.service = GNUNET_strdup (service);
    GROW_SS;
  }
  if (NULL != slist)
  {
    /* Add trailing NULL block */
    (void) memset (&ss, 0, sizeof (struct GNUNET_TESTING_SharedService));
    GROW_SS;
  }
  return slist;
#undef GROW_SS
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
  char *ss_str;
  struct GNUNET_TESTING_SharedService *ss;
  unsigned int cnt;
  uint16_t msize;

  if (NULL != GST_context)
  {
    LOG_DEBUG ("We are being connected to laterally\n");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
  ss_str = NULL;
  ss = NULL;
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (GST_config, "TESTBED",
                                                          "SHARED_SERVICES",
                                                          &ss_str))
  {
    ss = parse_shared_services (ss_str, GST_config);
    GNUNET_free (ss_str);
    ss_str = NULL;
  }
  GST_context = GNUNET_new (struct Context);
  GNUNET_SERVER_client_keep (client);
  GST_context->client = client;
  GST_context->host_id = ntohl (msg->host_id);
  GST_context->master_ip = GNUNET_strdup (controller_hostname);
  LOG_DEBUG ("Our IP: %s\n", GST_context->master_ip);
  GST_context->system =
      GNUNET_TESTING_system_create ("testbed", GST_context->master_ip,
                                    hostname, ss);
  if (NULL != ss)
  {
    for (cnt = 0; NULL != ss[cnt].service; cnt++)
    {
      ss_str = (char *) ss[cnt].service;
      GNUNET_free (ss_str);
    }
    GNUNET_free (ss);
    ss = NULL;
  }
  host =
      GNUNET_TESTBED_host_create_with_id (GST_context->host_id,
                                          GST_context->master_ip, NULL,
                                          GST_config, 0);
  host_list_add (host);
  LOG_DEBUG ("Created master context with host ID: %u\n", GST_context->host_id);
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
  struct GNUNET_CONFIGURATION_Handle *host_cfg;
  char *username;
  char *hostname;
  char *emsg;
  const void *ptr;
  uint32_t host_id;
  uint16_t username_length;
  uint16_t hostname_length;
  uint16_t reply_size;
  uint16_t msize;

  msg = (const struct GNUNET_TESTBED_AddHostMessage *) message;
  msize = ntohs (msg->header.size);
  if (msize <= sizeof (struct GNUNET_TESTBED_AddHostMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  username_length = ntohs (msg->username_length);
  hostname_length = ntohs (msg->hostname_length);
  /* msg must contain hostname */
  if ((msize <= (sizeof (struct GNUNET_TESTBED_AddHostMessage) +
                 username_length))
      || (0 == hostname_length))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  /* msg must contain configuration */
  if (msize <= (sizeof (struct GNUNET_TESTBED_AddHostMessage) +
                username_length + hostname_length))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  username = NULL;
  hostname = NULL;
  ptr = &msg[1];
  if (0 != username_length)
  {
    username = GNUNET_malloc (username_length + 1);
    strncpy (username, ptr, username_length);
    ptr += username_length;
  }
  hostname = GNUNET_malloc (hostname_length + 1);
  strncpy (hostname, ptr, hostname_length);
  if (NULL == (host_cfg = GNUNET_TESTBED_extract_config_ (message)))
  {
    GNUNET_free_non_null (username);
    GNUNET_free_non_null (hostname);
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  host_id = ntohl (msg->host_id);
  LOG_DEBUG ("Received ADDHOST %u message\n", host_id);
  LOG_DEBUG ("-------host id: %u\n", host_id);
  LOG_DEBUG ("-------hostname: %s\n", hostname);
  if (NULL != username)
    LOG_DEBUG ("-------username: %s\n", username);
  else
    LOG_DEBUG ("-------username: <not given>\n");
  LOG_DEBUG ("-------ssh port: %u\n", ntohs (msg->ssh_port));
  host =
      GNUNET_TESTBED_host_create_with_id (host_id, hostname, username,
                                          host_cfg, ntohs (msg->ssh_port));
  GNUNET_free_non_null (username);
  GNUNET_free (hostname);
  GNUNET_CONFIGURATION_destroy (host_cfg);
  if (NULL == host)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
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
  {
    LOG_DEBUG ("Added host %u at %u\n", host_id, GST_context->host_id);
    reply = GNUNET_malloc (reply_size);
  }
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST_SUCCESS);
  reply->header.size = htons (reply_size);
  reply->host_id = htonl (host_id);
  GST_queue_message (client, &reply->header);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_GETSLAVECONFIG messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_slave_get_config (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_TESTBED_SlaveGetConfigurationMessage *msg;
  struct Slave *slave;
  struct GNUNET_TESTBED_SlaveConfiguration *reply;
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  char *config;
  char *xconfig;
  size_t config_size;
  size_t xconfig_size;
  size_t reply_size;
  uint64_t op_id;
  uint32_t slave_id;

  msg = (struct GNUNET_TESTBED_SlaveGetConfigurationMessage *) message;
  slave_id = ntohl (msg->slave_id);
  op_id = GNUNET_ntohll (msg->operation_id);
  if ((GST_slave_list_size <= slave_id) || (NULL == GST_slave_list[slave_id]))
  {
    /* FIXME: Add forwardings for this type of message here.. */
    GST_send_operation_fail_msg (client, op_id, "Slave not found");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  slave = GST_slave_list[slave_id];
  GNUNET_assert (NULL != (cfg = GNUNET_TESTBED_host_get_cfg_ (GST_host_list[slave->host_id])));
  config = GNUNET_CONFIGURATION_serialize (cfg, &config_size);
  xconfig_size =
      GNUNET_TESTBED_compress_config_ (config, config_size, &xconfig);
  GNUNET_free (config);
  reply_size = xconfig_size + sizeof (struct GNUNET_TESTBED_SlaveConfiguration);
  GNUNET_break (reply_size <= UINT16_MAX);
  GNUNET_break (config_size <= UINT16_MAX);
  reply = GNUNET_realloc (xconfig, reply_size);
  (void) memmove (&reply[1], reply, xconfig_size);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_SLAVE_CONFIGURATION);
  reply->header.size = htons ((uint16_t) reply_size);
  reply->slave_id = msg->slave_id;
  reply->operation_id = msg->operation_id;
  reply->config_size = htons ((uint16_t) config_size);
  GST_queue_message (client, &reply->header);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Clears the forwarded operations queue
 */
void
GST_clear_fopcq ()
{
  struct ForwardedOperationContext *fopc;

  while (NULL != (fopc = fopcq_head))
  {
    GNUNET_CONTAINER_DLL_remove (fopcq_head, fopcq_tail, fopc);
    GNUNET_TESTBED_forward_operation_msg_cancel_ (fopc->opc);
    if (NULL != fopc->timeout_task)
      GNUNET_SCHEDULER_cancel (fopc->timeout_task);
    GNUNET_SERVER_client_drop (fopc->client);
    switch (fopc->type)
    {
    case OP_PEER_CREATE:
      GNUNET_free (fopc->cls);
      break;
    case OP_SHUTDOWN_PEERS:
      {
        struct HandlerContext_ShutdownPeers *hc = fopc->cls;

        GNUNET_assert (0 < hc->nslaves);
        hc->nslaves--;
        if (0 == hc->nslaves)
          GNUNET_free (hc);
      }
      break;
    case OP_PEER_START:
    case OP_PEER_STOP:
    case OP_PEER_DESTROY:
    case OP_PEER_INFO:
    case OP_OVERLAY_CONNECT:
    case OP_LINK_CONTROLLERS:
    case OP_GET_SLAVE_CONFIG:
    case OP_MANAGE_SERVICE:
    case OP_PEER_RECONFIGURE:
      break;
    case OP_FORWARDED:
      GNUNET_assert (0);
    };
    GNUNET_free (fopc);
  }
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
  struct MessageQueue *mq_entry;
  uint32_t id;

  shutdown_task_id = NULL;
  LOG_DEBUG ("Shutting down testbed service\n");
  /* cleanup any remaining forwarded operations */
  GST_clear_fopcq ();
  GST_free_lcfq ();
  GST_free_mctxq ();
  GST_free_occq ();
  GST_free_roccq ();
  GST_free_nccq ();
  GST_neighbour_list_clean();
  GST_free_prcq ();
  /* Clear peer list */
  GST_destroy_peers ();
  /* Clear route list */
  GST_route_list_clear ();
  /* Clear GST_slave_list */
  GST_slave_list_clear ();
  /* Clear host list */
  for (id = 0; id < GST_host_list_size; id++)
    if (NULL != GST_host_list[id])
      GNUNET_TESTBED_host_destroy (GST_host_list[id]);
  GNUNET_free_non_null (GST_host_list);
  if (NULL != GST_context)
  {
    GNUNET_free_non_null (GST_context->master_ip);
    if (NULL != GST_context->system)
      GNUNET_TESTING_system_destroy (GST_context->system, GNUNET_YES);
    GNUNET_SERVER_client_drop (GST_context->client);
    GNUNET_free (GST_context);
    GST_context = NULL;
  }
  if (NULL != transmit_handle)
    GNUNET_SERVER_notify_transmit_ready_cancel (transmit_handle);
  while (NULL != (mq_entry = mq_head))
  {
    GNUNET_free (mq_entry->msg);
    GNUNET_SERVER_client_drop (mq_entry->client);
    GNUNET_CONTAINER_DLL_remove (mq_head, mq_tail, mq_entry);
    GNUNET_free (mq_entry);
  }
  GNUNET_free_non_null (hostname);
  /* Free hello cache */
  GST_cache_clear ();
  GST_connection_pool_destroy ();
  GNUNET_TESTBED_operation_queue_destroy_ (GST_opq_openfds);
  GST_opq_openfds = NULL;
  GST_stats_destroy ();
  GST_barriers_destroy ();
  GNUNET_CONFIGURATION_destroy (GST_config);
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
  if (NULL == GST_context)
    return;
  if (client == GST_context->client)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Master client disconnected\n");
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
    {&handle_add_host, NULL, GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST, 0},
    {&GST_handle_link_controllers, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS,
     sizeof (struct GNUNET_TESTBED_ControllerLinkRequest)},
    {&GST_handle_peer_create, NULL, GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER, 0},
    {&GST_handle_peer_destroy, NULL, GNUNET_MESSAGE_TYPE_TESTBED_DESTROY_PEER,
     sizeof (struct GNUNET_TESTBED_PeerDestroyMessage)},
    {&GST_handle_peer_start, NULL, GNUNET_MESSAGE_TYPE_TESTBED_START_PEER,
     sizeof (struct GNUNET_TESTBED_PeerStartMessage)},
    {&GST_handle_peer_stop, NULL, GNUNET_MESSAGE_TYPE_TESTBED_STOP_PEER,
     sizeof (struct GNUNET_TESTBED_PeerStopMessage)},
    {&GST_handle_peer_get_config, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_GET_PEER_INFORMATION,
     sizeof (struct GNUNET_TESTBED_PeerGetConfigurationMessage)},
    {&GST_handle_overlay_connect, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_OVERLAY_CONNECT,
     sizeof (struct GNUNET_TESTBED_OverlayConnectMessage)},
    {&GST_handle_remote_overlay_connect, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_REMOTE_OVERLAY_CONNECT, 0},
    {&GST_handle_manage_peer_service, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_MANAGE_PEER_SERVICE, 0},
    {&handle_slave_get_config, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_GET_SLAVE_CONFIGURATION,
     sizeof (struct GNUNET_TESTBED_SlaveGetConfigurationMessage)},
    {&GST_handle_shutdown_peers, NULL, GNUNET_MESSAGE_TYPE_TESTBED_SHUTDOWN_PEERS,
     sizeof (struct GNUNET_TESTBED_ShutdownPeersMessage)},
    {&GST_handle_peer_reconfigure, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_RECONFIGURE_PEER, 0},
    {&GST_handle_barrier_init, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_INIT, 0},
    {&GST_handle_barrier_cancel, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_CANCEL, 0},
    {&GST_handle_barrier_status, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS, 0},
    {NULL, NULL, 0, 0}
  };
  char *logfile;
  unsigned long long num;

  LOG_DEBUG ("Starting testbed\n");
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_filename (cfg, "TESTBED", "LOG_FILE",
                                               &logfile))
  {
    GNUNET_break (GNUNET_OK == GNUNET_log_setup ("testbed", "DEBUG", logfile));
    GNUNET_free (logfile);
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_number (cfg, "TESTBED",
                                                        "CACHE_SIZE", &num));
  GST_cache_init ((unsigned int) num);
  GST_connection_pool_init ((unsigned int) num);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_number (cfg, "TESTBED",
                                                        "MAX_OPEN_FDS", &num));
  GST_opq_openfds = GNUNET_TESTBED_operation_queue_create_
      (OPERATION_QUEUE_TYPE_FIXED, (unsigned int) num);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_time (cfg, "TESTBED",
                                                      "OPERATION_TIMEOUT",
                                                      (struct
                                                       GNUNET_TIME_Relative *)
                                                      &GST_timeout));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (cfg, "testbed",
                                                        "HOSTNAME", &hostname));
  GST_config = GNUNET_CONFIGURATION_dup (cfg);
  GNUNET_SERVER_add_handlers (server, message_handlers);
  GNUNET_SERVER_disconnect_notify (server, &client_disconnect_cb, NULL);
  shutdown_task_id =
      GNUNET_SCHEDULER_add_delayed_with_priority (GNUNET_TIME_UNIT_FOREVER_REL,
                                                  GNUNET_SCHEDULER_PRIORITY_IDLE,
                                                  &shutdown_task, NULL);
  LOG_DEBUG ("Testbed startup complete\n");
  GST_stats_init (GST_config);
  GST_barriers_init (GST_config);
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
