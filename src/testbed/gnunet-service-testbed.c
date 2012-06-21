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
 * The message queue head
 */
static struct MessageQueue *mq_head;

/**
 * The message queue tail
 */
static struct MessageQueue *mq_tail;

/**
 * Current Transmit Handle; NULL if no notify transmit exists currently
 */
struct GNUNET_SERVER_TransmitHandle *transmit_handle;


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
handle_addhost (void *cls,
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
  if (GNUNET_OK == host_list_add (host))
    return;
  /* We are unable to add a host */
  emsg = "A host exists with given host-id";
  GNUNET_TESTBED_host_destroy (host);
  reply_size = sizeof (struct GNUNET_TESTBED_HostConfirmedMessage)
    + strlen (emsg) + 1;
  reply = GNUNET_malloc (reply_size);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_ADDHOSTSUCCESS);
  reply->header.size = htons (reply_size);
  reply->host_id = htonl (host_id);
  memcpy (&reply[1], emsg, strlen (emsg) + 1);
  queue_message (client, (struct GNUNET_MessageHeader *) reply);
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

  shutdown_task_id = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_SCHEDULER_shutdown ();
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down testbed service\n");
  if (NULL != fh)
  {
    GNUNET_DISK_file_close (fh);
    fh = NULL;
  }
  for (host_id = 0; host_id < host_list_size; host_id++)
    if (NULL != host_list[host_id])
      GNUNET_TESTBED_host_destroy (host_list[host_id]);
  GNUNET_free_non_null (master_context);
  master_context = NULL;
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
      {&handle_addhost, NULL, GNUNET_MESSAGE_TYPE_TESTBED_ADDHOST, 0},
      {NULL}
    };

  GNUNET_SERVER_add_handlers (server,
                              message_handlers);
  GNUNET_SERVER_disconnect_notify (server,
                                   &client_disconnect_cb,
                                   NULL);  
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
