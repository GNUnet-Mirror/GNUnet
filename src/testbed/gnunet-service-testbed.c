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

#define LOG(kind,...)                           \
  GNUNET_log (kind, __VA_ARGS__)


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
 * The master context; generated with the first INIT message
 */
static struct Context *master_context;

/**
 * The shutdown task handle
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task_id;


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
  const struct GNUNET_TESTBED_Message *msg;

  if (NULL != master_context)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GNUNET_TESTBED_Message *) message;  
  master_context = GNUNET_malloc (sizeof (struct Context));
  master_context->client = client;
  master_context->host_id = ntohl (msg->host_id);
  master_context->event_mask = GNUNET_ntohll (msg->event_mask);
  GNUNET_SERVER_client_keep (client);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Created master context with host ID: %u\n", master_context->host_id);
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
  char *username;
  char *hostname;
  uint16_t username_length;
  uint16_t hostname_length;
  
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
  host = GNUNET_TESTBED_host_create (hostname, username, ntohs
                                     (msg->ssh_port));
  /* Store host in a hashmap? But the host_id will be different */
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
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down testbed service\n");
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
    GNUNET_SCHEDULER_cancel (shutdown_task_id);    
    shutdown_task_id = 
      GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
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
       sizeof (struct GNUNET_TESTBED_Message)},
      {&handle_addhost, NULL, GNUNET_MESSAGE_TYPE_TESTBED_ADDHOST, 0},
      {NULL}
    };

  GNUNET_SERVER_add_handlers (server,
                              message_handlers);
  GNUNET_SERVER_disconnect_notify (server,
                                   &client_disconnect_cb,
                                   NULL);
  shutdown_task_id = 
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
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
