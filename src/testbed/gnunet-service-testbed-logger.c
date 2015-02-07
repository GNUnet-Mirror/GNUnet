/*
  This file is part of GNUnet.
  Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-service-testbed-logger.c
 * @brief service for collecting messages and writing to a file
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_util_lib.h"

/**
 * Generic logging shorthand
 */
#define LOG(type, ...)                         \
  GNUNET_log (type, __VA_ARGS__)

/**
 * Debug logging shorthand
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

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
 * The message queue head
 */
static struct MessageQueue *mq_head;

/**
 * The message queue tail
 */
static struct MessageQueue *mq_tail;

/**
 * Handle for buffered writing.
 */
struct GNUNET_BIO_WriteHandle *bio;

/**
 * The shutdown task handle
 */
static struct GNUNET_SCHEDULER_Task * shutdown_task_id;

/**
 * The number of connections we have
 */
static unsigned int nconn;

/**
 * Are we shutting down?
 */
static int in_shutdown;

/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_ADDHOST messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param msg the actual message
 */
static void
handle_log_msg (void *cls, struct GNUNET_SERVER_Client *client,
                const struct GNUNET_MessageHeader *msg)
{
  uint16_t ms;

  ms = ntohs (msg->size);
  ms -= sizeof (struct GNUNET_MessageHeader);
  GNUNET_BIO_write (bio, &msg[1], ms);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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

  shutdown_task_id = NULL;
  in_shutdown = GNUNET_YES;
  if (0 != nconn)
  {
    /* Delay shutdown if there are active connections */
    shutdown_task_id = GNUNET_SCHEDULER_add_delayed
        (GNUNET_TIME_UNIT_FOREVER_REL,
         &shutdown_task, NULL);
    return;
  }
  while (NULL != (mq_entry = mq_head))
  {
    GNUNET_free (mq_entry->msg);
    GNUNET_SERVER_client_drop (mq_entry->client);
    GNUNET_CONTAINER_DLL_remove (mq_head, mq_tail, mq_entry);
    GNUNET_free (mq_entry);
  }
  GNUNET_break (GNUNET_OK == GNUNET_BIO_write_close (bio));
}


/**
 * Functions with this signature are called whenever a client
 * is disconnected on the network level.
 *
 * @param cls closure
 * @param client identification of the client; NULL
 *        for the last call when the server is destroyed
 */
static void 
client_disconnected (void *cls, struct GNUNET_SERVER_Client *client)
{
  if (NULL == client)
  {
    GNUNET_break (0 == nconn);
    return;
  }
  nconn--;
  if (GNUNET_YES != in_shutdown)
    return;
  GNUNET_assert (NULL != shutdown_task_id);
  GNUNET_SCHEDULER_cancel (shutdown_task_id);
  shutdown_task_id = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}


/**
 * Functions with this signature are called whenever a client
 * is connected on the network level.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
client_connected (void *cls, struct GNUNET_SERVER_Client *client)
{
  if (NULL == client)
  {
    GNUNET_break (0 == nconn);
    return;
  }
  GNUNET_SERVER_client_persist_ (client);
  nconn++;
}


/**
 * Testbed setup
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
logger_run (void *cls, struct GNUNET_SERVER_Handle *server,
             const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler message_handlers[] = {
    {&handle_log_msg, NULL, GNUNET_MESSAGE_TYPE_TESTBED_LOGGER_MSG, 0},
    {NULL, NULL, 0, 0}
  };
  char *dir;
  char *fn;
  char *hname;
  size_t hname_len;
  pid_t pid;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "TESTBED-LOGGER", "DIR",
                                               &dir))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Not logging directory definied.  Exiting\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  pid = getpid ();
  hname_len = GNUNET_OS_get_hostname_max_length ();
  hname = GNUNET_malloc (hname_len);
  if (0 != gethostname (hname, hname_len))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Cannot get hostname.  Exiting\n");
    GNUNET_free (hname);
    GNUNET_free (dir);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  (void) GNUNET_asprintf (&fn, "%s/%.*s_%jd.dat", dir, hname_len, hname,
                          (intmax_t) pid);
  GNUNET_free (hname);
  GNUNET_free (dir);
  if (NULL == (bio = GNUNET_BIO_write_open (fn)))
  {
    GNUNET_free (fn);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_free (fn);
  GNUNET_SERVER_add_handlers (server, message_handlers);
  GNUNET_SERVER_connect_notify (server, &client_connected, NULL);
  GNUNET_SERVER_disconnect_notify (server, &client_disconnected, NULL);
  shutdown_task_id =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                    &shutdown_task, NULL);
  LOG_DEBUG ("TESTBED-LOGGER startup complete\n");
}


/**
 * The starting point of execution
 */
int
main (int argc, char *const *argv)
{
  //sleep (15);                 /* Debugging */
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "testbed-logger",
                              GNUNET_SERVICE_OPTION_NONE,
                              &logger_run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-testbed.c */
