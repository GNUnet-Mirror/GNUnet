/*
   This file is part of GNUnet.
   Copyright (C) 2008--2013 GNUnet e.V.

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
 * @file testbed-logger/gnunet-service-testbed-logger.c
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
 * Handle for buffered writing.
 */
struct GNUNET_BIO_WriteHandle *bio;

/**
 * The number of connections we have
 */
static unsigned int nconn;

/**
 * Are we shutting down?
 */
static int in_shutdown;


/**
 * Check #GNUNET_MESSAGE_TYPE_TESTBED_LOGGER_MSG messages
 *
 * @param cls client identification of the client
 * @param msg the actual message
 * @return #GNUNET_OK (they are all always OK)
 */
static int
check_log_msg (void *cls,
               const struct GNUNET_MessageHeader *msg)
{
  return GNUNET_OK;
}


/**
 * Message handler for #GNUNET_MESSAGE_TYPE_TESTBED_LOGGER_MSG messages
 *
 * @param cls client identification of the client
 * @param msg the actual message
 */
static void
handle_log_msg (void *cls,
                const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;
  uint16_t ms;

  ms = ntohs (msg->size) - sizeof(struct GNUNET_MessageHeader);
  GNUNET_BIO_write (bio,
                    "testbed-logger-handle-log-msg",
                    &msg[1],
                    ms);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Task to clean up and shutdown nicely
 *
 * @param cls NULL
 */
static void
shutdown_task (void *cls)
{
  in_shutdown = GNUNET_YES;
  if (0 != nconn)
  {
    /* Delay shutdown if there are active connections */
    GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                   NULL);
    return;
  }
  GNUNET_break (GNUNET_OK ==
                GNUNET_BIO_write_close (bio, NULL));
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return @a c
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *c,
                   struct GNUNET_MQ_Handle *mq)
{
  /* FIXME: is this really what we want here? */
  GNUNET_SERVICE_client_persist (c);
  nconn++;
  return c;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls should be equal to @a c
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *c,
                      void *internal_cls)
{
  nconn--;
  if (GNUNET_YES == in_shutdown)
    GNUNET_SCHEDULER_shutdown ();
  GNUNET_assert (c == internal_cls);
}


/**
 * Testbed setup
 *
 * @param cls closure
 * @param cfg configuration to use
 * @param service the initialized service
 */
static void
logger_run (void *cls,
            const struct GNUNET_CONFIGURATION_Handle *cfg,
            struct GNUNET_SERVICE_Handle *service)
{
  char *dir;
  char *fn;
  char *hname;
  size_t hname_len;
  pid_t pid;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               "TESTBED-LOGGER",
                                               "DIR",
                                               &dir))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "TESTBED-LOGGER",
                               "DIR");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  pid = getpid ();
  hname_len = GNUNET_OS_get_hostname_max_length ();
  hname = GNUNET_malloc (hname_len);
  if (0 != gethostname (hname,
                        hname_len))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Cannot get hostname.  Exiting\n");
    GNUNET_free (hname);
    GNUNET_free (dir);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_asprintf (&fn,
                   "%s/%.*s_%jd.dat",
                   dir,
                   hname_len,
                   hname,
                   (intmax_t) pid);
  GNUNET_free (hname);
  GNUNET_free (dir);
  if (NULL == (bio = GNUNET_BIO_write_open_file (fn)))
  {
    GNUNET_free (fn);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_free (fn);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
  LOG_DEBUG ("TESTBED-LOGGER startup complete\n");
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
  ("testbed-logger",
  GNUNET_SERVICE_OPTION_NONE,
  &logger_run,
  &client_connect_cb,
  &client_disconnect_cb,
  NULL,
  GNUNET_MQ_hd_var_size (log_msg,
                         GNUNET_MESSAGE_TYPE_TESTBED_LOGGER_MSG,
                         struct GNUNET_MessageHeader,
                         NULL),
  GNUNET_MQ_handler_end ());


/* end of gnunet-service-testbed-logger.c */
