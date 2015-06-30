/*
     This file is part of GNUnet.
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file util/test_mq_client.c
 * @brief tests for mq with connection client
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define PORT 23336

#define MY_TYPE 128


static struct GNUNET_SERVER_Handle *server;

static struct GNUNET_CLIENT_Connection *client;

static struct GNUNET_CONFIGURATION_Handle *cfg;

static int ok;

static int notify = GNUNET_NO;

static int received = 0;


static void
recv_cb (void *cls, struct GNUNET_SERVER_Client *argclient,
         const struct GNUNET_MessageHeader *message)
{
  received++;
  if (received == 2)
  {
    GNUNET_SERVER_receive_done (argclient, GNUNET_NO);
    return;
  }

  /* can happen if notify does not work */
  GNUNET_assert (received < 2);

  GNUNET_SERVER_receive_done (argclient, GNUNET_YES);
}


static void
clean_up (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_SERVER_destroy (server);
  server = NULL;
  GNUNET_CONFIGURATION_destroy (cfg);
  cfg = NULL;
}


/**
 * Functions with this signature are called whenever a client
 * is disconnected on the network level.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
notify_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  if (client == NULL)
    return;
  ok = 0;
  GNUNET_SCHEDULER_add_now (&clean_up, NULL);
}


static struct GNUNET_SERVER_MessageHandler handlers[] = {
  {&recv_cb, NULL, MY_TYPE, sizeof (struct GNUNET_MessageHeader)},
  {NULL, NULL, 0, 0}
};


static void
send_cb (void *cls)
{
  /* the notify should only be called once */
  GNUNET_assert (GNUNET_NO == notify);
  notify = GNUNET_YES;
}

static void
send_trap_cb (void *cls)
{
  GNUNET_assert (0);
}


static void
test_mq (struct GNUNET_CLIENT_Connection *client)
{
  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_MQ_Envelope *mqm;

  /* FIXME: test handling responses */
  mq = GNUNET_MQ_queue_for_connection_client (client, NULL, NULL, NULL);

  mqm = GNUNET_MQ_msg_header (MY_TYPE);
  GNUNET_MQ_send (mq, mqm);

  mqm = GNUNET_MQ_msg_header (MY_TYPE);
  GNUNET_MQ_notify_sent (mqm, send_trap_cb, NULL);
  GNUNET_MQ_send (mq, mqm);
  GNUNET_MQ_send_cancel (mqm);

  mqm = GNUNET_MQ_msg_header (MY_TYPE);
  GNUNET_MQ_notify_sent (mqm, send_cb, NULL);
  GNUNET_MQ_send (mq, mqm);

}


static void
task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct sockaddr_in sa;
  struct sockaddr *sap[2];
  socklen_t slens[2];

  sap[0] = (struct sockaddr *) &sa;
  slens[0] = sizeof (sa);
  sap[1] = NULL;
  slens[1] = 0;
  memset (&sa, 0, sizeof (sa));
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif
  sa.sin_family = AF_INET;
  sa.sin_port = htons (PORT);
  server =
      GNUNET_SERVER_create (NULL, NULL, sap, slens,
                            GNUNET_TIME_relative_multiply
                            (GNUNET_TIME_UNIT_MILLISECONDS, 250), GNUNET_NO);
  GNUNET_assert (server != NULL);
  handlers[0].callback_cls = cls;
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server, &notify_disconnect, cls);
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_set_value_number (cfg, "test", "PORT", PORT);
  GNUNET_CONFIGURATION_set_value_string (cfg, "test", "HOSTNAME", "localhost");
  GNUNET_CONFIGURATION_set_value_string (cfg, "resolver", "HOSTNAME",
                                         "localhost");
  client = GNUNET_CLIENT_connect ("test", cfg);
  GNUNET_assert (client != NULL);

  test_mq (client);
}


int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-mq-client",
                    "INFO",
                    NULL);
  ok = 1;
  GNUNET_SCHEDULER_run (&task, NULL);
  GNUNET_assert (GNUNET_YES == notify);
  return ok;
}

