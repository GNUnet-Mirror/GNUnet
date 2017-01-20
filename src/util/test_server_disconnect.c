/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2016 GNUnet e.V.

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
 * @file util/test_server_disconnect.c
 * @brief tests for server.c,  specifically GNUNET_SERVER_client_disconnect
 */
#include "platform.h"
#include "gnunet_util_lib.h"


#define PORT 12435

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 250)

#define MY_TYPE 128

static struct GNUNET_SERVER_Handle *server;

static struct GNUNET_MQ_Handle *mq;

static struct GNUNET_CONFIGURATION_Handle *cfg;

static int ok;


static void
finish_up (void *cls)
{
  GNUNET_assert (ok == 5);
  ok = 0;
  GNUNET_SERVER_destroy (server);
  GNUNET_MQ_destroy (mq);
  GNUNET_CONFIGURATION_destroy (cfg);
}


static void
notify_disconnect (void *cls,
                   struct GNUNET_SERVER_Client *clientarg)
{
  if (NULL == clientarg)
    return;
  GNUNET_assert (ok == 4);
  ok = 5;
  GNUNET_SCHEDULER_add_now (&finish_up, NULL);
}


static void
server_disconnect (void *cls)
{
  struct GNUNET_SERVER_Client *argclient = cls;

  GNUNET_assert (ok == 3);
  ok = 4;
  GNUNET_SERVER_client_disconnect (argclient);
  GNUNET_SERVER_client_drop (argclient);
}


static void
recv_cb (void *cls,
	 struct GNUNET_SERVER_Client *client,
         const struct GNUNET_MessageHeader *message)
{
  GNUNET_assert (ok == 2);
  ok = 3;
  GNUNET_SERVER_client_keep (client);
  GNUNET_SCHEDULER_add_now (&server_disconnect, client);
  GNUNET_assert (sizeof (struct GNUNET_MessageHeader) == ntohs (message->size));
  GNUNET_assert (MY_TYPE == ntohs (message->type));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static struct GNUNET_SERVER_MessageHandler handlers[] = {
  {&recv_cb, NULL, MY_TYPE, sizeof (struct GNUNET_MessageHeader)},
  {NULL, NULL, 0, 0}
};


static void
task (void *cls)
{
  struct sockaddr_in sa;
  struct sockaddr *sap[2];
  socklen_t slens[2];
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

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
  server = GNUNET_SERVER_create (NULL, NULL, sap, slens, TIMEOUT, GNUNET_NO);
  GNUNET_assert (server != NULL);
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server, &notify_disconnect, NULL);
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_set_value_number (cfg, "test-server", "PORT", PORT);
  GNUNET_CONFIGURATION_set_value_string (cfg, "test-server", "HOSTNAME",
                                         "localhost");
  GNUNET_CONFIGURATION_set_value_string (cfg, "resolver", "HOSTNAME",
                                         "localhost");
  mq = GNUNET_CLIENT_connect (cfg,
                              "test-server",
                              NULL,
                              NULL,
                              NULL);
  GNUNET_assert (NULL != mq);
  ok = 2;
  env = GNUNET_MQ_msg (msg,
                       MY_TYPE);
  GNUNET_MQ_send (mq,
                  env);
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
check ()
{
  ok = 1;
  GNUNET_SCHEDULER_run (&task, &ok);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup ("test_server_disconnect", "WARNING", NULL);
  ret += check ();

  return ret;
}

/* end of test_server_disconnect.c */
