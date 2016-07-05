/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2016 GNUnet e.V.

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
 * @file util/test_server_with_client.c
 * @brief tests for server.c and client.c,
 *       specifically disconnect_notify,
 *       client_get_address and receive_done (resume processing)
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define PORT 22335

#define MY_TYPE 128


static struct GNUNET_SERVER_Handle *server;

static struct GNUNET_MQ_Handle *mq;

static struct GNUNET_CONFIGURATION_Handle *cfg;

static int ok;


static void
send_done (void *cls)
{
  struct GNUNET_SERVER_Client *argclient = cls;

  GNUNET_assert (ok == 3);
  ok++;
  GNUNET_SERVER_receive_done (argclient, GNUNET_OK);
}


static void
recv_cb (void *cls,
         struct GNUNET_SERVER_Client *argclient,
         const struct GNUNET_MessageHeader *message)
{
  void *addr;
  size_t addrlen;
  struct sockaddr_in sa;
  struct sockaddr_in *have;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_SERVER_client_get_address (argclient,
                                                   &addr,
                                                   &addrlen));

  GNUNET_assert (addrlen == sizeof (struct sockaddr_in));
  have = addr;
  memset (&sa, 0, sizeof (sa));
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif
  sa.sin_family = AF_INET;
  sa.sin_port = have->sin_port;
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  GNUNET_assert (0 == memcmp (&sa, addr, addrlen));
  GNUNET_free (addr);
  switch (ok)
  {
  case 2:
    ok++;
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MILLISECONDS, 50),
                                  &send_done,
                                  argclient);
    break;
  case 4:
    ok++;
    GNUNET_MQ_destroy (mq);
    GNUNET_SERVER_receive_done (argclient,
                                GNUNET_OK);
    break;
  default:
    GNUNET_assert (0);
  }

}


static void
clean_up (void *cls)
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
notify_disconnect (void *cls,
                   struct GNUNET_SERVER_Client *client)
{
  if (client == NULL)
    return;
  GNUNET_assert (ok == 5);
  ok = 0;
  GNUNET_SCHEDULER_add_now (&clean_up, NULL);
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
  mq = GNUNET_CLIENT_connecT (cfg,
                              "test",
                              NULL,
                              NULL,
                              NULL);
  GNUNET_assert (NULL != mq);
  ok = 2;
  env = GNUNET_MQ_msg (msg,
                       MY_TYPE);
  GNUNET_MQ_send (mq,
                  env);
  env = GNUNET_MQ_msg (msg,
                       MY_TYPE);
  GNUNET_MQ_send (mq,
                  env);
}


int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test_server_with_client",
                    "WARNING",
                    NULL);
  ok = 1;
  GNUNET_SCHEDULER_run (&task, NULL);
  return ok;
}

/* end of test_server_with_client.c */
