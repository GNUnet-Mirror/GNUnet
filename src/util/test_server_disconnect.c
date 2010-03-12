/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_server_disconnect.c
 * @brief tests for server.c and client.c,
 *       specifically client_disconnect
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_client_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"

#define VERBOSE GNUNET_NO

#define PORT 22335

#define MY_TYPE 128


static struct GNUNET_SERVER_Handle *server;

static struct GNUNET_CLIENT_Connection *client;

static struct GNUNET_SCHEDULER_Handle *sched;

static struct GNUNET_CONFIGURATION_Handle *cfg;

static int ok;

static void
send_done (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SERVER_Client *argclient = cls;
  GNUNET_assert (ok == 3);
  ok++;
  GNUNET_SERVER_receive_done (argclient, GNUNET_OK);
}

static void
server_disconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SERVER_Client *argclient = cls;
  GNUNET_assert (ok == 5);
  ok++;
  GNUNET_SERVER_client_disconnect (argclient);
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
                                                   &addr, &addrlen));

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
      GNUNET_SCHEDULER_add_delayed (sched,
                                    GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MILLISECONDS, 50),
                                    &send_done, argclient);
      break;
    case 4:
      ok++;
      GNUNET_SCHEDULER_add_delayed (sched,
                                    GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MILLISECONDS, 50),
                                    &server_disconnect, argclient);
      GNUNET_SERVER_receive_done (argclient, GNUNET_OK);
      break;
    default:
      GNUNET_assert (0);
    }

}

static void
disconnect_notify (void *cls, const struct GNUNET_MessageHeader *msg)
{
  GNUNET_assert (msg == NULL);
  GNUNET_assert (ok == 7);
  ok = 0;
  GNUNET_CLIENT_disconnect (client, GNUNET_YES);
  client = NULL;
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
notify_disconnect (void *cls, struct GNUNET_SERVER_Client *clientarg)
{
  if (clientarg == NULL)
    return;
  GNUNET_assert (ok == 6);
  ok++;
  GNUNET_CLIENT_receive (client,
                         &disconnect_notify,
                         NULL, GNUNET_TIME_UNIT_FOREVER_REL);
}


static size_t
notify_ready (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg;

  GNUNET_assert (size >= 256);
  GNUNET_assert (1 == ok);
  ok++;
  msg = buf;
  msg->type = htons (MY_TYPE);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  msg++;
  msg->type = htons (MY_TYPE);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  return 2 * sizeof (struct GNUNET_MessageHeader);
}


static struct GNUNET_SERVER_MessageHandler handlers[] = {
  {&recv_cb, NULL, MY_TYPE, sizeof (struct GNUNET_MessageHeader)},
  {NULL, NULL, 0, 0}
};


static void
task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct sockaddr_in sa;
  struct sockaddr * sap[2];
  socklen_t slens[2];

  sap[0] = (struct sockaddr*) &sa;
  slens[0] = sizeof (sa);
  sap[1] = NULL;
  slens[1] = 0;
  sched = tc->sched;
  memset (&sa, 0, sizeof (sa));
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif
  sa.sin_family = AF_INET;
  sa.sin_port = htons (PORT);
  server = GNUNET_SERVER_create (tc->sched,
                                 NULL,
                                 NULL,
                                 sap,
				 slens,
                                 1024,
                                 GNUNET_TIME_relative_multiply
                                 (GNUNET_TIME_UNIT_MILLISECONDS, 250),
                                 GNUNET_NO);
  GNUNET_assert (server != NULL);
  handlers[0].callback_cls = cls;
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server, &notify_disconnect, cls);
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_set_value_number (cfg, "test", "PORT", PORT);
  GNUNET_CONFIGURATION_set_value_string (cfg, "test", "HOSTNAME",
                                         "localhost");
  GNUNET_CONFIGURATION_set_value_string (cfg, "resolver", "HOSTNAME",
                                         "localhost");
  client = GNUNET_CLIENT_connect (tc->sched, "test", cfg);
  GNUNET_assert (client != NULL);
  GNUNET_CLIENT_notify_transmit_ready (client,
                                       256,
                                       GNUNET_TIME_relative_multiply
                                       (GNUNET_TIME_UNIT_MILLISECONDS, 250),
                                       GNUNET_NO, &notify_ready, NULL);
}


/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
check ()
{

  ok = 1;
  GNUNET_SCHEDULER_run (&task, NULL);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup ("test_server_disconnect",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret += check ();

  return ret;
}

/* end of test_server_disconnect.c */
