/*
     This file is part of GNUnet.
     Copyright (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_connection.c
 * @brief tests for connection.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define PORT 12435


static struct GNUNET_CONNECTION_Handle *csock;

static struct GNUNET_CONNECTION_Handle *asock;

static struct GNUNET_CONNECTION_Handle *lsock;

static size_t sofar;

static struct GNUNET_NETWORK_Handle *ls;

static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Create and initialize a listen socket for the server.
 *
 * @return -1 on error, otherwise the listen socket
 */
static struct GNUNET_NETWORK_Handle *
open_listen_socket ()
{
  const static int on = 1;
  struct sockaddr_in sa;
  struct GNUNET_NETWORK_Handle *desc;

  memset (&sa, 0, sizeof (sa));
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa.sin_len = sizeof (sa);
#endif
  sa.sin_port = htons (PORT);
  sa.sin_family = AF_INET;
  desc = GNUNET_NETWORK_socket_create (AF_INET, SOCK_STREAM, 0);
  GNUNET_assert (desc != NULL);
  if (GNUNET_NETWORK_socket_setsockopt
      (desc, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) != GNUNET_OK)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "setsockopt");
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_NETWORK_socket_bind (desc, (const struct sockaddr *) &sa,
					     sizeof (sa)));
  GNUNET_NETWORK_socket_listen (desc, 5);
  return desc;
}

static void
receive_check (void *cls, const void *buf, size_t available,
               const struct sockaddr *addr, socklen_t addrlen, int errCode)
{
  int *ok = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Receive validates incoming data\n");
  GNUNET_assert (buf != NULL);  /* no timeout */
  if (0 == memcmp (&"Hello World"[sofar], buf, available))
    sofar += available;
  if (sofar < 12)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Receive needs more data\n");
    GNUNET_CONNECTION_receive (asock, 1024,
                               GNUNET_TIME_relative_multiply
                               (GNUNET_TIME_UNIT_SECONDS, 5), &receive_check,
                               cls);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Receive closes accepted socket\n");
    *ok = 0;
    GNUNET_CONNECTION_destroy (asock);
    GNUNET_CONNECTION_destroy (csock);
  }
}


static void
run_accept (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test accepts connection\n");
  asock = GNUNET_CONNECTION_create_from_accept (NULL, NULL, ls);
  GNUNET_assert (asock != NULL);
  GNUNET_assert (GNUNET_YES == GNUNET_CONNECTION_check (asock));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test destroys listen socket\n");
  GNUNET_CONNECTION_destroy (lsock);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test asks to receive on accepted socket\n");
  GNUNET_CONNECTION_receive (asock, 1024,
                             GNUNET_TIME_relative_multiply
                             (GNUNET_TIME_UNIT_SECONDS, 5), &receive_check,
                             cls);
}


static size_t
make_hello (void *cls, size_t size, void *buf)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Test prepares to transmit on connect socket\n");
  GNUNET_assert (size >= 12);
  strcpy ((char *) buf, "Hello World");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test destroys client socket\n");
  return 12;
}


static void
task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  ls = open_listen_socket ();
  lsock = GNUNET_CONNECTION_create_from_existing (ls);
  GNUNET_assert (lsock != NULL);
  csock = GNUNET_CONNECTION_create_from_connect (cfg, "localhost", PORT);
  GNUNET_assert (csock != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test asks for write notification\n");
  GNUNET_assert (NULL !=
                 GNUNET_CONNECTION_notify_transmit_ready (csock, 12,
                                                          GNUNET_TIME_UNIT_SECONDS,
                                                          &make_hello, NULL));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test prepares to accept\n");
  GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, ls, &run_accept,
                                 cls);
}


int
main (int argc, char *argv[])
{
  int ok;

  GNUNET_log_setup ("test_connection",
                    "WARNING",
                    NULL);

  ok = 1;
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_set_value_string (cfg, "resolver", "HOSTNAME",
                                         "localhost");
  GNUNET_SCHEDULER_run (&task, &ok);
  GNUNET_CONFIGURATION_destroy (cfg);
  return ok;
}

/* end of test_connection.c */
