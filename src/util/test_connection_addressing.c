/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_connection_addressing.c
 * @brief tests for connection.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_connection_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

#define VERBOSE GNUNET_NO

#define PORT 12435


static struct GNUNET_CONNECTION_Handle *csock;

static struct GNUNET_CONNECTION_Handle *asock;

static struct GNUNET_CONNECTION_Handle *lsock;

static size_t sofar;

static struct GNUNET_NETWORK_Handle *ls;



/**
 * Create and initialize a listen socket for the server.
 *
 * @return NULL on error, otherwise the listen socket
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
  sa.sin_family = AF_INET;
  sa.sin_port = htons (PORT);
  desc = GNUNET_NETWORK_socket_create (AF_INET, SOCK_STREAM, 0);
  GNUNET_assert (desc != 0);
  if (GNUNET_NETWORK_socket_setsockopt
      (desc, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) != GNUNET_OK)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "setsockopt");
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_bind (desc, (const struct sockaddr *) &sa,
                                  sizeof (sa)))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                         "bind");
    GNUNET_assert (0);
  }
  GNUNET_NETWORK_socket_listen (desc, 5);
  return desc;
}


static void
receive_check (void *cls, const void *buf, size_t available,
               const struct sockaddr *addr, socklen_t addrlen, int errCode)
{
  int *ok = cls;

  GNUNET_assert (buf != NULL);  /* no timeout */
  if (0 == memcmp (&"Hello World"[sofar], buf, available))
    sofar += available;
  if (sofar < 12)
  {
    GNUNET_CONNECTION_receive (asock, 1024,
                               GNUNET_TIME_relative_multiply
                               (GNUNET_TIME_UNIT_SECONDS, 5), &receive_check,
                               cls);
  }
  else
  {
    *ok = 0;
    GNUNET_CONNECTION_destroy (asock, GNUNET_YES);
  }
}


static void
run_accept (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  void *addr;
  size_t alen;
  struct sockaddr_in *v4;
  struct sockaddr_in expect;

  asock = GNUNET_CONNECTION_create_from_accept (NULL, NULL, ls);
  GNUNET_assert (asock != NULL);
  GNUNET_assert (GNUNET_YES == GNUNET_CONNECTION_check (asock));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONNECTION_get_address (asock, &addr, &alen));
  GNUNET_assert (alen == sizeof (struct sockaddr_in));
  v4 = addr;
  memset (&expect, 0, sizeof (expect));
#if HAVE_SOCKADDR_IN_SIN_LEN
  expect.sin_len = sizeof (expect);
#endif
  expect.sin_family = AF_INET;
  expect.sin_port = v4->sin_port;
  expect.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  GNUNET_assert (0 == memcmp (&expect, v4, alen));
  GNUNET_free (addr);
  GNUNET_CONNECTION_destroy (lsock, GNUNET_YES);
  GNUNET_CONNECTION_receive (asock, 1024,
                             GNUNET_TIME_relative_multiply
                             (GNUNET_TIME_UNIT_SECONDS, 5), &receive_check,
                             cls);
}

static size_t
make_hello (void *cls, size_t size, void *buf)
{
  GNUNET_assert (size >= 12);
  strcpy ((char *) buf, "Hello World");
  return 12;
}

static void
task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct sockaddr_in v4;

  ls = open_listen_socket ();
  lsock = GNUNET_CONNECTION_create_from_existing (ls);
  GNUNET_assert (lsock != NULL);

#if HAVE_SOCKADDR_IN_SIN_LEN
  v4.sin_len = sizeof (v4);
#endif
  v4.sin_family = AF_INET;
  v4.sin_port = htons (PORT);
  v4.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  csock =
      GNUNET_CONNECTION_create_from_sockaddr (AF_INET,
                                              (const struct sockaddr *) &v4,
                                              sizeof (v4));
  GNUNET_assert (csock != NULL);
  GNUNET_assert (NULL !=
                 GNUNET_CONNECTION_notify_transmit_ready (csock, 12,
                                                          GNUNET_TIME_UNIT_SECONDS,
                                                          &make_hello, NULL));
  GNUNET_CONNECTION_destroy (csock, GNUNET_YES);
  GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, ls, &run_accept,
                                 cls);
}


/**
 * Main method, starts scheduler with task ,
 * checks that "ok" is correct at the end.
 */
static int
check ()
{
  int ok;

  ok = 1;
  GNUNET_SCHEDULER_run (&task, &ok);
  return ok;
}



int
main (int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup ("test_connection_addressing",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret += check ();
  return ret;
}

/* end of test_connection_addressing.c */
