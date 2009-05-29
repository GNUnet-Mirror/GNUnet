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
 * @file util/test_network_timeout.c
 * @brief tests for network.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_network_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

#define VERBOSE GNUNET_NO

#define PORT 12435

static struct GNUNET_NETWORK_SocketHandle *csock;

static struct GNUNET_NETWORK_SocketHandle *lsock;

static int ls;


/**
 * Create and initialize a listen socket for the server.
 *
 * @return -1 on error, otherwise the listen socket
 */
static int
open_listen_socket ()
{
  const static int on = 1;
  struct sockaddr_in sa;
  int fd;

  memset (&sa, 0, sizeof (sa));
  sa.sin_port = htons (PORT);
  fd = SOCKET (AF_INET, SOCK_STREAM, 0);
  GNUNET_assert (fd >= 0);
  if (SETSOCKOPT (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "setsockopt");
  GNUNET_assert (BIND (fd, &sa, sizeof (sa)) >= 0);
  LISTEN (fd, 5);
  return fd;
}


static size_t
send_kilo (void *cls, size_t size, void *buf)
{
  int *ok = cls;
  if (size == 0)
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got the desired timeout!\n");
#endif
      GNUNET_assert (buf == NULL);
      *ok = 0;
      GNUNET_NETWORK_socket_destroy (lsock);
      GNUNET_NETWORK_socket_destroy (csock);
      return 0;
    }
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending kilo to fill buffer.\n");
#endif
  GNUNET_assert (size >= 1024);
  memset (buf, 42, 1024);

  GNUNET_assert (NULL !=
                 GNUNET_NETWORK_notify_transmit_ready (csock,
                                                       1024,
                                                       GNUNET_TIME_UNIT_SECONDS,
                                                       &send_kilo, cls));
  return 1024;
}


static void
task_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  ls = open_listen_socket ();
  lsock = GNUNET_NETWORK_socket_create_from_existing (tc->sched, ls, 0);
  GNUNET_assert (lsock != NULL);
  csock = GNUNET_NETWORK_socket_create_from_connect (tc->sched,
                                                     "localhost", PORT, 1024);
  GNUNET_assert (csock != NULL);
  GNUNET_assert (NULL !=
                 GNUNET_NETWORK_notify_transmit_ready (csock,
                                                       1024,
                                                       GNUNET_TIME_UNIT_SECONDS,
                                                       &send_kilo, cls));
}



/**
 * Main method, starts scheduler with task_timeout.
 */
static int
check_timeout ()
{
  int ok;

  ok = 1;
  GNUNET_SCHEDULER_run (&task_timeout, &ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup ("test_network_timeout",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret += check_timeout ();
  return ret;
}

/* end of test_network_timeout.c */
