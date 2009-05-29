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
 * @file util/test_network_addressing.c
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

static struct GNUNET_NETWORK_SocketHandle *asock;

static struct GNUNET_NETWORK_SocketHandle *lsock;

static size_t sofar;

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


static void
receive_check (void *cls,
               const void *buf,
               size_t available,
               const struct sockaddr *addr, socklen_t addrlen, int errCode)
{
  int *ok = cls;

  GNUNET_assert (buf != NULL);  /* no timeout */
  if (0 == memcmp (&"Hello World"[sofar], buf, available))
    sofar += available;
  if (sofar < 12)
    {
      GNUNET_NETWORK_receive (asock,
                              1024,
                              GNUNET_TIME_relative_multiply
                              (GNUNET_TIME_UNIT_SECONDS, 5), &receive_check,
                              cls);
    }
  else
    {
      *ok = 0;
      GNUNET_NETWORK_socket_destroy (asock);
    }
}


static void
run_accept (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  void *addr;
  size_t alen;
  struct sockaddr_in *v4;
  struct sockaddr_in expect;

  asock = GNUNET_NETWORK_socket_create_from_accept (tc->sched,
                                                    NULL, NULL, ls, 1024);
  GNUNET_assert (asock != NULL);
  GNUNET_assert (GNUNET_YES == GNUNET_NETWORK_socket_check (asock));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_NETWORK_socket_get_address (asock, &addr, &alen));
  GNUNET_assert (alen == sizeof (struct sockaddr_in));
  v4 = addr;
  memset (&expect, 0, sizeof (expect));
  expect.sin_family = AF_INET;
  expect.sin_port = v4->sin_port;
  expect.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  GNUNET_assert (0 == memcmp (&expect, v4, alen));
  GNUNET_NETWORK_socket_destroy (lsock);
  GNUNET_NETWORK_receive (asock,
                          1024,
                          GNUNET_TIME_relative_multiply
                          (GNUNET_TIME_UNIT_SECONDS, 5), &receive_check, cls);
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
  lsock = GNUNET_NETWORK_socket_create_from_existing (tc->sched, ls, 0);
  GNUNET_assert (lsock != NULL);

  v4.sin_family = AF_INET;
  v4.sin_port = htons (PORT);
  v4.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  csock = GNUNET_NETWORK_socket_create_from_sockaddr (tc->sched,
                                                      AF_INET,
                                                      (const struct sockaddr
                                                       *) &v4, sizeof (v4),
                                                      1024);
  GNUNET_assert (csock != NULL);
  GNUNET_assert (NULL !=
                 GNUNET_NETWORK_notify_transmit_ready (csock,
                                                       12,
                                                       GNUNET_TIME_UNIT_SECONDS,
                                                       &make_hello, NULL));
  GNUNET_NETWORK_socket_destroy (csock);
  GNUNET_SCHEDULER_add_read (tc->sched,
                             GNUNET_NO,
                             GNUNET_SCHEDULER_PRIORITY_HIGH,
                             GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                             GNUNET_TIME_UNIT_FOREVER_REL,
                             ls, &run_accept, cls);
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

  GNUNET_log_setup ("test_network_addressing", "WARNING", NULL);
  ret += check ();
  return ret;
}

/* end of test_network_addressing.c */
