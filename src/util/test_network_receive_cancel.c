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
 * @file util/test_network_receive_cancel.c
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

static int ls;

static GNUNET_SCHEDULER_TaskIdentifier receive_task;




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
dead_receive (void *cls,
              const void *buf,
              size_t available,
              const struct sockaddr *addr, socklen_t addrlen, int errCode)
{
  GNUNET_assert (0);
}


static void
run_accept_cancel (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  asock = GNUNET_NETWORK_socket_create_from_accept (tc->sched,
                                                    NULL, NULL, ls, 1024);
  GNUNET_assert (asock != NULL);
  GNUNET_assert (GNUNET_YES == GNUNET_NETWORK_socket_check (asock));
  GNUNET_NETWORK_socket_destroy (lsock);
  receive_task
    = GNUNET_NETWORK_receive (asock,
                              1024,
                              GNUNET_TIME_relative_multiply
                              (GNUNET_TIME_UNIT_SECONDS, 5), &dead_receive,
                              cls);
}


static void
receive_cancel_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;
  GNUNET_NETWORK_receive_cancel (asock, receive_task);
  GNUNET_NETWORK_socket_destroy (csock);
  GNUNET_NETWORK_socket_destroy (asock);
  *ok = 0;
}



static void
task_receive_cancel (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  ls = open_listen_socket ();
  lsock = GNUNET_NETWORK_socket_create_from_existing (tc->sched, ls, 0);
  GNUNET_assert (lsock != NULL);
  csock = GNUNET_NETWORK_socket_create_from_connect (tc->sched,
                                                     "localhost", PORT, 1024);
  GNUNET_assert (csock != NULL);
  GNUNET_SCHEDULER_add_read (tc->sched,
                             GNUNET_NO,
                             GNUNET_SCHEDULER_PRIORITY_HIGH,
                             GNUNET_SCHEDULER_NO_TASK,
                             GNUNET_TIME_UNIT_FOREVER_REL,
                             ls, &run_accept_cancel, cls);
  GNUNET_SCHEDULER_add_delayed (tc->sched,
                                GNUNET_NO,
                                GNUNET_SCHEDULER_PRIORITY_KEEP,
                                GNUNET_SCHEDULER_NO_TASK,
                                GNUNET_TIME_UNIT_SECONDS,
                                &receive_cancel_task, cls);
}



/**
 * Main method, starts scheduler with task_timeout.
 */
static int
check_receive_cancel ()
{
  int ok;

  ok = 1;
  GNUNET_SCHEDULER_run (&task_receive_cancel, &ok);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup ("test_network_receive_cancel", "WARNING", NULL);
  ret += check_receive_cancel ();

  return ret;
}

/* end of test_network.c */
