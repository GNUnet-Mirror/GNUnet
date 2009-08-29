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
 * @file util/test_connection_receive_cancel.c
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

static struct GNUNET_NETWORK_Handle *ls;

static GNUNET_SCHEDULER_TaskIdentifier receive_task;




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
  sa.sin_port = htons (PORT);
  desc = GNUNET_NETWORK_socket_socket (AF_INET, SOCK_STREAM, 0);
  GNUNET_assert (desc != NULL);
  if (GNUNET_NETWORK_socket_setsockopt (desc, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "setsockopt");
  GNUNET_assert (GNUNET_NETWORK_socket_bind (desc,
					     (const struct sockaddr*) &sa,
					     sizeof (sa)) >= 0);
  GNUNET_NETWORK_socket_listen (desc, 5);
  return desc;
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

  asock = GNUNET_CONNECTION_create_from_accept (tc->sched,
                                                    NULL, NULL, ls, 1024);
  GNUNET_assert (asock != NULL);
  GNUNET_assert (GNUNET_YES == GNUNET_CONNECTION_check (asock));
  GNUNET_CONNECTION_destroy (lsock);
  receive_task
    = GNUNET_CONNECTION_receive (asock,
                              1024,
                              GNUNET_TIME_relative_multiply
                              (GNUNET_TIME_UNIT_SECONDS, 5), &dead_receive,
                              cls);
}


static void
receive_cancel_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;
  GNUNET_CONNECTION_receive_cancel (asock, receive_task);
  GNUNET_CONNECTION_destroy (csock);
  GNUNET_CONNECTION_destroy (asock);
  *ok = 0;
}



static void
task_receive_cancel (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  ls = open_listen_socket ();
  lsock = GNUNET_CONNECTION_create_from_existing (tc->sched, ls, 0);
  GNUNET_assert (lsock != NULL);
  csock = GNUNET_CONNECTION_create_from_connect (tc->sched,
                                                     "localhost", PORT, 1024);
  GNUNET_assert (csock != NULL);
  GNUNET_SCHEDULER_add_read_net (tc->sched,
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

  GNUNET_log_setup ("test_connection_receive_cancel", "WARNING", NULL);
  ret += check_receive_cancel ();

  return ret;
}

/* end of test_connection_receive_cancel.c */
