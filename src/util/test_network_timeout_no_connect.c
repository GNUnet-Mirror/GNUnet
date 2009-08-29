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
 * @brief tests for network.c, doing timeout which connect failure
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_connection_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

#define VERBOSE GNUNET_NO

#define PORT 13425

static struct GNUNET_NETWORK_ConnectionHandle *csock;

static size_t
handle_timeout (void *cls, size_t size, void *buf)
{
  int *ok = cls;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received timeout signal.\n");
#endif

  GNUNET_assert (size == 0);
  GNUNET_assert (buf == NULL);
  *ok = 0;
  return 0;
}


static void
task_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  csock = GNUNET_CONNECTION_create_from_connect (tc->sched,
                                                     "localhost", PORT, 1024);
  GNUNET_assert (csock != NULL);
  GNUNET_assert (NULL !=
                 GNUNET_CONNECTION_notify_transmit_ready (csock,
                                                       1024,
                                                       GNUNET_TIME_UNIT_SECONDS,
                                                       &handle_timeout, cls));
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

  GNUNET_log_setup ("test_network_timeout_no_connect",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret += check_timeout ();
  return ret;
}

/* end of test_network_timeout_no_connect.c */
