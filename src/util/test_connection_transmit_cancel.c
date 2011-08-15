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
 * @file util/test_connection_transmit_cancel.c
 * @brief tests for connection.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_connection_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

#define VERBOSE GNUNET_NO

#define PORT 12435

static struct GNUNET_CONFIGURATION_Handle *cfg;


static size_t
not_run (void *cls, size_t size, void *buf)
{
  GNUNET_assert (0);
  return 0;
}


static void
task_transmit_cancel (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int *ok = cls;
  struct GNUNET_CONNECTION_TransmitHandle *th;
  struct GNUNET_CONNECTION_Handle *csock;

  csock = GNUNET_CONNECTION_create_from_connect (cfg, "localhost", PORT);
  GNUNET_assert (csock != NULL);
  th = GNUNET_CONNECTION_notify_transmit_ready (csock, 12,
                                                GNUNET_TIME_UNIT_MINUTES,
                                                &not_run, cls);
  GNUNET_assert (NULL != th);
  GNUNET_CONNECTION_notify_transmit_ready_cancel (th);
  GNUNET_CONNECTION_destroy (csock, GNUNET_YES);
  *ok = 0;
}




/**
 * Main method, starts scheduler with task_timeout.
 */
static int
check_transmit_cancel ()
{
  int ok;

  ok = 1;
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_set_value_string (cfg, "resolver", "HOSTNAME",
                                         "localhost");
  GNUNET_SCHEDULER_run (&task_transmit_cancel, &ok);
  GNUNET_CONFIGURATION_destroy (cfg);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup ("test_connection_transmit_cancel",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret += check_transmit_cancel ();

  return ret;
}

/* end of test_connection_transmit_cancel.c */
