/*
     This file is part of GNUnet.
     Copyright (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file nse/test_nse_api.c
 * @brief testcase for nse_api.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_nse_service.h"
#include "gnunet_testing_lib.h"


static struct GNUNET_NSE_Handle *h;

static struct GNUNET_SCHEDULER_Task * die_task;


/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
end_test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (h != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from NSE service.\n");
    GNUNET_NSE_disconnect (h);
  }
}

/**
 * Callback to call when network size estimate is updated.
 *
 * @param cls unused
 * @param timestamp time when the estimate was received from the server (or created by the server)
 * @param estimate the value of the current network size estimate
 * @param std_dev standard deviation (rounded down to nearest integer)
 *                of the size estimation values seen
 *
 */
static void
check_nse_message (void *cls, struct GNUNET_TIME_Absolute timestamp,
                   double estimate, double std_dev)
{
  int *ok = cls;

  FPRINTF (stderr,
           "Received NSE message, estimate %f, standard deviation %f.\n",
           estimate, std_dev);
  /* Fantastic check below. Expect NaN, the only thing not equal to itself. */
  (*ok) = 0;
  if (die_task != NULL)
    GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_add_now (&end_test, NULL);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, 1), &end_test,
                                    NULL);

  h = GNUNET_NSE_connect (cfg, &check_nse_message, cls);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting to NSE service.\n");
  GNUNET_assert (h != NULL);
}


int
main (int argc, char *argv[])
{
  int ok = 1;

  if (0 != GNUNET_TESTING_peer_run ("test_nse_api",
				    "test_nse.conf",
				    &run, &ok))
    return 1;
  return ok;
}

/* end of test_nse_api.c */
