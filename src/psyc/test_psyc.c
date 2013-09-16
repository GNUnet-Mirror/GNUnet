/*
 * This file is part of GNUnet
 * (C) 2013 Christian Grothoff (and other contributing authors)
 *
 * GNUnet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUnet; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/**
 * @file psycstore/test_psycstore.c
 * @brief Test for the PSYCstore service.
 * @author Gabor X Toth
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_psycstore_service.h"
#include "gnunet_testing_lib.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

#define DEBUG_SERVICE 0


/**
 * Return value from 'main'.
 */
static int res;

/**
 * Handle for task for timeout termination.
 */
static GNUNET_SCHEDULER_TaskIdentifier end_badly_task;


/**
 * Clean up all resources used.
 */
static void
cleanup ()
{
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Terminate the testcase (failure).
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  res = 1;
  cleanup ();
}


/**
 * Terminate the testcase (success).
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
end_normally (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  res = 0;
  cleanup ();
}


/**
 * Finish the testcase (successfully).
 */
static void
end ()
{
  if (end_badly_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (end_badly_task);
    end_badly_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
				&end_normally, NULL);
}

/**
 * Main function of the test, run from scheduler.
 *
 * @param cls NULL
 * @param cfg configuration we use (also to connect to PSYCstore service)
 * @param peer handle to access more of the peer (not used)
 */
static void
#if DEBUG_SERVICE
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
#else
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
#endif
{
  end_badly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);
}


int
main (int argc, char *argv[])
{
  res = 1;
#if DEBUG_SERVICE
  const struct GNUNET_GETOPT_CommandLineOption opts[] = {
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_PROGRAM_run (argc, argv, "test-psyc",
                                       "test-psyc [options]",
                                       opts, &run, NULL))
    return 1;
#else
  if (0 != GNUNET_TESTING_service_run ("test-psyc", "psyc",
                                       "test_psyc.conf", &run, NULL))
    return 1;
#endif
  return res;
}

/* end of test_psyc.c */
