/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
#include "gnunet_common.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_nse_service.h"

#define DEBUG_NSE GNUNET_YES

#define START_ARM GNUNET_YES

static struct GNUNET_NSE_Handle *h;

static GNUNET_SCHEDULER_TaskIdentifier die_task;

struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
#if START_ARM
  struct GNUNET_OS_Process *arm_proc;
#endif
};

static struct PeerContext p1;


static void
stop_arm (struct PeerContext *p)
{
#if START_ARM
  if (0 != GNUNET_OS_process_kill (p->arm_proc, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  GNUNET_OS_process_wait (p->arm_proc);
  GNUNET_OS_process_close (p->arm_proc);
  p->arm_proc = NULL;
#endif
  GNUNET_CONFIGURATION_destroy (p->cfg);
}

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
  if (die_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_add_now (&end_test, NULL);
}


static void
setup_peer (struct PeerContext *p, const char *cfgname)
{
  p->cfg = GNUNET_CONFIGURATION_create ();
#if START_ARM
  p->arm_proc =
    GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm",
#if VERBOSE_ARM
                               "-L", "DEBUG",
#endif
                               "-c", cfgname, NULL);
#endif
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));

}



static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, 1), &end_test,
                                    NULL);

  setup_peer (&p1, cfgfile);
  h = GNUNET_NSE_connect (cfg, &check_nse_message, cls);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting to NSE service.\n");
  GNUNET_assert (h != NULL);
}


static int
check ()
{
  int ok = 1;

  char *const argv[] = { "test-nse-api",
    "-c",
    "test_nse.conf",
#if DEBUG_NSE
    "-L", "DEBUG",
#else
    "-L", "WARNING",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run (5, argv, "test-nse-api", "nohelp", options, &run, &ok);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping arm.\n");
  stop_arm (&p1);
  if (0 != ok)
    FPRINTF (stderr, "%s",  "No information received from NSE service!\n");
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test_nse_api",
#if DEBUG_NSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();

  return ret;
}

/* end of test_nse_api.c */
