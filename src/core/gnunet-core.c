/*
     This file is part of GNUnet.
     (C) 2011, 2012, 2014 Christian Grothoff (and other contributing authors)

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
 * @file core/gnunet-core.c
 * @brief Print information about other known _connected_ peers.
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"


/**
 * Option -m.
 */
static int monitor_connections;

/**
 * Current number of connections in monitor mode
 */
// static unsigned int monitor_connections_counter;

/**
 * Handle to the CORE monitor.
 */
static struct GNUNET_CORE_MonitorHandle *mh;


/**
 * Task run in monitor mode when the user presses CTRL-C to abort.
 * Stops monitoring activity.
 *
 * @param cls the 'struct GNUNET_TRANSPORT_PeerIterateContext *'
 * @param tc scheduler context
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != mh)
  {
    GNUNET_CORE_monitor_stop (mh);
    mh = NULL;
  }
}


/**
 * Function called to notify core users that another
 * peer changed its state with us.
 *
 * @param cls closure
 * @param peer the peer that changed state
 * @param state new state of the peer
 * @param timeout timeout for the new state
 */
static void
monitor_cb (void *cls,
            const struct GNUNET_PeerIdentity *peer,
            enum GNUNET_CORE_KxState state,
            struct GNUNET_TIME_Absolute timeout)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get();
  const char *now_str;

  if ( (NULL == peer) &&
       (GNUNET_NO == monitor_connections) )
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  now_str = GNUNET_STRINGS_absolute_time_to_string (now);
  FPRINTF (stdout,
           _("%24s: %-17s %d %4s\n"),
           now_str,
           "FIXME",
           state,
           GNUNET_i2s (peer));
}


/**
 * Function called with the result of the check if the CORE
 * service is running.
 *
 * @param cls closure with our configuration
 * @param result #GNUNET_YES if CORE is running
 */
static void
testservice_task (void *cls,
                  int result)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  if (GNUNET_OK != result)
  {
    FPRINTF (stderr, _("Service `%s' is not running\n"), "core");
    return;
  }

  mh = GNUNET_CORE_monitor_start (cfg,
                                  &monitor_cb,
                                  NULL);
  if (NULL == mh)
  {
    GNUNET_SCHEDULER_add_now (shutdown_task, NULL);
    fprintf (stderr, ("Failed to connect to CORE service!\n"));
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task, NULL);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  if (NULL != args[0])
  {
    FPRINTF (stderr,
             _("Invalid command line argument `%s'\n"),
             args[0]);
    return;
  }
  GNUNET_CLIENT_service_test ("core", cfg,
                              GNUNET_TIME_UNIT_SECONDS,
                              &testservice_task, (void *) cfg);
}


/**
 * The main function to obtain peer information from CORE.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int res;
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'m', "monitor", NULL,
     gettext_noop ("provide information about all current connections (continuously)"),
     0, &GNUNET_GETOPT_set_one, &monitor_connections},
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  res = GNUNET_PROGRAM_run (argc, argv, "gnunet-core",
                            gettext_noop
                            ("Print information about connected peers."),
                            options, &run, NULL);

  GNUNET_free ((void *) argv);
  if (GNUNET_OK == res)
    return 0;
  return 1;
}

/* end of gnunet-core.c */
