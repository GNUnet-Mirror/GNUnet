/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2012, 2014 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
 * @file core/gnunet-core.c
 * @brief Print information about other peers known to CORE.
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
 * Handle to the CORE monitor.
 */
static struct GNUNET_CORE_MonitorHandle *mh;


/**
 * Task run in monitor mode when the user presses CTRL-C to abort.
 * Stops monitoring activity.
 *
 * @param cls NULL
 */
static void
shutdown_task (void *cls)
{
  (void) cls;
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
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  const char *now_str;
  const char *state_str;

  (void) cls;
  if (((NULL == peer) || (GNUNET_CORE_KX_ITERATION_FINISHED == state)) &&
      (GNUNET_NO == monitor_connections))
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  switch (state)
  {
  case GNUNET_CORE_KX_STATE_DOWN:
    /* should never happen, as we immediately send the key */
    state_str = _ ("fresh connection");
    break;
  case GNUNET_CORE_KX_STATE_KEY_SENT:
    state_str = _ ("key sent");
    break;
  case GNUNET_CORE_KX_STATE_KEY_RECEIVED:
    state_str = _ ("key received");
    break;
  case GNUNET_CORE_KX_STATE_UP:
    state_str = _ ("connection established");
    break;
  case GNUNET_CORE_KX_STATE_REKEY_SENT:
    state_str = _ ("rekeying");
    break;
  case GNUNET_CORE_KX_PEER_DISCONNECT:
    state_str = _ ("disconnected");
    break;
  case GNUNET_CORE_KX_ITERATION_FINISHED:
    return;
  case GNUNET_CORE_KX_CORE_DISCONNECT:
    fprintf (stderr,
             "%s\n",
             _ ("Connection to CORE service lost (reconnecting)"));
    return;
  default:
    state_str = _ ("unknown state");
    break;
  }
  now_str = GNUNET_STRINGS_absolute_time_to_string (now);
  fprintf (stdout,
           _ ("%24s: %-30s %4s (timeout in %6s)\n"),
           now_str,
           state_str,
           GNUNET_i2s (peer),
           GNUNET_STRINGS_relative_time_to_string (
             GNUNET_TIME_absolute_get_remaining (timeout),
             GNUNET_YES));
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  (void) cls;
  (void) cfgfile;
  if (NULL != args[0])
  {
    fprintf (stderr, _ ("Invalid command line argument `%s'\n"), args[0]);
    return;
  }
  mh = GNUNET_CORE_monitor_start (cfg, &monitor_cb, NULL);
  if (NULL == mh)
  {
    fprintf (stderr, "%s", _ ("Failed to connect to CORE service!\n"));
    return;
  }
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
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
  struct GNUNET_GETOPT_CommandLineOption options[] =
    {GNUNET_GETOPT_option_flag (
       'm',
       "monitor",
       gettext_noop (
         "provide information about all current connections (continuously)"),
       &monitor_connections),
     GNUNET_GETOPT_OPTION_END};

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  res = GNUNET_PROGRAM_run (argc,
                            argv,
                            "gnunet-core",
                            gettext_noop (
                              "Print information about connected peers."),
                            options,
                            &run,
                            NULL);

  GNUNET_free ((void *) argv);
  if (GNUNET_OK == res)
    return 0;
  return 1;
}

/* end of gnunet-core.c */
