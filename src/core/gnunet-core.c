/*
     This file is part of GNUnet.
     (C) 2011, 2012 Christian Grothoff (and other contributing authors)

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
#include "gnunet_crypto_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_core_service.h"
#include "gnunet_program_lib.h"

/**
 * Option -m.
 */
static int monitor_connections;

/**
 * Current number of connections in monitor mode
 */
static int monitor_connections_counter;

static struct GNUNET_CORE_Handle *ch;

static struct GNUNET_PeerIdentity my_id;

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
  if (NULL != ch)
  {
    GNUNET_CORE_disconnect (ch);
    ch = NULL;
  }
}


/**
 * Callback for retrieving a list of connected peers.
 *
 * @param cls closure (unused)
 * @param peer peer identity this notification is about
 */
static void
connected_peer_callback (void *cls, 
			 const struct GNUNET_PeerIdentity *peer)
{
  if (NULL == peer)
    return;
  printf (_("Peer `%s'\n"),
	  GNUNET_i2s_full (peer));
}


static void
monitor_notify_startup (void *cls,
			const struct GNUNET_PeerIdentity *my_identity)
{
  my_id = (*my_identity);
}


/**
 * Function called to notify core users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 */
static void
monitor_notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get();
  const char *now_str;

  if (0 != memcmp (&my_id, peer, sizeof (my_id)))
  {
    monitor_connections_counter ++;
    now_str = GNUNET_STRINGS_absolute_time_to_string (now);
    FPRINTF (stdout, _("%24s: %-17s %4s   (%u connections in total)\n"),
             now_str,
             _("Connected to"),
             GNUNET_i2s (peer),
             monitor_connections_counter);
  }
}


/**
 * Function called to notify core users that another
 * peer disconnected from us.
 *
 * @param cls closure
 * @param peer the peer that disconnected
 */
static void
monitor_notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get();
  const char *now_str;

  if (0 != memcmp (&my_id, peer, sizeof (my_id)))
  {
    now_str = GNUNET_STRINGS_absolute_time_to_string (now);

    GNUNET_assert (monitor_connections_counter > 0);
    monitor_connections_counter--;
    FPRINTF (stdout, _("%24s: %-17s %4s   (%u connections in total)\n"),
             now_str,
             _("Disconnected from"),
             GNUNET_i2s (peer),
             monitor_connections_counter);
  }
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
  static const struct GNUNET_CORE_MessageHandler handlers[] = {
    {NULL, 0, 0}
  };
  if (args[0] != NULL)
  {
    FPRINTF (stderr, _("Invalid command line argument `%s'\n"), args[0]);
    return;
  }
  if (GNUNET_NO == monitor_connections)
    GNUNET_CORE_iterate_peers (cfg, &connected_peer_callback, NULL);
  else
  {
    memset(&my_id, '\0', sizeof (my_id));
    ch = GNUNET_CORE_connect (cfg, NULL,
                              monitor_notify_startup,
                              monitor_notify_connect,
                              monitor_notify_disconnect,
                              NULL, GNUNET_NO,
                              NULL, GNUNET_NO,
                              handlers);

    if (NULL == ch)
      GNUNET_SCHEDULER_add_now (shutdown_task, NULL);
    else
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, shutdown_task, NULL);
  }
}


/**
 * The main function to obtain peer information.
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
  else
    return 1;
}

/* end of gnunet-core.c */
