/*
     This file is part of GNUnet.
     (C) 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file hostlist/gnunet-daemon-hostlist.c
 * @brief code for bootstrapping via hostlist servers
 * @author Christian Grothoff
 *
 * TODO:
 * - implement -a and -e switches (send P2P messages about our hostlist URL,
 *   receive such messages and automatically update our hostlist URL config
 *   value).
 */

#include <stdlib.h>
#include "platform.h"
#include "hostlist-client.h"
#include "hostlist-server.h"
#include "gnunet_core_service.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_program_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_strings_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_util_lib.h"


/**
 * Set if we are allowed to advertise our hostlist to others.
 */
static int advertising;

/**
 * Set if we are allowed to learn about peers by accessing
 * hostlist servers.
 */
static int bootstrapping;

/**
 * Set if the user allows us to learn about new hostlists
 * from the network.
 */
static int learning;

/**
 * Set if the user wants us to run a hostlist server.
 */
static int provide_hostlist;

/**
 * Statistics handle.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to the core service (NULL until we've connected to it).
 */
struct GNUNET_CORE_Handle *core;

/**
 * gnunet-daemon-hostlist command line options.
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  { 'a', "advertise", NULL, 
    gettext_noop ("advertise our hostlist to other peers"),
    GNUNET_NO, &GNUNET_GETOPT_set_one, &advertising },
  { 'b', "bootstrap", NULL, 
    gettext_noop ("bootstrap using hostlists (it is highly recommended that you always use this option)"),
    GNUNET_NO, &GNUNET_GETOPT_set_one, &bootstrapping },
  { 'e', "enable-learning", NULL,
    gettext_noop ("enable learning about hostlist servers from other peers"),
    GNUNET_NO, &GNUNET_GETOPT_set_one, &learning},
  { 'p', "provide-hostlist", NULL, 
    gettext_noop ("provide a hostlist server"),
    GNUNET_NO, &GNUNET_GETOPT_set_one, &provide_hostlist},
  GNUNET_GETOPT_OPTION_END
};


static void
core_init (void *cls,
	   struct GNUNET_CORE_Handle * server,
	   const struct GNUNET_PeerIdentity *
	   my_identity,
	   const struct
	   GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *
	   publicKey)
{
  if (advertising && (NULL != server))
    {    
      /* FIXME: provide "server" to 'hostlist' module */
    }
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the other services.
 */
static void
cleaning_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Hostlist daemon is shutting down.\n");
  if (bootstrapping)
    {
      GNUNET_HOSTLIST_client_stop ();
    }
  if (provide_hostlist)
    {      
      GNUNET_HOSTLIST_server_stop ();
    }
  if (core != NULL)
    {
      GNUNET_CORE_disconnect (core);
      core = NULL;
    }
  if (stats != NULL)
    {
      GNUNET_STATISTICS_destroy (stats,
				 GNUNET_NO);
      stats = NULL;
    }
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param sched the scheduler to use
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void 
run (void *cls,
     struct GNUNET_SCHEDULER_Handle * sched,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle * cfg)
{
  GNUNET_CORE_ConnectEventHandler ch = NULL;
  GNUNET_CORE_DisconnectEventHandler dh = NULL;
  struct GNUNET_CORE_MessageHandler handlers[] = 
    {
      { NULL, 0, 0 }
    };

  if ( (! bootstrapping) &&
       (! learning) &&
       (! provide_hostlist) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("None of the functions for the hostlist daemon were enabled.  I have no reason to run!\n"));
      return;
    }
  stats = GNUNET_STATISTICS_create (sched, "hostlist", cfg);
  if (learning)
    {
      /* FIXME (register handler with core for hostlist ads) */
    }
  if (bootstrapping)
    {
      GNUNET_HOSTLIST_client_start (cfg, sched, stats,
				    &ch, &dh);
    }
  if (provide_hostlist)
    {      
      GNUNET_HOSTLIST_server_start (cfg, sched, stats);
    }
  core = GNUNET_CORE_connect (sched, cfg,
			      GNUNET_TIME_UNIT_FOREVER_REL,
			      NULL,
			      &core_init,
			      NULL, ch, dh,
			      NULL, GNUNET_NO,
			      NULL, GNUNET_NO,
			      handlers);
  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &cleaning_task, NULL);
  if (NULL == core)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to `%s' service.\n"),
		  "core");
      GNUNET_SCHEDULER_shutdown (sched);
      return;     
    }
}


/**
 * The main function for the hostlist daemon.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;

  ret = (GNUNET_OK ==
         GNUNET_PROGRAM_run (argc,
                             argv,
                             "hostlist", 
			     _("GNUnet hostlist server and client"),
			     options,
			     &run, NULL)) ? 0 : 1;
  return ret;
}

/* end of gnunet-daemon-hostlist.c */
