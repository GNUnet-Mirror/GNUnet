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
 */

#include <stdlib.h>
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_program_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_strings_lib.h"
#include "gnunet_time_lib.h"


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
 * gnunet-daemon-hostlist command line options.
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  { 'b', "bootstrap", NULL, gettext_noop ("bootstrap using hostlists (it is highly recommended that you always use this option)"),
    GNUNET_NO, &GNUNET_GETOPT_set_one, &bootstrapping },
  { 'e', "enable-learning", NULL, gettext_noop ("enable learning about hostlist servers from other peers"),
    GNUNET_NO, &GNUNET_GETOPT_set_one, &learning},
  { 'p', "provide-hostlist", NULL, gettext_noop ("provide a hostlist server"),
    GNUNET_NO, &GNUNET_GETOPT_set_one, &provide_hostlist},
  GNUNET_GETOPT_OPTION_END
};



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
     struct GNUNET_CONFIGURATION_Handle * cfg)
{
  if ( (! bootstrapping) &&
       (! learning) &&
       (! provide_hostlist) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("None of the functions for the hostlist daemon were enabled.  I have no reason to run!\n"));
      return;
    }
  if (learning)
    {
      // FIXME!
      // (register handler with core for hostlist ads)
    }
  if (bootstrapping)
    {
      // FIXME!
      // (register handler with core to monitor number of active
      //  connections; trigger hostlist download via CURL if
      //  number is low)
    }
  if (provide_hostlist)
    {      
      // FIXME!
      // (initialize MHD server and run using scheduler;
      //  use peerinfo to gather HELLOs)
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
