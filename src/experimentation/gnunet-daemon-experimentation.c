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
 * @file experimentation/gnunet-daemon-experimentation.c
 * @brief experimentation daemon
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-daemon-experimentation.h"

struct GNUNET_STATISTICS_Handle *GSE_stats;

struct GNUNET_CONFIGURATION_Handle *GSE_cfg;

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Experimentation daemon shutting down ...\n"));
  GNUNET_EXPERIMENTATION_nodes_stop ();
  GNUNET_EXPERIMENTATION_experiments_stop ();
  GNUNET_EXPERIMENTATION_capabilities_stop ();
}



/**
 * Function starting all submodules of the experimentation daemon.
 *
 * @param cls always NULL
 * @param args temaining command line arguments
 * @param cfgfile configuration file used
 * @param cfg configuration handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Experimentation daemon starting ...\n"));

	GSE_cfg = (struct GNUNET_CONFIGURATION_Handle *) cfg;
	GSE_stats = GNUNET_STATISTICS_create ("experimentation", cfg);
	if (NULL == GSE_stats)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Failed to create statistics!\n"));
		return;
	}

	GNUNET_EXPERIMENTATION_capabilities_start ();
	if (GNUNET_SYSERR == GNUNET_EXPERIMENTATION_experiments_start ())
	{
	  GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
	  return;
	}
	GNUNET_EXPERIMENTATION_nodes_start ();

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
}


/**
 * The main function for the experimentation daemon.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "experimentation",
          										_("GNUnet hostlist server and client"), options,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-daemon-experimentation.c */
