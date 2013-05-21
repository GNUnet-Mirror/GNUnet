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
#include "gnunet_program_lib.h"
#include "gnunet_core_service.h"

static struct GNUNET_CORE_Handle *ch;


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Experimentation daemon shutting down ...\n"));
  if (NULL != ch)
  {
  		GNUNET_CORE_disconnect (ch);
  		ch = NULL;
  }

}

/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
void core_connect_handler (void *cls,
                           const struct GNUNET_PeerIdentity * peer)
{
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Connected to peer %s\n"),
			GNUNET_i2s (peer));
	/* Send request */

	/* TBD */
}


/**
 * Method called whenever a given peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
void core_disconnect_handler (void *cls,
                           const struct GNUNET_PeerIdentity * peer)
{
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Disconnected from peer %s\n"),
			GNUNET_i2s (peer));

}

/**
 * The main function for the experimentation daemon.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Experimentation daemon starting ...\n"));

	/* Connecting to core service to find partners */
	ch = GNUNET_CORE_connect (cfg, NULL, NULL,
														&core_connect_handler,
													 	&core_disconnect_handler,
														NULL, GNUNET_NO, NULL, GNUNET_NO, NULL);
	if (NULL == ch)
	{
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Failed to connect to CORE service!\n"));
			return;
	}

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
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
