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
 * @file src/transport/gnunet-transport.c
 * @brief Tool to help configure the transports.
 * @author Christian Grothoff
 *
 * This utility can be used to test if a transport mechanism for
 * GNUnet is properly configured.
 */

#include "platform.h"
#include "gnunet_program_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"

static char *cpid;

static struct GNUNET_TRANSPORT_Handle *handle;

static void
do_disconnect (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_TRANSPORT_disconnect (handle);  
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
  struct GNUNET_PeerIdentity pid;
  if (NULL != cpid)
  {
    handle = GNUNET_TRANSPORT_connect (cfg, NULL, NULL,
				       NULL, NULL, NULL);
    if (GNUNET_OK !=
	GNUNET_CRYPTO_hash_from_string (cpid, &pid.hashPubKey))
    {
      fprintf (stderr,
	       _("Failed to parse peer identity `%s'\n"),
	       cpid);
      GNUNET_TRANSPORT_disconnect (handle);
      return;
    }
    GNUNET_TRANSPORT_try_connect (handle, &pid);
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				  &do_disconnect,
				  NULL);
  }
}


int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'C', "connect", "PEER",
     gettext_noop ("try to connect to the given peer"),
     1, &GNUNET_GETOPT_set_string, &cpid},
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-transport",
                              gettext_noop ("Direct access to transport service."),
                              options, &run, NULL)) ? 0 : 1;
}


/* end of gnunet-transport.c */
