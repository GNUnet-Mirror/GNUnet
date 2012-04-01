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
 * Callback for retrieving a list of connected peers.
 *
 * @param cls closure (unused)
 * @param peer peer identity this notification is about
 * @param atsi performance data for the connection
 * @param atsi_count number of records in 'atsi'
 */
static void
connected_peer_callback (void *cls, const struct GNUNET_PeerIdentity *peer,
                         const struct GNUNET_ATS_Information *atsi,
                         unsigned int atsi_count)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;

  if (NULL == peer)
    return;
  GNUNET_CRYPTO_hash_to_enc (&peer->hashPubKey, &enc);
  printf (_("Peer `%s'\n"), (const char *) &enc);
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
  if (args[0] != NULL)
  {
    FPRINTF (stderr, _("Invalid command line argument `%s'\n"), args[0]);
    return;
  }
  GNUNET_CORE_iterate_peers (cfg, &connected_peer_callback, NULL);
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
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-core",
                              gettext_noop
                              ("Print information about connected peers."),
                              options, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-core.c */
