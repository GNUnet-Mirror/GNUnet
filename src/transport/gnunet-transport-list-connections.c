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
 * @file transport/gnunet-transport-list-connections.c
 *
 * @brief Print all known address information about other peers.
 *
 * Lists all peers and connections that the transport service is
 * aware of.  Pretty prints addresses, peer id's, and whether
 * or not the _address_ is connected.  Note that these are not
 * core level connections, only transport level connections.
 *
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_program_lib.h"

#define VERBOSE 0
static int no_resolve;

#if VERBOSE
static unsigned int connection_count;
#endif

static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Function to call with a human-readable format of an address
 *
 * @param cls closure
 * @param address NULL on error, otherwise 0-terminated printable UTF-8 string
 */
static void
process_address (void *cls, const char *address)
{
#if VERBOSE
  connection_count++;
#endif
  if (address != NULL)
    fprintf (stdout, "%s\n", address);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{

  cfg = c;
  if (args[0] != NULL)
  {
    fprintf (stderr, _("Invalid command line argument `%s'\n"), args[0]);
    return;
  }

  GNUNET_TRANSPORT_address_iterate (cfg, GNUNET_TIME_UNIT_MINUTES,
                                    &process_address, NULL);
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
    {'n', "numeric", NULL,
     gettext_noop ("don't resolve host names"),
     0, &GNUNET_GETOPT_set_one, &no_resolve},
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-list-connections",
                              gettext_noop
                              ("Print information about connected peers."),
                              options, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-transport-list-connections.c */
