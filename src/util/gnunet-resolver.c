/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file util/gnunet-resolver.c
 * @brief tool to test resolver
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"

#define GET_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * Callback function to display address.
 */
static void
printer (void *cls,
	 const struct sockaddr * addr,
	 socklen_t addrlen)
{
  if (addr == NULL)
    return;
  FPRINTF (stdout,
           "%s\n",
           GNUNET_a2s (addr, addrlen));
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
  if (args[0] == NULL)
    return;
  GNUNET_RESOLVER_ip_get (cfg,
			  args[0],
			  AF_UNSPEC,
			  GET_TIMEOUT,
			  &printer,
			  NULL);
}

/**
 * The main function to obtain statistics in GNUnet.
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
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-resolver [hostname]",
                              gettext_noop
                              ("Test GNUnet DNS resolver code."),
                              options, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-resolver.c */
