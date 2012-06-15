/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-ats.c
 * @brief ATS command line tool
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"

/**
 * Final status code.
 */
static int ret;

static char * peer_str;

static int all_peers;

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
  if (GNUNET_YES == all_peers)
  {
    /* list information for all peers */
    printf ("To be implemented!\n");

    /* TODO: get all peers */

    /* TODO: get addresses for each peer */
  }
  else if (NULL != peer_str)
  {
    /* list information for a specific peer */
    printf ("To be implemented!\n");
    struct GNUNET_PeerIdentity id;
    if (GNUNET_SYSERR == GNUNET_CRYPTO_hash_from_string2(peer_str, strlen (peer_str), &id.hashPubKey))
    {
      printf ("`%s' is not a valid peer identity\n", peer_str);
      GNUNET_free (peer_str);
      return;
    }

    printf ("Peer `%s':\n", GNUNET_i2s_full (&id));

    /* TODO: get addresses for each peer */
    GNUNET_free (peer_str);
  }
}


/**
 * The main function.
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
    {'P', "peer", "PEER",
     gettext_noop ("list information for the given peer"),
     1, &GNUNET_GETOPT_set_string, &peer_str},
    {'A', "all", NULL,
     gettext_noop ("list information for all peers"),
     0, &GNUNET_GETOPT_set_one, &all_peers},
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  res = GNUNET_PROGRAM_run (argc, argv, "gnunet-ats",
                              gettext_noop ("Print information about ATS state"), options, &run,
                              NULL);
  GNUNET_free ((void *) argv);

  if (GNUNET_OK == res)
    return ret;
  else
    return 1;

}

/* end of gnunet-ats.c */
