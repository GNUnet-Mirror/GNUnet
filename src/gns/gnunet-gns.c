/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file gnunet-gns.c
 * @brief command line tool to manipulate the local zone
 * @author Christian Grothoff
 *
 * TODO:
 * - everything
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_namestore_service.h>

/**
 * Handle to the namestore.
 */
static struct GNUNET_NAMESTORE_Handle *ns;

/**
 * Hash of the public key of our zone.
 */
static GNUNET_HashCode zone;

/**
 * Private key for the our zone.
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *zone_pkey;

/**
 * Keyfile to manipulate.
 */
static char *keyfile;	
		

/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
do_shutdown (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != ns)
  {
    GNUNET_NAMESTORE_disconnect (ns, GNUNET_NO);
    ns = NULL;
  }
  if (NULL != zone_pkey)
  {
    GNUNET_CRYPTO_rsa_key_free (zone_pkey);
    zone_pkey = NULL;
  }
}


/**
 * Main function that will be run.
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
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;

  if (NULL == keyfile)
  {
    fprintf (stderr,
	     _("Option `%s' not given, but I need a zone key file!\n"),
	     "z");
    return;
  }
  zone_pkey = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  keyfile = NULL;
  if (NULL == zone_pkey)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to read or create private zone key\n"));
    return;
  }
  GNUNET_CRYPTO_rsa_key_get_public (zone_pkey,
				    &pub);
  GNUNET_CRYPTO_hash (&pub, sizeof (pub), &zone);
  ns = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == ns)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to namestore\n"));
      return;
    }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&do_shutdown, NULL);
}


/**
 * The main function for gnunet-gns.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'z', "zonekey", "FILENAME",
     gettext_noop ("filename with the zone key"), 1,
     &GNUNET_GETOPT_set_string, &keyfile},   
    GNUNET_GETOPT_OPTION_END
  };

  int ret;

  GNUNET_log_setup ("gnunet-gns", "WARNING", NULL);
  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "gnunet-gns",
                           _("GNUnet GNS zone manipulation tool"), 
			   options,
                           &run, NULL)) ? 0 : 1;

  return ret;
}

/* end of gnunet-gns.c */
