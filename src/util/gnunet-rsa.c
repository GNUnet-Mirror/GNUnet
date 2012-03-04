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
 * @file util/gnunet-rsa.c
 * @brief tool to manipulate RSA key files
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_rsa_service.h"


/**
 * Flag for reverse lookup.
 */
static int print;


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
  struct GNUNET_CRYPTO_RsaPrivateKey *pk;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub;
  char *s;

  if (argc == 0)
  {
    fprintf (stderr, _("No hostkey file specified on command line\n"));
    return;
  }
  pk = GNUNET_CRYPTO_rsa_key_create_from_file (argv[0]);
  if (print)
  {
    GNUNET_CRYPTO_rsa_key_get_public (pk, &pub);
    s = GNUNET_CRYPTO_rsa_public_key_to_string (&pub);
    fprintf (stdout, "%s\n", s);
    GNUNET_free (s);
  }
  GNUNET_CRYPTO_rsa_key_free (pk);
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
    { 'p', "print", NULL,
      gettext_noop ("print the public key in ASCII format"),
      0, &GNUNET_GETOPT_set_one, &print },
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-rsa [OPTIONS] keyfile",
                              gettext_noop ("Manipulate GNUnet private RSA key files"),
                              options, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-rsa.c */
