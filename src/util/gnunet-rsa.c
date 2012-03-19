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


/**
 * Flag for printing public key.
 */
static int print_public_key;

/**
 * Flag for printing hash of public key.
 */
static int print_peer_identity;

/**
 * Flag for printing short hash of public key.
 */
static int print_short_identity;


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
  struct GNUNET_PeerIdentity pid;

  if (NULL == args[0])
  {
    fprintf (stderr, _("No hostkey file specified on command line\n"));
    return;
  }
  pk = GNUNET_CRYPTO_rsa_key_create_from_file (args[0]);
  if (print_public_key)
  {
    char *s;

    GNUNET_CRYPTO_rsa_key_get_public (pk, &pub);
    s = GNUNET_CRYPTO_rsa_public_key_to_string (&pub);
    fprintf (stdout, "%s\n", s);
    GNUNET_free (s);
  }
  if (print_peer_identity)
  {
    struct GNUNET_CRYPTO_HashAsciiEncoded enc;

    GNUNET_CRYPTO_rsa_key_get_public (pk, &pub);
    GNUNET_CRYPTO_hash (&pub, sizeof (pub), &pid.hashPubKey);
    GNUNET_CRYPTO_hash_to_enc (&pid.hashPubKey, &enc);
    fprintf (stdout, "%s\n", enc.encoding);
  }
  if (print_short_identity)
  {
    struct GNUNET_CRYPTO_ShortHashAsciiEncoded enc;
    struct GNUNET_CRYPTO_ShortHashCode sh;

    GNUNET_CRYPTO_rsa_key_get_public (pk, &pub);
    GNUNET_CRYPTO_short_hash (&pub, sizeof (pub), &sh);
    GNUNET_CRYPTO_short_hash_to_enc (&sh, &enc);
    fprintf (stdout, "%s\n", enc.short_encoding);
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
    { 'p', "print-public-key", NULL,
      gettext_noop ("print the public key in ASCII format"),
      0, &GNUNET_GETOPT_set_one, &print_public_key },
    { 'P', "print-peer-identity", NULL,
      gettext_noop ("print the hash of the public key in ASCII format"),
      0, &GNUNET_GETOPT_set_one, &print_peer_identity },
    { 's', "print-short-identity", NULL,
      gettext_noop ("print the short hash of the public key in ASCII format"),
      0, &GNUNET_GETOPT_set_one, &print_short_identity },
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-rsa [OPTIONS] keyfile",
                              gettext_noop ("Manipulate GNUnet private RSA key files"),
                              options, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-rsa.c */
