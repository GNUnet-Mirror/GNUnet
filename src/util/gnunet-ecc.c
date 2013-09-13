/*
     This file is part of GNUnet.
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file util/gnunet-ecc.c
 * @brief tool to manipulate ECC key files
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include <gcrypt.h>


/**
 * Flag for printing public key.
 */
static int print_public_key;

/**
 * Flag for printing hash of public key.
 */
static int print_peer_identity;

/**
 * Option set to create a bunch of keys at once.
 */
static unsigned int make_keys;


/**
 * Create a flat file with a large number of key pairs for testing.
 */
static void
create_keys (const char *fn)
{
  FILE *f;
  struct GNUNET_CRYPTO_EccPrivateKey *pk;

  if (NULL == (f = fopen (fn, "w+")))
  {
    fprintf (stderr,
	     _("Failed to open `%s': %s\n"),
	     fn,
	     STRERROR (errno));
    return;
  }
  fprintf (stderr,
	   _("Generating %u keys, please wait"),
	   make_keys);
  while (0 < make_keys--)
  {    
    fprintf (stderr,
	     ".");
    if (NULL == (pk = GNUNET_CRYPTO_ecc_key_create ()))
    {
       GNUNET_break (0);
       break;
    }
    if (GNUNET_TESTING_HOSTKEYFILESIZE != 
	fwrite (pk, 1,
		GNUNET_TESTING_HOSTKEYFILESIZE, f))
    {
      fprintf (stderr,
	       _("\nFailed to write to `%s': %s\n"),
	       fn,
	       STRERROR (errno));
      GNUNET_free (pk);
      break;
    }
    GNUNET_free (pk);
  }
  if (UINT_MAX == make_keys)
    fprintf (stderr,
	     _("\nFinished!\n"));
  else
    fprintf (stderr,
	     _("\nError, %u keys not generated\n"), make_keys);
  fclose (f);
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
  struct GNUNET_CRYPTO_EccPrivateKey *pk;
  struct GNUNET_CRYPTO_EccPublicSignKey pub;
  struct GNUNET_PeerIdentity pid;

  if (NULL == args[0])
  {
    fprintf (stderr, _("No hostkey file specified on command line\n"));
    return;
  }
  if (make_keys > 0)
  {
    create_keys (args[0]);
    return;
  }
  pk = GNUNET_CRYPTO_ecc_key_create_from_file (args[0]);
  if (NULL == pk)
    return;
  if (print_public_key)
  {
    char *s;

    GNUNET_CRYPTO_ecc_key_get_public_for_signature (pk, &pub);
    s = GNUNET_CRYPTO_ecc_public_sign_key_to_string (&pub);
    fprintf (stdout, "%s\n", s);
    GNUNET_free (s);
  }
  if (print_peer_identity)
  {
    struct GNUNET_CRYPTO_HashAsciiEncoded enc;

    GNUNET_CRYPTO_ecc_key_get_public_for_signature (pk, &pub);
    GNUNET_CRYPTO_hash (&pub, sizeof (pub), &pid.hashPubKey);
    GNUNET_CRYPTO_hash_to_enc (&pid.hashPubKey, &enc);
    fprintf (stdout, "%s\n", enc.encoding);
  }
  GNUNET_free (pk);
}


/**
 * Program to manipulate ECC key files.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    { 'g', "generate-keys", "COUNT",
      gettext_noop ("create COUNT public-private key pairs (for testing)"),
      1, &GNUNET_GETOPT_set_uint, &make_keys },
    { 'p', "print-public-key", NULL,
      gettext_noop ("print the public key in ASCII format"),
      0, &GNUNET_GETOPT_set_one, &print_public_key },
    { 'P', "print-peer-identity", NULL,
      gettext_noop ("print the hash of the public key in ASCII format"),
      0, &GNUNET_GETOPT_set_one, &print_peer_identity },
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK ==
	 GNUNET_PROGRAM_run (argc, argv, "gnunet-ecc [OPTIONS] keyfile",
			     gettext_noop ("Manipulate GNUnet private ECC key files"),
			     options, &run, NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-ecc.c */
