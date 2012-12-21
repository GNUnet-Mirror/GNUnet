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
 * Flag for printing short hash of public key.
 */
static int print_short_identity;

/**
 * Use weak random number generator for key generation.
 */
static int weak_random;

/**
 * Option set to create a bunch of keys at once.
 */
static unsigned int make_keys;

/**
 * The private information of an ECC key pair.
 * NOTE: this must match the definition in crypto_ksk.c and crypto_ecc.c!
 */
struct GNUNET_CRYPTO_EccPrivateKey
{
  gcry_sexp_t sexp;
};


/**
 * Create a new private key. Caller must free return value.
 *
 * @return fresh private key
 */
static struct GNUNET_CRYPTO_EccPrivateKey *
ecc_key_create ()
{
  struct GNUNET_CRYPTO_EccPrivateKey *ret;
  gcry_sexp_t s_key;
  gcry_sexp_t s_keyparam;

  GNUNET_assert (0 ==
                 gcry_sexp_build (&s_keyparam, NULL,
                                  "(genkey(ecc(nbits %d)(ecc-use-e 3:257)))",
                                  2048));
  GNUNET_assert (0 == gcry_pk_genkey (&s_key, s_keyparam));
  gcry_sexp_release (s_keyparam);
#if EXTRA_CHECKS
  GNUNET_assert (0 == gcry_pk_testkey (s_key));
#endif
  ret = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EccPrivateKey));
  ret->sexp = s_key;
  return ret;
}


/**
 * Create a flat file with a large number of key pairs for testing.
 */
static void
create_keys (const char *fn)
{
  FILE *f;
  struct GNUNET_CRYPTO_EccPrivateKey *pk;
  struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded *enc;

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
    if (NULL == (pk = ecc_key_create ()))
    {
       GNUNET_break (0);
       break;
    }
    enc = GNUNET_CRYPTO_ecc_encode_key (pk);
    if (htons (enc->size) != fwrite (enc, 1, htons (enc->size), f))
      {
	fprintf (stderr,
		 _("\nFailed to write to `%s': %s\n"),
		 fn,
		 STRERROR (errno));
	GNUNET_CRYPTO_ecc_key_free (pk);
	GNUNET_free (enc);
	break;
      }
    GNUNET_CRYPTO_ecc_key_free (pk);
    GNUNET_free (enc);
  }
  if (0 == make_keys)
    fprintf (stderr,
	     _("Finished!\n"));
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
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded pub;
  struct GNUNET_PeerIdentity pid;

  if (NULL == args[0])
  {
    fprintf (stderr, _("No hostkey file specified on command line\n"));
    return;
  }
  if (0 != weak_random)    
    GNUNET_CRYPTO_random_disable_entropy_gathering ();  
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

    GNUNET_CRYPTO_ecc_key_get_public (pk, &pub);
    s = GNUNET_CRYPTO_ecc_public_key_to_string (&pub);
    fprintf (stdout, "%s\n", s);
    GNUNET_free (s);
  }
  if (print_peer_identity)
  {
    struct GNUNET_CRYPTO_HashAsciiEncoded enc;

    GNUNET_CRYPTO_ecc_key_get_public (pk, &pub);
    GNUNET_CRYPTO_hash (&pub, sizeof (pub), &pid.hashPubKey);
    GNUNET_CRYPTO_hash_to_enc (&pid.hashPubKey, &enc);
    fprintf (stdout, "%s\n", enc.encoding);
  }
  if (print_short_identity)
  {
    struct GNUNET_CRYPTO_ShortHashAsciiEncoded enc;
    struct GNUNET_CRYPTO_ShortHashCode sh;

    GNUNET_CRYPTO_ecc_key_get_public (pk, &pub);
    GNUNET_CRYPTO_short_hash (&pub, sizeof (pub), &sh);
    GNUNET_CRYPTO_short_hash_to_enc (&sh, &enc);
    fprintf (stdout, "%s\n", enc.short_encoding);
  }
  GNUNET_CRYPTO_ecc_key_free (pk);
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
    { 's', "print-short-identity", NULL,
      gettext_noop ("print the short hash of the public key in ASCII format"),
      0, &GNUNET_GETOPT_set_one, &print_short_identity },
    { 'w', "weak-random", NULL,
      gettext_noop ("use insecure, weak random number generator for key generation (for testing only)"),
      0, &GNUNET_GETOPT_set_one, &weak_random },
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
