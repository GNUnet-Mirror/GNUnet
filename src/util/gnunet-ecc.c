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
 * @brief tool to manipulate EDDSA key files
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include <gcrypt.h>


/**
 * Flag for listing public key.
 */
static int list_keys;

/**
 * Flag for listing public key.
 */
static int list_keys_count;

/**
 * Flag for printing public key.
 */
static int print_public_key;

/**
 * Flag for printing the output of random example operations.
 */
static int print_examples_flag;

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
  struct GNUNET_CRYPTO_EddsaPrivateKey *pk;

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
    if (NULL == (pk = GNUNET_CRYPTO_eddsa_key_create ()))
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


static void
print_hex (char *msg, void *buf, size_t size)
{
  size_t i;
  printf ("%s: ", msg);
  for (i = 0; i < size; i++)
  {
    printf ("%02hhx", ((char *)buf)[i]);
  }
  printf ("\n");
}


static void
print_examples_ecdh ()
{
  struct GNUNET_CRYPTO_EcdhePrivateKey *dh_priv1;
  struct GNUNET_CRYPTO_EcdhePublicKey *dh_pub1;
  struct GNUNET_CRYPTO_EcdhePrivateKey *dh_priv2;
  struct GNUNET_CRYPTO_EcdhePublicKey *dh_pub2;
  struct GNUNET_HashCode hash;
  char buf[128];

  dh_pub1 = GNUNET_new (struct GNUNET_CRYPTO_EcdhePublicKey);
  dh_priv1 = GNUNET_CRYPTO_ecdhe_key_create ();
  dh_pub2 = GNUNET_new (struct GNUNET_CRYPTO_EcdhePublicKey);
  dh_priv2 = GNUNET_CRYPTO_ecdhe_key_create ();
  GNUNET_CRYPTO_ecdhe_key_get_public (dh_priv1, dh_pub1);
  GNUNET_CRYPTO_ecdhe_key_get_public (dh_priv2, dh_pub2);

  GNUNET_assert (NULL != GNUNET_STRINGS_data_to_string (dh_priv1, 32, buf, 128));
  printf ("ECDHE key 1:\n");
  printf ("private: %s\n", buf);
  print_hex ("private(hex)", dh_priv1, sizeof *dh_priv1);
  GNUNET_assert (NULL != GNUNET_STRINGS_data_to_string (dh_pub1, 32, buf, 128));
  printf ("public: %s\n", buf);
  print_hex ("public(hex)", dh_pub1, sizeof *dh_pub1);

  GNUNET_assert (NULL != GNUNET_STRINGS_data_to_string (dh_priv2, 32, buf, 128));
  printf ("ECDHE key 2:\n");
  printf ("private: %s\n", buf);
  print_hex ("private(hex)", dh_priv2, sizeof *dh_priv2);
  GNUNET_assert (NULL != GNUNET_STRINGS_data_to_string (dh_pub2, 32, buf, 128));
  printf ("public: %s\n", buf);
  print_hex ("public(hex)", dh_pub2, sizeof *dh_pub2);

  GNUNET_assert (GNUNET_OK == GNUNET_CRYPTO_ecc_ecdh (dh_priv1, dh_pub2, &hash));
  GNUNET_assert (NULL != GNUNET_STRINGS_data_to_string (&hash, 64, buf, 128));
  printf ("ECDH shared secret: %s\n", buf);

  GNUNET_free (dh_priv1);
  GNUNET_free (dh_priv2);
  GNUNET_free (dh_pub1);
  GNUNET_free (dh_pub2);
}


/**
 * Print some random example operations to stdout.
 */
static void
print_examples ()
{
  print_examples_ecdh ();
  // print_examples_ecdsa ();
  // print_examples_eddsa ();
}


static void
print_key (const char *filename)
{
  struct GNUNET_DISK_FileHandle *fd;
  struct GNUNET_CRYPTO_EddsaPrivateKey private_key;
  struct GNUNET_CRYPTO_EddsaPublicKey public_key;
  char *hostkeys_data;
  char *hostkey_str;
  uint64_t fs;
  unsigned int total_hostkeys;
  unsigned int c;

  if (GNUNET_YES != GNUNET_DISK_file_test (filename))
  {
    fprintf (stderr,
             _("Hostkeys file `%s' not found\n"),
             filename);
    return;
  }

  /* Check hostkey file size, read entire thing into memory */
  if (GNUNET_OK != GNUNET_DISK_file_size (filename, &fs, GNUNET_YES, GNUNET_YES))
    fs = 0;
  if (0 == fs)
  {
    fprintf (stderr,
             _("Hostkeys file `%s' is empty\n"),
             filename);
    return;       /* File is empty */
  }
  if (0 != (fs % GNUNET_TESTING_HOSTKEYFILESIZE))
  {
    fprintf (stderr,
             _("Incorrect hostkey file format: %s\n"),
             filename);
    return;
  }
  fd = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ,
                                         GNUNET_DISK_PERM_NONE);
  if (NULL == fd)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", filename);
    return;
  }
  hostkeys_data = GNUNET_malloc (fs);
  if (fs != GNUNET_DISK_file_read (fd, hostkeys_data, fs))
  {
    fprintf (stderr,
             _("Could not read hostkey file: %s\n"),
             filename);
    GNUNET_free (hostkeys_data);
    GNUNET_DISK_file_close (fd);
    return;
  }
  GNUNET_DISK_file_close (fd);

  if (NULL == hostkeys_data)
    return;
  total_hostkeys = fs / GNUNET_TESTING_HOSTKEYFILESIZE;
  for (c = 0; (c < total_hostkeys) && (c < list_keys_count); c++)
  {
    memcpy (&private_key,
            hostkeys_data + (c * GNUNET_TESTING_HOSTKEYFILESIZE),
            GNUNET_TESTING_HOSTKEYFILESIZE);
    GNUNET_CRYPTO_eddsa_key_get_public (&private_key, &public_key);
    hostkey_str = GNUNET_CRYPTO_eddsa_public_key_to_string (&public_key);
    if (NULL != hostkey_str)
    {
      fprintf (stderr, "%4u: %s\n", c, hostkey_str);
      GNUNET_free (hostkey_str);
    }
    else
      fprintf (stderr, "%4u: %s\n", c, "invalid");
  }
  GNUNET_free (hostkeys_data);
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
  if (print_examples_flag)
  {
    print_examples ();
    return;
  }
  if (NULL == args[0])
  {
    FPRINTF (stderr,
             "%s",
             _("No hostkey file specified on command line\n"));
    return;
  }
  if (list_keys)
  {
    print_key (args[0]);
    return;
  }
  if (make_keys > 0)
  {
    create_keys (args[0]);
    return;
  }
  if (print_public_key)
  {
    struct GNUNET_CRYPTO_EddsaPrivateKey *pk;
    struct GNUNET_CRYPTO_EddsaPublicKey pub;
    char *s;

    pk = GNUNET_CRYPTO_eddsa_key_create_from_file (args[0]);
    if (NULL == pk)
      return;
    GNUNET_CRYPTO_eddsa_key_get_public (pk, &pub);
    s = GNUNET_CRYPTO_eddsa_public_key_to_string (&pub);
    FPRINTF (stdout,
             "%s\n",
             s);
    GNUNET_free (s);
    GNUNET_free (pk);
  }
  if (print_peer_identity)
  {
    char *str;
    struct GNUNET_DISK_FileHandle *keyfile;
    struct GNUNET_CRYPTO_EddsaPrivateKey pk;
    struct GNUNET_CRYPTO_EddsaPublicKey pub;

    keyfile = GNUNET_DISK_file_open (args[0], GNUNET_DISK_OPEN_READ,
                                     GNUNET_DISK_PERM_NONE);
    if (NULL == keyfile)
      return;
    while (sizeof (pk) == GNUNET_DISK_file_read (keyfile, &pk, sizeof (pk)))
    {
      GNUNET_CRYPTO_eddsa_key_get_public (&pk, &pub);
      str = GNUNET_CRYPTO_eddsa_public_key_to_string (&pub);
      FPRINTF (stdout, "%s\n", str);
      GNUNET_free (str);
    }
    GNUNET_DISK_file_close (keyfile);
  }

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
  list_keys_count = UINT32_MAX;
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    { 'i', "iterate", "FILE",
      gettext_noop ("list keys included in a file (for testing)"),
      0, &GNUNET_GETOPT_set_one, &list_keys },
    { 'e', "end=", "COUNT",
      gettext_noop ("number of keys to list included in a file (for testing)"),
      1, &GNUNET_GETOPT_set_uint, &list_keys_count },
    { 'g', "generate-keys", "COUNT",
      gettext_noop ("create COUNT public-private key pairs (for testing)"),
      1, &GNUNET_GETOPT_set_uint, &make_keys },
    { 'p', "print-public-key", NULL,
      gettext_noop ("print the public key in ASCII format"),
      0, &GNUNET_GETOPT_set_one, &print_public_key },
    { 'P', "print-peer-identity", NULL,
      gettext_noop ("print the hash of the public key in ASCII format"),
      0, &GNUNET_GETOPT_set_one, &print_peer_identity },
    { 'E', "examples", NULL,
      gettext_noop ("print examples of ECC operations (used for compatibility testing)"),
      0, &GNUNET_GETOPT_set_one, &print_examples_flag },
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
