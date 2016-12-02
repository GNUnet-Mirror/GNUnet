/*
     This file is part of GNUnet.
     Copyright (C) 2012-2013 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file gnunet-credential.c
 * @brief command line tool to access command line Credential service
 * @author Adnan Husain
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_credential_service.h>

/**
 * Configuration we are using.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to Credential service.
 */
static struct GNUNET_CREDENTIAL_Handle *credential;

/**
 * Desired timeout for the lookup (default is no timeout).
 */
static struct GNUNET_TIME_Relative timeout;

/**
 * Handle to verify request
 */
static struct GNUNET_CREDENTIAL_Request *verify_request;

/**
 * Task scheduled to handle timeout.
 */
static struct GNUNET_SCHEDULER_Task *tt;

/**
 * Subject pubkey string
 */
static char *subject_key;

/**
 * Subject credential string
 */
static char *subject_credential;

/**
 * Issuer pubkey string
 */
static char *issuer_key;

/**
 * Issuer attribute
 */
static char *issuer_attr;


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 */
static void
do_shutdown (void *cls)
{
  if (NULL != verify_request)
  {
    GNUNET_CREDENTIAL_verify_cancel (verify_request);
    verify_request = NULL;
  }
  if (NULL != credential)
  {
    GNUNET_CREDENTIAL_disconnect (credential);
    credential = NULL;
  }
  if (NULL != tt)
  {
    GNUNET_SCHEDULER_cancel (tt);
    tt = NULL;
  }
}


/**
 * Task run on timeout. Triggers shutdown.
 *
 * @param cls unused
 */
static void
do_timeout (void *cls)
{
  tt = NULL;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Function called with the result of a Credential lookup.
 *
 * @param cls the 'const char *' name that was resolved
 * @param cd_count number of records returned
 * @param cd array of @a cd_count records with the results
 */
static void
handle_verify_result (void *cls,
                      struct GNUNET_CRYPTO_EcdsaPublicKey *issuer,
                      uint32_t status)
{


  verify_request = NULL;
  if (GNUNET_NO == status)
    printf ("Verify failed.\n");
  else
    printf ("Successful.\n");


  GNUNET_SCHEDULER_shutdown ();
}




/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{

  cfg = c;
  credential = GNUNET_CREDENTIAL_connect (cfg);

  if (NULL == credential)
  {
    fprintf (stderr,
             _("Failed to connect to CREDENTIAL\n"));
    return;
  }
  tt = GNUNET_SCHEDULER_add_delayed (timeout,
                                     &do_timeout, NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);



  struct GNUNET_CRYPTO_EcdsaPublicKey subject_pkey;
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_pkey;

  if (NULL != subject_key && NULL != issuer_key)
  {
    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecdsa_public_key_from_string (subject_key,
                                                    strlen (subject_key),
                                                    &subject_pkey))
    {
      fprintf (stderr,
               _("Subject public key `%s' is not well-formed\n"),
               subject_key);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecdsa_public_key_from_string (issuer_key,
                                                    strlen (issuer_key),
                                                    &issuer_pkey))
    {
      fprintf (stderr,
               _("Authority public key `%s' is not well-formed\n"),
               issuer_key);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

    verify_request = GNUNET_CREDENTIAL_verify(credential,
                                              &issuer_pkey,
                                              issuer_attr, //TODO argument
                                              &subject_pkey,
                                              subject_credential,
                                              &handle_verify_result,
                                              NULL);
    return;
  }
  else
  {
    fprintf (stderr,
             _("Please specify name to lookup, subject key and issuer key!\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
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
    {'s', "subject", "PKEY",
      gettext_noop ("The public key of the subject to lookup the credential for"), 1,
      &GNUNET_GETOPT_set_string, &subject_key},
    {'c', "credential", "CRED",
      gettext_noop ("The name of the credential presented by the subject"), 1,
      &GNUNET_GETOPT_set_string, &subject_credential},
    {'i', "issuer", "PKEY",
      gettext_noop ("The public key of the authority to verify the credential against"), 1,
      &GNUNET_GETOPT_set_string, &issuer_key},
    {'a', "attribute", "ATTR",
      gettext_noop ("The issuer attribute to verify against"), 1, 
      &GNUNET_GETOPT_set_string, &issuer_attr},
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  GNUNET_log_setup ("gnunet-credential", "WARNING", NULL);
  ret =
    (GNUNET_OK ==
     GNUNET_PROGRAM_run (argc, argv, "gnunet-credential",
                         _("GNUnet credential resolver tool"),
                         options,
                         &run, NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-credential.c */
