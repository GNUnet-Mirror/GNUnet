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
#include <gnunet_gnsrecord_lib.h>
#include "credential_misc.h"
#include "credential_serialization.h"

/**
 * Configuration we are using.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * EgoLookup
 */
static struct GNUNET_IDENTITY_EgoLookup *el;

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
 * Handle to collect request
 */
static struct GNUNET_CREDENTIAL_Request *collect_request;

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
 * Credential TTL
 */
static char *expiration;

/**
 * Subject key
 */
struct GNUNET_CRYPTO_EcdsaPublicKey subject_pkey;

/**
 * Issuer key
 */
struct GNUNET_CRYPTO_EcdsaPublicKey issuer_pkey;


/**
 * Issuer pubkey string
 */
static char *issuer_key;

/**
 * ego
 */
static char *ego_name;

/**
 * Issuer attribute
 */
static char *issuer_attr;

/**
 * Verify mode
 */
static uint32_t verify;

/**
 * Issue mode
 */
static uint32_t create_cred;

/**
 * Collect mode
 */
static uint32_t collect;

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
handle_collect_result (void *cls,
                      unsigned int d_count,
                      struct GNUNET_CREDENTIAL_Delegation *dc,
                      unsigned int c_count,
                      struct GNUNET_CREDENTIAL_Credential *cred)
{
  int i;
  char* line;

  verify_request = NULL;
  if (NULL != cred)
  {
    for (i=0;i<c_count;i++)
    {
      line = GNUNET_CREDENTIAL_credential_to_string (&cred[i]);
      printf ("%s\n",
              line);
      GNUNET_free (line);
    }
  }


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
                      unsigned int d_count,
                      struct GNUNET_CREDENTIAL_Delegation *dc,
                      unsigned int c_count,
                      struct GNUNET_CREDENTIAL_Credential *cred)
{
  int i;
  char* iss_key;
  char* sub_key;

  verify_request = NULL;
  if (NULL == cred)
    printf ("Failed.\n");
  else
  {
    printf("Delegation Chain:\n");
    for (i=0;i<d_count;i++)
    {
      iss_key = GNUNET_CRYPTO_ecdsa_public_key_to_string (&dc[i].issuer_key);
      sub_key = GNUNET_CRYPTO_ecdsa_public_key_to_string (&dc[i].subject_key);
      if (0 != dc[i].subject_attribute_len)
      {
        printf ("(%d) %s.%s <- %s.%s\n", i,
                iss_key, dc[i].issuer_attribute,
                sub_key, dc[i].subject_attribute);
      } else {
        printf ("(%d) %s.%s <- %s\n", i,
                iss_key, dc[i].issuer_attribute,
                sub_key);
      }
      GNUNET_free (iss_key);
      GNUNET_free (sub_key);
    }
    printf("\nCredentials:\n");
    for (i=0;i<c_count;i++)
    {
      iss_key = GNUNET_CRYPTO_ecdsa_public_key_to_string (&cred[i].issuer_key);
      sub_key = GNUNET_CRYPTO_ecdsa_public_key_to_string (&cred[i].subject_key);
      printf ("%s.%s <- %s\n",
              iss_key, cred[i].issuer_attribute,
              sub_key);
      GNUNET_free (iss_key);
      GNUNET_free (sub_key);

    }
    printf ("Successful.\n");
  }


  GNUNET_SCHEDULER_shutdown ();
}

/**
 * Callback invoked from identity service with ego information.
 * An @a ego of NULL means the ego was not found.
 *
 * @param cls closure with the configuration
 * @param ego an ego known to identity service, or NULL
 */
static void
identity_cb (void *cls,
             const struct GNUNET_IDENTITY_Ego *ego)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;
  struct GNUNET_CREDENTIAL_Credential *crd;
  struct GNUNET_TIME_Absolute etime_abs;
  struct GNUNET_TIME_Relative etime_rel;
  char *res;

  el = NULL;
  if (NULL == ego)
  {
    if (NULL != ego_name)
    {
      fprintf (stderr,
               _("Ego `%s' not known to identity service\n"),
               ego_name);
    }
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_YES == collect)
  {
    
    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecdsa_public_key_from_string (issuer_key,
                                                    strlen (issuer_key),
                                                    &issuer_pkey))
    {
      fprintf (stderr,
               _("Issuer public key `%s' is not well-formed\n"),
               issuer_key);
      GNUNET_SCHEDULER_shutdown ();
    }
    privkey = GNUNET_IDENTITY_ego_get_private_key (ego);

    collect_request = GNUNET_CREDENTIAL_collect(credential,
                                                &issuer_pkey,
                                                issuer_attr, //TODO argument
                                                privkey,
                                                &handle_collect_result,
                                                NULL);
    return;
  }

  //Else issue

  if (NULL == expiration)
  {
    fprintf (stderr,
             "Please specify a TTL\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  } else if (GNUNET_OK == GNUNET_STRINGS_fancy_time_to_relative (expiration,
                                                                 &etime_rel))
  {
    etime_abs = GNUNET_TIME_relative_to_absolute (etime_rel);
  } else if (GNUNET_OK != GNUNET_STRINGS_fancy_time_to_absolute (expiration,
                                                                 &etime_abs))
  {
    fprintf (stderr,
             "%s is not a valid ttl!\n",
             expiration);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }


  privkey = GNUNET_IDENTITY_ego_get_private_key (ego);
  GNUNET_free_non_null (ego_name);
  ego_name = NULL;
  crd = GNUNET_CREDENTIAL_credential_issue (privkey,
                                            &subject_pkey,
                                            issuer_attr,
                                            &etime_abs);

  res = GNUNET_CREDENTIAL_credential_to_string (crd);
  GNUNET_free (crd);
  printf ("%s\n", res);
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


  tt = GNUNET_SCHEDULER_add_delayed (timeout,
                                     &do_timeout, NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);

  if (GNUNET_YES == collect) {
    if (NULL == issuer_key)
    {
      fprintf (stderr,
               _("Issuer public key not well-formed\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;

    }

    credential = GNUNET_CREDENTIAL_connect (cfg);

    if (NULL == credential)
    {
      fprintf (stderr,
               _("Failed to connect to CREDENTIAL\n"));
      GNUNET_SCHEDULER_shutdown ();
    }
    if (NULL == issuer_attr)
    {
      fprintf (stderr,
               _("You must provide issuer the attribute\n"));
      GNUNET_SCHEDULER_shutdown ();
    }

    if (NULL == ego_name)
    {
      fprintf (stderr,
               _("ego required\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;

    }
    el = GNUNET_IDENTITY_ego_lookup (cfg,
                                     ego_name,
                                     &identity_cb,
                                     (void *) cfg);
    return;

  } 

  if (NULL == subject_key)
  {
    fprintf (stderr,
             _("Subject public key needed\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;

  }
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
  if (GNUNET_YES == verify) {
    if (NULL == issuer_key)
    {
      fprintf (stderr,
               _("Issuer public key not well-formed\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;

    }
    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecdsa_public_key_from_string (issuer_key,
                                                    strlen (issuer_key),
                                                    &issuer_pkey))
    {
      fprintf (stderr,
               _("Issuer public key `%s' is not well-formed\n"),
               issuer_key);
      GNUNET_SCHEDULER_shutdown ();
    }
    credential = GNUNET_CREDENTIAL_connect (cfg);

    if (NULL == credential)
    {
      fprintf (stderr,
               _("Failed to connect to CREDENTIAL\n"));
      GNUNET_SCHEDULER_shutdown ();
    }
    if (NULL == issuer_attr || NULL == subject_credential)
    {
      fprintf (stderr,
               _("You must provide issuer and subject attributes\n"));
      GNUNET_SCHEDULER_shutdown ();
    }

    //Subject credentials are comma separated
    char *tmp = GNUNET_strdup (subject_credential);
    char *tok = strtok (tmp, ",");
    if (NULL == tok)
    {
      fprintf (stderr,
               "Invalid subject credentials\n");
      GNUNET_free (tmp);
      GNUNET_SCHEDULER_shutdown ();
    }
    int count = 1;
    int i;
    while (NULL != (tok = strtok(NULL, ",")))
      count++;
    struct GNUNET_CREDENTIAL_Credential credentials[count];
    struct GNUNET_CREDENTIAL_Credential *cred;
    GNUNET_free (tmp);
    tmp = GNUNET_strdup (subject_credential);
    tok = strtok (tmp, ",");
    for (i=0;i<count;i++)
    {
      cred = GNUNET_CREDENTIAL_credential_from_string (tok);
      GNUNET_memcpy (&credentials[i],
                     cred,
                     sizeof (struct GNUNET_CREDENTIAL_Credential));
      credentials[i].issuer_attribute = GNUNET_strdup (cred->issuer_attribute);
      tok = strtok(NULL, ",");
      GNUNET_free (cred);
    }

    verify_request = GNUNET_CREDENTIAL_verify(credential,
                                              &issuer_pkey,
                                              issuer_attr, //TODO argument
                                              &subject_pkey,
                                              count,
                                              credentials,
                                              &handle_verify_result,
                                              NULL);
    for (i=0;i<count;i++)
    {
      GNUNET_free ((char*)credentials[i].issuer_attribute);
    }
  } else if (GNUNET_YES == create_cred) {
    if (NULL == ego_name)
    {
      fprintf (stderr,
               _("Issuer ego required\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;

    }
    el = GNUNET_IDENTITY_ego_lookup (cfg,
                                     ego_name,
                                     &identity_cb,
                                     (void *) cfg);
    return;
  } else {
    fprintf (stderr,
             _("Please specify name to lookup, subject key and issuer key!\n"));
    GNUNET_SCHEDULER_shutdown ();
  }
  return;
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
    {'I', "issue", NULL,
      gettext_noop ("create credential"), 0,
      &GNUNET_GETOPT_set_one, &create_cred},
    {'V', "verify", NULL,
      gettext_noop ("verify credential against attribute"), 0,
      &GNUNET_GETOPT_set_one, &verify},
    {'s', "subject", "PKEY",
      gettext_noop ("The public key of the subject to lookup the credential for"), 1,
      &GNUNET_GETOPT_set_string, &subject_key},
    {'b', "credential", "CRED",
      gettext_noop ("The name of the credential presented by the subject"), 1,
      &GNUNET_GETOPT_set_string, &subject_credential},
    {'i', "issuer", "PKEY",
      gettext_noop ("The public key of the authority to verify the credential against"), 1,
      &GNUNET_GETOPT_set_string, &issuer_key},
    {'e', "ego", "EGO",
      gettext_noop ("The ego to use"), 1,
      &GNUNET_GETOPT_set_string, &ego_name},
    {'a', "attribute", "ATTR",
      gettext_noop ("The issuer attribute to verify against or to issue"), 1, 
      &GNUNET_GETOPT_set_string, &issuer_attr},
    {'T', "ttl", "EXP",
      gettext_noop ("The time to live for the credential"), 1,
      &GNUNET_GETOPT_set_string, &expiration},
    {'g', "collect", NULL,
      gettext_noop ("collect credentials"), 0,
      &GNUNET_GETOPT_set_one, &collect},
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
