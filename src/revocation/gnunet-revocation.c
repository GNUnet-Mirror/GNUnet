/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file revocation/gnunet-revocation.c
 * @brief tool for revoking public keys
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_revocation_service.h"
#include "gnunet_identity_service.h"

/**
 * Pow passes
 */
static unsigned int pow_passes = 1;

/**
 * Final status code.
 */
static int ret;

/**
 * Was "-p" specified?
 */
static int perform;

/**
 * -f option.
 */
static char *filename;

/**
 * -R option
 */
static char *revoke_ego;

/**
 * -t option.
 */
static char *test_ego;

/**
 * Handle for revocation query.
 */
static struct GNUNET_REVOCATION_Query *q;

/**
 * Handle for revocation.
 */
static struct GNUNET_REVOCATION_Handle *h;

/**
 * Handle for our ego lookup.
 */
static struct GNUNET_IDENTITY_EgoLookup *el;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Number of matching bits required for revocation.
 */
static unsigned long long matching_bits;

/**
 * Epoch length
 */
static struct GNUNET_TIME_Relative epoch_length;

/**
 * Task used for proof-of-work calculation.
 */
static struct GNUNET_SCHEDULER_Task *pow_task;


/**
 * Function run if the user aborts with CTRL-C.
 *
 * @param cls closure
 */
static void
do_shutdown (void *cls)
{
  fprintf (stderr, "%s", _ ("Shutting down...\n"));
  if (NULL != el)
  {
    GNUNET_IDENTITY_ego_lookup_cancel (el);
    el = NULL;
  }
  if (NULL != q)
  {
    GNUNET_REVOCATION_query_cancel (q);
    q = NULL;
  }
  if (NULL != h)
  {
    GNUNET_REVOCATION_revoke_cancel (h);
    h = NULL;
  }
}


/**
 * Print the result from a revocation query.
 *
 * @param cls NULL
 * @param is_valid #GNUNET_YES if the key is still valid, #GNUNET_NO if not, #GNUNET_SYSERR on error
 */
static void
print_query_result (void *cls, int is_valid)
{
  q = NULL;
  switch (is_valid)
  {
  case GNUNET_YES:
    fprintf (stdout, _ ("Key `%s' is valid\n"), test_ego);
    break;

  case GNUNET_NO:
    fprintf (stdout, _ ("Key `%s' has been revoked\n"), test_ego);
    break;

  case GNUNET_SYSERR:
    fprintf (stdout, "%s", _ ("Internal error\n"));
    break;

  default:
    GNUNET_break (0);
    break;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Print the result from a revocation request.
 *
 * @param cls NULL
 * @param is_valid #GNUNET_YES if the key is still valid, #GNUNET_NO if not, #GNUNET_SYSERR on error
 */
static void
print_revocation_result (void *cls, int is_valid)
{
  h = NULL;
  switch (is_valid)
  {
  case GNUNET_YES:
    if (NULL != revoke_ego)
      fprintf (stdout,
               _ ("Key for ego `%s' is still valid, revocation failed (!)\n"),
               revoke_ego);
    else
      fprintf (stdout, "%s", _ ("Revocation failed (!)\n"));
    break;

  case GNUNET_NO:
    if (NULL != revoke_ego)
      fprintf (stdout,
               _ ("Key for ego `%s' has been successfully revoked\n"),
               revoke_ego);
    else
      fprintf (stdout, "%s", _ ("Revocation successful.\n"));
    break;

  case GNUNET_SYSERR:
    fprintf (stdout,
             "%s",
             _ ("Internal error, key revocation might have failed\n"));
    break;

  default:
    GNUNET_break (0);
    break;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Data needed to perform a revocation.
 */
struct RevocationData
{
  /**
   * Public key.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey key;

  /**
   * Revocation signature data.
   */
  struct GNUNET_CRYPTO_EcdsaSignature sig;

  /**
   * Time of revocation
   */
  struct GNUNET_TIME_AbsoluteNBO ts;

  /**
   * Proof of work (in NBO).
   */
  uint64_t pow GNUNET_PACKED;
};


/**
 * Perform the revocation.
 */
static void
perform_revocation (const struct GNUNET_REVOCATION_Pow *pow)
{
  h = GNUNET_REVOCATION_revoke (cfg,
                                pow,
                                &print_revocation_result,
                                NULL);
}


/**
 * Write the current state of the revocation data
 * to disk.
 *
 * @param rd data to sync
 */
static void
sync_pow (const struct GNUNET_REVOCATION_Pow *pow)
{
  if ((NULL != filename) &&
      (sizeof(struct GNUNET_REVOCATION_Pow) !=
       GNUNET_DISK_fn_write (filename,
                             pow,
                             sizeof(struct GNUNET_REVOCATION_Pow),
                             GNUNET_DISK_PERM_USER_READ
                             | GNUNET_DISK_PERM_USER_WRITE)))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "write", filename);
}


/**
 * Perform the proof-of-work calculation.
 *
 * @param cls the `struct RevocationData`
 */
static void
calculate_pow_shutdown (void *cls)
{
  struct GNUNET_REVOCATION_PowCalculationHandle *ph = cls;
  fprintf (stderr, "%s", _ ("Cancelling calculation.\n"));
  sync_pow (GNUNET_REVOCATION_pow_get (ph));
  if (NULL != pow_task)
  {
    GNUNET_SCHEDULER_cancel (pow_task);
    pow_task = NULL;
  }
  GNUNET_REVOCATION_pow_cleanup (ph);
}


/**
 * Perform the proof-of-work calculation.
 *
 * @param cls the `struct RevocationData`
 */
static void
calculate_pow (void *cls)
{
  struct GNUNET_REVOCATION_PowCalculationHandle *ph = cls;

  /* store temporary results */
  pow_task = NULL;
  if (0 == (pow_passes % 128))
    sync_pow (GNUNET_REVOCATION_pow_get(ph));
  /* actually do POW calculation */
  if (GNUNET_OK == GNUNET_REVOCATION_pow_round (ph))
  {
    const struct GNUNET_REVOCATION_Pow *pow = GNUNET_REVOCATION_pow_get (ph);
    if ((NULL != filename) &&
        (sizeof(struct GNUNET_REVOCATION_Pow) !=
         GNUNET_DISK_fn_write (filename,
                               pow,
                               sizeof(struct GNUNET_REVOCATION_Pow),
                               GNUNET_DISK_PERM_USER_READ
                               | GNUNET_DISK_PERM_USER_WRITE)))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "write", filename);
    if (perform)
    {
      perform_revocation (pow);
    }
    else
    {
      fprintf (stderr, "%s", "\n");
      fprintf (stderr,
               _ ("Revocation certificate for `%s' stored in `%s'\n"),
               revoke_ego,
               filename);
      GNUNET_SCHEDULER_shutdown ();
    }
    return;
  }
  pow_passes++;
  /**
   * Otherwise CTRL-C does not work
   */
  if (0 == pow_passes % 128)
    pow_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
                                             &calculate_pow,
                                             ph);
  else
    pow_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
                                             &calculate_pow,
                                             ph);

}


/**
 * Function called with the result from the ego lookup.
 *
 * @param cls closure
 * @param ego the ego, NULL if not found
 */
static void
ego_callback (void *cls, const struct GNUNET_IDENTITY_Ego *ego)
{
  struct GNUNET_REVOCATION_Pow *pow;
  struct GNUNET_CRYPTO_EcdsaPublicKey key;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;
  struct GNUNET_REVOCATION_PowCalculationHandle *ph = NULL;

  el = NULL;
  if (NULL == ego)
  {
    fprintf (stdout, _ ("Ego `%s' not found.\n"), revoke_ego);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_IDENTITY_ego_get_public_key (ego, &key);
  privkey = GNUNET_IDENTITY_ego_get_private_key (ego);
  pow = GNUNET_new (struct GNUNET_REVOCATION_Pow);
  if ((NULL != filename) && (GNUNET_YES == GNUNET_DISK_file_test (filename)) &&
      (sizeof(struct GNUNET_REVOCATION_Pow) ==
       GNUNET_DISK_fn_read (filename, pow, sizeof(struct
                                                  GNUNET_REVOCATION_Pow))))
  {
    if (0 != GNUNET_memcmp (&pow->key, &key))
    {
      fprintf (stderr,
               _ ("Error: revocation certificate in `%s' is not for `%s'\n"),
               filename,
               revoke_ego);
      GNUNET_free (pow);
      return;
    }
    if (GNUNET_YES ==
        GNUNET_REVOCATION_check_pow (pow,
                                     (unsigned int) matching_bits,
                                     epoch_length))
    {
      fprintf (stderr, "%s", _ ("Revocation certificate ready\n"));
      if (perform)
        perform_revocation (pow);
      else
        GNUNET_SCHEDULER_shutdown ();
      GNUNET_free (pow);
      return;
    }
    /**
     * Certificate not yet ready
     */
    fprintf (stderr,
             "%s",
             _("Continuing calculation where left off...\n"));
    ph = GNUNET_REVOCATION_pow_init2 (pow,
                                      1, /* Epochs */
                                      matching_bits);
    GNUNET_free (pow);
  }
  fprintf (stderr,
           "%s",
           _ ("Revocation certificate not ready, calculating proof of work\n"));
  if (NULL == ph)
    ph = GNUNET_REVOCATION_pow_init (privkey,
                                     1, /* Epochs */
                                     matching_bits);
  pow_task = GNUNET_SCHEDULER_add_now (&calculate_pow, ph);
  GNUNET_SCHEDULER_add_shutdown (&calculate_pow_shutdown, ph);
}


/**
 * Main function that will be run by the scheduler.
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
  struct GNUNET_CRYPTO_EcdsaPublicKey pk;
  struct GNUNET_REVOCATION_Pow pow;

  cfg = c;
  if (NULL != test_ego)
  {
    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecdsa_public_key_from_string (test_ego,
                                                    strlen (test_ego),
                                                    &pk))
    {
      fprintf (stderr, _ ("Public key `%s' malformed\n"), test_ego);
      return;
    }
    GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
    q = GNUNET_REVOCATION_query (cfg, &pk, &print_query_result, NULL);
    if (NULL != revoke_ego)
      fprintf (
        stderr,
        "%s",
        _ (
          "Testing and revoking at the same time is not allowed, only executing test.\n"));
    return;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg,
                                                          "REVOCATION",
                                                          "WORKBITS",
                                                          &matching_bits))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "REVOCATION",
                               "WORKBITS");
    return;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time (cfg,
                                                        "REVOCATION",
                                                        "EPOCH_LENGTH",
                                                        &epoch_length))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "REVOCATION",
                               "EPOCH_LENGTH");
    return;
  }

  if (NULL != revoke_ego)
  {
    if (! perform && (NULL == filename))
    {
      fprintf (stderr,
               "%s",
               _ ("No filename to store revocation certificate given.\n"));
      return;
    }
    /* main code here */
    el = GNUNET_IDENTITY_ego_lookup (cfg, revoke_ego, &ego_callback, NULL);
    GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
    return;
  }
  if ((NULL != filename) && (perform))
  {
    if (sizeof(pow) != GNUNET_DISK_fn_read (filename, &pow, sizeof(pow)))
    {
      fprintf (stderr,
               _ ("Failed to read revocation certificate from `%s'\n"),
               filename);
      return;
    }
    GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
    if (GNUNET_YES !=
        GNUNET_REVOCATION_check_pow (&pow,
                                     (unsigned int) matching_bits,
                                     epoch_length))
    {
      struct GNUNET_REVOCATION_PowCalculationHandle *ph;
      ph = GNUNET_REVOCATION_pow_init2 (&pow,
                                       1, /* Epochs */
                                       matching_bits);

      pow_task = GNUNET_SCHEDULER_add_now (&calculate_pow, ph);
      GNUNET_SCHEDULER_add_shutdown (&calculate_pow_shutdown, ph);
      return;
    }
    perform_revocation (&pow);
    return;
  }
  fprintf (stderr, "%s", _ ("No action specified. Nothing to do.\n"));
}


/**
 * The main function of gnunet-revocation.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_string ('f',
                                 "filename",
                                 "NAME",
                                 gettext_noop (
                                   "use NAME for the name of the revocation file"),
                                 &filename),

    GNUNET_GETOPT_option_string (
      'R',
      "revoke",
      "NAME",
      gettext_noop (
        "revoke the private key associated for the the private key associated with the ego NAME "),
      &revoke_ego),

    GNUNET_GETOPT_option_flag (
      'p',
      "perform",
      gettext_noop (
        "actually perform revocation, otherwise we just do the precomputation"),
      &perform),

    GNUNET_GETOPT_option_string ('t',
                                 "test",
                                 "KEY",
                                 gettext_noop (
                                   "test if the public key KEY has been revoked"),
                                 &test_ego),

    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK == GNUNET_PROGRAM_run (argc,
                                          argv,
                                          "gnunet-revocation",
                                          gettext_noop ("help text"),
                                          options,
                                          &run,
                                          NULL))
        ? ret
        : 1;
  GNUNET_free ((void *) argv);
  return ret;
}


/* end of gnunet-revocation.c */
