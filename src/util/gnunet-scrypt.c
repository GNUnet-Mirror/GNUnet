/*
     This file is part of GNUnet.
     Copyright (C) 2014 GNUnet e.V.

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
 * @file util/gnunet-scrypt.c
 * @brief tool to manipulate SCRYPT proofs of work.
 * @author Bart Polot
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>

/**
 * Amount of work required (W-bit collisions) for NSE proofs, in collision-bits.
 */
static unsigned long long nse_work_required;

/**
 * Interval between proof find runs.
 */
static struct GNUNET_TIME_Relative proof_find_delay;

static struct GNUNET_CRYPTO_EddsaPublicKey pub;

static uint64_t proof;

static struct GNUNET_SCHEDULER_Task *proof_task;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static char *pkfn;

static char *pwfn;


/**
 * Write our current proof to disk.
 *
 * @param cls closure
 */
static void
shutdown_task (void *cls)
{
  (void) cls;
  if (sizeof(proof) != GNUNET_DISK_fn_write (pwfn,
                                             &proof,
                                             sizeof(proof),
                                             GNUNET_DISK_PERM_USER_READ
                                             | GNUNET_DISK_PERM_USER_WRITE))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "write", pwfn);
}


/**
 * Count the leading zeroes in hash.
 *
 * @param hash to count leading zeros in
 * @return the number of leading zero bits.
 */
static unsigned int
count_leading_zeroes (const struct GNUNET_HashCode *hash)
{
  unsigned int hash_count;

  hash_count = 0;
  while (0 == GNUNET_CRYPTO_hash_get_bit_ltr (hash, hash_count))
    hash_count++;
  return hash_count;
}


/**
 * Find our proof of work.
 *
 * @param cls closure (unused)
 * @param tc task context
 */
static void
find_proof (void *cls)
{
#define ROUND_SIZE 10
  uint64_t counter;
  char buf[sizeof(struct GNUNET_CRYPTO_EddsaPublicKey)
           + sizeof(uint64_t)] GNUNET_ALIGN;
  struct GNUNET_HashCode result;
  unsigned int i;
  struct GNUNET_TIME_Absolute timestamp;
  struct GNUNET_TIME_Relative elapsed;

  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got Proof of Work %llu\n",
              (unsigned long long) proof);
  proof_task = NULL;
  GNUNET_memcpy (&buf[sizeof(uint64_t)],
                 &pub,
                 sizeof(struct GNUNET_CRYPTO_EddsaPublicKey));
  i = 0;
  counter = proof;
  timestamp = GNUNET_TIME_absolute_get ();
  while ((counter != UINT64_MAX) && (i < ROUND_SIZE))
  {
    GNUNET_memcpy (buf, &counter, sizeof(uint64_t));
    GNUNET_CRYPTO_pow_hash ("gnunet-nse-proof",
                            buf,
                            sizeof(buf),
                            &result);
    if (nse_work_required <= count_leading_zeroes (&result))
    {
      proof = counter;
      fprintf (stdout,
               "Proof of work found: %llu!\n",
               (unsigned long long) proof);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    counter++;
    i++;
  }
  elapsed = GNUNET_TIME_absolute_get_duration (timestamp);
  elapsed = GNUNET_TIME_relative_divide (elapsed, ROUND_SIZE);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Current: %llu [%s/proof]\n",
              (unsigned long long) counter,
              GNUNET_STRINGS_relative_time_to_string (elapsed, 0));
  if (proof / (100 * ROUND_SIZE) < counter / (100 * ROUND_SIZE))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Testing proofs currently at %llu\n",
                (unsigned long long) counter);
    /* remember progress every 100 rounds */
    proof = counter;
    shutdown_task (NULL);
  }
  else
  {
    proof = counter;
  }
  proof_task =
    GNUNET_SCHEDULER_add_delayed_with_priority (proof_find_delay,
                                                GNUNET_SCHEDULER_PRIORITY_IDLE,
                                                &find_proof,
                                                NULL);
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  struct GNUNET_CRYPTO_EddsaPrivateKey pk;
  char *pids;

  (void) cls;
  (void) args;
  (void) cfgfile;
  cfg = config;
  /* load proof of work */
  if (NULL == pwfn)
  {
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                              "NSE",
                                                              "PROOFFILE",
                                                              &pwfn))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "NSE", "PROOFFILE");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Proof of Work file: %s\n", pwfn);
  if ((GNUNET_YES != GNUNET_DISK_file_test (pwfn)) ||
      (sizeof(proof) != GNUNET_DISK_fn_read (pwfn, &proof, sizeof(proof))))
    proof = 0;

  /* load private key */
  if (NULL == pkfn)
  {
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                              "PEER",
                                                              "PRIVATE_KEY",
                                                              &pkfn))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                                 "PEER",
                                 "PRIVATE_KEY");
      return;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Private Key file: %s\n", pkfn);
  if (GNUNET_SYSERR ==
      GNUNET_CRYPTO_eddsa_key_from_file (pkfn,
                                         GNUNET_YES,
                                         &pk))
  {
    fprintf (stderr, _ ("Loading hostkey from `%s' failed.\n"), pkfn);
    GNUNET_free (pkfn);
    return;
  }
  GNUNET_free (pkfn);
  GNUNET_CRYPTO_eddsa_key_get_public (&pk,
                                      &pub);
  pids = GNUNET_CRYPTO_eddsa_public_key_to_string (&pub);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Peer ID: %s\n", pids);
  GNUNET_free (pids);

  /* get target bit amount */
  if (0 == nse_work_required)
  {
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg,
                                                            "NSE",
                                                            "WORKBITS",
                                                            &nse_work_required))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "NSE", "WORKBITS");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if (nse_work_required >= sizeof(struct GNUNET_HashCode) * 8)
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                                 "NSE",
                                 "WORKBITS",
                                 _ ("Value is too large.\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    else if (0 == nse_work_required)
    {
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Bits: %llu\n", nse_work_required);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Delay between tries: %s\n",
              GNUNET_STRINGS_relative_time_to_string (proof_find_delay, 1));
  proof_task =
    GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
                                        &find_proof,
                                        NULL);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
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
  struct GNUNET_GETOPT_CommandLineOption options[] =
  { GNUNET_GETOPT_option_ulong (
      'b',
      "bits",
      "BITS",
      gettext_noop ("number of bits to require for the proof of work"),
      &nse_work_required),
    GNUNET_GETOPT_option_filename (
      'k',
      "keyfile",
      "FILE",
      gettext_noop ("file with private key, otherwise default is used"),
      &pkfn),
    GNUNET_GETOPT_option_filename (
      'o',
      "outfile",
      "FILE",
      gettext_noop ("file with proof of work, otherwise default is used"),
      &pwfn),
    GNUNET_GETOPT_option_relative_time ('t',
                                        "timeout",
                                        "TIME",
                                        gettext_noop (
                                          "time to wait between calculations"),
                                        &proof_find_delay),
    GNUNET_GETOPT_OPTION_END };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret =
    (GNUNET_OK ==
     GNUNET_PROGRAM_run (argc,
                         argv,
                         "gnunet-scrypt [OPTIONS] prooffile",
                         gettext_noop ("Manipulate GNUnet proof of work files"),
                         options,
                         &run,
                         NULL))
    ? 0
    : 1;
  GNUNET_free_nz ((void *) argv);
  GNUNET_free_non_null (pwfn);
  return ret;
}


/* end of gnunet-scrypt.c */
