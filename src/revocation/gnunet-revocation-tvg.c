/*
     This file is part of GNUnet.
     Copyright (C) 2020 GNUnet e.V.

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
 * @file util/gnunet-revocation-tvg.c
 * @brief Generate test vectors for revocation.
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_revocation_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_testing_lib.h"
#include <inttypes.h>

#define TEST_EPOCHS 2
#define TEST_DIFFICULTY 5

static void
print_bytes (void *buf,
             size_t buf_len,
             int fold)
{
  int i;

  for (i = 0; i < buf_len; i++)
  {
    if ((0 != i) && (0 != fold) && (i%fold == 0))
      printf("\n");
    printf("%02x", ((unsigned char*)buf)[i]);
  }
  printf("\n");
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CRYPTO_EcdsaPrivateKey id_priv;
  struct GNUNET_CRYPTO_EcdsaPublicKey id_pub;
  struct GNUNET_REVOCATION_PowP pow;
  struct GNUNET_REVOCATION_PowCalculationHandle *ph;
  struct GNUNET_TIME_Relative exp;

  GNUNET_CRYPTO_ecdsa_key_create (&id_priv);
  GNUNET_CRYPTO_ecdsa_key_get_public (&id_priv,
                                      &id_pub);
  fprintf(stdout, "Zone private key (d, little-endian scalar):\n");
  print_bytes (&id_priv, sizeof(id_priv), 0);
  fprintf(stdout, "\n");
  fprintf(stdout, "Zone public key (zk):\n");
  print_bytes (&id_pub, sizeof(id_pub), 0);
  fprintf(stdout, "\n");
  memset (&pow, 0, sizeof (pow));
  GNUNET_REVOCATION_pow_init (&id_priv,
                              &pow);
  ph = GNUNET_REVOCATION_pow_start (&pow,
                                    TEST_EPOCHS,
                                    TEST_DIFFICULTY);
  fprintf (stdout, "Difficulty (%d base difficulty + %d epochs): %d\n\n",
           TEST_DIFFICULTY,
           TEST_EPOCHS,
           TEST_DIFFICULTY + TEST_EPOCHS);
  uint64_t pow_passes = 0;
  while (GNUNET_YES != GNUNET_REVOCATION_pow_round (ph))
  {
    pow_passes++;
  }
  exp = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_YEARS,
                                       TEST_EPOCHS);
  GNUNET_assert (GNUNET_OK == GNUNET_REVOCATION_check_pow (&pow,
                                                           TEST_DIFFICULTY,
                                                           exp));
  fprintf(stdout, "Proof:\n");
  print_bytes (&pow,
               sizeof (pow),
               8);
}


/**
 * The main function of the test vector generation tool.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_log_setup ("gnunet-revocation-tvg",
                                   "INFO",
                                   NULL));
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv,
                          "gnunet-revocation-tvg",
                          "Generate test vectors for revocation",
                          options,
                          &run, NULL))
    return 1;
  return 0;
}


/* end of gnunet-revocation-tvg.c */
