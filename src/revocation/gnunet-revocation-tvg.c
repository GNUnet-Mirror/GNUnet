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
  char* data_enc;

  GNUNET_CRYPTO_ecdsa_key_create (&id_priv);
  GNUNET_CRYPTO_ecdsa_key_get_public (&id_priv,
                                      &id_pub);
  GNUNET_STRINGS_base64_encode (&id_priv,
                                sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey),
                                &data_enc);
  fprintf(stdout, "Zone private key (d):\n%s\n\n", data_enc);
  GNUNET_free (data_enc);
  GNUNET_STRINGS_base64_encode (&id_pub,
                                sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey),
                                &data_enc);
  fprintf(stdout, "Zone public key (zk):\n%s\n\n", data_enc);
  GNUNET_free (data_enc);

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
  GNUNET_STRINGS_base64_encode (&pow,
                                sizeof (struct GNUNET_REVOCATION_PowP),
                                &data_enc);
  fprintf(stdout, "Proof:\n%s\n", data_enc);
  GNUNET_free (data_enc);
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
