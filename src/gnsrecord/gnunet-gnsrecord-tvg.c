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
 * @file util/gnunet-gns-tvg.c
 * @brief Generate test vectors for GNS.
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_gns_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_testing_lib.h"
#include <inttypes.h>

#define TEST_RECORD_LABEL "test"
#define TEST_RECORD_A "1.2.3.4"
#define TEST_RRCOUNT 2

static void
print_bytes (void *buf,
             size_t buf_len,
             int fold)
{
  int i;

  for (i = 0; i < buf_len; i++)
  {
    if ((0 != i) && (0 != fold) && (i % fold == 0))
      printf ("\n");
    printf ("%02x", ((unsigned char*) buf)[i]);
  }
  printf ("\n");
}


static void
print_record (const struct GNUNET_GNSRECORD_Data *rd)
{

  fprintf (stdout,
           "EXPIRATION: %" PRIu64 "\n", rd->expiration_time);
  fprintf (stdout,
           "DATA_SIZE: %zu\n", rd->data_size);
  fprintf (stdout,
           "TYPE: %d\n", rd->record_type);
  fprintf (stdout,
           "FLAGS: %d\n", rd->flags);
  fprintf (stdout,
           "DATA:\n");
  print_bytes ((char*) rd->data, rd->data_size, 8);
  fprintf (stdout, "\n");
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
  struct GNUNET_GNSRECORD_Data rd[2];
  struct GNUNET_TIME_Absolute exp_abs = GNUNET_TIME_absolute_get ();
  struct GNUNET_GNSRECORD_Block *rrblock;
  char *bdata;
  struct GNUNET_CRYPTO_EcdsaPrivateKey id_priv;
  struct GNUNET_CRYPTO_EcdsaPublicKey id_pub;
  struct GNUNET_CRYPTO_EcdsaPrivateKey pkey_data_p;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey_data;
  void *data;
  size_t data_size;
  char *rdata;
  size_t rdata_size;

  GNUNET_CRYPTO_ecdsa_key_create (&id_priv);
  GNUNET_CRYPTO_ecdsa_key_get_public (&id_priv,
                                      &id_pub);
  fprintf (stdout, "Zone private key (d, little-endian scalar):\n");
  print_bytes (&id_priv, sizeof(id_priv), 0);
  fprintf (stdout, "\n");
  fprintf (stdout, "Zone public key (zk):\n");
  print_bytes (&id_pub, sizeof(id_pub), 0);
  fprintf (stdout, "\n");

  GNUNET_CRYPTO_ecdsa_key_create (&pkey_data_p);
  GNUNET_CRYPTO_ecdsa_key_get_public (&pkey_data_p,
                                      &pkey_data);
  fprintf (stdout,
           "Label: %s\nRRCOUNT: %d\n\n", TEST_RECORD_LABEL, TEST_RRCOUNT);
  memset (rd, 0, sizeof (struct GNUNET_GNSRECORD_Data) * 2);
  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_string_to_value (
                   GNUNET_DNSPARSER_TYPE_A, TEST_RECORD_A, &data, &data_size));
  rd[0].data = data;
  rd[0].data_size = data_size;
  rd[0].expiration_time = exp_abs.abs_value_us;
  rd[0].record_type = GNUNET_DNSPARSER_TYPE_A;
  fprintf (stdout, "Record #0\n");
  print_record (&rd[0]);

  rd[1].data = &pkey_data;
  rd[1].data_size = sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey);
  rd[1].expiration_time = exp_abs.abs_value_us;
  rd[1].record_type = GNUNET_GNSRECORD_TYPE_PKEY;
  rd[1].flags = GNUNET_GNSRECORD_RF_PRIVATE;
  fprintf (stdout, "Record #1\n");
  print_record (&rd[1]);

  rdata_size = GNUNET_GNSRECORD_records_get_size (2,
                                                  rd);
  rdata = GNUNET_malloc (rdata_size);
  GNUNET_GNSRECORD_records_serialize (2,
                                      rd,
                                      rdata_size,
                                      rdata);
  fprintf (stdout, "RDATA:\n");
  print_bytes (rdata, rdata_size, 8);
  fprintf (stdout, "\n");
  rrblock = GNUNET_GNSRECORD_block_create (&id_priv,
                                           exp_abs,
                                           TEST_RECORD_LABEL,
                                           rd,
                                           TEST_RRCOUNT);
  size_t bdata_size = ntohl (rrblock->purpose.size)
                      - sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
                      - sizeof(struct GNUNET_TIME_AbsoluteNBO);
  size_t rrblock_size = ntohl (rrblock->purpose.size)
                        + sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)
                        + sizeof(struct GNUNET_CRYPTO_EcdsaSignature);

  bdata = (char*) &rrblock[1];
  fprintf (stdout, "BDATA:\n");
  print_bytes (bdata, bdata_size, 8);
  fprintf (stdout, "\n");
  fprintf (stdout, "RRBLOCK:\n");
  print_bytes (rrblock, rrblock_size, 8);
  fprintf (stdout, "\n");

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
                 GNUNET_log_setup ("gnunet-gns-tvg",
                                   "INFO",
                                   NULL));
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv,
                          "gnunet-gns-tvg",
                          "Generate test vectors for GNS",
                          options,
                          &run, NULL))
    return 1;
  return 0;
}


/* end of gnunet-gns-tvg.c */
