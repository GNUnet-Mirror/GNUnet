/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file gnsrecord/test_gnsrecord_crypto.c
 * @brief testcase for block creation, verification and decryption
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"

#define RECORDS 5

#define TEST_RECORD_TYPE 1234

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'

#define TEST_REMOVE_RECORD_TYPE 4321

#define TEST_REMOVE_RECORD_DATALEN 255

#define TEST_REMOVE_RECORD_DATA 'b'


static struct GNUNET_CRYPTO_EcdsaPrivateKey * privkey;

static struct GNUNET_GNSRECORD_Data *s_rd;

static char *s_name;

static int res;


static struct GNUNET_GNSRECORD_Data *
create_record (int count)
{
  unsigned int c;
  struct GNUNET_GNSRECORD_Data *rd;

  rd = GNUNET_malloc (count * sizeof (struct GNUNET_GNSRECORD_Data));
  for (c = 0; c < count; c++)
  {
    rd[c].expiration_time = GNUNET_TIME_absolute_get().abs_value_us + 1000000000;
    rd[c].record_type = TEST_RECORD_TYPE;
    rd[c].data_size = TEST_RECORD_DATALEN;
    rd[c].data = GNUNET_malloc(TEST_RECORD_DATALEN);
    memset ((char *) rd[c].data, TEST_RECORD_DATA, TEST_RECORD_DATALEN);
  }
  return rd;
}


static void
rd_decrypt_cb (void *cls,
               unsigned int rd_count,
               const struct GNUNET_GNSRECORD_Data *rd)
{
  char rd_cmp_data[TEST_RECORD_DATALEN];
  int c;

  GNUNET_assert (RECORDS == rd_count);
  GNUNET_assert (NULL != rd);

  memset (rd_cmp_data, 'a', TEST_RECORD_DATALEN);
  for (c = 0; c < rd_count; c++)
  {
    GNUNET_assert (TEST_RECORD_TYPE == rd[c].record_type);
    GNUNET_assert (TEST_RECORD_DATALEN == rd[c].data_size);
    GNUNET_assert (0 == memcmp (&rd_cmp_data, rd[c].data, TEST_RECORD_DATALEN));
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Block was decrypted successfully \n");
  res = 0;

}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_CRYPTO_EcdsaPublicKey pubkey;

  /* load privat key */
  char *hostkey_file;
  GNUNET_asprintf(&hostkey_file,
                  "zonefiles%s%s",
                  DIR_SEPARATOR_STR,
                  "N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Using zonekey file `%s'\n",
              hostkey_file);
  privkey = GNUNET_CRYPTO_ecdsa_key_create_from_file(hostkey_file);
  GNUNET_free (hostkey_file);
  GNUNET_assert (privkey != NULL);
  struct GNUNET_TIME_Absolute expire = GNUNET_TIME_absolute_get();
  /* get public key */
  GNUNET_CRYPTO_ecdsa_key_get_public(privkey, &pubkey);

  /* create record */
  s_name = "DUMMY.dummy.gnunet";
  s_rd = create_record (RECORDS);

  /* Create block */
  GNUNET_assert (NULL != (block = GNUNET_GNSRECORD_block_create (privkey, expire,s_name, s_rd, RECORDS)));
  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_block_verify (block));
  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_block_decrypt (block, &pubkey, s_name, &rd_decrypt_cb, s_name));

  GNUNET_free (block);
}


int
main (int argc, char *argv[])
{
  static char *const argvx[] = { "test-gnsrecord-crypto",
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  res = 1;
  GNUNET_PROGRAM_run ((sizeof (argvx) / sizeof (char *)) - 1, argvx, "test-namestore-api",
                      "nohelp", options, &run, &res);
  return res;
}

/* end of test_gnsrecord_crypto.c */
