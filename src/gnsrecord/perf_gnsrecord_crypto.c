/*
     This file is part of GNUnet.
     Copyright (C) 2018 GNUnet e.V.

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
 * @file gnsrecord/test_gnsrecord_crypto.c
 * @brief testcase for block creation, verification and decryption
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"

#define ROUNDS 1000

#define RECORDS 5

#define TEST_RECORD_TYPE 1234

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'

#define TEST_REMOVE_RECORD_TYPE 4321

#define TEST_REMOVE_RECORD_DATALEN 255

#define TEST_REMOVE_RECORD_DATA 'b'


static struct GNUNET_GNSRECORD_Data *
create_record (int count)
{
  struct GNUNET_GNSRECORD_Data *rd;

  rd = GNUNET_new_array (count,
                         struct GNUNET_GNSRECORD_Data);
  for (unsigned int c = 0; c < count; c++)
  {
    rd[c].expiration_time = GNUNET_TIME_absolute_get ().abs_value_us
                            + 1000000000;
    rd[c].record_type = TEST_RECORD_TYPE;
    rd[c].data_size = TEST_RECORD_DATALEN;
    rd[c].data = GNUNET_malloc (TEST_RECORD_DATALEN);
    memset ((char *) rd[c].data, TEST_RECORD_DATA, TEST_RECORD_DATALEN);
  }
  return rd;
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_HashCode query;
  struct GNUNET_GNSRECORD_Data *s_rd;
  const char *s_name;
  struct GNUNET_TIME_Absolute start_time;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *privkey;
  struct GNUNET_TIME_Absolute expire;

  (void) cls;
  (void) args;
  (void) cfgfile;
  (void) cfg;
  expire = GNUNET_TIME_absolute_get ();
  privkey = GNUNET_CRYPTO_ecdsa_key_create ();
  GNUNET_assert (NULL != privkey);

  /* test block creation */
  s_name = "DUMMY.dummy.gnunet";
  s_rd = create_record (RECORDS);
  start_time = GNUNET_TIME_absolute_get ();
  for (unsigned int i = 0; i < ROUNDS; i++)
  {
    GNUNET_assert (NULL != (block =
                              GNUNET_GNSRECORD_block_create2 (privkey,
                                                              expire,
                                                              s_name,
                                                              s_rd,
                                                              RECORDS)));
    GNUNET_GNSRECORD_query_from_private_key (privkey,
                                             s_name,
                                             &query);
    GNUNET_free (block);
  }
  fprintf (stderr,
           "Took %s to produce %u GNS blocks for the DHT\n",
           GNUNET_STRINGS_relative_time_to_string (
             GNUNET_TIME_absolute_get_duration (start_time),
             GNUNET_YES),
           ROUNDS);
  for (unsigned int i = 0; i < RECORDS; i++)
    GNUNET_free ((void *) s_rd[i].data);
  GNUNET_free (s_rd);
  GNUNET_free (privkey);
}


int
main (int argc, char *argv[])
{
  static char *const argvx[] = {
    "perf-gnsrecord-crypto",
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK !=
      GNUNET_PROGRAM_run ((sizeof(argvx) / sizeof(char *)) - 1,
                          argvx,
                          "perf-gnsrecord-crypto",
                          "nohelp", options,
                          &run,
                          NULL))
    return 1;
  return 0;
}


/* end of test_gnsrecord_crypto.c */
