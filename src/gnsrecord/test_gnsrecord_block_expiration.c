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

static int res;



static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_GNSRECORD_Data rd[2];
  struct GNUNET_TIME_Absolute expiration_abs;
  struct GNUNET_TIME_Absolute expiration_abs_shadow;

  expiration_abs.abs_value_us = GNUNET_TIME_absolute_get().abs_value_us +
      GNUNET_TIME_UNIT_SECONDS.rel_value_us;
  expiration_abs_shadow.abs_value_us = GNUNET_TIME_absolute_get().abs_value_us +
      GNUNET_TIME_UNIT_MINUTES.rel_value_us;

  /* create record */
  rd[0].expiration_time = expiration_abs.abs_value_us;
  rd[0].record_type = TEST_RECORD_TYPE;
  rd[0].data_size = TEST_RECORD_DATALEN;
  rd[0].data = GNUNET_malloc(TEST_RECORD_DATALEN);
  rd[0].flags = GNUNET_GNSRECORD_RF_NONE;
  memset ((char *) rd[0].data, TEST_RECORD_DATA, TEST_RECORD_DATALEN);

  rd[1].expiration_time = expiration_abs.abs_value_us;
  rd[1].record_type = TEST_RECORD_TYPE;
  rd[1].data_size = TEST_RECORD_DATALEN;
  rd[1].data = GNUNET_malloc(TEST_RECORD_DATALEN);
  rd[1].flags = GNUNET_GNSRECORD_RF_NONE;
  memset ((char *) rd[1].data, TEST_RECORD_DATA, TEST_RECORD_DATALEN);

  GNUNET_assert (expiration_abs.abs_value_us == GNUNET_GNSRECORD_record_get_expiration_time(2, rd).abs_value_us);

  rd[1].expiration_time = expiration_abs_shadow.abs_value_us;
  rd[1].record_type = TEST_RECORD_TYPE;
  rd[1].data_size = TEST_RECORD_DATALEN;
  rd[1].data = GNUNET_malloc(TEST_RECORD_DATALEN);
  rd[1].flags = GNUNET_GNSRECORD_RF_SHADOW_RECORD;
  memset ((char *) rd[1].data, TEST_RECORD_DATA, TEST_RECORD_DATALEN);

  GNUNET_assert (expiration_abs_shadow.abs_value_us == GNUNET_GNSRECORD_record_get_expiration_time(2, rd).abs_value_us);
  res = 0;
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
