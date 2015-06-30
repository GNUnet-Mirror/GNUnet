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
 * @file gnsrecord/test_gnsrecord_serialization.c
 * @brief testcase for gnsrecord_serialization.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_gnsrecord_lib.h"

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)

static int res;


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  size_t len;
  int c;

  int rd_count = 3;
  size_t data_len;
  struct GNUNET_GNSRECORD_Data src[rd_count];

  memset(src, '\0', rd_count * sizeof (struct GNUNET_GNSRECORD_Data));

  data_len = 0;
  for (c = 0; c < rd_count; c++)
  {
    src[c].record_type = c+1;
    src[c].data_size = data_len;
    src[c].data = GNUNET_malloc (data_len);

    /* Setting data to data_len * record_type */
    memset ((char *) src[c].data, 'a', data_len);
    data_len += 10;
  }
  res = 0;

  len = GNUNET_GNSRECORD_records_get_size(rd_count, src);
  char rd_ser[len];
  GNUNET_assert (len == GNUNET_GNSRECORD_records_serialize(rd_count, src, len, rd_ser));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Serialized data len: %u\n",len);

  GNUNET_assert (rd_ser != NULL);

  struct GNUNET_GNSRECORD_Data dst[rd_count];
  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_records_deserialize (len, rd_ser, rd_count, dst));

  GNUNET_assert (dst != NULL);

  for (c = 0; c < rd_count; c++)
  {
    if (src[c].data_size != dst[c].data_size)
    {
      GNUNET_break (0);
      res = 1;
    }
    if (src[c].expiration_time != dst[c].expiration_time)
    {
      GNUNET_break (0);
      res = 1;
    }
    if (src[c].flags != dst[c].flags)
    {
      GNUNET_break (0);
      res = 1;
    }
    if (src[c].record_type != dst[c].record_type)
    {
      GNUNET_break (0);
      res = 1;
    }

    size_t data_size = src[c].data_size;
    char data[data_size];
    memset (data, 'a', data_size);
    if (0 != memcmp (data, dst[c].data, data_size))
    {
      GNUNET_break (0);
      res = 1;
    }
    if (0 != memcmp (data, src[c].data, data_size))
    {
      GNUNET_break (0);
      res = 1;
    }
    if (0 != memcmp (src[c].data, dst[c].data, src[c].data_size))
    {
      GNUNET_break (0);
      res = 1;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Element [%i]: EQUAL\n", c);
  }

  for (c = 0; c < rd_count; c++)
  {
    GNUNET_free ((void *)src[c].data);
  }
}


int
main (int argcx, char *argvx[])
{
  static char *const argv[] = { "test_gnsrecord_serialization",
    NULL
  };
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  res = 1;
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv, "test_namestore_record_serialization",
                      "nohelp", options, &run, &res);
  return res;
}

/* end of test_gnsrecord_serialization.c */
