/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/
/**
 * @file namestore/test_namestore_record_serialization.c
 * @brief testcase for test_namestore_record_serialization.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_namestore_service.h"
#include "namestore.h"

#define VERBOSE GNUNET_NO

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

static int res;

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char * dest = NULL;
  size_t len;
  int c;
  int elem = 0;

  int rd_count = 3;
  size_t data_len;
  struct GNUNET_NAMESTORE_RecordData src[rd_count];
  struct GNUNET_NAMESTORE_RecordData *dst = NULL;

  memset(src, '\0', rd_count * sizeof (struct GNUNET_NAMESTORE_RecordData));

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

  len = GNUNET_NAMESTORE_records_serialize (&dest, rd_count, src);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Serialized data len: %u\n",len);

  GNUNET_assert (dest != NULL);

  elem = GNUNET_NAMESTORE_records_deserialize(&dst, dest, len);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deserialized elements: %u\n",elem);

  GNUNET_assert (elem == rd_count);
  GNUNET_assert (dst != NULL);

  for (c = 0; c < elem; c++)
  {
    if (src[c].data_size != dst[c].data_size)
    {
      GNUNET_break (0);
      res = 1;
    }
    if (GNUNET_TIME_absolute_get_difference(src[c].expiration, dst[c].expiration).rel_value != GNUNET_TIME_relative_get_zero().rel_value)
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
    /* clean up */
    GNUNET_free((char *) dst[c].data);
    GNUNET_free((char *) src[c].data);
  }
  GNUNET_free (dest);
  GNUNET_free (dst);
}

static int
check ()
{
  static char *const argv[] = { "test_namestore_record_serialization",
    "-c",
    "test_namestore_api.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
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

int
main (int argc, char *argv[])
{
  int ret;

  ret = check ();

  return ret;
}

/* end of test_namestore_record_serialization.c */
