/*
     This file is part of GNUnet.
     Copyright (C) 2002, 2003, 2004, 2006 GNUnet e.V.

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
 * @author Christian Grothoff
 * @file util/perf_crypto_hash.c
 * @brief measure performance of hash function
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gauger.h>
#include <gcrypt.h>


static void
perfHash ()
{
  struct GNUNET_HashCode hc;
  unsigned int i;
  char buf[64 * 1024];

  memset (buf, 1, sizeof(buf));
  for (i = 0; i < 1024; i++)
    GNUNET_CRYPTO_hash (buf, sizeof(buf), &hc);
}


static void
perfHashSmall ()
{
  struct GNUNET_HashCode hc;
  unsigned int i;
  char buf[64];

  memset (buf, 1, sizeof(buf));
  for (i = 0; i < 1024; i++)
    GNUNET_CRYPTO_hash (buf, sizeof(buf), &hc);
}


static void
perfHKDF ()
{
  unsigned int i;
  char res[128];
  char buf[128];
  char skm[64];

  memset (buf, 1, sizeof(buf));
  memset (skm, 2, sizeof(skm));
  for (i = 0; i < 1024; i++)
    GNUNET_CRYPTO_hkdf (res, sizeof(res),
                        GCRY_MD_SHA512, GCRY_MD_SHA256,
                        buf, sizeof(buf),
                        skm, sizeof(skm),
                        "test", (size_t) 4,
                        NULL, 0);
}


int
main (int argc, char *argv[])
{
  struct GNUNET_TIME_Absolute start;

  start = GNUNET_TIME_absolute_get ();
  perfHashSmall ();
  printf ("1024x 64-byte Hash perf took %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));

  start = GNUNET_TIME_absolute_get ();
  perfHash ();
  printf ("1024x 64k Hash perf took %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  GAUGER ("UTIL", "Cryptographic hashing",
          64 * 1024 / (1
                       + GNUNET_TIME_absolute_get_duration
                         (start).rel_value_us / 1000LL), "kb/ms");
  start = GNUNET_TIME_absolute_get ();
  perfHKDF ();
  printf ("HKDF perf took %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  GAUGER ("UTIL", "Cryptographic HKDF",
          64 * 1024 / (1
                       + GNUNET_TIME_absolute_get_duration
                         (start).rel_value_us / 1000LL), "kb/ms");
  return 0;
}


/* end of perf_crypto_hash.c */
