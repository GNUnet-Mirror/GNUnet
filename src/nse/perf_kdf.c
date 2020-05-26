/*
     This file is part of GNUnet.
     Copyright (C) 2002, 2003, 2004, 2006, 2013 GNUnet e.V.

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
 * @file nse/perf_kdf.c
 * @brief measure performance of KDF hash function
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>
#include <gauger.h>


static void
perfHash ()
{
  struct GNUNET_HashCode hc;
  char buf[64];

  memset (buf, 1, sizeof(buf));
  for (unsigned int i = 0; i < 1024; i++)
    GNUNET_CRYPTO_pow_hash ("gnunet-nse-proof",
                            buf,
                            sizeof(buf),
                            &hc);
}


int
main (int argc, char *argv[])
{
  struct GNUNET_TIME_Absolute start;

  start = GNUNET_TIME_absolute_get ();
  perfHash ();
  printf ("Hash perf took %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  GAUGER ("NSE", "Proof-of-work hashing",
          1024.0 / (1.0
                    + GNUNET_TIME_absolute_get_duration
                      (start).rel_value_us / 1000.0), "hashes/ms");
  return 0;
}


/* end of perf_kdf.c */
