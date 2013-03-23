/*
     This file is part of GNUnet.
     (C) 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @author Christian Grothoff
 * @file util/perf_crypto_hash.c
 * @brief measure performance of hash function
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include <gauger.h>


static void
perfHash ()
{
  struct GNUNET_HashCode hc;
  unsigned int i;
  char buf[64 * 1024];

  memset (buf, 1, sizeof (buf));
  for (i = 0; i < 1024; i++)
    GNUNET_CRYPTO_hash (buf, sizeof (buf), &hc);
}


int
main (int argc, char *argv[])
{
  struct GNUNET_TIME_Absolute start;

  start = GNUNET_TIME_absolute_get ();
  perfHash ();
  printf ("Hash perf took %s\n",
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start),
						  GNUNET_YES));
  GAUGER ("UTIL", "Cryptographic hashing",
          1024 * 64 * 1024 / (1 +
                              GNUNET_TIME_absolute_get_duration
                              (start).rel_value), "kb/s");
  return 0;
}

/* end of perf_crypto_hash.c */
