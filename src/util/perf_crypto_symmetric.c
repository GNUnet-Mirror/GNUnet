/*
     This file is part of GNUnet.
     Copyright (C) 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @file util/perf_crypto_symmetric.c
 * @brief measure performance of encryption function
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gauger.h>


static void
perfEncrypt ()
{
  unsigned int i;
  char buf[64 * 1024];
  char rbuf[64 * 1024];
  struct GNUNET_CRYPTO_SymmetricSessionKey sk;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;

  GNUNET_CRYPTO_symmetric_create_session_key (&sk);

  memset (buf, 1, sizeof (buf));
  for (i = 0; i < 1024; i++)
  {
    memset (&iv, (int8_t) i, sizeof (iv));
    GNUNET_CRYPTO_symmetric_encrypt (buf, sizeof (buf),
                               &sk, &iv,
                               rbuf);
    GNUNET_CRYPTO_symmetric_decrypt (rbuf, sizeof (buf),
                               &sk, &iv,
                               buf);
  }
  memset (rbuf, 1, sizeof (rbuf));
  GNUNET_assert (0 == memcmp (rbuf, buf, sizeof (buf)));
}


int
main (int argc, char *argv[])
{
  struct GNUNET_TIME_Absolute start;

  start = GNUNET_TIME_absolute_get ();
  perfEncrypt ();
  printf ("Encrypt perf took %s\n",
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start),
						  GNUNET_YES));
  GAUGER ("UTIL", "Symmetric encryption",
          64 * 1024 / (1 +
		       GNUNET_TIME_absolute_get_duration
		       (start).rel_value_us / 1000LL), "kb/ms");
  return 0;
}

/* end of perf_crypto_aes.c */
