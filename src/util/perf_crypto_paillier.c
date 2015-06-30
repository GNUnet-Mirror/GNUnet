/*
     This file is part of GNUnet.
     Copyright (C) 2014 Christian Grothoff (and other contributing authors)

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
 * @file util/perf_crypto_paillier.c
 * @brief measure performance of Paillier encryption
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gauger.h>


int
main (int argc, char *argv[])
{
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_CRYPTO_PaillierPublicKey public_key;
  struct GNUNET_CRYPTO_PaillierPrivateKey private_key;
  struct GNUNET_CRYPTO_PaillierCiphertext c1;
  gcry_mpi_t m1;
  unsigned int i;

  start = GNUNET_TIME_absolute_get ();
  for (i=0;i<10;i++)
    GNUNET_CRYPTO_paillier_create (&public_key,
                                   &private_key);
  printf ("10x key generation took %s\n",
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start),
						  GNUNET_YES));
  GAUGER ("UTIL", "Paillier key generation",
          64 * 1024 / (1 +
		       GNUNET_TIME_absolute_get_duration
		       (start).rel_value_us / 1000LL), "keys/ms");

  m1 = gcry_mpi_new (0);
  m1 = gcry_mpi_set_ui (m1, 1);
  /* m1 = m1 * 2 ^ (GCPB - 3) */
  gcry_mpi_mul_2exp (m1,
                     m1,
                     GNUNET_CRYPTO_PAILLIER_BITS - 3);
  start = GNUNET_TIME_absolute_get ();
  for (i=0;i<10;i++)
    GNUNET_CRYPTO_paillier_encrypt (&public_key,
                                    m1,
                                    2,
                                    &c1);
  printf ("10x encryption took %s\n",
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start),
						  GNUNET_YES));
  GAUGER ("UTIL", "Paillier encryption",
          64 * 1024 / (1 +
		       GNUNET_TIME_absolute_get_duration
		       (start).rel_value_us / 1000LL), "ops/ms");

  start = GNUNET_TIME_absolute_get ();
  for (i=0;i<10;i++)
    GNUNET_CRYPTO_paillier_decrypt (&private_key,
                                    &public_key,
                                    &c1,
                                    m1);
  printf ("10x decryption took %s\n",
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start),
						  GNUNET_YES));
  GAUGER ("UTIL", "Paillier decryption",
          64 * 1024 / (1 +
		       GNUNET_TIME_absolute_get_duration
		       (start).rel_value_us / 1000LL), "ops/ms");


  return 0;
}

/* end of perf_crypto_paillier.c */
