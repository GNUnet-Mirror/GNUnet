/*
     This file is part of GNUnet.
     Copyright (C) 2015 Christian Grothoff (and other contributing authors)

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
 * @file util/test_crypto_ecc_dlog.c
 * @brief testcase for ECC DLOG calculation
 * @author Christian Grothoff
 *
 * TODO:
 * - test negative numbers
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>


/**
 * Name of the curve we are using.  Note that we have hard-coded
 * structs that use 256 bits, so using a bigger curve will require
 * changes that break stuff badly.  The name of the curve given here
 * must be agreed by all peers and be supported by libgcrypt.
 */
#define CURVE "Ed25519"

/**
 * Maximum value we test dlog for.
 */
#define MAX_FACT 1000000

/**
 * Maximum memory to use, sqrt(MAX_FACT) is a good choice.
 */
#define MAX_MEM 1000


static void
test_dlog (struct GNUNET_CRYPTO_EccDlogContext *edc)
{
  gcry_mpi_t fact;
  gcry_ctx_t ctx;
  gcry_mpi_point_t q;
  gcry_mpi_point_t g;
  unsigned int i;
  unsigned int x;

  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, NULL, CURVE));
  g = gcry_mpi_ec_get_point ("g", ctx, 0);
  GNUNET_assert (NULL != g);
  q = gcry_mpi_point_new (0);
  fact = gcry_mpi_new (0);
  for (i=0;i<10;i++)
  {
    x = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
				  MAX_FACT);
    gcry_mpi_set_ui (fact, x);
    gcry_mpi_ec_mul (q, fact, g, ctx);
    if  (x !=
	 GNUNET_CRYPTO_ecc_dlog (edc,
				 q))
    {
      fprintf (stderr, 
	       "DLOG failed for value %u\n", 
	       x);
      GNUNET_assert (0);
    }
  }
  gcry_mpi_release (fact);
  gcry_mpi_point_release (g);
  gcry_mpi_point_release (q);
  gcry_ctx_release (ctx);
}


int
main (int argc, char *argv[])
{
  struct GNUNET_CRYPTO_EccDlogContext *edc;

  if (! gcry_check_version ("1.6.0"))
  {
    FPRINTF (stderr,
             _
             ("libgcrypt has not the expected version (version %s is required).\n"),
             "1.6.0");
    return 0;
  }
  if (getenv ("GNUNET_GCRYPT_DEBUG"))
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);
  GNUNET_log_setup ("test-crypto-ecc-dlog", 
		    "WARNING", 
		    NULL);
  edc = GNUNET_CRYPTO_ecc_dlog_prepare (MAX_FACT,
					MAX_MEM);
  test_dlog (edc);
  GNUNET_CRYPTO_ecc_dlog_release (edc);
  return 0;
}

/* end of test_crypto_ecc_dlog.c */
