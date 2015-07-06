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
#define MAX_FACT 100

/**
 * Maximum memory to use, sqrt(MAX_FACT) is a good choice.
 */
#define MAX_MEM 10

/**
 * How many values do we test?
 */  
#define TEST_ITER 10

/**
 * Range of values to use for MATH tests.
 */  
#define MATH_MAX 5


/**
 * Do some DLOG operations for testing.
 *
 * @param edc context for ECC operations
 */
static void
test_dlog (struct GNUNET_CRYPTO_EccDlogContext *edc)
{
  gcry_mpi_t fact;
  gcry_mpi_t n;
  gcry_ctx_t ctx;
  gcry_mpi_point_t q;
  gcry_mpi_point_t g;
  unsigned int i;
  int x;
  int iret;

  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, NULL, CURVE));
  g = gcry_mpi_ec_get_point ("g", ctx, 0);
  GNUNET_assert (NULL != g);
  n = gcry_mpi_ec_get_mpi ("n", ctx, 0);
  q = gcry_mpi_point_new (0);
  fact = gcry_mpi_new (0);
  for (i=0;i<TEST_ITER;i++)
  {
    fprintf (stderr, ".");
    x = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
				  MAX_FACT);
    if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
				       2))
    {
      gcry_mpi_set_ui (fact, x);
      gcry_mpi_sub (fact, n, fact);
      x = - x;
    }
    else 
    {
      gcry_mpi_set_ui (fact, x);
    }
    gcry_mpi_ec_mul (q, fact, g, ctx);
    if  (x !=
	 (iret = GNUNET_CRYPTO_ecc_dlog (edc,
					 q)))
    {
      fprintf (stderr, 
	       "DLOG failed for value %d (%d)\n", 
	       x,
	       iret);
      GNUNET_assert (0);
    }
  }
  gcry_mpi_release (fact);
  gcry_mpi_release (n);
  gcry_mpi_point_release (g);
  gcry_mpi_point_release (q);
  gcry_ctx_release (ctx);
  fprintf (stderr, "\n");
}


/**
 * Do some arithmetic operations for testing.
 *
 * @param edc context for ECC operations
 */
static void
test_math (struct GNUNET_CRYPTO_EccDlogContext *edc)
{
  int i;
  int j;
  gcry_mpi_point_t ip;
  gcry_mpi_point_t jp;
  gcry_mpi_point_t r;
  gcry_mpi_point_t ir;
  gcry_mpi_point_t irj;
  gcry_mpi_point_t r_inv;
  gcry_mpi_point_t sum;

  for (i=-MATH_MAX;i<MATH_MAX;i++)
  {
    ip = GNUNET_CRYPTO_ecc_dexp (edc, i);
    for (j=-MATH_MAX;j<MATH_MAX;j++)
    {
      fprintf (stderr, ".");
      jp = GNUNET_CRYPTO_ecc_dexp (edc, j);
      GNUNET_CRYPTO_ecc_rnd (edc,
			     &r,
			     &r_inv);
      ir = GNUNET_CRYPTO_ecc_add (edc, ip, r);
      irj = GNUNET_CRYPTO_ecc_add (edc, ir, jp);
      sum = GNUNET_CRYPTO_ecc_add (edc, irj, r_inv);
      GNUNET_assert (i + j ==
		     GNUNET_CRYPTO_ecc_dlog (edc,
					     sum));
      GNUNET_CRYPTO_ecc_free (jp);
      GNUNET_CRYPTO_ecc_free (ir);
      GNUNET_CRYPTO_ecc_free (irj);
      GNUNET_CRYPTO_ecc_free (r);
      GNUNET_CRYPTO_ecc_free (r_inv);
      GNUNET_CRYPTO_ecc_free (sum);
    }
    GNUNET_CRYPTO_ecc_free (ip);
  }
  fprintf (stderr, "\n");
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
  test_math (edc);
  GNUNET_CRYPTO_ecc_dlog_release (edc);
  return 0;
}

/* end of test_crypto_ecc_dlog.c */
