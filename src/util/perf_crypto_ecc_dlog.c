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
 * @file util/perf_crypto_ecc_dlog.c
 * @brief benchmark for ECC DLOG calculation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>
#include <gauger.h>


/**
 * Name of the curve we are using.  Note that we have hard-coded
 * structs that use 256 bits, so using a bigger curve will require
 * changes that break stuff badly.  The name of the curve given here
 * must be agreed by all peers and be supported by libgcrypt.
 */
#define CURVE "Ed25519"

/**
 * Maximum value we benchmark dlog for.
 */
#define MAX_FACT (1024 * 1024)

/**
 * Maximum memory to use, sqrt(MAX_FACT) is a good choice.
 */
#define MAX_MEM 1024

/**
 * How many values do we test?
 */  
#define TEST_ITER 10

/**
 * Range of values to use for MATH tests.
 */  
#define MATH_MAX 500000


/**
 * Do some DLOG operations for testing.
 *
 * @param edc context for ECC operations
 * @param do_dlog #GNUNET_YES if we want to actually do the bencharked operation
 */
static void
test_dlog (struct GNUNET_CRYPTO_EccDlogContext *edc, 
           int do_dlog)
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
    if ( (GNUNET_YES == do_dlog) &&
	 (x !=
	  (iret = GNUNET_CRYPTO_ecc_dlog (edc,
					  q))) )
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


int
main (int argc, char *argv[])
{
  struct GNUNET_CRYPTO_EccDlogContext *edc;
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Relative delta;

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
  GNUNET_log_setup ("perf-crypto-ecc-dlog", 
		    "WARNING", 
		    NULL);
  start = GNUNET_TIME_absolute_get ();
  edc = GNUNET_CRYPTO_ecc_dlog_prepare (MAX_FACT,
					MAX_MEM);
  printf ("DLOG precomputation 1M/1K took %s\n",
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start),
						  GNUNET_YES));
  GAUGER ("UTIL", "ECC DLOG initialization",
	  GNUNET_TIME_absolute_get_duration
	  (start).rel_value_us / 1000LL, "ms/op");
  start = GNUNET_TIME_absolute_get ();
  /* first do a baseline run without the DLOG */
  test_dlog (edc, GNUNET_NO);
  delta = GNUNET_TIME_absolute_get_duration (start);
  start = GNUNET_TIME_absolute_get ();
  test_dlog (edc, GNUNET_YES);
  delta = GNUNET_TIME_relative_subtract (GNUNET_TIME_absolute_get_duration (start),
					 delta);
  printf ("%u DLOG calculations took %s\n",
	  TEST_ITER,
          GNUNET_STRINGS_relative_time_to_string (delta,
						  GNUNET_YES));
  GAUGER ("UTIL", "ECC DLOG operations",
	  delta.rel_value_us / 1000LL / TEST_ITER, 
	  "ms/op");

  GNUNET_CRYPTO_ecc_dlog_release (edc);
  return 0;
}

/* end of perf_crypto_ecc_dlog.c */
