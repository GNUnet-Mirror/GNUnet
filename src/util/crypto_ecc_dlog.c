/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2015 Christian Grothoff (and other contributing authors)

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
 * @file util/crypto_ecc_dlog.c
 * @brief ECC addition and discreate logarithm for small values.
 *        Allows us to use ECC for computations as long as the
 *        result is relativey small.
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gcrypt.h>
#include "gnunet_crypto_lib.h"
#include "gnunet_container_lib.h"


/**
 * Name of the curve we are using.  Note that we have hard-coded
 * structs that use 256 bits, so using a bigger curve will require
 * changes that break stuff badly.  The name of the curve given here
 * must be agreed by all peers and be supported by libgcrypt.
 */
#define CURVE "Ed25519"


/**
 *
 */
static void
extract_pk (gcry_mpi_point_t pt,
            gcry_ctx_t ctx,
            struct GNUNET_PeerIdentity *pid)
{
  gcry_mpi_t q_y;

  GNUNET_assert (0 == gcry_mpi_ec_set_point ("q", pt, ctx));
  q_y = gcry_mpi_ec_get_mpi ("q@eddsa", ctx, 0);
  GNUNET_assert (q_y);
  GNUNET_CRYPTO_mpi_print_unsigned (pid->public_key.q_y,
				    sizeof (pid->public_key.q_y),
                                    q_y);
  gcry_mpi_release (q_y);
}


/**
 * Internal structure used to cache pre-calculated values for DLOG calculation.
 */
struct GNUNET_CRYPTO_EccDlogContext
{
  /**
   * Maximum absolute value the calculation supports.
   */
  unsigned int max;

  /**
   * How much memory should we use (relates to the number of entries in the map).
   */
  unsigned int mem;

  /**
   * Map mapping points (here "interpreted" as EdDSA public keys) to
   * a "void * = long" which corresponds to the numeric value of the
   * point.  As NULL is used to represent "unknown", the actual value
   * represented by the entry in the map is the "long" minus @e max.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *map;

  /**
   * Context to use for operations on the elliptic curve.
   */
  gcry_ctx_t ctx;

};


/**
 * Convert point value to binary representation.
 *
 * @param edc calculation context for ECC operations
 * @param point computational point representation
 * @param[out] bin binary point representation
 */
void
GNUNET_CRYPTO_ecc_point_to_bin (struct GNUNET_CRYPTO_EccDlogContext *edc,
                                gcry_mpi_point_t point,
                                struct GNUNET_CRYPTO_EccPoint *bin)
{
  gcry_mpi_t q_y;

  GNUNET_assert (0 == gcry_mpi_ec_set_point ("q", point, edc->ctx));
  q_y = gcry_mpi_ec_get_mpi ("q@eddsa", edc->ctx, 0);
  GNUNET_assert (q_y);
  GNUNET_CRYPTO_mpi_print_unsigned (bin->q_y,
				    sizeof (bin->q_y),
                                    q_y);
  gcry_mpi_release (q_y);
}


/**
 * Convert binary representation of a point to computational representation.
 *
 * @param edc calculation context for ECC operations
 * @param bin binary point representation
 * @return computational representation
 */
gcry_mpi_point_t
GNUNET_CRYPTO_ecc_bin_to_point (struct GNUNET_CRYPTO_EccDlogContext *edc,
                                const struct GNUNET_CRYPTO_EccPoint *bin)
{
  gcry_sexp_t pub_sexpr;
  gcry_ctx_t ctx;
  gcry_mpi_point_t q;

  if (0 != gcry_sexp_build (&pub_sexpr, NULL,
                            "(public-key(ecc(curve " CURVE ")(q %b)))",
                            (int) sizeof (bin->q_y),
                            bin->q_y))
  {
    GNUNET_break (0);
    return NULL;
  }
  GNUNET_assert (0 == gcry_mpi_ec_new (&ctx, pub_sexpr, NULL));
  gcry_sexp_release (pub_sexpr);
  q = gcry_mpi_ec_get_point ("q", ctx, 0);
  gcry_ctx_release (ctx);
  return q;
}


/**
 * Do pre-calculation for ECC discrete logarithm for small factors.
 *
 * @param max maximum value the factor can be
 * @param mem memory to use (should be smaller than @a max), must not be zero.
 * @return @a max if dlog failed, otherwise the factor
 */
struct GNUNET_CRYPTO_EccDlogContext *
GNUNET_CRYPTO_ecc_dlog_prepare (unsigned int max,
				unsigned int mem)
{
  struct GNUNET_CRYPTO_EccDlogContext *edc;
  unsigned int K = ((max + (mem-1)) / mem);
  gcry_mpi_point_t g;
  struct GNUNET_PeerIdentity key;
  gcry_mpi_point_t gKi;
  gcry_mpi_t fact;
  gcry_mpi_t n;
  unsigned int i;

  GNUNET_assert (max < INT32_MAX);
  edc = GNUNET_new (struct GNUNET_CRYPTO_EccDlogContext);
  edc->max = max;
  edc->mem = mem;

  edc->map = GNUNET_CONTAINER_multipeermap_create (mem * 2,
						   GNUNET_NO);

  GNUNET_assert (0 == gcry_mpi_ec_new (&edc->ctx,
				       NULL,
				       CURVE));
  g = gcry_mpi_ec_get_point ("g", edc->ctx, 0);
  GNUNET_assert (NULL != g);
  fact = gcry_mpi_new (0);
  gKi = gcry_mpi_point_new (0);
  for (i=0;i<=mem;i++)
  {
    gcry_mpi_set_ui (fact, i * K);
    gcry_mpi_ec_mul (gKi, fact, g, edc->ctx);
    extract_pk (gKi, edc->ctx, &key);
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_multipeermap_put (edc->map,
						      &key,
						      (void*) (long) i + max,
						      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  /* negative values */
  n = gcry_mpi_ec_get_mpi ("n", edc->ctx, 1);
  for (i=1;i<mem;i++)
  {
    gcry_mpi_set_ui (fact, i * K);
    gcry_mpi_sub (fact, n, fact);
    gcry_mpi_ec_mul (gKi, fact, g, edc->ctx);
    extract_pk (gKi, edc->ctx, &key);
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_multipeermap_put (edc->map,
						      &key,
						      (void*) (long) max - i,
						      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  gcry_mpi_release (fact);
  gcry_mpi_release (n);
  gcry_mpi_point_release (gKi);
  gcry_mpi_point_release (g);
  return edc;
}


/**
 * Calculate ECC discrete logarithm for small factors.
 *
 * @param edc precalculated values, determine range of factors
 * @param input point on the curve to factor
 * @return `edc->max` if dlog failed, otherwise the factor
 */
int
GNUNET_CRYPTO_ecc_dlog (struct GNUNET_CRYPTO_EccDlogContext *edc,
			gcry_mpi_point_t input)
{
  unsigned int K = ((edc->max + (edc->mem-1)) / edc->mem);
  gcry_mpi_point_t g;
  struct GNUNET_PeerIdentity key;
  gcry_mpi_point_t q;
  unsigned int i;
  int res;
  void *retp;

  g = gcry_mpi_ec_get_point ("g", edc->ctx, 0);
  GNUNET_assert (NULL != g);
  q = gcry_mpi_point_new (0);

  res = edc->max;
  for (i=0;i<=edc->max/edc->mem;i++)
  {
    if (0 == i)
      extract_pk (input, edc->ctx, &key);
    else
      extract_pk (q, edc->ctx, &key);
    retp = GNUNET_CONTAINER_multipeermap_get (edc->map,
					      &key);
    if (NULL != retp)
    {
      res = (((long) retp) - edc->max) * K - i;
      /* we continue the loop here to make the implementation
	 "constant-time". If we do not care about this, we could just
	 'break' here and do fewer operations... */
    }
    if (i == edc->max/edc->mem)
      break;
    /* q = q + g */
    if (0 == i)
      gcry_mpi_ec_add (q, input, g, edc->ctx);
    else
      gcry_mpi_ec_add (q, q, g, edc->ctx);
  }
  gcry_mpi_point_release (g);
  gcry_mpi_point_release (q);

  return res;
}


/**
 * Generate a random value mod n.
 *
 * @param edc ECC context
 * @return random value mod n.
 */
gcry_mpi_t
GNUNET_CRYPTO_ecc_random_mod_n (struct GNUNET_CRYPTO_EccDlogContext *edc)
{
  gcry_mpi_t n;
  unsigned int highbit;
  gcry_mpi_t r;

  n = gcry_mpi_ec_get_mpi ("n", edc->ctx, 1);

  /* check public key for number of bits, bail out if key is all zeros */
  highbit = 256; /* Curve25519 */
  while ( (! gcry_mpi_test_bit (n, highbit)) &&
          (0 != highbit) )
    highbit--;
  GNUNET_assert (0 != highbit);
  /* generate fact < n (without bias) */
  GNUNET_assert (NULL != (r = gcry_mpi_new (0)));
  do {
    gcry_mpi_randomize (r,
			highbit + 1,
			GCRY_STRONG_RANDOM);
  }
  while (gcry_mpi_cmp (r, n) >= 0);
  gcry_mpi_release (n);
  return r;
}


/**
 * Release precalculated values.
 *
 * @param edc dlog context
 */
void
GNUNET_CRYPTO_ecc_dlog_release (struct GNUNET_CRYPTO_EccDlogContext *edc)
{
  gcry_ctx_release (edc->ctx);
  GNUNET_CONTAINER_multipeermap_destroy (edc->map);
  GNUNET_free (edc);
}


/**
 * Multiply the generator g of the elliptic curve by @a val
 * to obtain the point on the curve representing @a val.
 * Afterwards, point addition will correspond to integer
 * addition.  #GNUNET_CRYPTO_ecc_dlog() can be used to
 * convert a point back to an integer (as long as the
 * integer is smaller than the MAX of the @a edc context).
 *
 * @param edc calculation context for ECC operations
 * @param val value to encode into a point
 * @return representation of the value as an ECC point,
 *         must be freed using #GNUNET_CRYPTO_ecc_free()
 */
gcry_mpi_point_t
GNUNET_CRYPTO_ecc_dexp (struct GNUNET_CRYPTO_EccDlogContext *edc,
			int val)
{
  gcry_mpi_t fact;
  gcry_mpi_t n;
  gcry_mpi_point_t g;
  gcry_mpi_point_t r;

  g = gcry_mpi_ec_get_point ("g", edc->ctx, 0);
  GNUNET_assert (NULL != g);
  fact = gcry_mpi_new (0);
  if (val < 0)
  {
    n = gcry_mpi_ec_get_mpi ("n", edc->ctx, 1);
    gcry_mpi_set_ui (fact, - val);
    gcry_mpi_sub (fact, n, fact);
    gcry_mpi_release (n);
  }
  else
  {
    gcry_mpi_set_ui (fact, val);
  }
  r = gcry_mpi_point_new (0);
  gcry_mpi_ec_mul (r, fact, g, edc->ctx);
  gcry_mpi_release (fact);
  gcry_mpi_point_release (g);
  return r;
}


/**
 * Multiply the generator g of the elliptic curve by @a val
 * to obtain the point on the curve representing @a val.
 *
 * @param edc calculation context for ECC operations
 * @param val (positive) value to encode into a point
 * @return representation of the value as an ECC point,
 *         must be freed using #GNUNET_CRYPTO_ecc_free()
 */
gcry_mpi_point_t
GNUNET_CRYPTO_ecc_dexp_mpi (struct GNUNET_CRYPTO_EccDlogContext *edc,
			    gcry_mpi_t val)
{
  gcry_mpi_point_t g;
  gcry_mpi_point_t r;

  g = gcry_mpi_ec_get_point ("g", edc->ctx, 0);
  GNUNET_assert (NULL != g);
  r = gcry_mpi_point_new (0);
  gcry_mpi_ec_mul (r, val, g, edc->ctx);
  gcry_mpi_point_release (g);
  return r;
}


/**
 * Add two points on the elliptic curve.
 *
 * @param edc calculation context for ECC operations
 * @param a some value
 * @param b some value
 * @return @a a + @a b, must be freed using #GNUNET_CRYPTO_ecc_free()
 */
gcry_mpi_point_t
GNUNET_CRYPTO_ecc_add (struct GNUNET_CRYPTO_EccDlogContext *edc,
		       gcry_mpi_point_t a,
		       gcry_mpi_point_t b)
{
  gcry_mpi_point_t r;

  r = gcry_mpi_point_new (0);
  gcry_mpi_ec_add (r, a, b, edc->ctx);
  return r;
}


/**
 * Obtain a random point on the curve and its
 * additive inverse. Both returned values
 * must be freed using #GNUNET_CRYPTO_ecc_free().
 *
 * @param edc calculation context for ECC operations
 * @param[out] r set to a random point on the curve
 * @param[out] r_inv set to the additive inverse of @a r
 */
void
GNUNET_CRYPTO_ecc_rnd (struct GNUNET_CRYPTO_EccDlogContext *edc,
		       gcry_mpi_point_t *r,
		       gcry_mpi_point_t *r_inv)
{
  gcry_mpi_t fact;
  gcry_mpi_t n;
  gcry_mpi_point_t g;

  fact = GNUNET_CRYPTO_ecc_random_mod_n (edc);

  /* calculate 'r' */
  g = gcry_mpi_ec_get_point ("g", edc->ctx, 0);
  GNUNET_assert (NULL != g);
  *r = gcry_mpi_point_new (0);
  gcry_mpi_ec_mul (*r, fact, g, edc->ctx);

  /* calculate 'r_inv' */
  n = gcry_mpi_ec_get_mpi ("n", edc->ctx, 1);
  gcry_mpi_sub (fact, n, fact); /* fact = n - fact = - fact */
  *r_inv = gcry_mpi_point_new (0);
  gcry_mpi_ec_mul (*r_inv, fact, g, edc->ctx);

  gcry_mpi_release (n);
  gcry_mpi_release (fact);
  gcry_mpi_point_release (g);
}


/**
 * Free a point value returned by the API.
 *
 * @param p point to free
 */
void
GNUNET_CRYPTO_ecc_free (gcry_mpi_point_t p)
{
  gcry_mpi_point_release (p);
}


/* end of crypto_ecc_dlog.c */
