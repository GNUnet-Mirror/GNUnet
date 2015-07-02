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
 * @brief ECC discreate logarithm for small values
 * @author Christian Grothoff
 *
 * TODO:
 * - support negative factors
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
  unsigned int max;
  unsigned int mem;
  struct GNUNET_CONTAINER_MultiPeerMap *map;
  gcry_ctx_t ctx;

};


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
  unsigned int i;

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
						      (void*) (long) i + 1,
						      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  gcry_mpi_release (fact);
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
unsigned int
GNUNET_CRYPTO_ecc_dlog (struct GNUNET_CRYPTO_EccDlogContext *edc,
			gcry_mpi_point_t input)
{
  unsigned int K = ((edc->max + (edc->mem-1)) / edc->mem);
  gcry_mpi_point_t g;
  struct GNUNET_PeerIdentity key;
  gcry_mpi_point_t q;
  unsigned int i;
  unsigned int res;
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
      res = (((long) retp) - 1) * K - i;
      fprintf (stderr,
	       "Got DLOG %u\n",
	       res);
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
  
/* end of crypto_ecc_dlog.c */

