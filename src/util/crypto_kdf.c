/*
     This file is part of GNUnet.
     Copyright (C) 2010 GNUnet e.V.

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
 * @file src/util/crypto_kdf.c
 * @brief Key derivation
 * @author Nils Durner
 * @author Jeffrey Burdges <burdges@gnunet.org>
 */

#include <gcrypt.h>

#include "platform.h"
#include "gnunet_crypto_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

/**
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xts salt
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param argp va_list of void * & size_t pairs for context chunks
 * @return #GNUNET_YES on success
 */
int
GNUNET_CRYPTO_kdf_v (void *result, size_t out_len,
                     const void *xts, size_t xts_len,
                     const void *skm, size_t skm_len,
                     va_list argp)
{
  /*
   * "Finally, we point out to a particularly advantageous instantiation using
   * HMAC-SHA512 as XTR and HMAC-SHA256 in PRF* (in which case the output from SHA-512 is
   * truncated to 256 bits). This makes sense in two ways: First, the extraction part is where we need a
   * stronger hash function due to the unconventional demand from the hash function in the extraction
   * setting. Second, as shown in Section 6, using HMAC with a truncated output as an extractor
   * allows to prove the security of HKDF under considerably weaker assumptions on the underlying
   * hash function."
   *
   * http://eprint.iacr.org/2010/264
   */

  return GNUNET_CRYPTO_hkdf_v (result, out_len, GCRY_MD_SHA512, GCRY_MD_SHA256,
                               xts, xts_len, skm, skm_len, argp);
}


/**
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xts salt
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param ... void * & size_t pairs for context chunks
 * @return #GNUNET_YES on success
 */
int
GNUNET_CRYPTO_kdf (void *result, size_t out_len,
                   const void *xts, size_t xts_len,
                   const void *skm, size_t skm_len, ...)
{
  va_list argp;
  int ret;

  va_start (argp, skm_len);
  ret = GNUNET_CRYPTO_kdf_v (result, out_len, xts, xts_len, skm, skm_len, argp);
  va_end (argp);

  return ret;
}


/**
 * Deterministically generate a pseudo-random number uniformly from the
 * integers modulo a libgcrypt mpi.
 *
 * @param[out] r MPI value set to the FDH
 * @param n MPI to work modulo
 * @param xts salt
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param ctx context string
 */
void
GNUNET_CRYPTO_kdf_mod_mpi (gcry_mpi_t *r,
                           gcry_mpi_t n,
                           const void *xts,  size_t xts_len, 
                           const void *skm,  size_t skm_len,
                           const char *ctx)
{
  gcry_error_t rc;
  unsigned int nbits;
  size_t rsize;
  unsigned int ctr;

  nbits = gcry_mpi_get_nbits (n);
  /* GNUNET_assert (nbits > 512); */

  ctr = 0;
  do {
    /* Ain't clear if n is always divisible by 8 */
    uint8_t buf[ (nbits-1)/8 + 1 ];

    rc = GNUNET_CRYPTO_kdf (buf,
                            sizeof (buf),
                            xts, xts_len,
                            skm, skm_len,
                            ctx, strlen(ctx),
                            &ctr, sizeof(ctr),
                            NULL, 0);
    GNUNET_assert (GNUNET_YES == rc);

    rc = gcry_mpi_scan (r,
                        GCRYMPI_FMT_USG,
                        (const unsigned char *) buf,
                        sizeof (buf),
                        &rsize);
    GNUNET_assert (0 == rc);  /* Allocation erro? */

    gcry_mpi_clear_highbit (*r, nbits);
    GNUNET_assert( 0 == gcry_mpi_test_bit (*r, nbits) );
    ++ctr;
    /* We reject this FDH if either *r > n and retry with another ctr */
  } while ( 0 <= gcry_mpi_cmp(*r,n) );
}


