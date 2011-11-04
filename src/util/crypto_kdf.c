/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file src/util/crypto_kdf.c
 * @brief Key derivation
 * @author Nils Durner
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
 * @param xts_len length of xts
 * @param skm source key material
 * @param skm_len length of skm
 * @param argp va_list of void * & size_t pairs for context chunks
 * @return GNUNET_YES on success
 */
int
GNUNET_CRYPTO_kdf_v (void *result, size_t out_len, const void *xts,
                     size_t xts_len, const void *skm, size_t skm_len,
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
 * @param xts_len length of xts
 * @param skm source key material
 * @param skm_len length of skm
 * @param ... void * & size_t pairs for context chunks
 * @return GNUNET_YES on success
 */
int
GNUNET_CRYPTO_kdf (void *result, size_t out_len, const void *xts,
                   size_t xts_len, const void *skm, size_t skm_len, ...)
{
  va_list argp;
  int ret;

  va_start (argp, skm_len);
  ret = GNUNET_CRYPTO_kdf_v (result, out_len, xts, xts_len, skm, skm_len, argp);
  va_end (argp);

  return ret;
}
