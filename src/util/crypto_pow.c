/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2019 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file util/crypto_pow.c
 * @brief proof-of-work hashing
 * @author Christian Grothoff
 * @author Bart Polot
 */
#include "platform.h"
#include "gnunet_crypto_lib.h"
#include <gcrypt.h>


/**
 * Calculate the 'proof-of-work' hash (an expensive hash).
 * We're using a non-standard formula to avoid issues with
 * ASICs appearing (see #3795).
 *
 * @param salt salt for the hash
 * @param buf data to hash
 * @param buf_len number of bytes in @a buf
 * @param result where to write the resulting hash
 */
void
GNUNET_CRYPTO_pow_hash (const char *salt,
                        const void *buf,
                        size_t buf_len,
                        struct GNUNET_HashCode *result)
{
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_CRYPTO_SymmetricSessionKey skey;
  char rbuf[buf_len];

  GNUNET_break (0 == gcry_kdf_derive (buf,
                                      buf_len,
                                      GCRY_KDF_SCRYPT,
                                      1 /* subalgo */,
                                      salt,
                                      strlen (salt),
                                      2 /* iterations; keep cost of individual op small */,
                                      sizeof(skey),
                                      &skey));
  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &skey,
                                     "gnunet-proof-of-work-iv",
                                     strlen ("gnunet-proof-of-work-iv"),
                                     salt,
                                     strlen (salt),
                                     NULL, 0);
  GNUNET_CRYPTO_symmetric_encrypt (buf,
                                   buf_len,
                                   &skey,
                                   &iv,
                                   &rbuf);
  GNUNET_break (0 == gcry_kdf_derive (rbuf,
                                      buf_len,
                                      GCRY_KDF_SCRYPT,
                                      1 /* subalgo */,
                                      salt,
                                      strlen (salt),
                                      2 /* iterations; keep cost of individual op small */,
                                      sizeof(struct GNUNET_HashCode),
                                      result));
}


/* end of crypto_pow.c */
