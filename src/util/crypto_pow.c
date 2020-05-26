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
#include <sodium.h>

/**
 * Calculate the 'proof-of-work' hash (an expensive hash).
 * We're using a non-standard formula to avoid issues with
 * ASICs appearing (see #3795).
 *
 * @param salt salt for the hash. Must be crypto_pwhash_argon2id_SALTBYTES long.
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
  GNUNET_assert (strlen (salt) == crypto_pwhash_argon2id_SALTBYTES);
  /* Threads hardcoded at 1 in libsodium */
  GNUNET_break (0 ==
                crypto_pwhash_argon2id ((unsigned char *) result,
                                        sizeof (struct GNUNET_HashCode),
                                        buf,
                                        buf_len,
                                        (unsigned char*) salt,
                                        3, /* iterations */
                                        1024 * 1024, /* memory (1 MiB) */
                                        crypto_pwhash_argon2id_ALG_ARGON2ID13));
}


/* end of crypto_pow.c */
