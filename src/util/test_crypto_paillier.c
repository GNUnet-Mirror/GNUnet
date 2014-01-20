/*
     This file is part of GNUnet.
     (C) 2014 Christian Grothoff (and other contributing authors)

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
 * @file util/test_crypto_paillier.c
 * @brief testcase paillier crypto
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>


int
main (int argc, char *argv[])
{
  struct GNUNET_CRYPTO_PaillierPlaintext plaintext;
  struct GNUNET_CRYPTO_PaillierPlaintext plaintext_result;
  struct GNUNET_CRYPTO_PaillierCiphertext ciphertext;
  struct GNUNET_CRYPTO_PaillierPublicKey public_key;
  struct GNUNET_CRYPTO_PaillierPrivateKey private_key;

  GNUNET_CRYPTO_paillier_create (&public_key, &private_key);

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK, &plaintext, sizeof plaintext);
  plaintext.bits[0] = 0;

  GNUNET_CRYPTO_paillier_encrypt (&public_key, &plaintext, &ciphertext);

  GNUNET_CRYPTO_paillier_decrypt (&private_key, &public_key,
                                  &ciphertext, &plaintext_result);

  if (0 != memcmp (&plaintext, &plaintext_result, sizeof plaintext))
    return 1;
  return 0;
}

/* end of test_crypto_paillier.c */
