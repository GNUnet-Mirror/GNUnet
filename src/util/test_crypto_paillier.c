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
 * @author Christian Fuchs
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>


int
main (int argc, char *argv[])
{
  int ret;
  gcry_mpi_t m1;
  gcry_mpi_t m2;
  gcry_mpi_t result;
  gcry_mpi_t hom_result;
  struct GNUNET_CRYPTO_PaillierCiphertext c1;
  struct GNUNET_CRYPTO_PaillierCiphertext c2;
  struct GNUNET_CRYPTO_PaillierCiphertext c_result;
  struct GNUNET_CRYPTO_PaillierPublicKey public_key;
  struct GNUNET_CRYPTO_PaillierPrivateKey private_key;
  
  GNUNET_CRYPTO_paillier_create (&public_key, &private_key);

  GNUNET_assert (NULL != (m1 = gcry_mpi_new (0)));
  GNUNET_assert (NULL != (m2 = gcry_mpi_new (0)));
  GNUNET_assert (NULL != (result = gcry_mpi_new (0)));
  GNUNET_assert (NULL != (hom_result = gcry_mpi_new (0)));
  //gcry_mpi_randomize (m1, GNUNET_CRYPTO_PAILLIER_BITS-2, GCRY_WEAK_RANDOM);
  m1 = gcry_mpi_set_ui(m1,1);
  gcry_mpi_mul_2exp(m1,m1,GNUNET_CRYPTO_PAILLIER_BITS-3);
  //gcry_mpi_randomize (m2, GNUNET_CRYPTO_PAILLIER_BITS-2, GCRY_WEAK_RANDOM);
  m2 = gcry_mpi_set_ui(m2,1);
  gcry_mpi_mul_2exp(m2,m2,GNUNET_CRYPTO_PAILLIER_BITS-3);
  gcry_mpi_add(result,m1,m2);

  if (1 != (ret = GNUNET_CRYPTO_paillier_encrypt (&public_key, m1, &c1))){
    printf ("GNUNET_CRYPTO_paillier_encrypt 1 failed, should return 1 allowed operation, got %d!\n", ret);
    return 1;
  }
  if (1 != (ret = GNUNET_CRYPTO_paillier_encrypt (&public_key, m2, &c2))){
    printf ("GNUNET_CRYPTO_paillier_encrypt 2 failed, should return 1 allowed operation, got %d!\n", ret);
    return 1;
  }
  
  GNUNET_CRYPTO_paillier_encrypt (&public_key, m2, &c2);

  if (0 != (ret = GNUNET_CRYPTO_paillier_hom_add (&public_key, &c1,&c2, &c_result))){
    printf ("GNUNET_CRYPTO_paillier_hom_add failed, expected 0 remaining operations, got %d!\n", ret);
    return 1;
  }
  
  GNUNET_CRYPTO_paillier_decrypt (&private_key, &public_key,
                                  &c_result, hom_result);
  
  gcry_log_debugmpi("\n", hom_result);
  gcry_log_debugmpi("\n", result);
  if (0 != gcry_mpi_cmp(result, hom_result)){
    printf ("GNUNET_CRYPTO_paillier miscalculated!\n");
    return 1;
  }
  
  return 0;
}

/* end of test_crypto_paillier.c */