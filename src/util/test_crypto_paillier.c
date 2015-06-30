/*
     This file is part of GNUnet.
     Copyright (C) 2014 Christian Grothoff (and other contributing authors)

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
 * @file util/test_crypto_paillier.c
 * @brief testcase paillier crypto
 * @author Christian Fuchs
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>


static int
test_crypto ()
{
  gcry_mpi_t plaintext;
  gcry_mpi_t plaintext_result;
  struct GNUNET_CRYPTO_PaillierCiphertext ciphertext;
  struct GNUNET_CRYPTO_PaillierPublicKey public_key;
  struct GNUNET_CRYPTO_PaillierPrivateKey private_key;

  GNUNET_CRYPTO_paillier_create (&public_key,
                                 &private_key);
  GNUNET_assert (NULL != (plaintext = gcry_mpi_new (0)));
  GNUNET_assert (NULL != (plaintext_result = gcry_mpi_new (0)));
  gcry_mpi_randomize (plaintext,
                      GNUNET_CRYPTO_PAILLIER_BITS / 2,
                      GCRY_WEAK_RANDOM);

  GNUNET_CRYPTO_paillier_encrypt (&public_key,
                                  plaintext,
                                  0 /* 0 hom ops */,
                                  &ciphertext);
  GNUNET_CRYPTO_paillier_decrypt (&private_key,
                                  &public_key,
                                  &ciphertext,
                                  plaintext_result);

  if (0 != gcry_mpi_cmp (plaintext,
                         plaintext_result))
  {
    fprintf (stderr,
             "Paillier decryption failed with plaintext of size %u\n",
             gcry_mpi_get_nbits (plaintext));
    gcry_log_debugmpi ("\n",
                       plaintext);
    gcry_log_debugmpi ("\n",
                       plaintext_result);
    return 1;
  }
  return 0;
}


static int
test_hom_simple (unsigned int a,
                 unsigned int b)
{
  gcry_mpi_t m1;
  gcry_mpi_t m2;
  gcry_mpi_t result;
  gcry_mpi_t hom_result;
  struct GNUNET_CRYPTO_PaillierCiphertext c1;
  struct GNUNET_CRYPTO_PaillierCiphertext c2;
  struct GNUNET_CRYPTO_PaillierCiphertext c_result;
  struct GNUNET_CRYPTO_PaillierPublicKey public_key;
  struct GNUNET_CRYPTO_PaillierPrivateKey private_key;

  GNUNET_CRYPTO_paillier_create (&public_key,
                                 &private_key);

  GNUNET_assert (NULL != (m1 = gcry_mpi_new (0)));
  GNUNET_assert (NULL != (m2 = gcry_mpi_new (0)));
  GNUNET_assert (NULL != (result = gcry_mpi_new (0)));
  GNUNET_assert (NULL != (hom_result = gcry_mpi_new (0)));
  m1 = gcry_mpi_set_ui (m1, a);
  m2 = gcry_mpi_set_ui (m2, b);
  gcry_mpi_add (result,
                m1,
                m2);
  GNUNET_CRYPTO_paillier_encrypt (&public_key,
                                  m1,
                                  2,
                                  &c1);
  GNUNET_CRYPTO_paillier_encrypt (&public_key,
                                  m2,
                                  2,
                                  &c2);
  GNUNET_CRYPTO_paillier_hom_add (&public_key,
                                  &c1,
                                  &c2,
                                  &c_result);
  GNUNET_CRYPTO_paillier_decrypt (&private_key,
                                  &public_key,
                                  &c_result,
                                  hom_result);
  if (0 != gcry_mpi_cmp (result, hom_result))
  {
    fprintf (stderr,
             "GNUNET_CRYPTO_paillier failed simple math!\n");
    gcry_log_debugmpi ("got ", hom_result);
    gcry_log_debugmpi ("wanted ", result);
    return 1;
  }
  return 0;
}


static int
test_hom ()
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

  GNUNET_CRYPTO_paillier_create (&public_key,
                                 &private_key);

  GNUNET_assert (NULL != (m1 = gcry_mpi_new (0)));
  GNUNET_assert (NULL != (m2 = gcry_mpi_new (0)));
  GNUNET_assert (NULL != (result = gcry_mpi_new (0)));
  GNUNET_assert (NULL != (hom_result = gcry_mpi_new (0)));
  m1 = gcry_mpi_set_ui (m1, 1);
  /* m1 = m1 * 2 ^ (GCPB - 3) */
  gcry_mpi_mul_2exp (m1,
                     m1,
                     GNUNET_CRYPTO_PAILLIER_BITS - 3);
  m2 = gcry_mpi_set_ui (m2, 15);
  /* m1 = m1 * 2 ^ (GCPB / 2) */
  gcry_mpi_mul_2exp (m2,
                     m2,
                     GNUNET_CRYPTO_PAILLIER_BITS / 2);
  gcry_mpi_add (result,
                m1,
                m2);

  if (1 != (ret = GNUNET_CRYPTO_paillier_encrypt (&public_key,
                                                  m1,
                                                  2,
                                                  &c1)))
  {
    fprintf (stderr,
             "GNUNET_CRYPTO_paillier_encrypt 1 failed, should return 1 allowed operation, got %d!\n",
             ret);
    return 1;
  }
  if (2 != (ret = GNUNET_CRYPTO_paillier_encrypt (&public_key,
                                                  m2,
                                                  2,
                                                  &c2)))
  {
    fprintf (stderr,
             "GNUNET_CRYPTO_paillier_encrypt 2 failed, should return 2 allowed operation, got %d!\n",
             ret);
    return 1;
  }

  if (0 != (ret = GNUNET_CRYPTO_paillier_hom_add (&public_key,
                                                  &c1,
                                                  &c2,
                                                  &c_result)))
  {
    fprintf (stderr,
             "GNUNET_CRYPTO_paillier_hom_add failed, expected 0 remaining operations, got %d!\n",
             ret);
    return 1;
  }

  GNUNET_CRYPTO_paillier_decrypt (&private_key,
                                  &public_key,
                                  &c_result,
                                  hom_result);

  if (0 != gcry_mpi_cmp (result, hom_result))
  {
    fprintf (stderr,
             "GNUNET_CRYPTO_paillier miscalculated with large numbers!\n");
    gcry_log_debugmpi ("got", hom_result);
    gcry_log_debugmpi ("wanted", result);
    return 1;
  }
  return 0;
}


int
main (int argc,
      char *argv[])
{
  int ret;
  ret = test_crypto ();
  if (0 != ret)
    return ret;
  ret = test_hom_simple (2,4);
  if (0 != ret)
    return ret;
  ret = test_hom_simple (13,17);
  if (0 != ret)
    return ret;
  ret = test_hom ();
  return ret;
}

/* end of test_crypto_paillier.c */
