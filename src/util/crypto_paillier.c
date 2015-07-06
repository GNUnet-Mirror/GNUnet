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
 * @file util/crypto_paillier.c
 * @brief implementation of the paillier crypto system with libgcrypt
 * @author Florian Dold
 * @author Christian Fuchs
 */
#include "platform.h"
#include <gcrypt.h>
#include "gnunet_util_lib.h"


/**
 * Create a freshly generated paillier public key.
 *
 * @param[out] public_key Where to store the public key?
 * @param[out] private_key Where to store the private key?
 */
void
GNUNET_CRYPTO_paillier_create (struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
                               struct GNUNET_CRYPTO_PaillierPrivateKey *private_key)
{
  gcry_mpi_t p;
  gcry_mpi_t q;
  gcry_mpi_t phi;
  gcry_mpi_t mu;
  gcry_mpi_t n;

  /* Generate two distinct primes.  The probability that the loop body
     is executed more than once is very very low... */
  p = NULL;
  q = NULL;
  do {
    if (NULL != p)
      gcry_mpi_release (p);
    if (NULL != q)
      gcry_mpi_release (q);
    GNUNET_assert (0 ==
                   gcry_prime_generate (&p,
                                        GNUNET_CRYPTO_PAILLIER_BITS / 2,
                                        0, NULL, NULL, NULL,
                                        GCRY_STRONG_RANDOM, 0));
    GNUNET_assert (0 ==
                   gcry_prime_generate (&q,
                                        GNUNET_CRYPTO_PAILLIER_BITS / 2,
                                        0, NULL, NULL, NULL,
                                        GCRY_STRONG_RANDOM, 0));
  }
  while (0 == gcry_mpi_cmp (p, q));
  /* n = p * q */
  GNUNET_assert (NULL != (n = gcry_mpi_new (0)));
  gcry_mpi_mul (n,
                p,
                q);
  GNUNET_CRYPTO_mpi_print_unsigned (public_key,
                                    sizeof (struct GNUNET_CRYPTO_PaillierPublicKey),
                                    n);

  /* compute phi(n) = (p-1)(q-1) */
  GNUNET_assert (NULL != (phi = gcry_mpi_new (0)));
  gcry_mpi_sub_ui (p, p, 1);
  gcry_mpi_sub_ui (q, q, 1);
  gcry_mpi_mul (phi, p, q);
  gcry_mpi_release (p);
  gcry_mpi_release (q);

  /* lambda equals phi(n) in the simplified key generation */
  GNUNET_CRYPTO_mpi_print_unsigned (private_key->lambda,
                                    GNUNET_CRYPTO_PAILLIER_BITS / 8,
                                    phi);
  /* mu = phi^{-1} mod n, as we use g = n + 1 */
  GNUNET_assert (NULL != (mu = gcry_mpi_new (0)));
  GNUNET_assert (0 != gcry_mpi_invm (mu,
                                     phi,
                                     n));
  gcry_mpi_release (phi);
  gcry_mpi_release (n);
  GNUNET_CRYPTO_mpi_print_unsigned (private_key->mu,
                                    GNUNET_CRYPTO_PAILLIER_BITS / 8,
                                    mu);
  gcry_mpi_release (mu);
}


/**
 * Encrypt a plaintext with a paillier public key.
 *
 * @param public_key Public key to use.
 * @param m Plaintext to encrypt.
 * @param desired_ops How many homomorphic ops the caller intends to use
 * @param[out] ciphertext Encrytion of @a plaintext with @a public_key.
 * @return guaranteed number of supported homomorphic operations >= 1,
 *         or desired_ops, in case that is lower,
 *         or -1 if less than one homomorphic operation is possible
 */
int
GNUNET_CRYPTO_paillier_encrypt1 (const struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
                                const gcry_mpi_t m,
                                int desired_ops,
                                struct GNUNET_CRYPTO_PaillierCiphertext *ciphertext)
{
  int possible_opts;
  gcry_mpi_t n_square;
  gcry_mpi_t r;
  gcry_mpi_t c;
  gcry_mpi_t n;
  gcry_mpi_t tmp1;
  gcry_mpi_t tmp2;
  unsigned int highbit;

  /* determine how many operations we could allow, if the other number
     has the same length. */
  GNUNET_assert (NULL != (tmp1 = gcry_mpi_set_ui (NULL, 1)));
  GNUNET_assert (NULL != (tmp2 = gcry_mpi_set_ui (NULL, 2)));
  gcry_mpi_mul_2exp (tmp1, tmp1, GNUNET_CRYPTO_PAILLIER_BITS);

  /* count number of possible operations
     this would be nicer with gcry_mpi_get_nbits, however it does not return
     the BITLENGTH of the given MPI's value, but the bits required
     to represent the number as MPI. */
  for (possible_opts = -2; gcry_mpi_cmp (tmp1, m) > 0; possible_opts++)
    gcry_mpi_div (tmp1, NULL, tmp1, tmp2, 0);
  gcry_mpi_release (tmp1);
  gcry_mpi_release (tmp2);

  if (possible_opts < 1)
    possible_opts = 0;
  /* soft-cap by caller */
  possible_opts = (desired_ops < possible_opts)? desired_ops : possible_opts;

  ciphertext->remaining_ops = htonl (possible_opts);

  GNUNET_CRYPTO_mpi_scan_unsigned (&n,
                                   public_key,
                                   sizeof (struct GNUNET_CRYPTO_PaillierPublicKey));
  highbit = GNUNET_CRYPTO_PAILLIER_BITS - 1;
  while ( (! gcry_mpi_test_bit (n, highbit)) &&
          (0 != highbit) )
    highbit--;
  if (0 == highbit)
  {
    /* invalid public key */
    GNUNET_break_op (0);
    gcry_mpi_release (n);
    return GNUNET_SYSERR;
  }
  GNUNET_assert (0 != (n_square = gcry_mpi_new (0)));
  GNUNET_assert (0 != (r = gcry_mpi_new (0)));
  GNUNET_assert (0 != (c = gcry_mpi_new (0)));
  gcry_mpi_mul (n_square, n, n);

  /* generate r < n (without bias) */
  do {
    gcry_mpi_randomize (r, highbit + 1, GCRY_STRONG_RANDOM);
  }
  while (gcry_mpi_cmp (r, n) >= 0);

  /* c = (n+1)^m mod n^2 */
  /* c = n + 1 */
  gcry_mpi_add_ui (c, n, 1);
  /* c = (n+1)^m mod n^2 */
  gcry_mpi_powm (c, c, m, n_square);
  /* r <- r^n mod n^2 */
  gcry_mpi_powm (r, r, n, n_square);
  /* c <- r*c mod n^2 */
  gcry_mpi_mulm (c, r, c, n_square);

  GNUNET_CRYPTO_mpi_print_unsigned (ciphertext->bits,
                                    sizeof ciphertext->bits,
                                    c);

  gcry_mpi_release (n_square);
  gcry_mpi_release (n);
  gcry_mpi_release (r);
  gcry_mpi_release (c);

  return possible_opts;
}


/**
 * Encrypt a plaintext with a paillier public key.
 *
 * @param public_key Public key to use.
 * @param m Plaintext to encrypt.
 * @param desired_ops How many homomorphic ops the caller intends to use
 * @param[out] ciphertext Encrytion of @a plaintext with @a public_key.
 * @return guaranteed number of supported homomorphic operations >= 1,
 *         or desired_ops, in case that is lower,
 *         or -1 if less than one homomorphic operation is possible
 */
int
GNUNET_CRYPTO_paillier_encrypt (const struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
                                const gcry_mpi_t m,
                                int desired_ops,
                                struct GNUNET_CRYPTO_PaillierCiphertext *ciphertext)
{
  int possible_opts;
  gcry_mpi_t n_square;
  gcry_mpi_t r;
  gcry_mpi_t rn;
  gcry_mpi_t g;
  gcry_mpi_t gm;
  gcry_mpi_t c;
  gcry_mpi_t n;
  gcry_mpi_t max_num;
  unsigned int highbit;

  /* set max_num = 2^{GNUNET_CRYPTO_PAILLIER_BITS}, the largest
     number we can have as a result */
  GNUNET_assert (NULL != (max_num = gcry_mpi_set_ui (NULL, 1)));
  gcry_mpi_mul_2exp (max_num,
                     max_num,
                     GNUNET_CRYPTO_PAILLIER_BITS);

  /* Determine how many operations we could allow, assuming the other
     number has the same length (or is smaller), by counting the
     number of possible operations.  We essentially divide max_num by
     2 until the result is no longer larger than 'm', incrementing the
     maximum number of operations in each round, starting at -2 */
  for (possible_opts = -2; gcry_mpi_cmp (max_num, m) > 0; possible_opts++)
    gcry_mpi_div (max_num,
                  NULL,
                  max_num,
                  GCRYMPI_CONST_TWO,
                  0);
  gcry_mpi_release (max_num);

  if (possible_opts < 1)
    possible_opts = 0;
  /* Enforce soft-cap by caller */
  possible_opts = GNUNET_MIN (desired_ops, possible_opts);
  ciphertext->remaining_ops = htonl (possible_opts);

  GNUNET_CRYPTO_mpi_scan_unsigned (&n,
                                   public_key,
                                   sizeof (struct GNUNET_CRYPTO_PaillierPublicKey));

  /* check public key for number of bits, bail out if key is all zeros */
  highbit = GNUNET_CRYPTO_PAILLIER_BITS - 1;
  while ( (! gcry_mpi_test_bit (n, highbit)) &&
          (0 != highbit) )
    highbit--;
  if (0 == highbit)
  {
    /* invalid public key */
    GNUNET_break_op (0);
    gcry_mpi_release (n);
    return GNUNET_SYSERR;
  }

  /* generate r < n (without bias) */
  GNUNET_assert (NULL != (r = gcry_mpi_new (0)));
  do {
    gcry_mpi_randomize (r, highbit + 1, GCRY_STRONG_RANDOM);
  }
  while (gcry_mpi_cmp (r, n) >= 0);

  /* g = n + 1 */
  GNUNET_assert (0 != (g = gcry_mpi_new (0)));
  gcry_mpi_add_ui (g, n, 1);

  /* n_square = n^2 */
  GNUNET_assert (0 != (n_square = gcry_mpi_new (0)));
  gcry_mpi_mul (n_square,
                n,
                n);

  /* gm = g^m mod n^2 */
  GNUNET_assert (0 != (gm = gcry_mpi_new (0)));
  gcry_mpi_powm (gm, g, m, n_square);
  gcry_mpi_release (g);

  /* rn <- r^n mod n^2 */
  GNUNET_assert (0 != (rn = gcry_mpi_new (0)));
  gcry_mpi_powm (rn, r, n, n_square);
  gcry_mpi_release (r);
  gcry_mpi_release (n);

  /* c <- rn * gm mod n^2 */
  GNUNET_assert (0 != (c = gcry_mpi_new (0)));
  gcry_mpi_mulm (c, rn, gm, n_square);
  gcry_mpi_release (n_square);
  gcry_mpi_release (gm);
  gcry_mpi_release (rn);

  GNUNET_CRYPTO_mpi_print_unsigned (ciphertext->bits,
                                    sizeof (ciphertext->bits),
                                    c);
  gcry_mpi_release (c);

  return possible_opts;
}


/**
 * Decrypt a paillier ciphertext with a private key.
 *
 * @param private_key Private key to use for decryption.
 * @param public_key Public key to use for encryption.
 * @param ciphertext Ciphertext to decrypt.
 * @param[out] m Decryption of @a ciphertext with @private_key.
 */
void
GNUNET_CRYPTO_paillier_decrypt (const struct GNUNET_CRYPTO_PaillierPrivateKey *private_key,
                                const struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
                                const struct GNUNET_CRYPTO_PaillierCiphertext *ciphertext,
                                gcry_mpi_t m)
{
  gcry_mpi_t mu;
  gcry_mpi_t lambda;
  gcry_mpi_t n;
  gcry_mpi_t n_square;
  gcry_mpi_t c;
  gcry_mpi_t cmu;
  gcry_mpi_t cmum1;
  gcry_mpi_t mod;

  GNUNET_CRYPTO_mpi_scan_unsigned (&lambda,
                                   private_key->lambda,
                                   sizeof (private_key->lambda));
  GNUNET_CRYPTO_mpi_scan_unsigned (&mu,
                                   private_key->mu,
                                   sizeof (private_key->mu));
  GNUNET_CRYPTO_mpi_scan_unsigned (&n,
                                   public_key,
                                   sizeof (struct GNUNET_CRYPTO_PaillierPublicKey));
  GNUNET_CRYPTO_mpi_scan_unsigned (&c,
                                   ciphertext->bits,
                                   sizeof (ciphertext->bits));

  /* n_square = n * n */
  GNUNET_assert (0 != (n_square = gcry_mpi_new (0)));
  gcry_mpi_mul (n_square, n, n);

  /* cmu = c^lambda mod n^2 */
  GNUNET_assert (0 != (cmu = gcry_mpi_new (0)));
  gcry_mpi_powm (cmu,
                 c,
                 lambda,
                 n_square);
  gcry_mpi_release (n_square);
  gcry_mpi_release (lambda);
  gcry_mpi_release (c);

  /* cmum1 = cmu - 1 */
  GNUNET_assert (0 != (cmum1 = gcry_mpi_new (0)));
  gcry_mpi_sub_ui (cmum1, cmu, 1);
  gcry_mpi_release (cmu);

  /* mod = cmum1 / n (mod n) */
  GNUNET_assert (0 != (mod = gcry_mpi_new (0)));
  gcry_mpi_div (mod, NULL, cmum1, n, 0);

  /* m = mod * mu mod n */
  gcry_mpi_mulm (m, mod, mu, n);
  gcry_mpi_release (mu);
  gcry_mpi_release (n);
}


/**
 * Compute a ciphertext that represents the sum of the plaintext in @a
 * c1 and @a c2.
 *
 * Note that this operation can only be done a finite number of times
 * before an overflow occurs.
 *
 * @param public_key Public key to use for encryption.
 * @param c1 Paillier cipher text.
 * @param c2 Paillier cipher text.
 * @param[out] result Result of the homomorphic operation.
 * @return #GNUNET_OK if the result could be computed,
 *         #GNUNET_SYSERR if no more homomorphic operations are remaining.
 */
int
GNUNET_CRYPTO_paillier_hom_add (const struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
                                const struct GNUNET_CRYPTO_PaillierCiphertext *c1,
                                const struct GNUNET_CRYPTO_PaillierCiphertext *c2,
                                struct GNUNET_CRYPTO_PaillierCiphertext *result)
{
  gcry_mpi_t a;
  gcry_mpi_t b;
  gcry_mpi_t c;
  gcry_mpi_t n;
  gcry_mpi_t n_square;
  int32_t o1;
  int32_t o2;

  o1 = (int32_t) ntohl (c1->remaining_ops);
  o2 = (int32_t) ntohl (c2->remaining_ops);
  if ( (0 >= o1) || (0 >= o2) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  GNUNET_CRYPTO_mpi_scan_unsigned (&a,
                                   c1->bits,
                                   sizeof (c1->bits));
  GNUNET_CRYPTO_mpi_scan_unsigned (&b,
                                   c2->bits,
                                   sizeof (c2->bits));
  GNUNET_CRYPTO_mpi_scan_unsigned (&n,
                                   public_key,
                                   sizeof (struct GNUNET_CRYPTO_PaillierPublicKey));

  /* n_square = n * n */
  GNUNET_assert (0 != (n_square = gcry_mpi_new (0)));
  gcry_mpi_mul (n_square, n, n);
  gcry_mpi_release (n);

  /* c = a * b mod n_square */
  GNUNET_assert (0 != (c = gcry_mpi_new (0)));
  gcry_mpi_mulm (c, a, b, n_square);
  gcry_mpi_release (n_square);
  gcry_mpi_release (a);
  gcry_mpi_release (b);

  result->remaining_ops = htonl (GNUNET_MIN (o1, o2) - 1);
  GNUNET_CRYPTO_mpi_print_unsigned (result->bits,
                                    sizeof (result->bits),
                                    c);
  gcry_mpi_release (c);
  return ntohl (result->remaining_ops);
}


/**
 * Get the number of remaining supported homomorphic operations.
 *
 * @param c Paillier cipher text.
 * @return the number of remaining homomorphic operations
 */
int
GNUNET_CRYPTO_paillier_hom_get_remaining (const struct GNUNET_CRYPTO_PaillierCiphertext *c)
{
  GNUNET_assert (NULL != c);
  return ntohl (c->remaining_ops);
}

/* end of crypto_paillier.c */

