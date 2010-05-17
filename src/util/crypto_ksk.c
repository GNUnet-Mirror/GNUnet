/*
     This file is part of GNUnet.
     Copyright (C) 1994, 1996, 1998, 2001, 2002, 2003 Free Software Foundation, Inc.
     Copyright (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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

     Note: This code is based on code from libgcrypt
     The code was adapted for GNUnet to support RSA-key generation
     based on weak, pseudo-random keys.  Do NOT use to generate
     ordinary RSA keys!
*/


/**
 * @file util/crypto_ksk.c
 * @brief implementation of RSA-Key generation for KBlocks
 *        (do NOT use for pseudonyms or hostkeys!)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_os_lib.h"
#include <gmp.h>
#include <gcrypt.h>

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(level, cmd, rc) do { GNUNET_log(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0);


typedef struct
{
  mpz_t n;                      /* public modulus */
  mpz_t e;                      /* public exponent */
  mpz_t d;                      /* exponent */
  mpz_t p;                      /* prime  p. */
  mpz_t q;                      /* prime  q. */
  mpz_t u;                      /* inverse of p mod q. */
} KBlock_secret_key;

/**
 * The private information of an RSA key pair.
 * NOTE: this must match the definition in crypto_rsa.c
 */
struct GNUNET_CRYPTO_RsaPrivateKey
{
  gcry_sexp_t sexp;
};


/* Note: 2 is not included because it can be tested more easily by
   looking at bit 0. The last entry in this list is marked by a zero */
static uint16_t small_prime_numbers[] = {
  3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43,
  47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
  103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
  157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
  211, 223, 227, 229, 233, 239, 241, 251, 257, 263,
  269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
  331, 337, 347, 349, 353, 359, 367, 373, 379, 383,
  389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
  449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
  509, 521, 523, 541, 547, 557, 563, 569, 571, 577,
  587, 593, 599, 601, 607, 613, 617, 619, 631, 641,
  643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
  709, 719, 727, 733, 739, 743, 751, 757, 761, 769,
  773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
  853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
  919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
  991, 997, 1009, 1013, 1019, 1021, 1031, 1033,
  1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091,
  1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
  1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213,
  1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
  1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307,
  1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399,
  1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
  1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493,
  1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559,
  1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609,
  1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667,
  1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733,
  1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
  1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871,
  1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931,
  1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997,
  1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053,
  2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111,
  2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161,
  2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243,
  2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297,
  2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
  2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411,
  2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473,
  2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551,
  2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633,
  2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687,
  2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729,
  2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791,
  2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851,
  2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917,
  2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999,
  3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061,
  3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137,
  3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209,
  3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271,
  3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
  3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391,
  3407, 3413, 3433, 3449, 3457, 3461, 3463, 3467,
  3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533,
  3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583,
  3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643,
  3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709,
  3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779,
  3793, 3797, 3803, 3821, 3823, 3833, 3847, 3851,
  3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917,
  3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989,
  4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049,
  4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111,
  4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177,
  4201, 4211, 4217, 4219, 4229, 4231, 4241, 4243,
  4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,
  4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391,
  4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457,
  4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519,
  4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597,
  4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
  4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729,
  4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799,
  4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889,
  4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951,
  4957, 4967, 4969, 4973, 4987, 4993, 4999,
  0
};

#define DIM(v) (sizeof(v)/sizeof((v)[0]))
static int no_of_small_prime_numbers = DIM (small_prime_numbers) - 1;


static unsigned int
get_nbits (mpz_t a)
{
  return mpz_sizeinbase (a, 2);
}


static void
mpz_randomize (mpz_t n, unsigned int nbits, GNUNET_HashCode * rnd)
{
  GNUNET_HashCode *tmp;
  int bits_per_hc = sizeof (GNUNET_HashCode) * 8;
  int cnt;
  int i;

  GNUNET_assert (nbits > 0);
  cnt = (nbits + bits_per_hc - 1) / bits_per_hc;
  tmp = GNUNET_malloc (sizeof (GNUNET_HashCode) * cnt);

  tmp[0] = *rnd;
  for (i = 0; i < cnt - 1; i++)
    {
      GNUNET_CRYPTO_hash (&tmp[i], sizeof (GNUNET_HashCode), &tmp[i + 1]);
    }
  GNUNET_CRYPTO_hash (&tmp[i], sizeof (GNUNET_HashCode), rnd);
  mpz_import (n, cnt * sizeof (GNUNET_HashCode) / sizeof (unsigned int),
              1, sizeof (unsigned int), 1, 0, tmp);
  GNUNET_free (tmp);
  i = get_nbits (n);
  while (i > nbits)
    mpz_clrbit (n, i--);
}

/**
 * Return true if n is probably a prime
 */
static int
is_prime (mpz_t n, int steps, GNUNET_HashCode * hc)
{
  mpz_t x;
  mpz_t y;
  mpz_t z;
  mpz_t nminus1;
  mpz_t a2;
  mpz_t q;
  unsigned int i, j, k;
  int rc = 0;
  unsigned int nbits;

  mpz_init (x);
  mpz_init (y);
  mpz_init (z);
  mpz_init (nminus1);
  mpz_init_set_ui (a2, 2);
  nbits = get_nbits (n);
  mpz_sub_ui (nminus1, n, 1);

  /* Find q and k, so that n = 1 + 2^k * q . */
  mpz_init_set (q, nminus1);
  k = mpz_scan1 (q, 0);
  mpz_tdiv_q_2exp (q, q, k);

  for (i = 0; i < steps; i++)
    {
      if (!i)
        {
          mpz_set_ui (x, 2);
        }
      else
        {
          mpz_randomize (x, nbits - 1, hc);
          GNUNET_assert (mpz_cmp (x, nminus1) < 0 && mpz_cmp_ui (x, 1) > 0);
        }
      mpz_powm (y, x, q, n);
      if (mpz_cmp_ui (y, 1) && mpz_cmp (y, nminus1))
        {
          for (j = 1; j < k && mpz_cmp (y, nminus1); j++)
            {
              mpz_powm (y, y, a2, n);
              if (!mpz_cmp_ui (y, 1))
                goto leave;     /* Not a prime. */
            }
          if (mpz_cmp (y, nminus1))
            goto leave;         /* Not a prime. */
        }
    }
  rc = 1;                       /* May be a prime. */

leave:
  mpz_clear (x);
  mpz_clear (y);
  mpz_clear (z);
  mpz_clear (nminus1);
  mpz_clear (q);
  mpz_clear (a2);

  return rc;
}

static void
gen_prime (mpz_t ptest, unsigned int nbits, GNUNET_HashCode * hc)
{
  mpz_t prime, pminus1, val_2, val_3, result;
  int i;
  unsigned x, step;
  int *mods;
  mpz_t tmp;

  GNUNET_assert (nbits >= 16);

  mods = GNUNET_malloc (no_of_small_prime_numbers * sizeof (*mods));
  /* Make nbits fit into mpz_t implementation. */
  mpz_init_set_ui (val_2, 2);
  mpz_init_set_ui (val_3, 3);
  mpz_init (prime);
  mpz_init (result);
  mpz_init (pminus1);
  mpz_init (ptest);
  while (1)
    {
      /* generate a random number */
      mpz_randomize (prime, nbits, hc);
      /* Set high order bit to 1, set low order bit to 1.  If we are
         generating a secret prime we are most probably doing that
         for RSA, to make sure that the modulus does have the
         requested key size we set the 2 high order bits. */
      mpz_setbit (prime, nbits - 1);
      mpz_setbit (prime, nbits - 2);
      mpz_setbit (prime, 0);

      /* Calculate all remainders. */
      mpz_init (tmp);
      for (i = 0; (x = small_prime_numbers[i]); i++)
        mods[i] = mpz_fdiv_r_ui (tmp, prime, x);
      mpz_clear (tmp);
      /* Now try some primes starting with prime. */
      for (step = 0; step < 20000; step += 2)
        {
          /* Check against all the small primes we have in mods. */
          for (i = 0; (x = small_prime_numbers[i]); i++)
            {
              while (mods[i] + step >= x)
                mods[i] -= x;
              if (!(mods[i] + step))
                break;
            }
          if (x)
            continue;           /* Found a multiple of an already known prime. */

          mpz_add_ui (ptest, prime, step);
          if (!mpz_tstbit (ptest, nbits - 2))
            break;

          /* Do a fast Fermat test now. */
          mpz_sub_ui (pminus1, ptest, 1);
          mpz_powm (result, val_2, pminus1, ptest);
          if ((!mpz_cmp_ui (result, 1)) && (is_prime (ptest, 5, hc)))
            {
              /* Got it. */
              mpz_clear (val_2);
              mpz_clear (val_3);
              mpz_clear (result);
              mpz_clear (pminus1);
              mpz_clear (prime);
              GNUNET_free (mods);
              return;
            }
        }
    }
}

/**
 * Find the greatest common divisor G of A and B.
 * Return: 1 if this 1, 0 in all other cases
 */
static int
test_gcd (mpz_t g, mpz_t xa, mpz_t xb)
{
  mpz_t a, b;

  mpz_init_set (a, xa);
  mpz_init_set (b, xb);

  /* TAOCP Vol II, 4.5.2, Algorithm A */
  while (mpz_cmp_ui (b, 0))
    {
      mpz_fdiv_r (g, a, b);     /* g used as temorary variable */
      mpz_set (a, b);
      mpz_set (b, g);
    }
  mpz_set (g, a);

  mpz_clear (a);
  mpz_clear (b);
  return (0 == mpz_cmp_ui (g, 1));
}

/**
 * Generate a key pair with a key of size NBITS.
 * @param sk where to store the key
 * @param nbits the number of bits to use
 * @param hc the HC to use for PRNG (modified!)
 */
static void
generate_kblock_key (KBlock_secret_key * sk,
                     unsigned int nbits, GNUNET_HashCode * hc)
{
  mpz_t t1, t2;
  mpz_t phi;                    /* helper: (p-1)(q-1) */
  mpz_t g;
  mpz_t f;

  /* make sure that nbits is even so that we generate p, q of equal size */
  if ((nbits & 1))
    nbits++;

  mpz_init_set_ui (sk->e, 257);
  mpz_init (sk->n);
  mpz_init (sk->p);
  mpz_init (sk->q);
  mpz_init (sk->d);
  mpz_init (sk->u);

  mpz_init (t1);
  mpz_init (t2);
  mpz_init (phi);
  mpz_init (g);
  mpz_init (f);

  do
    {
      do
        {
          mpz_clear (sk->p);
          mpz_clear (sk->q);
          gen_prime (sk->p, nbits / 2, hc);
          gen_prime (sk->q, nbits / 2, hc);

          if (mpz_cmp (sk->p, sk->q) > 0)       /* p shall be smaller than q (for calc of u) */
            mpz_swap (sk->p, sk->q);
          /* calculate the modulus */
          mpz_mul (sk->n, sk->p, sk->q);
        }
      while (get_nbits (sk->n) != nbits);

      /* calculate Euler totient: phi = (p-1)(q-1) */
      mpz_sub_ui (t1, sk->p, 1);
      mpz_sub_ui (t2, sk->q, 1);
      mpz_mul (phi, t1, t2);
      mpz_gcd (g, t1, t2);
      mpz_fdiv_q (f, phi, g);

      while (0 == test_gcd (t1, sk->e, phi))
        {                       /* (while gcd is not 1) */
          mpz_add_ui (sk->e, sk->e, 2);
        }

      /* calculate the secret key d = e^1 mod phi */
    }
  while ((0 == mpz_invert (sk->d, sk->e, f)) ||
         (0 == mpz_invert (sk->u, sk->p, sk->q)));

  mpz_clear (t1);
  mpz_clear (t2);
  mpz_clear (phi);
  mpz_clear (f);
  mpz_clear (g);
}


/**
 * Internal representation of the private key.
 */
struct KskRsaPrivateKeyBinaryEncoded
{
  /**
   * Total size of the structure, in bytes, in big-endian!
   */
  uint16_t len GNUNET_PACKED;
  uint16_t sizen GNUNET_PACKED; /*  in big-endian! */
  uint16_t sizee GNUNET_PACKED; /*  in big-endian! */
  uint16_t sized GNUNET_PACKED; /*  in big-endian! */
  uint16_t sizep GNUNET_PACKED; /*  in big-endian! */
  uint16_t sizeq GNUNET_PACKED; /*  in big-endian! */
  uint16_t sizedmp1 GNUNET_PACKED;      /*  in big-endian! */
  uint16_t sizedmq1 GNUNET_PACKED;      /*  in big-endian! */
  /* followed by the actual values */
};


/**
 * Deterministically (!) create a hostkey using only the
 * given HashCode as input to the PRNG.
 */
static struct KskRsaPrivateKeyBinaryEncoded *
makeKblockKeyInternal (const GNUNET_HashCode * hc)
{
  KBlock_secret_key sk;
  GNUNET_HashCode hx;
  void *pbu[6];
  mpz_t *pkv[6];
  size_t sizes[6];
  struct KskRsaPrivateKeyBinaryEncoded *retval;
  int i;
  size_t size;

  hx = *hc;
  generate_kblock_key (&sk, 1024,       /* at least 10x as fast than 2048 bits
                                           -- we simply cannot afford 2048 bits
                                           even on modern hardware, and especially
                                           not since clearly a dictionary attack
                                           will still be much cheaper
                                           than breaking a 1024 bit RSA key.
                                           If an adversary can spend the time to
                                           break a 1024 bit RSA key just to forge
                                           a signature -- SO BE IT. [ CG, 6/2005 ] */
                       &hx);
  pkv[0] = &sk.n;
  pkv[1] = &sk.e;
  pkv[2] = &sk.d;
  pkv[3] = &sk.p;
  pkv[4] = &sk.q;
  pkv[5] = &sk.u;
  size = sizeof (struct KskRsaPrivateKeyBinaryEncoded);
  for (i = 0; i < 6; i++)
    {
      pbu[i] = mpz_export (NULL, &sizes[i], 1,  /* most significant word first */
                           1,   /* unit is bytes */
                           1,   /* big endian */
                           0,   /* nails */
                           *pkv[i]);
      size += sizes[i];
    }
  GNUNET_assert (size < 65536);
  retval = GNUNET_malloc (size);
  retval->len = htons (size);
  i = 0;
  retval->sizen = htons (sizes[0]);
  memcpy (&((char *) &retval[1])[i], pbu[0], sizes[0]);
  i += sizes[0];
  retval->sizee = htons (sizes[1]);
  memcpy (&((char *) &retval[1])[i], pbu[1], sizes[1]);
  i += sizes[1];
  retval->sized = htons (sizes[2]);
  memcpy (&((char *) &retval[1])[i], pbu[2], sizes[2]);
  i += sizes[2];
  /* swap p and q! */
  retval->sizep = htons (sizes[4]);
  memcpy (&((char *) &retval[1])[i], pbu[4], sizes[4]);
  i += sizes[4];
  retval->sizeq = htons (sizes[3]);
  memcpy (&((char *) &retval[1])[i], pbu[3], sizes[3]);
  i += sizes[3];
  retval->sizedmp1 = htons (0);
  retval->sizedmq1 = htons (0);
  memcpy (&((char *) &retval[1])[i], pbu[5], sizes[5]);
  for (i = 0; i < 6; i++)
    {
      mpz_clear (*pkv[i]);
      free (pbu[i]);
    }
  return retval;
}


/**
 * Decode the internal format into the format used
 * by libgcrypt.
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *
ksk_decode_key (const struct KskRsaPrivateKeyBinaryEncoded *encoding)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *ret;
  gcry_sexp_t res;
  gcry_mpi_t n, e, d, p, q, u;
  int rc;
  size_t size;
  int pos;

  pos = 0;
  size = ntohs (encoding->sizen);
  rc = gcry_mpi_scan (&n,
                      GCRYMPI_FMT_USG,
                      &((const unsigned char *) (&encoding[1]))[pos],
                      size, &size);
  pos += ntohs (encoding->sizen);
  if (rc)
    {
      LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
      return NULL;
    }
  size = ntohs (encoding->sizee);
  rc = gcry_mpi_scan (&e,
                      GCRYMPI_FMT_USG,
                      &((const unsigned char *) (&encoding[1]))[pos],
                      size, &size);
  pos += ntohs (encoding->sizee);
  if (rc)
    {
      LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
      gcry_mpi_release (n);
      return NULL;
    }
  size = ntohs (encoding->sized);
  rc = gcry_mpi_scan (&d,
                      GCRYMPI_FMT_USG,
                      &((const unsigned char *) (&encoding[1]))[pos],
                      size, &size);
  pos += ntohs (encoding->sized);
  if (rc)
    {
      LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
      gcry_mpi_release (n);
      gcry_mpi_release (e);
      return NULL;
    }
  /* swap p and q! */
  size = ntohs (encoding->sizep);
  if (size > 0)
    {
      rc = gcry_mpi_scan (&q,
                          GCRYMPI_FMT_USG,
                          &((const unsigned char *) (&encoding[1]))[pos],
                          size, &size);
      pos += ntohs (encoding->sizep);
      if (rc)
        {
          LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
          gcry_mpi_release (n);
          gcry_mpi_release (e);
          gcry_mpi_release (d);
          return NULL;
        }
    }
  else
    q = NULL;
  size = ntohs (encoding->sizeq);
  if (size > 0)
    {
      rc = gcry_mpi_scan (&p,
                          GCRYMPI_FMT_USG,
                          &((const unsigned char *) (&encoding[1]))[pos],
                          size, &size);
      pos += ntohs (encoding->sizeq);
      if (rc)
        {
          LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
          gcry_mpi_release (n);
          gcry_mpi_release (e);
          gcry_mpi_release (d);
          if (q != NULL)
            gcry_mpi_release (q);
          return NULL;
        }
    }
  else
    p = NULL;
  pos += ntohs (encoding->sizedmp1);
  pos += ntohs (encoding->sizedmq1);
  size =
    ntohs (encoding->len) - sizeof (struct KskRsaPrivateKeyBinaryEncoded) -
    pos;
  if (size > 0)
    {
      rc = gcry_mpi_scan (&u,
                          GCRYMPI_FMT_USG,
                          &((const unsigned char *) (&encoding[1]))[pos],
                          size, &size);
      if (rc)
        {
          LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
          gcry_mpi_release (n);
          gcry_mpi_release (e);
          gcry_mpi_release (d);
          if (p != NULL)
            gcry_mpi_release (p);
          if (q != NULL)
            gcry_mpi_release (q);
          return NULL;
        }
    }
  else
    u = NULL;

  if ((p != NULL) && (q != NULL) && (u != NULL))
    {
      rc = gcry_sexp_build (&res, &size,        /* erroff */
                            "(private-key(rsa(n %m)(e %m)(d %m)(p %m)(q %m)(u %m)))",
                            n, e, d, p, q, u);
    }
  else
    {
      if ((p != NULL) && (q != NULL))
        {
          rc = gcry_sexp_build (&res, &size,    /* erroff */
                                "(private-key(rsa(n %m)(e %m)(d %m)(p %m)(q %m)))",
                                n, e, d, p, q);
        }
      else
        {
          rc = gcry_sexp_build (&res, &size,    /* erroff */
                                "(private-key(rsa(n %m)(e %m)(d %m)))",
                                n, e, d);
        }
    }
  gcry_mpi_release (n);
  gcry_mpi_release (e);
  gcry_mpi_release (d);
  if (p != NULL)
    gcry_mpi_release (p);
  if (q != NULL)
    gcry_mpi_release (q);
  if (u != NULL)
    gcry_mpi_release (u);

  if (rc)
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_sexp_build", rc);
#if EXTRA_CHECKS
  if (gcry_pk_testkey (res))
    {
      LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_pk_testkey", rc);
      return NULL;
    }
#endif
  ret = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaPrivateKey));
  ret->sexp = res;
  return ret;
}




typedef struct
{
  GNUNET_HashCode hc;
  struct KskRsaPrivateKeyBinaryEncoded *pke;
} KBlockKeyCacheLine;

static KBlockKeyCacheLine **cache;
static unsigned int cacheSize;

/**
 * Deterministically (!) create a hostkey using only the
 * given HashCode as input to the PRNG.
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_key_create_from_hash (const GNUNET_HashCode * hc)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *ret;
  KBlockKeyCacheLine *line;
  int i;

  for (i = 0; i < cacheSize; i++)
    {
      if (0 == memcmp (hc, &cache[i]->hc, sizeof (GNUNET_HashCode)))
        {
          ret = ksk_decode_key (cache[i]->pke);
          return ret;
        }
    }

  line = GNUNET_malloc (sizeof (KBlockKeyCacheLine));
  line->hc = *hc;
  line->pke = makeKblockKeyInternal (hc);
  GNUNET_array_grow (cache, cacheSize, cacheSize + 1);
  cache[cacheSize - 1] = line;
  return ksk_decode_key (line->pke);
}


/**
 * Process ID of the "find" process that we use for
 * entropy gathering.
 */
static pid_t genproc;

/**
 * Function called by libgcrypt whenever we are
 * blocked gathering entropy.
 */
static void
entropy_generator (void *cls,
                   const char *what, int printchar, int current, int total)
{
  unsigned long code;
  enum GNUNET_OS_ProcessStatusType type;
  int ret;

  if (0 != strcmp (what, "need_entropy"))
    return;
  if (current == total)
    {
      if (genproc != 0)
        {
          if (0 != PLIBC_KILL (genproc, SIGTERM))
            GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "kill");
          GNUNET_break (GNUNET_OK == GNUNET_OS_process_wait (genproc));
          genproc = 0;
        }
      return;
    }
  if (genproc != 0)
    {
      ret = GNUNET_OS_process_status (genproc, &type, &code);
      if (ret == GNUNET_NO)
        return;                 /* still running */
      if (ret == GNUNET_SYSERR)
        {
          GNUNET_break (0);
          return;
        }
      if (0 != PLIBC_KILL (genproc, SIGTERM))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "kill");
      GNUNET_break (GNUNET_OK == GNUNET_OS_process_wait (genproc));
      genproc = 0;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Starting `%s' process to generate entropy\n"), "find");
  genproc = GNUNET_OS_start_process (NULL, NULL, "sh",
                                     "sh",
                                     "-c",
                                     "exec find / -mount -type f -exec cp {} /dev/null \\; 2>/dev/null",
                                     NULL);
}


static void
killfind ()
{
  if (genproc != 0)
    {
      PLIBC_KILL (genproc, SIGKILL);
      genproc = 0;
    }
}


void __attribute__ ((constructor)) GNUNET_CRYPTO_ksk_init ()
{
  gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
  if (!gcry_check_version (GCRYPT_VERSION))
    {
      fprintf (stderr,
               _
               ("libgcrypt has not the expected version (version %s is required).\n"),
               GCRYPT_VERSION);
      abort ();
    }
#ifdef gcry_fast_random_poll
  gcry_fast_random_poll ();
#endif
  gcry_set_progress_handler (&entropy_generator, NULL);
  atexit (&killfind);
}


void __attribute__ ((destructor)) GNUNET_CRYPTO_ksk_fini ()
{
  int i;

  for (i = 0; i < cacheSize; i++)
    {
      GNUNET_free (cache[i]->pke);
      GNUNET_free (cache[i]);
    }
  GNUNET_array_grow (cache, cacheSize, 0);
  gcry_set_progress_handler (NULL, NULL);
}

/* end of kblockkey.c */
