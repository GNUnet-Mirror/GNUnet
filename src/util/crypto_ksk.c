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
#include <gcrypt.h>
#include <limits.h>

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(level, cmd, rc) do { LOG(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0);


typedef struct
{
  gcry_mpi_t n;                 /* public modulus */
  gcry_mpi_t e;                 /* public exponent */
  gcry_mpi_t d;                 /* exponent */
  gcry_mpi_t p;                 /* prime  p. */
  gcry_mpi_t q;                 /* prime  q. */
  gcry_mpi_t u;                 /* inverse of p mod q. */
} KBlock_secret_key;

/**
 * The private information of an RSA key pair.
 * NOTE: this must match the definition in crypto_rsa.c
 */
struct GNUNET_CRYPTO_RsaPrivateKey
{
  gcry_sexp_t sexp;
};


static void
mpz_randomize (gcry_mpi_t n, unsigned int nbits, GNUNET_HashCode * rnd)
{
  GNUNET_HashCode hc;
  GNUNET_HashCode tmp;
  int bits_per_hc = sizeof (GNUNET_HashCode) * 8;
  int cnt;
  int i;

  GNUNET_assert (nbits > 0);
  cnt = (nbits + bits_per_hc - 1) / bits_per_hc;
  gcry_mpi_set_ui (n, 0);

  tmp = *rnd;
  for (i = 0; i < cnt; i++)
  {
    int j;

    if (i > 0)
      GNUNET_CRYPTO_hash (&hc, sizeof (GNUNET_HashCode), &tmp);
    for (j = 0; j < sizeof (GNUNET_HashCode) / sizeof (uint32_t); j++)
    {
#if HAVE_GCRY_MPI_LSHIFT
      gcry_mpi_lshift (n, n, sizeof (uint32_t) * 8);
#else
      gcry_mpi_mul_ui (n, n, 1 << (sizeof (uint32_t) * 4));
      gcry_mpi_mul_ui (n, n, 1 << (sizeof (uint32_t) * 4));
#endif
      gcry_mpi_add_ui (n, n, ntohl (((uint32_t *) & tmp)[j]));
    }
    hc = tmp;
  }
  GNUNET_CRYPTO_hash (&hc, sizeof (GNUNET_HashCode), rnd);
  i = gcry_mpi_get_nbits (n);
  while (i > nbits)
    gcry_mpi_clear_bit (n, --i);
}

static unsigned long
mpz_trailing_zeroes (gcry_mpi_t n)
{
  unsigned int idx, cnt;

  cnt = gcry_mpi_get_nbits (n);
  for (idx = 0; idx < cnt; idx++)
  {
    if (gcry_mpi_test_bit (n, idx) == 0)
      return idx;
  }

  return ULONG_MAX;
}

static void
mpz_tdiv_q_2exp (gcry_mpi_t q, gcry_mpi_t n, unsigned int b)
{
  gcry_mpi_t u, d;

  u = gcry_mpi_set_ui (NULL, 1);
  d = gcry_mpi_new (0);
  gcry_mpi_mul_2exp (d, u, b);
  gcry_mpi_div (q, NULL, n, d, 0);
}

/**
 * Return true if n is probably a prime
 */
static int
is_prime (gcry_mpi_t n, int steps, GNUNET_HashCode * hc)
{
  gcry_mpi_t x;
  gcry_mpi_t y;
  gcry_mpi_t z;
  gcry_mpi_t nminus1;
  gcry_mpi_t a2;
  gcry_mpi_t q;
  unsigned int i, j, k;
  int rc = 0;
  unsigned int nbits;

  x = gcry_mpi_new (0);
  y = gcry_mpi_new (0);
  z = gcry_mpi_new (0);
  nminus1 = gcry_mpi_new (0);
  a2 = gcry_mpi_set_ui (NULL, 2);

  nbits = gcry_mpi_get_nbits (n);
  gcry_mpi_sub_ui (nminus1, n, 1);

  /* Find q and k, so that n = 1 + 2^k * q . */
  q = gcry_mpi_set (NULL, nminus1);
  k = mpz_trailing_zeroes (q);
  mpz_tdiv_q_2exp (q, q, k);

  for (i = 0; i < steps; i++)
  {
    if (!i)
    {
      gcry_mpi_set_ui (x, 2);
    }
    else
    {
      mpz_randomize (x, nbits - 1, hc);
      GNUNET_assert (gcry_mpi_cmp (x, nminus1) < 0);
      GNUNET_assert (gcry_mpi_cmp_ui (x, 1) > 0);
    }
    gcry_mpi_powm (y, x, q, n);
    if (gcry_mpi_cmp_ui (y, 1) && gcry_mpi_cmp (y, nminus1))
    {
      for (j = 1; j < k && gcry_mpi_cmp (y, nminus1); j++)
      {
        gcry_mpi_powm (y, y, a2, n);
        if (!gcry_mpi_cmp_ui (y, 1))
          goto leave;           /* Not a prime. */
      }
      if (gcry_mpi_cmp (y, nminus1))
        goto leave;             /* Not a prime. */
    }
  }
  rc = 1;                       /* May be a prime. */

leave:
  gcry_mpi_release (x);
  gcry_mpi_release (y);
  gcry_mpi_release (z);
  gcry_mpi_release (nminus1);
  gcry_mpi_release (q);
  gcry_mpi_release (a2);

  return rc;
}

/**
 * If target != size, move target bytes to the
 * end of the size-sized buffer and zero out the
 * first target-size bytes.
 */
static void
adjust (unsigned char *buf, size_t size, size_t target)
{
  if (size < target)
  {
    memmove (&buf[target - size], buf, size);
    memset (buf, 0, target - size);
  }
}


static void
gen_prime (gcry_mpi_t * ptest, unsigned int nbits, GNUNET_HashCode * hc)
{
  /* Note: 2 is not included because it can be tested more easily by
   * looking at bit 0. The last entry in this list is marked by a zero */
  static const uint16_t small_prime_numbers[] = {
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

  gcry_mpi_t prime, pminus1, val_2, val_3, result;
  unsigned int i;
  unsigned int step;
  unsigned int mods[no_of_small_prime_numbers];
  gcry_mpi_t tmp;
  gcry_mpi_t sp;

  GNUNET_assert (nbits >= 16);

  /* Make nbits fit into mpz_t implementation. */
  val_2 = gcry_mpi_set_ui (NULL, 2);
  val_3 = gcry_mpi_set_ui (NULL, 3);
  prime = gcry_mpi_snew (0);
  result = gcry_mpi_new (0);
  pminus1 = gcry_mpi_new (0);
  *ptest = gcry_mpi_new (0);
  tmp = gcry_mpi_new (0);
  sp = gcry_mpi_new (0);
  while (1)
  {
    /* generate a random number */
    mpz_randomize (prime, nbits, hc);
    /* Set high order bit to 1, set low order bit to 1.  If we are
     * generating a secret prime we are most probably doing that
     * for RSA, to make sure that the modulus does have the
     * requested key size we set the 2 high order bits. */
    gcry_mpi_set_bit (prime, nbits - 1);
    gcry_mpi_set_bit (prime, nbits - 2);
    gcry_mpi_set_bit (prime, 0);

    /* Calculate all remainders. */
    for (i = 0; i < no_of_small_prime_numbers; i++)
    {
      size_t written;

      gcry_mpi_set_ui (sp, small_prime_numbers[i]);
      gcry_mpi_div (NULL, tmp, prime, sp, -1);
      mods[i] = 0;
      written = sizeof (unsigned int);
      GNUNET_assert (0 ==
                     gcry_mpi_print (GCRYMPI_FMT_USG,
                                     (unsigned char *) &mods[i], written,
                                     &written, tmp));
      adjust ((unsigned char *) &mods[i], written, sizeof (unsigned int));
      mods[i] = ntohl (mods[i]);
    }
    /* Now try some primes starting with prime. */
    for (step = 0; step < 20000; step += 2)
    {
      /* Check against all the small primes we have in mods. */
      for (i = 0; i < no_of_small_prime_numbers; i++)
      {
        uint16_t x = small_prime_numbers[i];

        while (mods[i] + step >= x)
          mods[i] -= x;
        if (!(mods[i] + step))
          break;
      }
      if (i < no_of_small_prime_numbers)
        continue;               /* Found a multiple of an already known prime. */

      gcry_mpi_add_ui (*ptest, prime, step);
      if (!gcry_mpi_test_bit (*ptest, nbits - 2))
        break;

      /* Do a fast Fermat test now. */
      gcry_mpi_sub_ui (pminus1, *ptest, 1);
      gcry_mpi_powm (result, val_2, pminus1, *ptest);
      if ((!gcry_mpi_cmp_ui (result, 1)) && (is_prime (*ptest, 5, hc)))
      {
        /* Got it. */
        gcry_mpi_release (sp);
        gcry_mpi_release (tmp);
        gcry_mpi_release (val_2);
        gcry_mpi_release (val_3);
        gcry_mpi_release (result);
        gcry_mpi_release (pminus1);
        gcry_mpi_release (prime);
        return;
      }
    }
  }
}

/**
 * Generate a key pair with a key of size NBITS.
 * @param sk where to store the key
 * @param nbits the number of bits to use
 * @param hc the HC to use for PRNG (modified!)
 */
static void
generate_kblock_key (KBlock_secret_key *sk, unsigned int nbits,
                     GNUNET_HashCode * hc)
{
  gcry_mpi_t t1, t2;
  gcry_mpi_t phi;               /* helper: (p-1)(q-1) */
  gcry_mpi_t g;
  gcry_mpi_t f;

  /* make sure that nbits is even so that we generate p, q of equal size */
  if ((nbits & 1))
    nbits++;

  sk->e = gcry_mpi_set_ui (NULL, 257);
  sk->n = gcry_mpi_new (0);
  sk->p = gcry_mpi_new (0);
  sk->q = gcry_mpi_new (0);
  sk->d = gcry_mpi_new (0);
  sk->u = gcry_mpi_new (0);

  t1 = gcry_mpi_new (0);
  t2 = gcry_mpi_new (0);
  phi = gcry_mpi_new (0);
  g = gcry_mpi_new (0);
  f = gcry_mpi_new (0);

  do
  {
    do
    {
      gcry_mpi_release (sk->p);
      gcry_mpi_release (sk->q);
      gen_prime (&sk->p, nbits / 2, hc);
      gen_prime (&sk->q, nbits / 2, hc);

      if (gcry_mpi_cmp (sk->p, sk->q) > 0)      /* p shall be smaller than q (for calc of u) */
        gcry_mpi_swap (sk->p, sk->q);
      /* calculate the modulus */
      gcry_mpi_mul (sk->n, sk->p, sk->q);
    }
    while (gcry_mpi_get_nbits (sk->n) != nbits);

    /* calculate Euler totient: phi = (p-1)(q-1) */
    gcry_mpi_sub_ui (t1, sk->p, 1);
    gcry_mpi_sub_ui (t2, sk->q, 1);
    gcry_mpi_mul (phi, t1, t2);
    gcry_mpi_gcd (g, t1, t2);
    gcry_mpi_div (f, NULL, phi, g, 0);
    while (0 == gcry_mpi_gcd (t1, sk->e, phi))
    {                           /* (while gcd is not 1) */
      gcry_mpi_add_ui (sk->e, sk->e, 2);
    }

    /* calculate the secret key d = e^1 mod phi */
  }
  while ((0 == gcry_mpi_invm (sk->d, sk->e, f)) ||
         (0 == gcry_mpi_invm (sk->u, sk->p, sk->q)));

  gcry_mpi_release (t1);
  gcry_mpi_release (t2);
  gcry_mpi_release (phi);
  gcry_mpi_release (f);
  gcry_mpi_release (g);
}

GNUNET_NETWORK_STRUCT_BEGIN

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
GNUNET_NETWORK_STRUCT_END

/**
 * Deterministically (!) create a hostkey using only the
 * given HashCode as input to the PRNG.
 */
static struct KskRsaPrivateKeyBinaryEncoded *
makeKblockKeyInternal (const GNUNET_HashCode * hc)
{
  KBlock_secret_key sk;
  GNUNET_HashCode hx;
  unsigned char *pbu[6];
  gcry_mpi_t *pkv[6];
  size_t sizes[6];
  struct KskRsaPrivateKeyBinaryEncoded *retval;
  int i;
  size_t size;

  hx = *hc;
  generate_kblock_key (&sk, 1024,       /* at least 10x as fast than 2048 bits
                                         * -- we simply cannot afford 2048 bits
                                         * even on modern hardware, and especially
                                         * not since clearly a dictionary attack
                                         * will still be much cheaper
                                         * than breaking a 1024 bit RSA key.
                                         * If an adversary can spend the time to
                                         * break a 1024 bit RSA key just to forge
                                         * a signature -- SO BE IT. [ CG, 6/2005 ] */
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
    gcry_mpi_aprint (GCRYMPI_FMT_STD, &pbu[i], &sizes[i], *pkv[i]);
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
    gcry_mpi_release (*pkv[i]);
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
  rc = gcry_mpi_scan (&n, GCRYMPI_FMT_USG,
                      &((const unsigned char *) (&encoding[1]))[pos], size,
                      &size);
  pos += ntohs (encoding->sizen);
  if (rc)
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    return NULL;
  }
  size = ntohs (encoding->sizee);
  rc = gcry_mpi_scan (&e, GCRYMPI_FMT_USG,
                      &((const unsigned char *) (&encoding[1]))[pos], size,
                      &size);
  pos += ntohs (encoding->sizee);
  if (rc)
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    gcry_mpi_release (n);
    return NULL;
  }
  size = ntohs (encoding->sized);
  rc = gcry_mpi_scan (&d, GCRYMPI_FMT_USG,
                      &((const unsigned char *) (&encoding[1]))[pos], size,
                      &size);
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
    rc = gcry_mpi_scan (&q, GCRYMPI_FMT_USG,
                        &((const unsigned char *) (&encoding[1]))[pos], size,
                        &size);
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
    rc = gcry_mpi_scan (&p, GCRYMPI_FMT_USG,
                        &((const unsigned char *) (&encoding[1]))[pos], size,
                        &size);
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
    rc = gcry_mpi_scan (&u, GCRYMPI_FMT_USG,
                        &((const unsigned char *) (&encoding[1]))[pos], size,
                        &size);
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
    rc = gcry_sexp_build (&res, &size,  /* erroff */
                          "(private-key(rsa(n %m)(e %m)(d %m)(p %m)(q %m)(u %m)))",
                          n, e, d, p, q, u);
  }
  else
  {
    if ((p != NULL) && (q != NULL))
    {
      rc = gcry_sexp_build (&res, &size,        /* erroff */
                            "(private-key(rsa(n %m)(e %m)(d %m)(p %m)(q %m)))",
                            n, e, d, p, q);
    }
    else
    {
      rc = gcry_sexp_build (&res, &size,        /* erroff */
                            "(private-key(rsa(n %m)(e %m)(d %m)))", n, e, d);
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


struct KBlockKeyCacheLine
{
  GNUNET_HashCode hc;
  struct KskRsaPrivateKeyBinaryEncoded *pke;
};

static struct KBlockKeyCacheLine **cache;

static unsigned int cacheSize;

/**
 * Deterministically (!) create a hostkey using only the
 * given HashCode as input to the PRNG.
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_key_create_from_hash (const GNUNET_HashCode * hc)
{
  struct GNUNET_CRYPTO_RsaPrivateKey *ret;
  struct KBlockKeyCacheLine *line;
  unsigned int i;

  for (i = 0; i < cacheSize; i++)
  {
    if (0 == memcmp (hc, &cache[i]->hc, sizeof (GNUNET_HashCode)))
    {
      ret = ksk_decode_key (cache[i]->pke);
      return ret;
    }
  }

  line = GNUNET_malloc (sizeof (struct KBlockKeyCacheLine));
  line->hc = *hc;
  line->pke = makeKblockKeyInternal (hc);
  GNUNET_array_grow (cache, cacheSize, cacheSize + 1);
  cache[cacheSize - 1] = line;
  return ksk_decode_key (line->pke);
}


void __attribute__ ((destructor)) GNUNET_CRYPTO_ksk_fini ()
{
  unsigned int i;

  for (i = 0; i < cacheSize; i++)
  {
    GNUNET_free (cache[i]->pke);
    GNUNET_free (cache[i]);
  }
  GNUNET_array_grow (cache, cacheSize, 0);
}


/* end of crypto_ksk.c */
