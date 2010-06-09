/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/crypto_random.c
 * @brief functions to gather random numbers
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"
#include <gcrypt.h>

/**
 * Create a cryptographically weak pseudo-random number in the interval of 0 to 1.
 * 
 * @return number between 0 and 1.
 */
static double
weak_random ()
{
  return ((double) RANDOM () / RAND_MAX);
}


/**
 * Produce a random value.
 *
 * @param mode desired quality of the random number
 * @param i the upper limit (exclusive) for the random number
 * @return a random value in the interval [0,i[.
 */
uint32_t
GNUNET_CRYPTO_random_u32 (enum GNUNET_CRYPTO_Quality mode, uint32_t i)
{
#ifdef gcry_fast_random_poll
  static unsigned int invokeCount;
#endif
  uint32_t ret;
  uint32_t ul;

  GNUNET_assert (i > 0);

  if (mode == GNUNET_CRYPTO_QUALITY_STRONG)
    {
      /* see http://lists.gnupg.org/pipermail/gcrypt-devel/2004-May/000613.html */
#ifdef gcry_fast_random_poll
      if ((invokeCount++ % 256) == 0)
        gcry_fast_random_poll ();
#endif
      ul = ((uint32_t)-1) - (((uint32_t)-1) % i);
      do
	{
	  gcry_randomize ((unsigned char *) &ret,
			  sizeof (uint32_t), GCRY_STRONG_RANDOM);
	}
      while (ret >= ul);
      return ret % i;
    }
  else
    {
      ret = i * weak_random ();
      if (ret >= i)
        ret = i - 1;
      return ret;
    }
}


/**
 * Get an array with a random permutation of the
 * numbers 0...n-1.
 * @param mode GNUNET_RANDOM_QUALITY_STRONG if the strong (but expensive)
 *        PRNG should be used, GNUNET_RANDOM_QUALITY_WEAK otherwise
 * @param n the size of the array
 * @return the permutation array (allocated from heap)
 */
unsigned int *
GNUNET_CRYPTO_random_permute (enum GNUNET_CRYPTO_Quality mode, unsigned int n)
{
  unsigned int *ret;
  unsigned int i;
  unsigned int tmp;
  uint32_t x;

  GNUNET_assert (n > 0);
  ret = GNUNET_malloc (n * sizeof (unsigned int));
  for (i = 0; i < n; i++)
    ret[i] = i;
  for (i = n - 1; i > 0; i--)
    {
      x = GNUNET_CRYPTO_random_u32 (mode, i+1);
      tmp = ret[x];
      ret[x] = ret[i];
      ret[i] = tmp;
    }
  return ret;
}

/**
 * Random on unsigned 64-bit values.
 *
 *
 * @param mode desired quality of the random number
 * @param max value returned will be in range [0,max) (exclusive)
 * @return random 64-bit number
 */
uint64_t
GNUNET_CRYPTO_random_u64 (enum GNUNET_CRYPTO_Quality mode, uint64_t max)
{
  uint64_t ret;
  uint64_t ul;

  GNUNET_assert (max > 0);
  if (mode == GNUNET_CRYPTO_QUALITY_STRONG)
    {
      ul = ((uint64_t)-1LL) - (((uint64_t)-1LL) % max);
      do
	{
	  gcry_randomize ((unsigned char *) &ret,
			  sizeof (uint64_t), GCRY_STRONG_RANDOM);
	}
      while (ret >= ul);
      return ret % max;
    }
  else
    {
      ret = max * weak_random ();
      if (ret >= max)
        ret = max - 1;
      return ret;
    }
}

/**
 * This function should only be called in testcases
 * where strong entropy gathering is not desired
 * (for example, for hostkey generation).
 */
void
GNUNET_CRYPTO_random_disable_entropy_gathering ()
{
  gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
}

/**
 * Initializer
 */
void __attribute__ ((constructor)) GNUNET_util_random_init ()
{
  SRANDOM (time (NULL));
}

/* end of crypto_random.c */
