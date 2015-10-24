/*
      This file is part of GNUnet
      Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file set/ibf_sim.c
 * @brief implementation of simulation for invertible bloom filter
 * @author Florian Dold
 *
 * This code was used for some internal experiments, it is not
 * build or shipped as part of the GNUnet system.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAX_IBF_DECODE 16

/* report average over how many rounds? */
#define ROUNDS 100000

/* enable one of the three below */
// simple fix
#define FIX1 0
// possibly slightly better fix for large IBF_DECODE values
#define FIX2 1

// SIGCOMM algorithm
#define STRATA 0

// print each value?
#define VERBOSE 0
// avoid assembly? (ASM is about 50% faster)
#define SLOW 0

int
main(int argc, char **argv)
{
  unsigned int round;
  unsigned int buckets[31]; // max is 2^31 as 'random' returns only between 0 and 2^31
  unsigned int i;
  int j;
  unsigned int r;
  unsigned int ret;
  unsigned long long total;
  unsigned int want;
  double predict;

  srandom (time (NULL));
  total = 0;
  want = atoi (argv[1]);
  for (round=0;round<ROUNDS;round++)
  {
    memset (buckets, 0, sizeof (buckets));
    for (i=0;i<want;i++)
    {
      /* FIXME: might want to use 'better' PRNG to avoid
	 PRNG-induced biases */
      r = random ();
      if (0 == r)
	continue;
#if SLOW
      for (j=0;(j < 31) && (0 == (r & (1 << j)));j++) ;
#else
      /* use assembly / gcc */
      j = __builtin_ffs (r) - 1;
#endif
      buckets[j]++;
    }
    ret = 0;
    predict = 0.0;
    for (j=31;j >= 0; j--)
    {
#if FIX1
      /* improved algorithm, for 1000 elements with IBF-DECODE 8, I
	 get 990/1000 elements on average over 1 million runs; key
	 idea being to stop short of the 'last' possible IBF as
	 otherwise a "lowball" per-chance would unduely influence the
	 result */
      if ( (j > 0) &&
	   (buckets[j - 1] > MAX_IBF_DECODE) )
      {
	ret *= (1 << (j + 1));
	break;
      }
#endif
#if FIX2
      /* another improvement: don't just always cut off the last one,
	 but rather try to predict based on all previous values where
	 that "last" one is; additional prediction can only really
	 work if MAX_IBF_DECODE is sufficiently high */
      if (  (j > 0) &&
	    ( (buckets[j - 1] > MAX_IBF_DECODE) ||
	      (predict > MAX_IBF_DECODE) ) )
      {
	ret *= (1 << (j + 1));
	break;
      }
#endif
#if STRATA
      /* original algorithm, for 1000 elements with IBF-DECODE 8,
	 I get 920/1000 elements on average over 1 million runs */
      if (buckets[j] > MAX_IBF_DECODE)
	{
	  ret *= (1 << (j+1));
	  break;
	}
#endif
      ret += buckets[j];
      predict = (buckets[j] + 2.0 * predict) / 2.0;
    }
#if VERBOSE
    fprintf (stderr, "%u ", ret);
#endif
    total += ret;
  }
  fprintf (stderr, "\n");
  fprintf (stdout, "average %llu\n", total / ROUNDS);
  return 0;
}

/* TODO: should calculate stddev of the results to also be able to
   say something about the stability of the results, outside of
   large-scale averages -- gaining 8% precision at the expense of
   50% additional variance might not be worth it... */
