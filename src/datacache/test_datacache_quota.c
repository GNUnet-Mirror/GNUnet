/*
     This file is part of GNUnet.
     (C) 2006, 2009 Christian Grothoff (and other contributing authors)

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
/*
 * @file datacache/test_datacache_quota.c
 * @brief Test for the quota code of the datacache implementations.
 * @author Nils Durner
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_datacache_lib.h"

#define VERBOSE GNUNET_NO

#define ASSERT(x) do { if (! (x)) { printf("Error at %s:%d\n", __FILE__, __LINE__); goto FAILURE;} } while (0)

static int ok;

/**
 * Quota is 1 MB.  Each iteration of the test puts in about 1 MB of
 * data.  We do 10 iterations. Afterwards we check that the data from
 * the first 5 iterations has all been discarded and that at least
 * some of the data from the last iteration is still there.
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile, 
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_DATACACHE_Handle *h;
  GNUNET_HashCode k;
  GNUNET_HashCode n;
  unsigned int i;
  unsigned int j;
  char buf[3200];
  struct GNUNET_TIME_Absolute exp;

  ok = 0;
  h = GNUNET_DATACACHE_create (sched,
			       cfg,
			       "testcache");

  ASSERT (NULL != h);
  exp = GNUNET_TIME_absolute_get ();
  exp.value += 20 * 60 * 1000;
  memset (buf, 1, sizeof (buf));
  memset (&k, 0, sizeof (GNUNET_HashCode));
  for (i = 0; i < 10; i++)
    {
      fprintf (stderr, ".");
      GNUNET_CRYPTO_hash (&k, sizeof (GNUNET_HashCode), &n);
      for (j = i; j < sizeof (buf); j += 10)
        {
	  exp.value++;
          buf[j] = i;
          ASSERT (GNUNET_OK == 
		  GNUNET_DATACACHE_put (h,
					&k,
					j,
					buf,
					1+i,
					exp));
          ASSERT (0 < GNUNET_DATACACHE_get (h, 
					    &k, 1+i, 
					    NULL, NULL));
        }
      k = n;
    }
  fprintf (stderr, "\n");
  memset (&k, 0, sizeof (GNUNET_HashCode));
  for (i = 0; i < 10; i++)
    {
      fprintf (stderr, ".");
      GNUNET_CRYPTO_hash (&k, sizeof (GNUNET_HashCode), &n);
      if (i < 2)
	ASSERT (0 == GNUNET_DATACACHE_get  (h, 
					    &k, 1+i, 
					    NULL, NULL));
      if (i == 9)
	ASSERT (0 < GNUNET_DATACACHE_get  (h, 
					   &k, 1+i, 
					   NULL, NULL));
      k = n;
    }
  fprintf (stderr, "\n");
  GNUNET_DATACACHE_destroy (h);
  return;
FAILURE:
  if (h != NULL)
    GNUNET_DATACACHE_destroy (h);
  ok = GNUNET_SYSERR;
}


static int
check ()
{
  char *const argv[] = { "test-datacache-api-quota",
    "-c",
    "test_datacache_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-datacache-api-quota", "nohelp",
                      options, &run, NULL);
  if (ok != 0)
    fprintf (stderr, "Missed some testcases: %d\n", ok);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;
  
  GNUNET_log_setup ("test-datacache-api-quota",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();

  return ret;
}

/* end of test_datacache_quota.c */
