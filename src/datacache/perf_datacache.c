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
 * @file datacache/perf_datacache.c
 * @brief Performance evaluation for the datacache implementations.
 * @author Nils Durner
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_datacache_lib.h"

#define VERBOSE GNUNET_NO

#define ASSERT(x) do { if (! (x)) { printf("Error at %s:%d\n", __FILE__, __LINE__); goto FAILURE;} } while (0)

#define ITERATIONS 10000

static int ok;

static unsigned int found;

static int
checkIt (void *cls,
	 struct GNUNET_TIME_Absolute exp,
	 const GNUNET_HashCode * key,
         uint32_t size, 
	 const char *data, 
	 uint32_t type)
{
  if ( (size == sizeof (GNUNET_HashCode)) &&
       (0 == memcmp (data, cls, size)) )
    found++;
  return GNUNET_OK;
}


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
  struct GNUNET_TIME_Absolute exp;
  struct GNUNET_TIME_Absolute start;
  unsigned int i;
  
  ok = 0;
  h = GNUNET_DATACACHE_create (sched,
			       cfg,
			       "perfcache");

  ASSERT (NULL != h);
  exp = GNUNET_TIME_absolute_get ();
  start = exp;
  exp.value += 5 * 60 * 1000;
  memset (&k, 0, sizeof (GNUNET_HashCode));
  for (i = 0; i < ITERATIONS; i++)
    {
      if (0 == i % (ITERATIONS / 80))
	fprintf (stderr, ".");
      GNUNET_CRYPTO_hash (&k, sizeof (GNUNET_HashCode), &n);
      ASSERT (GNUNET_OK == GNUNET_DATACACHE_put (h,
						 &k,
						 sizeof (GNUNET_HashCode),
						 (const char *) &n,
						 1+i%16,
						 exp));
      k = n;
    }
  fprintf (stderr, "\n");
  fprintf (stdout, "Stored %u items in %llums\n",
	   ITERATIONS,
	   (unsigned long long) GNUNET_TIME_absolute_get_duration(start).value);
  start = GNUNET_TIME_absolute_get ();
  memset (&k, 0, sizeof (GNUNET_HashCode));
  for (i = 0; i < ITERATIONS; i++)
    {
      if (0 == i % (ITERATIONS / 80))
	fprintf (stderr, ".");
      GNUNET_CRYPTO_hash (&k, sizeof (GNUNET_HashCode), &n);
      GNUNET_DATACACHE_get (h, &k, 1+i%16,
			    &checkIt, &n);
      k = n;
    }
  fprintf (stderr, "\n");
  fprintf (stdout, "Found %u/%u items in %llums (%u were deleted during storage processing)\n",
	   found, ITERATIONS,
	   (unsigned long long) GNUNET_TIME_absolute_get_duration(start).value,
	   ITERATIONS - found);
	   
  GNUNET_DATACACHE_destroy (h);
  ASSERT (ok == 0);
  return;
FAILURE:
  if (h != NULL)
    GNUNET_DATACACHE_destroy (h);
  ok = GNUNET_SYSERR;
}


static int
check ()
{
  char *const argv[] = { "perf-datacache-api",
    "-c",
    "perf_datacache_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "perf-datacache-api", "nohelp",
                      options, &run, NULL);
  if (ok != 0)
    fprintf (stderr, "Missed some perfcases: %d\n", ok);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;
  
  GNUNET_DISK_directory_remove ("/tmp/perf-gnunetd-datacache");
  GNUNET_log_setup ("perf-datacache-api",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();

  return ret;
}

/* end of perf_datacache.c */
