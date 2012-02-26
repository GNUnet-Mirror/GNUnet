/*
     This file is part of GNUnet.
     (C) 2006, 2009, 2010 Christian Grothoff (and other contributing authors)

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
/*
 * @file datacache/perf_datacache.c
 * @brief Performance evaluation for the datacache implementations.
 * @author Nils Durner
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_datacache_lib.h"
#include <gauger.h>

#define VERBOSE GNUNET_NO

#define ASSERT(x) do { if (! (x)) { printf("Error at %s:%d\n", __FILE__, __LINE__); goto FAILURE;} } while (0)

#define ITERATIONS 10000

static int ok;

static unsigned int found;

/**
 * Name of plugin under test.
 */
static const char *plugin_name;


static int
checkIt (void *cls, struct GNUNET_TIME_Absolute exp,
         const GNUNET_HashCode * key, size_t size, const char *data,
         enum GNUNET_BLOCK_Type type)
{
  if ((size == sizeof (GNUNET_HashCode)) && (0 == memcmp (data, cls, size)))
    found++;
  return GNUNET_OK;
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_DATACACHE_Handle *h;
  GNUNET_HashCode k;
  GNUNET_HashCode n;
  struct GNUNET_TIME_Absolute exp;
  struct GNUNET_TIME_Absolute start;
  unsigned int i;
  char gstr[128];

  ok = 0;
  h = GNUNET_DATACACHE_create (cfg, "perfcache");

  if (h == NULL)
  {
    FPRINTF (stderr, "%s", "Failed to initialize datacache.  Database likely not setup, skipping test.\n");
    return;
  }
  exp = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_HOURS);
  start = GNUNET_TIME_absolute_get ();
  memset (&k, 0, sizeof (GNUNET_HashCode));
  for (i = 0; i < ITERATIONS; i++)
  {
    if (0 == i % (ITERATIONS / 80))
      FPRINTF (stderr, "%s",  ".");
    GNUNET_CRYPTO_hash (&k, sizeof (GNUNET_HashCode), &n);
    ASSERT (GNUNET_OK ==
            GNUNET_DATACACHE_put (h, &k, sizeof (GNUNET_HashCode),
                                  (const char *) &n, 1 + i % 16, exp));
    k = n;
  }
  FPRINTF (stderr, "%s",  "\n");
  FPRINTF (stdout, "Stored %u items in %llums\n", ITERATIONS,
           (unsigned long long)
           GNUNET_TIME_absolute_get_duration (start).rel_value);
  GNUNET_snprintf (gstr, sizeof (gstr), "DATACACHE-%s", plugin_name);
  GAUGER (gstr, "Time to PUT item in datacache",
          GNUNET_TIME_absolute_get_duration (start).rel_value / ITERATIONS,
          "ms/item");
  start = GNUNET_TIME_absolute_get ();
  memset (&k, 0, sizeof (GNUNET_HashCode));
  for (i = 0; i < ITERATIONS; i++)
  {
    if (0 == i % (ITERATIONS / 80))
      FPRINTF (stderr, "%s",  ".");
    GNUNET_CRYPTO_hash (&k, sizeof (GNUNET_HashCode), &n);
    GNUNET_DATACACHE_get (h, &k, 1 + i % 16, &checkIt, &n);
    k = n;
  }
  FPRINTF (stderr, "%s",  "\n");
  FPRINTF (stdout,
           "Found %u/%u items in %llums (%u were deleted during storage processing)\n",
           found, ITERATIONS,
           (unsigned long long)
           GNUNET_TIME_absolute_get_duration (start).rel_value,
           ITERATIONS - found);
  if (found > 0)
    GAUGER (gstr, "Time to GET item from datacache",
            GNUNET_TIME_absolute_get_duration (start).rel_value / found,
            "ms/item");
  GNUNET_DATACACHE_destroy (h);
  ASSERT (ok == 0);
  return;
FAILURE:
  if (h != NULL)
    GNUNET_DATACACHE_destroy (h);
  ok = GNUNET_SYSERR;
}


int
main (int argc, char *argv[])
{
  char *pos;
  char cfg_name[128];

  char *const xargv[] = {
    "perf-datacache",
    "-c",
    cfg_name,
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_log_setup ("perf-datacache",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  /* determine name of plugin to use */
  plugin_name = argv[0];
  while (NULL != (pos = strstr (plugin_name, "_")))
    plugin_name = pos + 1;
  if (NULL != (pos = strstr (plugin_name, ".")))
    pos[0] = 0;
  else
    pos = (char *) plugin_name;

  GNUNET_snprintf (cfg_name, sizeof (cfg_name), "perf_datacache_data_%s.conf",
                   plugin_name);
  if (pos != plugin_name)
    pos[0] = '.';
  GNUNET_PROGRAM_run ((sizeof (xargv) / sizeof (char *)) - 1, xargv,
                      "perf-datacache", "nohelp", options, &run, NULL);
  if (ok != 0)
    FPRINTF (stderr, "Missed some perfcases: %d\n", ok);
  return ok;
}

/* end of perf_datacache.c */
