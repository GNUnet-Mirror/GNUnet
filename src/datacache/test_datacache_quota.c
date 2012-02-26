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
 * Name of plugin under test.
 */
static const char *plugin_name;

/**
 * Quota is 1 MB.  Each iteration of the test puts in about 1 MB of
 * data.  We do 10 iterations. Afterwards we check that the data from
 * the first 5 iterations has all been discarded and that at least
 * some of the data from the last iteration is still there.
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
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
  h = GNUNET_DATACACHE_create (cfg, "testcache");

  if (h == NULL)
  {
    FPRINTF (stderr, "%s", "Failed to initialize datacache.  Database likely not setup, skipping test.\n");
    return;
  }
  exp = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_HOURS);
  memset (buf, 1, sizeof (buf));
  memset (&k, 0, sizeof (GNUNET_HashCode));
  for (i = 0; i < 10; i++)
  {
    FPRINTF (stderr, "%s",  ".");
    GNUNET_CRYPTO_hash (&k, sizeof (GNUNET_HashCode), &n);
    for (j = i; j < sizeof (buf); j += 10)
    {
      exp.abs_value++;
      buf[j] = i;
      ASSERT (GNUNET_OK == GNUNET_DATACACHE_put (h, &k, j, buf, 1 + i, exp));
      ASSERT (0 < GNUNET_DATACACHE_get (h, &k, 1 + i, NULL, NULL));
    }
    k = n;
  }
  FPRINTF (stderr, "%s",  "\n");
  memset (&k, 0, sizeof (GNUNET_HashCode));
  for (i = 0; i < 10; i++)
  {
    FPRINTF (stderr, "%s",  ".");
    GNUNET_CRYPTO_hash (&k, sizeof (GNUNET_HashCode), &n);
    if (i < 2)
      ASSERT (0 == GNUNET_DATACACHE_get (h, &k, 1 + i, NULL, NULL));
    if (i == 9)
      ASSERT (0 < GNUNET_DATACACHE_get (h, &k, 1 + i, NULL, NULL));
    k = n;
  }
  FPRINTF (stderr, "%s",  "\n");
  GNUNET_DATACACHE_destroy (h);
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
    "test-datacache-quota",
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

  GNUNET_log_setup ("test-datacache-quota",
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

  GNUNET_snprintf (cfg_name, sizeof (cfg_name), "test_datacache_data_%s.conf",
                   plugin_name);
  if (pos != plugin_name)
    pos[0] = '.';
  GNUNET_PROGRAM_run ((sizeof (xargv) / sizeof (char *)) - 1, xargv,
                      "test-datacache-quota", "nohelp", options, &run, NULL);
  if (ok != 0)
    FPRINTF (stderr, "Missed some testcases: %d\n", ok);
  return ok;
}

/* end of test_datacache_quota.c */
