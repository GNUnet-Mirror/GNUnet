/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2009, 2010 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/
/*
 * @file datacache/test_datacache_quota.c
 * @brief Test for the quota code of the datacache implementations.
 * @author Nils Durner
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_datacache_lib.h"
#include "gnunet_testing_lib.h"

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
  struct GNUNET_HashCode k;
  struct GNUNET_HashCode n;
  char buf[3200];
  struct GNUNET_TIME_Absolute exp;

  ok = 0;
  h = GNUNET_DATACACHE_create (cfg, "testcache");

  if (h == NULL)
  {
    FPRINTF (stderr,
             "%s",
             "Failed to initialize datacache.  Database likely not setup, skipping test.\n");
    return;
  }
  exp = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_HOURS);
  memset (buf, 1, sizeof (buf));
  memset (&k, 0, sizeof (struct GNUNET_HashCode));
  for (unsigned int i = 0; i < 10; i++)
  {
    FPRINTF (stderr,
             "%s",
             ".");
    GNUNET_CRYPTO_hash (&k,
                        sizeof (struct GNUNET_HashCode),
                        &n);
    for (unsigned int j = i; j < sizeof (buf); j += 10)
    {
      exp.abs_value_us++;
      buf[j] = i;
      ASSERT (GNUNET_OK ==
              GNUNET_DATACACHE_put (h,
                                    &k,
                                    GNUNET_YES,
                                    j,
                                    buf,
                                    1 + i,
                                    exp,
                                    0,
                                    NULL));
      ASSERT (0 < GNUNET_DATACACHE_get (h, &k, 1 + i, NULL, NULL));
    }
    k = n;
  }
  FPRINTF (stderr, "%s",  "\n");
  memset (&k, 0, sizeof (struct GNUNET_HashCode));
  for (unsigned int i = 0; i < 10; i++)
  {
    FPRINTF (stderr, "%s",  ".");
    GNUNET_CRYPTO_hash (&k, sizeof (struct GNUNET_HashCode), &n);
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
  char cfg_name[128];
  char *const xargv[] = {
    "test-datacache-quota",
    "-c",
    cfg_name,
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_log_setup ("test-datacache-quota",
                    "WARNING",
                    NULL);

  plugin_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  GNUNET_snprintf (cfg_name, sizeof (cfg_name), "test_datacache_data_%s.conf",
                   plugin_name);
  GNUNET_PROGRAM_run ((sizeof (xargv) / sizeof (char *)) - 1, xargv,
                      "test-datacache-quota", "nohelp", options, &run, NULL);
  if (0 != ok)
    FPRINTF (stderr, "Missed some testcases: %d\n", ok);
  return ok;
}

/* end of test_datacache_quota.c */
