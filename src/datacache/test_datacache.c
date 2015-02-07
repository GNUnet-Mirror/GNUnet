/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file datacache/test_datacache.c
 * @brief Test for the datacache implementations.
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


static int
checkIt (void *cls,
         const struct GNUNET_HashCode *key,
	 size_t size, const char *data,
         enum GNUNET_BLOCK_Type type,
	 struct GNUNET_TIME_Absolute exp,
	 unsigned int path_len,
	 const struct GNUNET_PeerIdentity *path)
{
  if (size != sizeof (struct GNUNET_HashCode))
  {
    GNUNET_break (0);
    ok = 2;
  }
  if (0 != memcmp (data, cls, size))
  {
    GNUNET_break (0);
    ok = 3;
  }
  return GNUNET_OK;
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_DATACACHE_Handle *h;
  struct GNUNET_HashCode k;
  struct GNUNET_HashCode n;
  struct GNUNET_TIME_Absolute exp;
  unsigned int i;

  ok = 0;
  h = GNUNET_DATACACHE_create (cfg, "testcache");
  if (h == NULL)
  {
    FPRINTF (stderr,
             "%s",
	     "Failed to initialize datacache.  Database likely not setup, skipping test.\n");
    return;
  }
  exp = GNUNET_TIME_absolute_get ();
  exp.abs_value_us += 5 * 60 * 1000 * 1000LL;
  memset (&k, 0, sizeof (struct GNUNET_HashCode));
  for (i = 0; i < 100; i++)
  {
    GNUNET_CRYPTO_hash (&k, sizeof (struct GNUNET_HashCode), &n);
    ASSERT (GNUNET_OK ==
            GNUNET_DATACACHE_put (h, &k, sizeof (struct GNUNET_HashCode),
                                  (const char *) &n, 1 + i % 16, exp,
				  0, NULL));
    k = n;
  }
  memset (&k, 0, sizeof (struct GNUNET_HashCode));
  for (i = 0; i < 100; i++)
  {
    GNUNET_CRYPTO_hash (&k, sizeof (struct GNUNET_HashCode), &n);
    ASSERT (1 == GNUNET_DATACACHE_get (h, &k, 1 + i % 16, &checkIt, &n));
    k = n;
  }

  memset (&k, 42, sizeof (struct GNUNET_HashCode));
  GNUNET_CRYPTO_hash (&k, sizeof (struct GNUNET_HashCode), &n);
  ASSERT (GNUNET_OK ==
          GNUNET_DATACACHE_put (h, &k, sizeof (struct GNUNET_HashCode),
                                (const char *) &n, 792,
                                GNUNET_TIME_UNIT_FOREVER_ABS,
				0, NULL));
  ASSERT (0 != GNUNET_DATACACHE_get (h, &k, 792, &checkIt, &n));

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
  char cfg_name[128];
  char *const xargv[] = {
    "test-datacache",
    "-c",
    cfg_name,
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_log_setup ("test-datacache",
                    "WARNING",
                    NULL);
  plugin_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  GNUNET_snprintf (cfg_name, sizeof (cfg_name), "test_datacache_data_%s.conf",
                   plugin_name);
  GNUNET_PROGRAM_run ((sizeof (xargv) / sizeof (char *)) - 1, xargv,
                      "test-datacache", "nohelp", options, &run, NULL);
  if (0 != ok)
    FPRINTF (stderr, "Missed some testcases: %d\n", ok);
  return ok;
}

/* end of test_datacache.c */
