/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file perf_datastore_api_iterators.c
 * @brief Profile database plugin directly, focusing on iterators.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "plugin_datastore.h"

/**
 * Target datastore size (in bytes).  Realistic sizes are
 * more like 16 GB (not the default of 16 MB); however,
 * those take too long to run them in the usual "make check"
 * sequence.  Hence the value used for shipping is tiny.
 */
#define MAX_SIZE 1024LL * 1024 * 128

#define ITERATIONS 10

/**
 * Number of put operations equivalent to 1/10th of MAX_SIZE
 */
#define PUT_10 (MAX_SIZE / 32 / 1024 / ITERATIONS)

static unsigned long long stored_bytes;

static unsigned long long stored_entries;

static unsigned long long stored_ops;

static struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_SCHEDULER_Handle *sched;

static int ok;

	     
static int
putValue (struct GNUNET_DATASTORE_PluginFunctions * api, int i, int k)
{
  char value[65536];
  size_t size;
  static GNUNET_HashCode key;
  static int ic;
  char *msg;

  /* most content is 32k */
  size = 32 * 1024;

  if (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16) == 0)  /* but some of it is less! */
    size = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 32 * 1024);
  size = size - (size & 7);     /* always multiple of 8 */

  /* generate random key */
  key.bits[0] = (unsigned int) GNUNET_TIME_absolute_get ().value;
  GNUNET_CRYPTO_hash (&key, sizeof (GNUNET_HashCode), &key);
  memset (value, i, size);
  if (i > 255)
    memset (value, i - 255, size / 2);
  value[0] = k;
  msg = NULL;
  if (GNUNET_OK != api->put (api->cls,
			     &key, 
			     size,
			     value,
			     i,
			     GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 100),
			     i,
			     GNUNET_TIME_relative_to_absolute 
			     (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
							     60 * 60 * 60 * 1000 +
							     GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 1000))),
			     &msg));
    {
      fprintf (stderr, "E: `%s'", msg);
      GNUNET_free_non_null (msg);
      return GNUNET_SYSERR;
    }
  ic++;
  stored_bytes += size;
  stored_ops++;
  stored_entries++;
  GNUNET_free (value);
  return GNUNET_OK;
}


static int
iterateDummy (void *cls,
	      void *next_cls,
	      const GNUNET_HashCode * key,
	      uint32_t size,
	      const void *data,
	      uint32_t type,
	      uint32_t priority,
	      uint32_t anonymity,
	      struct GNUNET_TIME_Absolute
	      expiration, 
	      uint64_t uid)
{
  return GNUNET_OK;
}

static int
test (struct GNUNET_DATASTORE_PluginFunctions * api)
{  
  int i;
  int j;
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Absolute end;

  /* FIXME: CPS the loop! */
  for (i = 0; i < ITERATIONS; i++)
    {
      /* insert data equivalent to 1/10th of MAX_SIZE */
      start = GNUNET_TIME_absolute_get ();
      for (j = 0; j < PUT_10; j++)
        {
          if (GNUNET_OK != putValue (api, j, i))
            break;
        }
      end = GNUNET_TIME_absolute_get ();
      printf ("%3u insertion              took %20llums\n", i,
	      (unsigned long long) (end.value - start.value));
      start = end;
      api->iter_low_priority (api->cls, 0, &iterateDummy, api);
      end = GNUNET_TIME_absolute_get ();
      printf ("%3u low priority iteration took %20llums\n", i,
              (unsigned long long) (end.value - start.value));
      start = end;
      api->iter_ascending_expiration (api->cls, 0, &iterateDummy, api);
      end = GNUNET_TIME_absolute_get ();
      printf ("%3u expiration t iteration took %20llums\n", i,
              (unsigned long long) (end.value - start.value));
      start = end;
      api->iter_zero_anonymity (api->cls, 0, &iterateDummy, api);
      end = GNUNET_TIME_absolute_get ();
      printf ("%3u non anonymou iteration took %20llums\n", i,
              (unsigned long long) (end.value - start.value));
      start = end;
      api->iter_migration_order (api->cls, 0, &iterateDummy, api);
      end = GNUNET_TIME_absolute_get ();
      printf ("%3u migration or iteration took %20llums\n", i,
              (unsigned long long) (end.value - start.value));
      start = end;
      api->iter_all_now (api->cls, 0, &iterateDummy, api);
      end = GNUNET_TIME_absolute_get ();
      printf ("%3u all now      iteration took %20llums\n", i,
              (unsigned long long) (end.value - start.value));
    }
  api->drop (api->cls);
  return GNUNET_OK;
}


/**
 * Load the datastore plugin.
 */
static struct GNUNET_DATASTORE_PluginFunctions *
load_plugin ()
{
  static struct GNUNET_DATASTORE_PluginEnvironment env;
  struct GNUNET_DATASTORE_PluginFunctions * ret; 
  char *name;
  char *libname;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "DATASTORE", "DATABASE", &name))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("No `%s' specified for `%s' in configuration!\n"),
		  "DATABASE",
		  "DATASTORE");
      return NULL;
    }
  env.cfg = cfg;
  env.sched = sched;  
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading `%s' datastore plugin\n"), name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_datastore_%s", name);
  GNUNET_assert (NULL != (ret = GNUNET_PLUGIN_load (libname, &env)));
  GNUNET_free (libname);
  GNUNET_free (name);
  return ret;
}


/**
 * Function called when the service shuts
 * down.  Unloads our datastore plugin.
 *
 * @param api api to unload
 */
static void
unload_plugin (struct GNUNET_DATASTORE_PluginFunctions * api)
{
  char *name;
  char *libname;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "DATASTORE", "DATABASE", &name))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("No `%s' specified for `%s' in configuration!\n"),
		  "DATABASE",
		  "DATASTORE");
      return;
    }
  GNUNET_asprintf (&libname, "libgnunet_plugin_datastore_%s", name);
  GNUNET_break (NULL == GNUNET_PLUGIN_unload (libname, api));
  GNUNET_free (libname);
  GNUNET_free (name);
}



/**
 * Last task run during shutdown.  Disconnects us from
 * the transport and core.
 */
static void
cleaning_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DATASTORE_PluginFunctions *api = cls;

  unload_plugin (api);
}



static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile, struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_DATASTORE_PluginFunctions *api;

  cfg = c;
  sched = s;
  api = load_plugin ();
  test(api);
  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_YES,
                                GNUNET_SCHEDULER_PRIORITY_IDLE,
                                GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &cleaning_task, api);
}


static int
check ()
{
  char *const argv[] = { "perf-datastore-api-iterators",
    "-c",
    "test_datastore_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "perf-datastore-api-iterators", "nohelp",
                      options, &run, NULL);
  if (ok != 0)
    fprintf (stderr, "Missed some testcases: %u\n", ok);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("perf-datastore-api-iterators",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();

  return ret;
}


/* end of perf_datastore_api_iterators.c */


