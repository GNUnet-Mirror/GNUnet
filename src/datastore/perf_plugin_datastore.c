/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file perf_plugin_datastore.c
 * @brief Profile database plugin directly, focusing on iterators.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "plugin_datastore.h"

#define VERBOSE GNUNET_NO

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

static const char *plugin_name;

static int ok;

enum RunPhase
  {
    RP_DONE = 0,
    RP_PUT,
    RP_LP_GET,
    RP_AE_GET,
    RP_ZA_GET,
    RP_MO_GET,
    RP_AN_GET
  };


struct CpsRunContext
{
  unsigned int i;
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Absolute end;
  struct GNUNET_SCHEDULER_Handle *sched;
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_DATASTORE_PluginFunctions * api;
  const char *msg;
  enum RunPhase phase;
  unsigned int cnt;
};


/**
 * Function called by plugins to notify us about a
 * change in their disk utilization.
 *
 * @param cls closure (NULL)
 * @param delta change in disk utilization, 
 *        0 for "reset to empty"
 */
static void
disk_utilization_change_cb (void *cls,
			    int delta)
{
}

	     
static void
putValue (struct GNUNET_DATASTORE_PluginFunctions * api, int i, int k)
{
  char value[65536];
  size_t size;
  static GNUNET_HashCode key;
  static int ic;
  char *msg;
  unsigned int prio;

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
  prio = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 100);
  if (GNUNET_OK != api->put (api->cls,
			     &key, 
			     size,
			     value,
			     i,
			     prio,
			     i,
			     GNUNET_TIME_relative_to_absolute 
			     (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
							     60 * 60 * 60 * 1000 +
							     GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 1000))),
			     &msg))
    {
      fprintf (stderr, "ERROR: `%s'\n", msg);
      GNUNET_free_non_null (msg);
      return;
    }
  ic++;
  stored_bytes += size;
  stored_ops++;
  stored_entries++;
}

static void
test (void *cls,
      const struct GNUNET_SCHEDULER_TaskContext *tc);


static int
iterateDummy (void *cls,
	      void *next_cls,
	      const GNUNET_HashCode * key,
	      uint32_t size,
	      const void *data,
	      enum GNUNET_BLOCK_Type type,
	      uint32_t priority,
	      uint32_t anonymity,
	      struct GNUNET_TIME_Absolute
	      expiration, 
	      uint64_t uid)
{
  struct CpsRunContext *crc = cls;
  
  if (key == NULL)
    {
      crc->end = GNUNET_TIME_absolute_get();
      printf (crc->msg,
	      crc->i,
	      (unsigned long long) (crc->end.value - crc->start.value),
	      crc->cnt);
      if (crc->phase != RP_AN_GET)
	{
	  crc->phase++;
	}
      else
	{
	  if (crc->i == ITERATIONS)
	    crc->phase = RP_DONE;
	  else
	    crc->phase = RP_PUT;
	}
      GNUNET_SCHEDULER_add_after (crc->sched,
				  GNUNET_SCHEDULER_NO_TASK,
				  &test, crc);
      return GNUNET_OK;
    }
#if VERBOSE
  fprintf (stderr, "Found result type=%u, priority=%u, size=%u, expire=%llu\n",
	   type, priority, size,
	   (unsigned long long) expiration.value);
#endif
  crc->cnt++;
  crc->api->next_request (next_cls,
			  GNUNET_NO);
  return GNUNET_OK;
}



/**
 * Function called when the service shuts
 * down.  Unloads our datastore plugin.
 *
 * @param api api to unload
 * @param cfg configuration to use
 */
static void
unload_plugin (struct GNUNET_DATASTORE_PluginFunctions * api,
	       const struct GNUNET_CONFIGURATION_Handle *cfg)
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
  struct CpsRunContext *crc = cls;

  unload_plugin (crc->api, crc->cfg);
  GNUNET_free (crc);
}


static void
test (void *cls,
      const struct GNUNET_SCHEDULER_TaskContext *tc)
{  
  struct CpsRunContext *crc = cls;
  int j;

  switch (crc->phase)
    {
    case RP_PUT:      
      crc->start = GNUNET_TIME_absolute_get ();
      for (j=0;j<PUT_10;j++)
	putValue (crc->api, j, crc->i);
      crc->end = GNUNET_TIME_absolute_get ();
      printf ("%3u insertion took                      %20llums for %u\n",
	      crc->i,
	      (unsigned long long) (crc->end.value - crc->start.value),
	      (unsigned int) PUT_10);
      crc->i++;
      crc->phase = RP_LP_GET;
      GNUNET_SCHEDULER_add_after (crc->sched,
				  GNUNET_SCHEDULER_NO_TASK,
				  &test, crc);
      break;
    case RP_LP_GET:
      crc->cnt = 0;
      crc->start = GNUNET_TIME_absolute_get ();      
      crc->msg = "%3u low priority iteration took         %20llums for %u\n";
      crc->api->iter_low_priority (crc->api->cls, 0, 
				   &iterateDummy,
				   crc);
      break;
    case RP_AE_GET:
      crc->cnt = 0;
      crc->start = GNUNET_TIME_absolute_get ();      
      crc->msg = "%3u ascending expiration iteration took %20llums for %u\n";
      crc->api->iter_ascending_expiration (crc->api->cls, 0, 
				      &iterateDummy,
				      crc);
      break;
    case RP_ZA_GET:
      crc->cnt = 0;
      crc->start = GNUNET_TIME_absolute_get ();      
      crc->msg = "%3u zero anonymity iteration took       %20llums for %u\n";
      crc->api->iter_zero_anonymity (crc->api->cls, 0, 
				     &iterateDummy,
				     crc);
      break;
    case RP_MO_GET:
      crc->cnt = 0;
      crc->start = GNUNET_TIME_absolute_get ();      
      crc->msg = "%3u migration order iteration took      %20llums for %u\n";
      crc->api->iter_migration_order (crc->api->cls, 0, 
				      &iterateDummy,
				      crc);
      break;
    case RP_AN_GET:
      crc->cnt = 0;
      crc->start = GNUNET_TIME_absolute_get ();      
      crc->msg = "%3u all now iteration took              %20llums for %u\n";
      crc->api->iter_all_now (crc->api->cls, 0,
			      &iterateDummy,
			      crc);
      break;
    case RP_DONE:
      crc->api->drop (crc->api->cls);
      GNUNET_SCHEDULER_add_with_priority (crc->sched,
				    GNUNET_SCHEDULER_PRIORITY_IDLE,
				    &cleaning_task, crc);
      break;
    }
}


/**
 * Load the datastore plugin.
 */
static struct GNUNET_DATASTORE_PluginFunctions *
load_plugin (const struct GNUNET_CONFIGURATION_Handle *cfg,
	     struct GNUNET_SCHEDULER_Handle *sched)
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
  env.duc = &disk_utilization_change_cb;
  env.cls = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Loading `%s' datastore plugin\n"), name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_datastore_%s", name);
  if (NULL == (ret = GNUNET_PLUGIN_load (libname, &env)))
    {
      fprintf (stderr,
	       "Failed to load plugin `%s'!\n",
	       name);
      return NULL;
    }
  GNUNET_free (libname);
  GNUNET_free (name);
  return ret;
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_DATASTORE_PluginFunctions *api;
  struct CpsRunContext *crc;

  api = load_plugin (c, s);
  if (api == NULL)
    {
      fprintf (stderr, 
	       "Could not initialize plugin, assuming database not configured. Test not run!\n");
      return;
    }
  crc = GNUNET_malloc(sizeof(struct CpsRunContext));
  crc->api = api;
  crc->sched = s;
  crc->cfg = c;
  crc->phase = RP_PUT;
  GNUNET_SCHEDULER_add_now (crc->sched,
			    &test, crc);
}


static int
check ()
{
  char cfg_name[128];
  char *const argv[] = { 
    "perf-plugin-datastore",
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

  GNUNET_snprintf (cfg_name,
		   sizeof (cfg_name),
		   "perf_plugin_datastore_data_%s.conf",
		   plugin_name);
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "perf-plugin-datastore", "nohelp",
                      options, &run, NULL);
  if (ok != 0)
    fprintf (stderr, "Missed some testcases: %u\n", ok);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;
  const char *pos;
  char dir_name[128];

  /* determine name of plugin to use */
  plugin_name = argv[0];
  while (NULL != (pos = strstr(plugin_name, "_")))
    plugin_name = pos+1;

  GNUNET_snprintf (dir_name,
		   sizeof (dir_name),
		   "/tmp/perf-gnunet-datastore-%s",
		   plugin_name);
  GNUNET_DISK_directory_remove (dir_name);
  GNUNET_log_setup ("perf-plugin-datastore",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove (dir_name);

  return ret;
}

/* end of perf_plugin_datastore.c */


