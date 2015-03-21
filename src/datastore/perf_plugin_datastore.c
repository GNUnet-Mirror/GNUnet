/*
     This file is part of GNUnet.
     Copyright (C) 2004, 2005, 2006, 2007, 2009, 2011 Christian Grothoff (and other contributing authors)

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
#include "gnunet_datastore_plugin.h"
#include "gnunet_testing_lib.h"
#include <gauger.h>

/**
 * Target datastore size (in bytes).  Realistic sizes are
 * more like 16 GB (not the default of 16 MB); however,
 * those take too long to run them in the usual "make check"
 * sequence.  Hence the value used for shipping is tiny.
 */
#define MAX_SIZE 1024LL * 1024 * 16 * 1

#define ITERATIONS 2

/**
 * Number of put operations equivalent to 1/10th of MAX_SIZE
 */
#define PUT_10 (MAX_SIZE / 32 / 1024 / ITERATIONS)

static char category[256];

static unsigned int hits[PUT_10 / 8 + 1];

static unsigned long long stored_bytes;

static unsigned long long stored_entries;

static unsigned long long stored_ops;

static const char *plugin_name;

static int ok;

enum RunPhase
{
  RP_ERROR = 0,
  RP_PUT,
  RP_REP_GET,
  RP_ZA_GET,
  RP_EXP_GET,
  RP_DONE
};


struct CpsRunContext
{
  unsigned int i;
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Absolute end;
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_DATASTORE_PluginFunctions *api;
  enum RunPhase phase;
  unsigned int cnt;
  unsigned int iter;
  uint64_t offset;
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
disk_utilization_change_cb (void *cls, int delta)
{
}


static void
test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
put_continuation (void *cls, const struct GNUNET_HashCode *key,
                  uint32_t size, int status, char *msg)
{
  struct CpsRunContext *crc = cls;

  if (GNUNET_OK != status)
  {
    FPRINTF (stderr, "ERROR: `%s'\n", msg);
  }
  else
  {
    stored_bytes += size;
    stored_ops++;
    stored_entries++;
  }
  GNUNET_SCHEDULER_add_now (&test, crc);
}

static void
do_put (struct CpsRunContext *crc)
{
  char value[65536];
  size_t size;
  static struct GNUNET_HashCode key;
  static int i;
  unsigned int prio;

  if (0 == i)
    crc->start = GNUNET_TIME_absolute_get ();
  if (PUT_10 == i)
  {
    i = 0;
    crc->end = GNUNET_TIME_absolute_get ();
    {
      printf ("%s took %s for %llu items\n", "Storing an item",
	      GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_difference (crc->start,
											   crc->end),
						      GNUNET_YES),
              PUT_10);
      if (PUT_10 > 0)
        GAUGER (category, "Storing an item",
                (crc->end.abs_value_us - crc->start.abs_value_us) / 1000LL / PUT_10,
                "ms/item");
    }
    crc->i++;
    crc->start = GNUNET_TIME_absolute_get ();
    crc->phase++;
    GNUNET_SCHEDULER_add_now (&test, crc);
    return;
  }
  /* most content is 32k */
  size = 32 * 1024;
  if (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16) == 0)   /* but some of it is less! */
    size = 8 + GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 32 * 1024);
  size = size - (size & 7);     /* always multiple of 8 */

  /* generate random key */
  key.bits[0] = (unsigned int) GNUNET_TIME_absolute_get ().abs_value_us;
  GNUNET_CRYPTO_hash (&key, sizeof (struct GNUNET_HashCode), &key);
  memset (value, i, size);
  if (i > 255)
    memset (value, i - 255, size / 2);
  value[0] = crc->i;
  memcpy (&value[4], &i, sizeof (i));
  prio = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 100);
  crc->api->put (crc->api->cls, &key, size, value, 1 + i % 4 /* type */ ,
                 prio, i % 4 /* anonymity */ ,
                 0 /* replication */ ,
                 GNUNET_TIME_relative_to_absolute
                 (GNUNET_TIME_relative_multiply
                   (GNUNET_TIME_UNIT_MILLISECONDS,
                    60 * 60 * 60 * 1000 +
                    GNUNET_CRYPTO_random_u32
                      (GNUNET_CRYPTO_QUALITY_WEAK, 1000))),
                 put_continuation, crc);
  i++;
}


static int
iterate_zeros (void *cls, const struct GNUNET_HashCode * key, uint32_t size,
               const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
               uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
               uint64_t uid)
{
  struct CpsRunContext *crc = cls;
  int i;
  const char *cdata = data;

  GNUNET_assert (key != NULL);
  GNUNET_assert (size >= 8);
  memcpy (&i, &cdata[4], sizeof (i));
  hits[i / 8] |= (1 << (i % 8));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Found result %d type=%u, priority=%u, size=%u, expire=%s\n",
	      i,
	      type, priority, size,
	      GNUNET_STRINGS_absolute_time_to_string (expiration));
  crc->cnt++;
  if (crc->cnt == PUT_10 / 4 - 1)
  {
    unsigned int bc;

    bc = 0;
    for (i = 0; i < PUT_10; i++)
      if (0 != (hits[i / 8] & (1 << (i % 8))))
        bc++;

    crc->end = GNUNET_TIME_absolute_get ();
    printf ("%s took %s yielding %u/%u items\n",
            "Select random zero-anonymity item",
            GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_difference (crc->start,
											 crc->end),
						    GNUNET_YES),
            bc, crc->cnt);
    if (crc->cnt > 0)
      GAUGER (category, "Select random zero-anonymity item",
              (crc->end.abs_value_us - crc->start.abs_value_us) / 1000LL / crc->cnt,
              "ms/item");
    memset (hits, 0, sizeof (hits));
    crc->phase++;
    crc->cnt = 0;
    crc->start = GNUNET_TIME_absolute_get ();
  }
  GNUNET_SCHEDULER_add_now (&test, crc);
  return GNUNET_OK;
}


static int
expiration_get (void *cls, const struct GNUNET_HashCode * key, uint32_t size,
                const void *data, enum GNUNET_BLOCK_Type type,
                uint32_t priority, uint32_t anonymity,
                struct GNUNET_TIME_Absolute expiration, uint64_t uid)
{
  struct CpsRunContext *crc = cls;
  int i;
  const char *cdata = data;

  GNUNET_assert (size >= 8);
  memcpy (&i, &cdata[4], sizeof (i));
  hits[i / 8] |= (1 << (i % 8));
  crc->cnt++;
  if (PUT_10 <= crc->cnt)
  {
    unsigned int bc;

    bc = 0;
    for (i = 0; i < PUT_10; i++)
      if (0 != (hits[i / 8] & (1 << (i % 8))))
        bc++;

    crc->end = GNUNET_TIME_absolute_get ();
    printf ("%s took %s yielding %u/%u items\n",
            "Selecting and deleting by expiration",
            GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_difference (crc->start,
											 crc->end),
						    GNUNET_YES),
            bc, (unsigned int) PUT_10);
    if (crc->cnt > 0)
      GAUGER (category, "Selecting and deleting by expiration",
              (crc->end.abs_value_us - crc->start.abs_value_us) / 1000LL / crc->cnt,
              "ms/item");
    memset (hits, 0, sizeof (hits));
    if (++crc->iter == ITERATIONS)
      crc->phase++;
    else
      crc->phase = RP_PUT;
    crc->cnt = 0;
    crc->start = GNUNET_TIME_absolute_get ();
  }
  GNUNET_SCHEDULER_add_now (&test, crc);
  return GNUNET_NO;
}


static int
replication_get (void *cls, const struct GNUNET_HashCode * key, uint32_t size,
                 const void *data, enum GNUNET_BLOCK_Type type,
                 uint32_t priority, uint32_t anonymity,
                 struct GNUNET_TIME_Absolute expiration, uint64_t uid)
{
  struct CpsRunContext *crc = cls;
  int i;
  const char *cdata = data;

  GNUNET_assert (NULL != key);
  GNUNET_assert (size >= 8);
  memcpy (&i, &cdata[4], sizeof (i));
  hits[i / 8] |= (1 << (i % 8));
  crc->cnt++;
  if (PUT_10 <= crc->cnt)
  {
    unsigned int bc;

    bc = 0;
    for (i = 0; i < PUT_10; i++)
      if (0 != (hits[i / 8] & (1 << (i % 8))))
        bc++;

    crc->end = GNUNET_TIME_absolute_get ();
    printf ("%s took %s yielding %u/%u items\n",
            "Selecting random item for replication",
            GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_difference (crc->start,
											 crc->end),
						    GNUNET_YES),
            bc, (unsigned int) PUT_10);
    if (crc->cnt > 0)
      GAUGER (category, "Selecting random item for replication",
              (crc->end.abs_value_us - crc->start.abs_value_us) / 1000LL / crc->cnt,
              "ms/item");
    memset (hits, 0, sizeof (hits));
    crc->phase++;
    crc->offset = 0;
    crc->cnt = 0;
    crc->start = GNUNET_TIME_absolute_get ();
  }

  GNUNET_SCHEDULER_add_now (&test, crc);
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
unload_plugin (struct GNUNET_DATASTORE_PluginFunctions *api,
               const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *name;
  char *libname;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "DATASTORE", "DATABASE",
                                             &name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("No `%s' specified for `%s' in configuration!\n"), "DATABASE",
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
test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CpsRunContext *crc = cls;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    GNUNET_break (0);
    crc->phase = RP_ERROR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "In phase %d, iteration %u\n", crc->phase, crc->cnt);
  switch (crc->phase)
  {
  case RP_ERROR:
    GNUNET_break (0);
    crc->api->drop (crc->api->cls);
    ok = 1;
    GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
                                        &cleaning_task, crc);
    break;
  case RP_PUT:
    do_put (crc);
    break;
  case RP_REP_GET:
    crc->api->get_replication (crc->api->cls, &replication_get, crc);
    break;
  case RP_ZA_GET:
    crc->api->get_zero_anonymity (crc->api->cls, crc->offset++, 1,
                                  &iterate_zeros, crc);
    break;
  case RP_EXP_GET:
    crc->api->get_expiration (crc->api->cls, &expiration_get, crc);
    break;
  case RP_DONE:
    crc->api->drop (crc->api->cls);
    ok = 0;
    GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
                                        &cleaning_task, crc);
    break;
  }
}


/**
 * Load the datastore plugin.
 */
static struct GNUNET_DATASTORE_PluginFunctions *
load_plugin (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static struct GNUNET_DATASTORE_PluginEnvironment env;
  struct GNUNET_DATASTORE_PluginFunctions *ret;
  char *name;
  char *libname;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "DATASTORE", "DATABASE",
                                             &name))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("No `%s' specified for `%s' in configuration!\n"), "DATABASE",
                "DATASTORE");
    return NULL;
  }
  env.cfg = cfg;
  env.duc = &disk_utilization_change_cb;
  env.cls = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Loading `%s' datastore plugin\n"),
              name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_datastore_%s", name);
  if (NULL == (ret = GNUNET_PLUGIN_load (libname, &env)))
  {
    FPRINTF (stderr, "Failed to load plugin `%s'!\n", name);
    GNUNET_free (name);
    GNUNET_free (libname);
    return NULL;
  }
  GNUNET_free (libname);
  GNUNET_free (name);
  return ret;
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_DATASTORE_PluginFunctions *api;
  struct CpsRunContext *crc;

  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }
  api = load_plugin (c);
  if (api == NULL)
  {
    FPRINTF (stderr,
             "%s", "Could not initialize plugin, assuming database not configured. Test not run!\n");
    return;
  }
  crc = GNUNET_new (struct CpsRunContext);
  crc->api = api;
  crc->cfg = c;
  crc->phase = RP_PUT;
  ok = 2;
  GNUNET_SCHEDULER_add_now (&test, crc);
}


int
main (int argc, char *argv[])
{
  char dir_name[128];
  char cfg_name[128];
  char *const xargv[] = {
    "perf-plugin-datastore",
    "-c",
    cfg_name,
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  plugin_name = GNUNET_TESTING_get_testname_from_underscore (argv[0]);
  GNUNET_snprintf (dir_name, sizeof (dir_name), "/tmp/perf-gnunet-datastore-%s",
                   plugin_name);
  GNUNET_DISK_directory_remove (dir_name);
  GNUNET_log_setup ("perf-plugin-datastore",
                    "WARNING",
                    NULL);
  GNUNET_snprintf (category, sizeof (category), "DATASTORE-%s", plugin_name);
  GNUNET_snprintf (cfg_name, sizeof (cfg_name),
                   "perf_plugin_datastore_data_%s.conf", plugin_name);
  GNUNET_PROGRAM_run ((sizeof (xargv) / sizeof (char *)) - 1, xargv,
                      "perf-plugin-datastore", "nohelp", options, &run, NULL);
  if (ok != 0)
    FPRINTF (stderr, "Missed some testcases: %u\n", ok);
  GNUNET_DISK_directory_remove (dir_name);

  return ok;
}

/* end of perf_plugin_datastore.c */
