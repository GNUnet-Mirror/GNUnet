/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file test_plugin_datastore.c
 * @brief Test database plugin directly, calling each API function once
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_datastore_plugin.h"

#define VERBOSE GNUNET_NO

/**
 * Number of put operations to perform.
 */
#define PUT_10 10

static unsigned long long stored_bytes;

static unsigned long long stored_entries;

static unsigned long long stored_ops;

static const char *plugin_name;

static int ok;

enum RunPhase
{
  RP_ERROR = 0,
  RP_PUT,
  RP_GET,
  RP_UPDATE,
  RP_ITER_ZERO,
  RP_REPL_GET,
  RP_EXPI_GET,
  RP_DROP
};


struct CpsRunContext
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_DATASTORE_PluginFunctions *api;
  enum RunPhase phase;
  unsigned int cnt;
  unsigned int i;
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
  /* do nothing */
}


static void
gen_key (int i, GNUNET_HashCode * key)
{
  memset (key, 0, sizeof (GNUNET_HashCode));
  key->bits[0] = (unsigned int) i;
  GNUNET_CRYPTO_hash (key, sizeof (GNUNET_HashCode), key);
}


static void
put_value (struct GNUNET_DATASTORE_PluginFunctions *api, int i, int k)
{
  char value[65536];
  size_t size;
  GNUNET_HashCode key;
  char *msg;
  unsigned int prio;

  /* most content is 32k */
  size = 32 * 1024;

  if (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 16) == 0)   /* but some of it is less! */
    size = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 32 * 1024);
  size = size - (size & 7);     /* always multiple of 8 */

  /* generate random key */
  gen_key (i, &key);
  memset (value, i, size);
  if (i > 255)
    memset (value, i - 255, size / 2);
  value[0] = k;
  msg = NULL;
  prio = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 100);
#if VERBOSE
  FPRINTF (stderr, "putting type %u, anon %u under key %s\n", i + 1, i,
           GNUNET_h2s (&key));
#endif
  if (GNUNET_OK != api->put (api->cls, &key, size, value, i + 1 /* type */ ,
                             prio, i /* anonymity */ ,
                             0 /* replication */ ,
                             GNUNET_TIME_relative_to_absolute
                             (GNUNET_TIME_relative_multiply
                              (GNUNET_TIME_UNIT_MILLISECONDS,
                               60 * 60 * 60 * 1000 +
                               GNUNET_CRYPTO_random_u32
                               (GNUNET_CRYPTO_QUALITY_WEAK, 1000))), &msg))
  {
    FPRINTF (stderr, "ERROR: `%s'\n", msg);
    GNUNET_free_non_null (msg);
    return;
  }
  stored_bytes += size;
  stored_ops++;
  stored_entries++;
}


static void
test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


static uint64_t guid;


static int
iterate_one_shot (void *cls, const GNUNET_HashCode * key, uint32_t size,
                  const void *data, enum GNUNET_BLOCK_Type type,
                  uint32_t priority, uint32_t anonymity,
                  struct GNUNET_TIME_Absolute expiration, uint64_t uid)
{
  struct CpsRunContext *crc = cls;

  GNUNET_assert (key != NULL);
  guid = uid;
  crc->phase++;
#if VERBOSE
  FPRINTF (stderr,
           "Found result type=%u, priority=%u, size=%u, expire=%llu, key %s\n",
           type, priority, size, (unsigned long long) expiration.abs_value,
           GNUNET_h2s (key));
#endif
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
  int j;
  unsigned long long os;
  unsigned long long cs;
  GNUNET_HashCode key;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Test aborted.\n");
    crc->phase = RP_ERROR;
  }
#if VERBOSE
  FPRINTF (stderr, "In phase %d, iteration %u\n", crc->phase, crc->cnt);
#endif
  switch (crc->phase)
  {
  case RP_ERROR:
    ok = 1;
    GNUNET_break (0);
    crc->api->drop (crc->api->cls);
    GNUNET_SCHEDULER_add_now (&cleaning_task, crc);
    break;
  case RP_PUT:
    os = 0;
    for (j = 0; j < PUT_10; j++)
    {
      put_value (crc->api, j, crc->i);
      cs = crc->api->estimate_size (crc->api->cls);
      GNUNET_assert (os <= cs);
      os = cs;
    }
    crc->phase++;
    GNUNET_SCHEDULER_add_now (&test, crc);
    break;
  case RP_GET:
    if (crc->cnt == 1)
    {
      crc->cnt = 0;
      crc->phase++;
      GNUNET_SCHEDULER_add_now (&test, crc);
      break;
    }
    gen_key (5, &key);
    crc->api->get_key (crc->api->cls, crc->offset++, &key, NULL,
                       GNUNET_BLOCK_TYPE_ANY, &iterate_one_shot, crc);
    break;
  case RP_UPDATE:
    GNUNET_assert (GNUNET_OK ==
                   crc->api->update (crc->api->cls, guid, 1,
                                     GNUNET_TIME_UNIT_ZERO_ABS, NULL));
    crc->phase++;
    GNUNET_SCHEDULER_add_now (&test, crc);
    break;

  case RP_ITER_ZERO:
    if (crc->cnt == 1)
    {
      crc->cnt = 0;
      crc->phase++;
      GNUNET_SCHEDULER_add_now (&test, crc);
      break;
    }
    crc->api->get_zero_anonymity (crc->api->cls, 0, 1, &iterate_one_shot, crc);
    break;
  case RP_REPL_GET:
    crc->api->get_replication (crc->api->cls, &iterate_one_shot, crc);
    break;
  case RP_EXPI_GET:
    crc->api->get_expiration (crc->api->cls, &iterate_one_shot, crc);
    break;
  case RP_DROP:
    crc->api->drop (crc->api->cls);
    GNUNET_SCHEDULER_add_now (&cleaning_task, crc);
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

  api = load_plugin (c);
  if (api == NULL)
  {
    FPRINTF (stderr,
             "%s", "Could not initialize plugin, assuming database not configured. Test not run!\n");
    return;
  }
  crc = GNUNET_malloc (sizeof (struct CpsRunContext));
  crc->api = api;
  crc->cfg = c;
  crc->phase = RP_PUT;
  GNUNET_SCHEDULER_add_now (&test, crc);
}


static int
check ()
{
  char cfg_name[128];

  char *const argv[] = {
    "test-plugin-datastore",
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

  GNUNET_snprintf (cfg_name, sizeof (cfg_name),
                   "test_plugin_datastore_data_%s.conf", plugin_name);
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-plugin-datastore", "nohelp", options, &run, NULL);
  if (ok != 0)
    FPRINTF (stderr, "Missed some testcases: %u\n", ok);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;
  char *pos;
  char dir_name[128];

  sleep (1);
  /* determine name of plugin to use */
  plugin_name = argv[0];
  while (NULL != (pos = strstr (plugin_name, "_")))
    plugin_name = pos + 1;
  if (NULL != (pos = strstr (plugin_name, ".")))
    pos[0] = 0;
  else
    pos = (char *) plugin_name;

  GNUNET_snprintf (dir_name, sizeof (dir_name),
                   "/tmp/test-gnunet-datastore-plugin-%s", plugin_name);
  GNUNET_DISK_directory_remove (dir_name);
  GNUNET_log_setup ("test-plugin-datastore",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  if (pos != plugin_name)
    pos[0] = '.';
  GNUNET_DISK_directory_remove (dir_name);

  return ret;
}

/* end of test_plugin_datastore.c */
