/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007, 2009, 2010 Christian Grothoff (and other contributing authors)

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

/**
 * @file datacache/datacache.c
 * @brief datacache API implementation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_datacache_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_datacache_plugin.h"

#define DEBUG_DATACACHE GNUNET_EXTRA_LOGGING

#define LOG(kind,...) GNUNET_log_from (kind, "datacache", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind,op,fn) GNUNET_log_from_strerror_file (kind, "datacache", op, fn)

/**
 * Internal state of the datacache library.
 */
struct GNUNET_DATACACHE_Handle
{

  /**
   * Bloomfilter to quickly tell if we don't have the content.
   */
  struct GNUNET_CONTAINER_BloomFilter *filter;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Opaque handle for the statistics service.
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Configuration section to use.
   */
  char *section;

  /**
   * API of the transport as returned by the plugin's
   * initialization function.
   */
  struct GNUNET_DATACACHE_PluginFunctions *api;

  /**
   * Short name for the plugin (i.e. "sqlite").
   */
  char *short_name;

  /**
   * Name of the library (i.e. "gnunet_plugin_datacache_sqlite").
   */
  char *lib_name;

  /**
   * Name for the bloom filter file.
   */
  char *bloom_name;

  /**
   * Environment provided to our plugin.
   */
  struct GNUNET_DATACACHE_PluginEnvironment env;

  /**
   * How much space is in use right now?
   */
  unsigned long long utilization;

};


/**
 * Function called by plugins to notify the datacache
 * about content deletions.
 *
 * @param cls closure
 * @param key key of the content that was deleted
 * @param size number of bytes that were made available
 */
static void
env_delete_notify (void *cls, const GNUNET_HashCode * key, size_t size)
{
  struct GNUNET_DATACACHE_Handle *h = cls;

#if DEBUG_DATACACHE
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Content under key `%s' discarded\n",
       GNUNET_h2s (key));
#endif
  GNUNET_assert (h->utilization >= size);
  h->utilization -= size;
  GNUNET_CONTAINER_bloomfilter_remove (h->filter, key);
  GNUNET_STATISTICS_update (h->stats, gettext_noop ("# bytes stored"), -size,
                            GNUNET_NO);
}


/**
 * Create a data cache.
 *
 * @param cfg configuration to use
 * @param section section in the configuration that contains our options
 * @return handle to use to access the service
 */
struct GNUNET_DATACACHE_Handle *
GNUNET_DATACACHE_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
                         const char *section)
{
  unsigned int bf_size;
  unsigned long long quota;
  struct GNUNET_DATACACHE_Handle *ret;
  char *libname;
  char *name;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_size (cfg, section, "QUOTA", &quota))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("No `%s' specified for `%s' in configuration!\n"), "QUOTA", section);
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, section, "DATABASE", &name))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("No `%s' specified for `%s' in configuration!\n"), "DATABASE",
         section);
    return NULL;
  }
  bf_size = quota / 32;         /* 8 bit per entry, 1 bit per 32 kb in DB */

  ret = GNUNET_malloc (sizeof (struct GNUNET_DATACACHE_Handle));
  ret->bloom_name = GNUNET_DISK_mktemp ("gnunet-datacachebloom");
  if (NULL != ret->bloom_name)
  {
    ret->filter = GNUNET_CONTAINER_bloomfilter_load (ret->bloom_name, quota / 1024,     /* 8 bit per entry in DB, expect 1k entries */
                                                     5);
  }
  if (NULL == ret->filter)
  {
    ret->filter = GNUNET_CONTAINER_bloomfilter_init (NULL, bf_size, 5); /* approx. 3% false positives at max use */
  }
  if (NULL == ret->filter)
  {
    GNUNET_free (name);
    GNUNET_free (ret->bloom_name);
    GNUNET_free (ret);
    return NULL;
  }
  ret->stats = GNUNET_STATISTICS_create ("datacache", cfg);
  ret->section = GNUNET_strdup (section);
  ret->env.cfg = cfg;
  ret->env.delete_notify = &env_delete_notify;
  ret->env.section = ret->section;
  ret->env.cls = ret;
  ret->env.delete_notify = &env_delete_notify;
  ret->env.quota = quota;
  LOG (GNUNET_ERROR_TYPE_INFO, _("Loading `%s' datacache plugin\n"), name);
  GNUNET_asprintf (&libname, "libgnunet_plugin_datacache_%s", name);
  ret->short_name = name;
  ret->lib_name = libname;
  ret->api = GNUNET_PLUGIN_load (libname, &ret->env);
  if (ret->api == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Failed to load datacache plugin for `%s'\n"), name);
    GNUNET_DATACACHE_destroy (ret);
    return NULL;
  }
  return ret;
}


/**
 * Destroy a data cache (and free associated resources).
 *
 * @param h handle to the datastore
 */
void
GNUNET_DATACACHE_destroy (struct GNUNET_DATACACHE_Handle *h)
{
  if (h->filter != NULL)
    GNUNET_CONTAINER_bloomfilter_free (h->filter);
  if (h->api != NULL)
    GNUNET_break (NULL == GNUNET_PLUGIN_unload (h->lib_name, h->api));
  GNUNET_free (h->lib_name);
  GNUNET_free (h->short_name);
  GNUNET_free (h->section);
  if (h->bloom_name != NULL)
  {
    if (0 != UNLINK (h->bloom_name))
      GNUNET_log_from_strerror_file (GNUNET_ERROR_TYPE_WARNING, "datacache",
                                     "unlink", h->bloom_name);
    GNUNET_free (h->bloom_name);
  }
  GNUNET_STATISTICS_destroy (h->stats, GNUNET_NO);
  GNUNET_free (h);
}


/**
 * Store an item in the datastore.
 *
 * @param h handle to the datacache
 * @param key key to store data under
 * @param size number of bytes in data
 * @param data data to store
 * @param type type of the value
 * @param discard_time when to discard the value in any case
 * @return GNUNET_OK on success, GNUNET_SYSERR on error (full, etc.)
 */
int
GNUNET_DATACACHE_put (struct GNUNET_DATACACHE_Handle *h,
                      const GNUNET_HashCode * key, size_t size,
                      const char *data, enum GNUNET_BLOCK_Type type,
                      struct GNUNET_TIME_Absolute discard_time)
{
  uint32_t used;

  used = h->api->put (h->api->cls, key, size, data, type, discard_time);
  if (used == 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
#if DEBUG_DATACACHE
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Stored data under key `%s' in cache\n",
       GNUNET_h2s (key));
#endif
  GNUNET_STATISTICS_update (h->stats, gettext_noop ("# bytes stored"), size,
                            GNUNET_NO);
  GNUNET_CONTAINER_bloomfilter_add (h->filter, key);
  while (h->utilization + used > h->env.quota)
    GNUNET_assert (GNUNET_OK == h->api->del (h->api->cls));
  h->utilization += used;
  return GNUNET_OK;
}


/**
 * Iterate over the results for a particular key
 * in the datacache.
 *
 * @param h handle to the datacache
 * @param key what to look up
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for iter
 * @return the number of results found
 */
unsigned int
GNUNET_DATACACHE_get (struct GNUNET_DATACACHE_Handle *h,
                      const GNUNET_HashCode * key, enum GNUNET_BLOCK_Type type,
                      GNUNET_DATACACHE_Iterator iter, void *iter_cls)
{
  GNUNET_STATISTICS_update (h->stats, gettext_noop ("# requests received"), 1,
                            GNUNET_NO);
#if DEBUG_DATACACHE
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Processing request for key `%s'\n",
       GNUNET_h2s (key));
#endif
  if (GNUNET_OK != GNUNET_CONTAINER_bloomfilter_test (h->filter, key))
  {
    GNUNET_STATISTICS_update (h->stats,
                              gettext_noop
                              ("# requests filtered by bloom filter"), 1,
                              GNUNET_NO);
#if DEBUG_DATACACHE
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Bloomfilter filters request for key `%s'\n",
         GNUNET_h2s (key));
#endif
    return 0;                   /* can not be present */
  }
  return h->api->get (h->api->cls, key, type, iter, iter_cls);
}



/* end of datacache_api.c */
