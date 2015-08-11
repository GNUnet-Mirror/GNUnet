 /*
  * This file is part of GNUnet
  * Copyright (C) 2009-2015 Christian Grothoff (and other contributing authors)
  *
  * GNUnet is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published
  * by the Free Software Foundation; either version 3, or (at your
  * option) any later version.
  *
  * GNUnet is distributed in the hope that it will be useful, but
  * WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  * General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with GNUnet; see the file COPYING.  If not, write to the
  * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  * Boston, MA 02110-1301, USA.
  */

/**
 * @file namecache/plugin_namecache_flat.c
 * @brief flat file-based namecache backend
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_namecache_plugin.h"
#include "gnunet_namecache_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "namecache.h"

/**
 * Context for all functions in this plugin.
 */
struct Plugin
{

  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Database filename.
   */
  char *fn;
  
  /**
   * HashMap
   */
  struct GNUNET_CONTAINER_MultiHashMap *hm;

};

struct FlatFileEntry
{
  /**
   * Block
   */
  struct GNUNET_GNSRECORD_Block *block;

  /**
   * query
   */
  struct GNUNET_HashCode query;

};

/**
 * Initialize the database connections and associated
 * data structures (create tables and indices
 * as needed as well).
 *
 * @param plugin the plugin context (state for this module)
 * @return #GNUNET_OK on success
 */
static int
database_setup (struct Plugin *plugin)
{
  char *afsdir;
  char* block_buffer;
  char* buffer;
  char* line;
  char* query;
  char* block;
  size_t size;
  struct FlatFileEntry *entry;
  struct GNUNET_DISK_FileHandle *fh;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->cfg, "namecache-flat",
                                               "FILENAME", &afsdir))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "namecache-flat", "FILENAME");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_DISK_file_test (afsdir))
  {
    if (GNUNET_OK != GNUNET_DISK_directory_create_for_file (afsdir))
    {
      GNUNET_break (0);
      GNUNET_free (afsdir);
      return GNUNET_SYSERR;
    }
  }
  /* afsdir should be UTF-8-encoded. If it isn't, it's a bug */
  plugin->fn = afsdir;

  /* Load data from file into hashmap */
  plugin->hm = GNUNET_CONTAINER_multihashmap_create (10,
                                                     GNUNET_NO);
  fh = GNUNET_DISK_file_open (afsdir,
                              GNUNET_DISK_OPEN_CREATE |
                              GNUNET_DISK_OPEN_READWRITE,
                              GNUNET_DISK_PERM_USER_WRITE |
                              GNUNET_DISK_PERM_USER_READ);
  if (NULL == fh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Unable to initialize file: %s.\n"),
                afsdir);
    return GNUNET_SYSERR;
  }

  if (GNUNET_SYSERR == GNUNET_DISK_file_size (afsdir,
                                              &size,
                                              GNUNET_YES,
                                              GNUNET_YES))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Unable to get filesize: %s.\n"),
                afsdir);
    return GNUNET_SYSERR;
  }

  buffer = GNUNET_malloc (size);

  if (GNUNET_SYSERR == GNUNET_DISK_file_read (fh,
                                              buffer,
                                              size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Unable to read file: %s.\n"),
                afsdir);
    return GNUNET_SYSERR;
  }

  GNUNET_DISK_file_close (fh);

  line = strtok ("\n", buffer);
  while (line != NULL) {
    query = strtok (",", line);
    block = strtok (NULL, line);
    line = strtok ("\n", buffer);
    entry = GNUNET_malloc (sizeof (struct FlatFileEntry));
    GNUNET_CRYPTO_hash_from_string (query,
                                    &entry->query);
    GNUNET_STRINGS_base64_decode (block,
                                  strlen (block),
                                  &block_buffer);
    entry->block = (struct GNUNET_GNSRECORD_Block *) block_buffer;
    if (GNUNET_OK != 
        GNUNET_CONTAINER_multihashmap_put (plugin->hm,
                                           &entry->query,
                                           entry,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_free (entry);
      GNUNET_break (0);
    }
  }
  GNUNET_free (buffer);
  return GNUNET_OK;
}

/**
 * Store values in hashmap in file and free data
 *
 * @param plugin the plugin context
 */
static int
store_and_free_entries (void *cls,
                        const struct GNUNET_HashCode *key,
                        void *value)
{
  struct GNUNET_DISK_FileHandle *fh = cls;
  struct FlatFileEntry *entry = value;

  char *line;
  char *block_b64;
  struct GNUNET_CRYPTO_HashAsciiEncoded query;
  size_t block_size;

  block_size = ntohl (entry->block->purpose.size) +
    sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
    sizeof (struct GNUNET_CRYPTO_EcdsaSignature);

  GNUNET_STRINGS_base64_encode ((char*)entry->block,
                                block_size,
                                &block_b64);
  GNUNET_CRYPTO_hash_to_enc (&entry->query,
                             &query);
  GNUNET_asprintf (&line,
                   "%s,%s\n",
                   (char*)&query,
                   block_b64);

  GNUNET_free (block_b64);

  GNUNET_DISK_file_write (fh,
                          line,
                          strlen (line));

  GNUNET_free (entry->block);
  GNUNET_free (entry);
  return GNUNET_YES;
}

/**
 * Shutdown database connection and associate data
 * structures.
 * @param plugin the plugin context (state for this module)
 */
static void
database_shutdown (struct Plugin *plugin)
{
  struct GNUNET_DISK_FileHandle *fh;
  fh = GNUNET_DISK_file_open (plugin->fn,
                              GNUNET_DISK_OPEN_CREATE |
                              GNUNET_DISK_OPEN_TRUNCATE,
                              GNUNET_DISK_PERM_USER_WRITE |
                              GNUNET_DISK_PERM_USER_READ);
  if (NULL == fh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Unable to initialize file: %s.\n"),
                plugin->fn);
    return;
  }

  GNUNET_CONTAINER_multihashmap_iterate (plugin->hm,
                                         &store_and_free_entries,
                                         fh);
  GNUNET_CONTAINER_multihashmap_destroy (plugin->hm);
  GNUNET_DISK_file_close (fh);

}

static int
expire_blocks (void *cls,
               const struct GNUNET_HashCode *key,
               void *value)
{
  struct Plugin *plugin = cls;
  struct FlatFileEntry *entry = value;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Absolute expiration;

  now = GNUNET_TIME_absolute_get ();
  expiration = GNUNET_TIME_absolute_ntoh (entry->block->expiration_time);

  if (0 == GNUNET_TIME_absolute_get_difference (now,
                                                expiration).rel_value_us)
  {
    GNUNET_CONTAINER_multihashmap_remove_all (plugin->hm, key);
  }
  return GNUNET_YES;
}



/**
 * Removes any expired block.
 *
 * @param plugin the plugin
 */
static void
namecache_expire_blocks (struct Plugin *plugin)
{
  GNUNET_CONTAINER_multihashmap_iterate (plugin->hm,
                                         &expire_blocks,
                                         plugin);
}


/**
 * Cache a block in the datastore.
 *
 * @param cls closure (internal context for the plugin)
 * @param block block to cache
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
namecache_cache_block (void *cls,
                              const struct GNUNET_GNSRECORD_Block *block)
{
  struct Plugin *plugin = cls;
  struct GNUNET_HashCode query;
  struct FlatFileEntry *entry;
  size_t block_size;

  namecache_expire_blocks (plugin);
  GNUNET_CRYPTO_hash (&block->derived_key,
                      sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
                      &query);
  block_size = ntohl (block->purpose.size) +
    sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
    sizeof (struct GNUNET_CRYPTO_EcdsaSignature);
  if (block_size > 64 * 65536)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  entry = GNUNET_malloc (sizeof (struct FlatFileEntry));
  entry->block = GNUNET_malloc (block_size);
  memcpy (entry->block, block, block_size);
  GNUNET_CONTAINER_multihashmap_remove_all (plugin->hm, &query);
  if (GNUNET_OK != 
      GNUNET_CONTAINER_multihashmap_put (plugin->hm,
                                         &query,
                                         entry,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_free (entry);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Caching block under derived key `%s'\n",
              GNUNET_h2s_full (&query));
  return GNUNET_OK;
}


/**
 * Get the block for a particular zone and label in the
 * datastore.  Will return at most one result to the iterator.
 *
 * @param cls closure (internal context for the plugin)
 * @param query hash of public key derived from the zone and the label
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
 */
static int
namecache_lookup_block (void *cls,
                        const struct GNUNET_HashCode *query,
                        GNUNET_NAMECACHE_BlockCallback iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  const struct GNUNET_GNSRECORD_Block *block;

  block = GNUNET_CONTAINER_multihashmap_get (plugin->hm, query);
  if (NULL == block)
    return GNUNET_NO;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Found block under derived key `%s'\n",
              GNUNET_h2s_full (query));
  iter (iter_cls, block);
  return GNUNET_YES;
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_NAMECACHE_PluginEnvironment*"
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_namecache_flat_init (void *cls)
{
  static struct Plugin plugin;
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_NAMECACHE_PluginFunctions *api;

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.cfg = cfg;
  if (GNUNET_OK != database_setup (&plugin))
  {
    database_shutdown (&plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_NAMECACHE_PluginFunctions);
  api->cls = &plugin;
  api->cache_block = &namecache_cache_block;
  api->lookup_block = &namecache_lookup_block;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
       _("flat plugin running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_namecache_flat_done (void *cls)
{
  struct GNUNET_NAMECACHE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
       "flat plugin is finished\n");
  return NULL;
}

/* end of plugin_namecache_sqlite.c */
