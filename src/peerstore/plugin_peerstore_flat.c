/*
 * This file is part of GNUnet
 * Copyright (C) 2015 Christian Grothoff (and other contributing authors)
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
 * @file peerstore/plugin_peerstore_flat.c
 * @brief flat file-based peerstore backend
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_peerstore_plugin.h"
#include "gnunet_peerstore_service.h"
#include "peerstore.h"

/**
 * Context for all functions in this plugin.
 */
struct Plugin
{

  /**
   * Configuration handle
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * HashMap
   */
  struct GNUNET_CONTAINER_MultiHashMap *hm;

  /**
   * Iterator
   */
  GNUNET_PEERSTORE_Processor iter;

  /**
   * Iterator cls
   */
  void *iter_cls;

  /**
   * iterator key
   */
  const char *iter_key;

  /**
   * Iterator peer
   */
  const struct GNUNET_PeerIdentity *iter_peer;

  /**
   * Iterator subsystem
   */
  const char *iter_sub_system;

  /**
   * Iterator time
   */
  struct GNUNET_TIME_Absolute iter_now;

  /**
   * Deleted entries
   */
  uint64_t deleted_entries;

  /**
   * Expired entries
   */
  uint64_t exp_changes;

  /**
   * Database filename.
   */
  char *fn;

  /**
   * Result found bool
   */
  int iter_result_found;

};


static int
delete_entries (void *cls,
                const struct GNUNET_HashCode *key,
                void *value)
{
  struct Plugin *plugin = cls;
  struct GNUNET_PEERSTORE_Record *entry = value;
  if (0 != strcmp (plugin->iter_key, entry->key))
    return GNUNET_YES;
  if (0 != memcmp (plugin->iter_peer, entry->peer, sizeof (struct GNUNET_PeerIdentity)))
    return GNUNET_YES;
  if (0 != strcmp (plugin->iter_sub_system, entry->sub_system))
    return GNUNET_YES;

  GNUNET_CONTAINER_multihashmap_remove (plugin->hm, key, value);
  plugin->deleted_entries++;
  return GNUNET_YES;
}


/**
 * Delete records with the given key
 *
 * @param cls closure (internal context for the plugin)
 * @param sub_system name of sub system
 * @param peer Peer identity (can be NULL)
 * @param key entry key string (can be NULL)
 * @return number of deleted records
 */
static int
peerstore_flat_delete_records (void *cls, const char *sub_system,
                               const struct GNUNET_PeerIdentity *peer,
                               const char *key)
{
  struct Plugin *plugin = cls;

  plugin->iter_sub_system = sub_system;
  plugin->iter_peer = peer;
  plugin->iter_key = key;
  plugin->deleted_entries = 0;

  GNUNET_CONTAINER_multihashmap_iterate (plugin->hm,
                                         &delete_entries,
                                         plugin);
  return plugin->deleted_entries;
}

static int
expire_entries (void *cls,
                const struct GNUNET_HashCode *key,
                void *value)
{
  struct Plugin *plugin = cls;
  struct GNUNET_PEERSTORE_Record *entry = value;

  if (entry->expiry->abs_value_us < plugin->iter_now.abs_value_us)
  {
    GNUNET_CONTAINER_multihashmap_remove (plugin->hm, key, value);
    plugin->exp_changes++;
  }
  return GNUNET_YES;
}



/**
 * Delete expired records (expiry < now)
 *
 * @param cls closure (internal context for the plugin)
 * @param now time to use as reference
 * @param cont continuation called with the number of records expired
 * @param cont_cls continuation closure
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error and cont is not
 * called
 */
static int
peerstore_flat_expire_records (void *cls, struct GNUNET_TIME_Absolute now,
                               GNUNET_PEERSTORE_Continuation cont,
                               void *cont_cls)
{
  struct Plugin *plugin = cls;
  plugin->exp_changes = 0;
  plugin->iter_now = now;

  GNUNET_CONTAINER_multihashmap_iterate (plugin->hm,
                                         &expire_entries,
                                         plugin);
  if (NULL != cont)
  {
    cont (cont_cls, plugin->exp_changes);
  }
  return GNUNET_OK;

}


static int
iterate_entries (void *cls,
                 const struct GNUNET_HashCode *key,
                 void *value)
{
  struct Plugin *plugin = cls;
  struct GNUNET_PEERSTORE_Record *entry = value;

  if ((NULL != plugin->iter_peer) &&
      (0 != memcmp (plugin->iter_peer,
                    entry->peer,
                    sizeof (struct GNUNET_PeerIdentity))))
  {
    return GNUNET_YES;
  }
  if ((NULL != plugin->iter_key) &&
      (0 != strcmp (plugin->iter_key,
                    entry->key)))
  {
    return GNUNET_YES;
  }
  if (NULL != plugin->iter)
    plugin->iter (plugin->iter_cls, entry, NULL);
  plugin->iter_result_found = GNUNET_YES;
  return GNUNET_YES;
}

/**
 * Iterate over the records given an optional peer id
 * and/or key.
 *
 * @param cls closure (internal context for the plugin)
 * @param sub_system name of sub system
 * @param peer Peer identity (can be NULL)
 * @param key entry key string (can be NULL)
 * @param iter function to call asynchronously with the results, terminated
 * by a NULL result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error and iter is not
 * called
 */
static int
peerstore_flat_iterate_records (void *cls, const char *sub_system,
                                const struct GNUNET_PeerIdentity *peer,
                                const char *key,
                                GNUNET_PEERSTORE_Processor iter,
                                void *iter_cls)
{
  struct Plugin *plugin = cls;
  plugin->iter = iter;
  plugin->iter_cls = iter_cls;
  plugin->iter_peer = peer;
  plugin->iter_sub_system = sub_system;
  plugin->iter_key = key;

  GNUNET_CONTAINER_multihashmap_iterate (plugin->hm,
                                         &iterate_entries,
                                         plugin);
  if (NULL != iter)
    iter (iter_cls, NULL, NULL);
  return GNUNET_OK;
}


/**
 * Store a record in the peerstore.
 * Key is the combination of sub system and peer identity.
 * One key can store multiple values.
 *
 * @param cls closure (internal context for the plugin)
 * @param sub_system name of the GNUnet sub system responsible
 * @param peer peer identity
 * @param key record key string
 * @param value value to be stored
 * @param size size of value to be stored
 * @param expiry absolute time after which the record is (possibly) deleted
 * @param options options related to the store operation
 * @param cont continuation called when record is stored
 * @param cont_cls continuation closure
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR and cont is not called
 */
static int
peerstore_flat_store_record (void *cls, const char *sub_system,
                             const struct GNUNET_PeerIdentity *peer,
                             const char *key, const void *value, size_t size,
                             struct GNUNET_TIME_Absolute expiry,
                             enum GNUNET_PEERSTORE_StoreOption options,
                             GNUNET_PEERSTORE_Continuation cont,
                             void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_HashCode hkey;
  struct GNUNET_PEERSTORE_Record *entry;
  const char *peer_id;


  entry = GNUNET_new (struct GNUNET_PEERSTORE_Record);
  entry->sub_system = GNUNET_strdup (sub_system);
  entry->key = GNUNET_strdup (key);
  entry->value = GNUNET_malloc (size);
  memcpy (entry->value, value, size);
  entry->value_size = size;
  entry->peer = GNUNET_new (struct GNUNET_PeerIdentity);
  memcpy (entry->peer, peer, sizeof (struct GNUNET_PeerIdentity));
  entry->expiry = GNUNET_new (struct GNUNET_TIME_Absolute);
  entry->expiry->abs_value_us = expiry.abs_value_us;

  peer_id = GNUNET_i2s (peer);
  GNUNET_CRYPTO_hash (peer_id,
                      strlen (peer_id),
                      &hkey);

  if (GNUNET_PEERSTORE_STOREOPTION_REPLACE == options)
  {
    peerstore_flat_delete_records (cls, sub_system, peer, key);
  }

  GNUNET_CONTAINER_multihashmap_put (plugin->hm,
                                     &hkey,
                                     entry,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  if (NULL != cont)
  {
    cont (cont_cls, GNUNET_OK);
  }
  return GNUNET_OK;
}


/**
 * Initialize the database connections and associated
 * data structures (create tables and indices
 * as needed as well).
 *
 * @param plugin the plugin context (state for this module)
 * @return GNUNET_OK on success
 */
static int
database_setup (struct Plugin *plugin)
{
  char *afsdir;
  char *key;
  char *sub_system;
  char *peer_id;
  char *value;
  char *expiry;
  struct GNUNET_DISK_FileHandle *fh;
  struct GNUNET_PEERSTORE_Record *entry;
  size_t size;
  char *buffer;
  char *line;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->cfg, "peerstore-flat",
                                               "FILENAME", &afsdir))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "peerstore-flat",
                               "FILENAME");
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

  /* Load data from file into hashmap */
  plugin->hm = GNUNET_CONTAINER_multihashmap_create (10,
                                                     GNUNET_NO);

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

  buffer = GNUNET_malloc (size) + 1;

  if (GNUNET_SYSERR == GNUNET_DISK_file_read (fh,
                                              buffer,
                                              size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Unable to read file: %s.\n"),
                afsdir);
    GNUNET_DISK_file_close (fh);
    GNUNET_free (buffer);
    return GNUNET_SYSERR;
  }
  
  buffer[size] = '\0';
  GNUNET_DISK_file_close (fh);
  if (0 < size) {
    line = strtok (buffer, "\n");
    while (line != NULL) {
      sub_system = strtok (line, ",");
      if (NULL == sub_system)
        break;
      peer_id = strtok (NULL, ",");
      if (NULL == peer_id)
        break;
      key = strtok (NULL, ",");
      if (NULL == key)
        break;
      value = strtok (NULL, ",");
      if (NULL == value)
        break;
      expiry = strtok (NULL, ",");
      if (NULL == expiry)
        break;
      entry = GNUNET_new (struct GNUNET_PEERSTORE_Record);
      entry->sub_system = GNUNET_strdup (sub_system);
      entry->key = GNUNET_strdup (key);
      GNUNET_STRINGS_base64_decode (peer_id,
                                    strlen (peer_id),
                                    (char**)&entry->peer);
      entry->value_size = GNUNET_STRINGS_base64_decode (value,
                                                        strlen (value),
                                                        (char**)&entry->value);
      GNUNET_STRINGS_fancy_time_to_absolute (expiry,
                                             entry->expiry);

    }
  }
  return GNUNET_OK;
}

static int
store_and_free_entries (void *cls,
                        const struct GNUNET_HashCode *key,
                        void *value)
{
  struct GNUNET_DISK_FileHandle *fh = cls;
  struct GNUNET_PEERSTORE_Record *entry = value;
  char *line;
  char *peer;
  const char *expiry;
  char *val;

  GNUNET_STRINGS_base64_encode (entry->value,
                                entry->value_size,
                                &val);
  expiry = GNUNET_STRINGS_absolute_time_to_string (*entry->expiry);
  GNUNET_STRINGS_base64_encode ((char*)entry->peer,
                                sizeof (struct GNUNET_PeerIdentity),
                                &peer);
  GNUNET_asprintf (&line,
                   "%s,%s,%s,%s,%s",
                   entry->sub_system,
                   peer,
                   entry->key,
                   val,
                   expiry);
  GNUNET_free (val);
  GNUNET_free (peer);
  GNUNET_DISK_file_write (fh,
                          line,
                          strlen (line));
  GNUNET_free (entry->sub_system);
  GNUNET_free (entry->peer);
  GNUNET_free (entry->key);
  GNUNET_free (entry->value);
  GNUNET_free (entry->expiry);
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
                              GNUNET_DISK_OPEN_TRUNCATE |
                              GNUNET_DISK_OPEN_READWRITE,
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


/**
 * Entry point for the plugin.
 *
 * @param cls The struct GNUNET_CONFIGURATION_Handle.
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_peerstore_flat_init (void *cls)
{
  static struct Plugin plugin;
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_PEERSTORE_PluginFunctions *api;

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.cfg = cfg;
  if (GNUNET_OK != database_setup (&plugin))
  {
    database_shutdown (&plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_PEERSTORE_PluginFunctions);
  api->cls = &plugin;
  api->store_record = &peerstore_flat_store_record;
  api->iterate_records = &peerstore_flat_iterate_records;
  api->expire_records = &peerstore_flat_expire_records;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Flat plugin is running\n");
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls The plugin context (as returned by "init")
 * @return Always NULL
 */
void *
libgnunet_plugin_peerstore_flat_done (void *cls)
{
  struct GNUNET_PEERSTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Flat plugin is finished\n");
  return NULL;
}

/* end of plugin_peerstore_sqlite.c */
