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
 * @file namestore/plugin_namestore_flat.c
 * @brief file-based namestore backend
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_namestore_plugin.h"
#include "gnunet_namestore_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "namestore.h"

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

  /**
   * Offset
   */
  uint32_t offset;

  /**
   * Target Offset
   */
  uint32_t target_offset;

  /**
   * Iterator closure
   */
  void *iter_cls;

  /**
   * Iterator
   */
  GNUNET_NAMESTORE_RecordIterator iter;

  /**
   * Zone to iterate
   */
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *iter_zone;

  /**
   * PKEY to look for in zone to name
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey *iter_pkey;

  /**
   * Iteration result found
   */
  int iter_result_found;

};

struct FlatFileEntry
{
  /**
   * Entry zone
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey *private_key;

  /**
   * Entry zone pkey
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey *pkey;

  /**
   * Record cound
   */
  uint32_t record_count;

  /**
   * Rvalue
   */
  uint64_t rvalue;

  /**
   * Record data
   */
  struct GNUNET_GNSRECORD_Data *record_data;

  /**
   * Label
   */
  char *label;


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
  char *key_str;
  char *record_data;
  char *zone_private_key;
  char *pkey;
  char *record_data_b64;
  char *buffer;
  char *line;
  char *label;
  char *rvalue;
  char *record_count;
  size_t record_data_size;
  size_t size;
  struct GNUNET_HashCode hkey;
  struct GNUNET_DISK_FileHandle *fh;
  struct FlatFileEntry *entry; 

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->cfg, 
                                               "namestore-flat",
                                               "FILENAME", &afsdir))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "namestore-flat", "FILENAME");
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
    zone_private_key = strtok (",", line);
    pkey = strtok (NULL, line);
    rvalue = strtok (NULL, line);
    record_count = strtok (NULL, line);
    record_data_b64 = strtok (NULL, line);
    label = strtok (NULL, line);
    line = strtok ("\n", buffer);
    entry = GNUNET_malloc (sizeof (struct FlatFileEntry));
    GNUNET_CRYPTO_ecdsa_public_key_from_string (pkey,
                                                strlen (pkey),
                                                entry->pkey);
    sscanf (rvalue, "%lu", &entry->rvalue);
    sscanf (record_count, "%u", &entry->record_count);
    entry->label = GNUNET_strdup (label);
    record_data_size = GNUNET_STRINGS_base64_decode (record_data_b64,
                                                     strlen (record_data_b64),
                                                     &record_data);
    entry->record_data = 
      GNUNET_malloc (sizeof (struct GNUNET_GNSRECORD_Data) * entry->record_count);
    GNUNET_GNSRECORD_records_deserialize (record_data_size,
                                          record_data,
                                          entry->record_count,
                                          entry->record_data);
    GNUNET_free (record_data);
    GNUNET_STRINGS_base64_decode (zone_private_key,
                                  strlen (zone_private_key),
                                  (char**)&entry->private_key);
    key_str = GNUNET_malloc (strlen (label) + sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
    memcpy (key_str, label, strlen (label));
    memcpy (key_str+strlen(label),
            entry->private_key,
            sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
    GNUNET_CRYPTO_hash (key_str,
                        strlen (key_str),
                        &hkey);
    GNUNET_free (key_str);
    if (GNUNET_OK != 
        GNUNET_CONTAINER_multihashmap_put (plugin->hm,
                                           &hkey,
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
  char *zone_private_key;
  char *pkey;
  char *rvalue;
  char *record_count;
  char *record_data_buf;
  char *record_data_b64;
  size_t record_data_len;

  GNUNET_STRINGS_base64_encode ((char*)entry->private_key,
                                sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey),
                                &zone_private_key);
  pkey = GNUNET_CRYPTO_ecdsa_public_key_to_string (entry->pkey);
  GNUNET_asprintf (&rvalue, "%hhu", entry->rvalue);
  GNUNET_asprintf (&record_count, "%u", entry->record_count);

  record_data_len = GNUNET_GNSRECORD_records_get_size (entry->record_count,
                                                       entry->record_data);

  record_data_buf = GNUNET_malloc (record_data_len);
  GNUNET_GNSRECORD_records_serialize (entry->record_count,
                                      entry->record_data,
                                      record_data_len,
                                      record_data_buf);

  GNUNET_STRINGS_base64_encode (record_data_buf,
                                strlen (record_data_buf),
                                &record_data_b64);

  GNUNET_asprintf (&line,
                   "%s,%s,%s,%s,%s,%s\n",
                   zone_private_key,
                   pkey,
                   rvalue,
                   record_count,
                   record_data_b64,
                   entry->label);

  GNUNET_free (rvalue);
  GNUNET_free (record_count);
  GNUNET_free (record_data_buf);
  GNUNET_free (record_data_b64);

  GNUNET_DISK_file_write (fh,
                          line,
                          strlen (line));

  GNUNET_free (entry->private_key);
  GNUNET_free (entry->pkey);
  GNUNET_free (entry->label);
  GNUNET_free (entry->record_data);
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
 * Store a record in the datastore.  Removes any existing record in the
 * same zone with the same name.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone_key private key of the zone
 * @param label name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
namestore_store_records (void *cls,
                         const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                         const char *label,
                         unsigned int rd_count,
                         const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Plugin *plugin = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  uint64_t rvalue;
  size_t data_size;
  unsigned int i;
  char *key_str;
  struct GNUNET_HashCode hkey;
  struct FlatFileEntry *entry;

  memset (&pkey, 0, sizeof (pkey));
  for (i=0;i<rd_count;i++)
    if (GNUNET_GNSRECORD_TYPE_PKEY == rd[i].record_type)
    {
      GNUNET_break (sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) == rd[i].data_size);
      memcpy (&pkey,
              rd[i].data,
              rd[i].data_size);
      break;
    }
  rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX);
  data_size = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
  if (data_size > 64 * 65536)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  char data[data_size];

  if (data_size != GNUNET_GNSRECORD_records_serialize (rd_count, rd,
                                                       data_size, data))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  key_str = GNUNET_malloc (strlen (label) + sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
  memcpy (key_str, label, strlen (label));
  memcpy (key_str+strlen(label),
          zone_key,
          sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
  GNUNET_CRYPTO_hash (key_str,
                      strlen (key_str),
                      &hkey);

  GNUNET_CONTAINER_multihashmap_remove_all (plugin->hm, &hkey);

  if (0 != rd_count)
  {
    entry = GNUNET_malloc (sizeof (struct FlatFileEntry));
    entry->private_key = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
    memcpy (&entry->private_key,
            zone_key,
            sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
    entry->pkey = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
    memcpy (entry->pkey,
            &pkey,
            sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
    entry->rvalue = rvalue;
    entry->record_count = rd_count;
    entry->record_data = GNUNET_malloc (data_size);
    memcpy (&entry->record_data, data, data_size);
    return GNUNET_CONTAINER_multihashmap_put (plugin->hm,
                                              &hkey,
                                              entry,
                                              GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }
  return GNUNET_NO;
}


/**
 * Lookup records in the datastore for which we are the authority.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone private key of the zone
 * @param label name of the record in the zone
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
namestore_lookup_records (void *cls,
                          const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                          const char *label,
                          GNUNET_NAMESTORE_RecordIterator iter,
                          void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct FlatFileEntry *entry;
  struct GNUNET_HashCode hkey;
  char *key_str;

  if (NULL == zone)
  {
    return GNUNET_SYSERR;
  }
  key_str = GNUNET_malloc (strlen (label) + sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
  memcpy (key_str, label, strlen (label));
  memcpy (key_str+strlen(label),
          zone,
          sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
  GNUNET_CRYPTO_hash (key_str,
                      strlen (key_str),
                      &hkey);
  GNUNET_free (key_str);

  entry = GNUNET_CONTAINER_multihashmap_get (plugin->hm, &hkey);

  if (NULL == entry)
    return GNUNET_NO;
  if (NULL != iter)
    iter (iter_cls, entry->private_key, entry->label, entry->record_count, entry->record_data);
  return GNUNET_YES;
}


static int
iterate_zones (void *cls,
               const struct GNUNET_HashCode *key,
               void *value)
{
  struct Plugin *plugin = cls;
  struct FlatFileEntry *entry = value;


  if ((plugin->target_offset > plugin->offset) ||
      (0 != memcmp (entry->private_key,
                    plugin->iter_zone,
                    sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey)))) {
    plugin->offset++;
    return GNUNET_YES;
  }

  plugin->iter (plugin->iter_cls,
                entry->private_key,
                entry->label,
                entry->record_count,
                entry->record_data);
  plugin->iter_result_found = GNUNET_YES;
  return GNUNET_NO;
}

/**
 * Iterate over the results for a particular key and zone in the
 * datastore.  Will return at most one result to the iterator.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone, NULL to iterate over all zones
 * @param offset offset in the list of all matching records
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
 */
static int
namestore_iterate_records (void *cls,
                           const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                           uint64_t offset,
                           GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  plugin->target_offset = offset;
  plugin->offset = 0;
  plugin->iter = iter;
  plugin->iter_cls = cls;
  plugin->iter_zone = zone;
  plugin->iter_result_found = GNUNET_NO;
  GNUNET_CONTAINER_multihashmap_iterate (plugin->hm,
                                         &iterate_zones,
                                         plugin);
  return plugin->iter_result_found;
}

static int
zone_to_name (void *cls,
              const struct GNUNET_HashCode *key,
              void *value)
{
  struct Plugin *plugin = cls;
  struct FlatFileEntry *entry = value;
  int i;

  if (0 != memcmp (entry->private_key,
                   plugin->iter_zone,
                   sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey)))
    return GNUNET_YES;

  for (i = 0; i < entry->record_count; i++) {
    if (GNUNET_GNSRECORD_TYPE_PKEY != entry->record_data[i].record_type)
      continue;
    if (0 == memcmp (plugin->iter_pkey,
                     entry->record_data[i].data,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
    {
      plugin->iter (plugin->iter_cls,
                    entry->private_key,
                    entry->label,
                    entry->record_count,
                    entry->record_data);
      plugin->iter_result_found = GNUNET_YES;

    }
  }

  return GNUNET_YES;
}

/**
 * Look for an existing PKEY delegation record for a given public key.
 * Returns at most one result to the iterator.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone private key of the zone to look up in, never NULL
 * @param value_zone public key of the target zone (value), never NULL
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
 */
static int
namestore_zone_to_name (void *cls,
                        const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                        const struct GNUNET_CRYPTO_EcdsaPublicKey *value_zone,
                        GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
       "Performing reverse lookup for `%s'\n",
       GNUNET_GNSRECORD_z2s (value_zone));

  GNUNET_CONTAINER_multihashmap_iterate (plugin->hm,
                                         &zone_to_name,
                                         plugin);


  return plugin->iter_result_found;
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_NAMESTORE_PluginEnvironment*"
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_namestore_flat_init (void *cls)
{
  static struct Plugin plugin;
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_NAMESTORE_PluginFunctions *api;

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.cfg = cfg;
  if (GNUNET_OK != database_setup (&plugin))
  {
    database_shutdown (&plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_NAMESTORE_PluginFunctions);
  api->cls = &plugin;
  api->store_records = &namestore_store_records;
  api->iterate_records = &namestore_iterate_records;
  api->zone_to_name = &namestore_zone_to_name;
  api->lookup_records = &namestore_lookup_records;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
       _("flat file database running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_namestore_flat_done (void *cls)
{
  struct GNUNET_NAMESTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
       "flat file plugin is finished\n");
  return NULL;
}

/* end of plugin_namestore_flat.c */
