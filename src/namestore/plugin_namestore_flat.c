 /*
  * This file is part of GNUnet
  * Copyright (C) 2009-2015, 2018 GNUnet e.V.
  *
  * GNUnet is free software: you can redistribute it and/or modify it
  * under the terms of the GNU General Public License as published
  * by the Free Software Foundation, either version 3 of the License,
  * or (at your option) any later version.
  *
  * GNUnet is distributed in the hope that it will be useful, but
  * WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  * Affero General Public License for more details.
  */

/**
 * @file namestore/plugin_namestore_flat.c
 * @brief file-based namestore backend
 * @author Martin Schanzenbach
 * @author Christian Grothoff
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

};


struct FlatFileEntry
{
  /**
   * Entry zone
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey *private_key;

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
  char *key;
  char *record_data;
  char *zone_private_key;
  char *record_data_b64;
  char *buffer;
  char *line;
  char *label;
  char *rvalue;
  char *record_count;
  size_t record_data_size;
  uint64_t size;
  size_t key_len;
  struct GNUNET_HashCode hkey;
  struct GNUNET_DISK_FileHandle *fh;
  struct FlatFileEntry *entry;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->cfg,
                                               "namestore-flat",
                                               "FILENAME",
					       &afsdir))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "namestore-flat",
			       "FILENAME");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_DISK_file_test (afsdir))
  {
    if (GNUNET_OK !=
	GNUNET_DISK_directory_create_for_file (afsdir))
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
  if (GNUNET_SYSERR ==
      GNUNET_DISK_file_size (afsdir,
                             &size,
                             GNUNET_YES,
                             GNUNET_YES))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
         _("Unable to get filesize: %s.\n"),
         afsdir);
    GNUNET_DISK_file_close (fh);
    return GNUNET_SYSERR;
  }

  buffer = GNUNET_malloc (size + 1);
  if (GNUNET_SYSERR ==
      GNUNET_DISK_file_read (fh,
                             buffer,
                             size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
         _("Unable to read file: %s.\n"),
         afsdir);
    GNUNET_free (buffer);
    GNUNET_DISK_file_close (fh);
    return GNUNET_SYSERR;
  }
  buffer[size] = '\0';
  GNUNET_DISK_file_close (fh);

  if (0 < size)
  {
    line = strtok (buffer, "\n");
    while (line != NULL)
    {
      zone_private_key = strtok (line, ",");
      if (NULL == zone_private_key)
        break;
      rvalue = strtok (NULL, ",");
      if (NULL == rvalue)
        break;
      record_count = strtok (NULL, ",");
      if (NULL == record_count)
        break;
      record_data_b64 = strtok (NULL, ",");
      if (NULL == record_data_b64)
        break;
      label = strtok (NULL, ",");
      if (NULL == label)
        break;
      line = strtok (NULL, "\n");
      entry = GNUNET_new (struct FlatFileEntry);
      {
        unsigned long long ll;

        if (1 != sscanf (rvalue,
                         "%llu",
                         &ll))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      "Error parsing entry\n");
          GNUNET_free (entry);
          break;
        }
        entry->rvalue = (uint64_t) ll;
      }
      {
        unsigned int ui;

        if (1 != sscanf (record_count,
                         "%u",
                         &ui))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      "Error parsing entry\n");
          GNUNET_free (entry);
          break;
        }
        entry->record_count = (uint32_t) ui;
      }
      entry->label = GNUNET_strdup (label);
      record_data_size
	= GNUNET_STRINGS_base64_decode (record_data_b64,
					strlen (record_data_b64),
					&record_data);
      entry->record_data =
        GNUNET_new_array (entry->record_count,
			  struct GNUNET_GNSRECORD_Data);
      if (GNUNET_OK !=
	  GNUNET_GNSRECORD_records_deserialize (record_data_size,
						record_data,
						entry->record_count,
						entry->record_data))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Unable to deserialize record %s\n",
		    label);
        GNUNET_free (entry->label);
        GNUNET_free (entry);
        GNUNET_free (record_data);
        break;
      }
      GNUNET_free (record_data);
      GNUNET_STRINGS_base64_decode (zone_private_key,
                                    strlen (zone_private_key),
                                    (char**)&entry->private_key);
      key_len = strlen (label) + sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey);
      key = GNUNET_malloc (strlen (label) + sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
      GNUNET_memcpy (key,
		     label,
		     strlen (label));
      GNUNET_memcpy (key+strlen(label),
		     entry->private_key,
		     sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
      GNUNET_CRYPTO_hash (key,
                          key_len,
                          &hkey);
      GNUNET_free (key);
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
  }
  GNUNET_free (buffer);
  return GNUNET_OK;
}


/**
 * Store values in hashmap in file and free data
 *
 * @param plugin the plugin context
 * @param key key in the map
 * @param value a `struct FlatFileEntry`
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
  char *record_data_b64;
  ssize_t data_size;

  (void) key;
  GNUNET_STRINGS_base64_encode ((char*)entry->private_key,
                                sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey),
                                &zone_private_key);
  data_size = GNUNET_GNSRECORD_records_get_size (entry->record_count,
                                                 entry->record_data);
  if (data_size < 0)
  {
    GNUNET_break (0);
    GNUNET_free (zone_private_key);
    return GNUNET_SYSERR;
  }
  if (data_size >= UINT16_MAX)
  {
    GNUNET_break (0);
    GNUNET_free (zone_private_key);
    return GNUNET_SYSERR;
  }
  {
    char data[data_size];
    ssize_t ret;

    ret = GNUNET_GNSRECORD_records_serialize (entry->record_count,
					      entry->record_data,
					      data_size,
					      data);
    if ( (ret < 0) ||
	 (data_size != ret) )
    {
      GNUNET_break (0);
      GNUNET_free (zone_private_key);
      return GNUNET_SYSERR;
    }
    GNUNET_STRINGS_base64_encode (data,
                                  data_size,
                                  &record_data_b64);
  }
  GNUNET_asprintf (&line,
                   "%s,%llu,%u,%s,%s\n",
                   zone_private_key,
                   (unsigned long long) entry->rvalue,
                   (unsigned int) entry->record_count,
                   record_data_b64,
                   entry->label);
  GNUNET_free (record_data_b64);
  GNUNET_free (zone_private_key);

  GNUNET_DISK_file_write (fh,
                          line,
                          strlen (line));

  GNUNET_free (line);
  GNUNET_free (entry->private_key);
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
namestore_flat_store_records (void *cls,
                              const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                              const char *label,
                              unsigned int rd_count,
                              const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Plugin *plugin = cls;
  uint64_t rvalue;
  size_t key_len;
  char *key;
  struct GNUNET_HashCode hkey;
  struct FlatFileEntry *entry;

  rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
				     UINT64_MAX);
  key_len = strlen (label) + sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey);
  key = GNUNET_malloc (key_len);
  GNUNET_memcpy (key,
                 label,
                 strlen (label));
  GNUNET_memcpy (key + strlen(label),
                 zone_key,
                 sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
  GNUNET_CRYPTO_hash (key,
                      key_len,
                      &hkey);
  GNUNET_CONTAINER_multihashmap_remove_all (plugin->hm,
                                            &hkey);
  if (0 == rd_count)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     "sqlite",
                     "Record deleted\n");
    return GNUNET_OK;
  }
  entry = GNUNET_new (struct FlatFileEntry);
  entry->private_key = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPrivateKey);
  GNUNET_asprintf (&entry->label,
                   label,
                   strlen (label));
  GNUNET_memcpy (entry->private_key,
                 zone_key,
                 sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
  entry->rvalue = rvalue;
  entry->record_count = rd_count;
  entry->record_data = GNUNET_new_array (rd_count,
                                         struct GNUNET_GNSRECORD_Data);
  for (unsigned int i = 0; i < rd_count; i++)
  {
    entry->record_data[i].expiration_time = rd[i].expiration_time;
    entry->record_data[i].record_type = rd[i].record_type;
    entry->record_data[i].flags = rd[i].flags;
    entry->record_data[i].data_size = rd[i].data_size;
    entry->record_data[i].data = GNUNET_malloc (rd[i].data_size);
    GNUNET_memcpy ((char*)entry->record_data[i].data,
                   rd[i].data,
                   rd[i].data_size);
  }
  return GNUNET_CONTAINER_multihashmap_put (plugin->hm,
                                            &hkey,
                                            entry,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
}


/**
 * Lookup records in the datastore for which we are the authority.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone private key of the zone
 * @param label name of the record in the zone
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO for no results, else #GNUNET_SYSERR
 */
static int
namestore_flat_lookup_records (void *cls,
                               const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                               const char *label,
                               GNUNET_NAMESTORE_RecordIterator iter,
                               void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct FlatFileEntry *entry;
  struct GNUNET_HashCode hkey;
  char *key;
  size_t key_len;

  if (NULL == zone)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  key_len = strlen (label) + sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey);
  key = GNUNET_malloc (key_len);
  GNUNET_memcpy (key,
		 label,
		 strlen (label));
  GNUNET_memcpy (key+strlen(label),
		 zone,
		 sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey));
  GNUNET_CRYPTO_hash (key,
                      key_len,
                      &hkey);
  GNUNET_free (key);

  entry = GNUNET_CONTAINER_multihashmap_get (plugin->hm,
					     &hkey);

  if (NULL == entry)
    return GNUNET_NO;
  if (NULL != iter)
    iter (iter_cls,
	  0,
	  entry->private_key,
	  entry->label,
	  entry->record_count,
	  entry->record_data);
  return GNUNET_YES;
}


/**
 * Closure for #iterate_zones.
 */
struct IterateContext
{
  /**
   * How many more records should we skip before returning results?
   */
  uint64_t offset;

  /**
   * How many more records should we return?
   */
  uint64_t limit;

  /**
   * What is the position of the current entry, counting
   * starts from 1.
   */
  uint64_t pos;

  /**
   * Target zone.
   */
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone;

  /**
   * Function to call on each record.
   */
  GNUNET_NAMESTORE_RecordIterator iter;

  /**
   * Closure for @e iter.
   */
  void *iter_cls;

};


/**
 * Helper function for #namestore_flat_iterate_records().
 *
 * @param cls a `struct IterateContext`
 * @param key unused
 * @param value a `struct FlatFileEntry`
 * @return #GNUNET_YES to continue the iteration
 */
static int
iterate_zones (void *cls,
               const struct GNUNET_HashCode *key,
               void *value)
{
  struct IterateContext *ic = cls;
  struct FlatFileEntry *entry = value;

  (void) key;
  if (0 == ic->limit)
    return GNUNET_NO;
  if ( (NULL != ic->zone) &&
       (0 != memcmp (entry->private_key,
                     ic->zone,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey))) )
    return GNUNET_YES;
  ic->pos++;
  if (ic->offset > 0)
  {
    ic->offset--;
    return GNUNET_YES;
  }
  ic->iter (ic->iter_cls,
	    ic->pos,
            entry->private_key,
            entry->label,
            entry->record_count,
            entry->record_data);
  ic->limit--;
  if (0 == ic->limit)
    return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Iterate over the results for a particular key and zone in the
 * datastore.  Will return at most one result to the iterator.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone, NULL to iterate over all zones
 * @param serial serial number to exclude in the list of all matching records
 * @param limit maximum number of results to return to @a iter
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no more results, #GNUNET_SYSERR on error
 */
static int
namestore_flat_iterate_records (void *cls,
                                const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                                uint64_t serial,
                                uint64_t limit,
                                GNUNET_NAMESTORE_RecordIterator iter,
                                void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct IterateContext ic;

  ic.offset = serial;
  ic.pos = 0;
  ic.limit = limit;
  ic.iter = iter;
  ic.iter_cls = iter_cls;
  ic.zone = zone;
  GNUNET_CONTAINER_multihashmap_iterate (plugin->hm,
                                         &iterate_zones,
                                         &ic);
  return (0 == ic.limit) ? GNUNET_OK : GNUNET_NO;
}


/**
 * Closure for #zone_to_name.
 */
struct ZoneToNameContext
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone;
  const struct GNUNET_CRYPTO_EcdsaPublicKey *value_zone;
  GNUNET_NAMESTORE_RecordIterator iter;
  void *iter_cls;

  int result_found;
};


static int
zone_to_name (void *cls,
              const struct GNUNET_HashCode *key,
              void *value)
{
  struct ZoneToNameContext *ztn = cls;
  struct FlatFileEntry *entry = value;

  (void) key;
  if (0 != memcmp (entry->private_key,
                   ztn->zone,
                   sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey)))
    return GNUNET_YES;

  for (unsigned int i = 0; i < entry->record_count; i++)
  {
    if (GNUNET_GNSRECORD_TYPE_PKEY != entry->record_data[i].record_type)
      continue;
    if (0 == memcmp (ztn->value_zone,
                     entry->record_data[i].data,
                     sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
    {
      ztn->iter (ztn->iter_cls,
                 0,
                 entry->private_key,
                 entry->label,
                 entry->record_count,
                 entry->record_data);
      ztn->result_found = GNUNET_YES;
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
namestore_flat_zone_to_name (void *cls,
                             const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                             const struct GNUNET_CRYPTO_EcdsaPublicKey *value_zone,
                             GNUNET_NAMESTORE_RecordIterator iter,
                             void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct ZoneToNameContext ztn = {
    .iter = iter,
    .iter_cls = iter_cls,
    .zone = zone,
    .value_zone = value_zone,
    .result_found = GNUNET_NO
  };

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Performing reverse lookup for `%s'\n",
              GNUNET_GNSRECORD_z2s (value_zone));
  GNUNET_CONTAINER_multihashmap_iterate (plugin->hm,
                                         &zone_to_name,
                                         &ztn);
  return ztn.result_found;
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
  memset (&plugin,
	  0,
	  sizeof (struct Plugin));
  plugin.cfg = cfg;
  if (GNUNET_OK != database_setup (&plugin))
  {
    database_shutdown (&plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_NAMESTORE_PluginFunctions);
  api->cls = &plugin;
  api->store_records = &namestore_flat_store_records;
  api->iterate_records = &namestore_flat_iterate_records;
  api->zone_to_name = &namestore_flat_zone_to_name;
  api->lookup_records = &namestore_flat_lookup_records;
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
