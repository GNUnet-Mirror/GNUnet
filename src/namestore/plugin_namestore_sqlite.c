/*
 * This file is part of GNUnet
 * Copyright (C) 2009-2017 GNUnet e.V.
 *
 * GNUnet is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file namestore/plugin_namestore_sqlite.c
 * @brief sqlite-based namestore backend
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_namestore_plugin.h"
#include "gnunet_namestore_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_sq_lib.h"
#include "namestore.h"
#include <sqlite3.h>

/**
 * After how many ms "busy" should a DB operation fail for good?  A
 * low value makes sure that we are more responsive to requests
 * (especially PUTs).  A high value guarantees a higher success rate
 * (SELECTs in iterate can take several seconds despite LIMIT=1).
 *
 * The default value of 1s should ensure that users do not experience
 * huge latencies while at the same time allowing operations to
 * succeed with reasonable probability.
 */
#define BUSY_TIMEOUT_MS 1000


/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(db, level, cmd) do { GNUNET_log_from (level, \
                                                         "namestore-sqlite", _ ( \
                                                           "`%s' failed at %s:%d with error: %s\n"), \
                                                         cmd, \
                                                         __FILE__, __LINE__, \
                                                         sqlite3_errmsg ( \
                                                           db->dbh)); \
} while (0)

#define LOG(kind, ...) GNUNET_log_from (kind, "namestore-sqlite", __VA_ARGS__)


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
   * Native SQLite database handle.
   */
  sqlite3 *dbh;

  /**
   * Precompiled SQL to store records.
   */
  sqlite3_stmt *store_records;

  /**
   * Precompiled SQL to deltete existing records.
   */
  sqlite3_stmt *delete_records;

  /**
   * Precompiled SQL for iterate records within a zone.
   */
  sqlite3_stmt *iterate_zone;

  /**
   * Precompiled SQL for iterate all records within all zones.
   */
  sqlite3_stmt *iterate_all_zones;

  /**
   * Precompiled SQL to for reverse lookup based on PKEY.
   */
  sqlite3_stmt *zone_to_name;

  /**
   * Precompiled SQL to lookup records based on label.
   */
  sqlite3_stmt *lookup_label;
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
  char *sqlite_filename;
  struct GNUNET_SQ_ExecuteStatement es[] = {
    GNUNET_SQ_make_try_execute ("PRAGMA temp_store=MEMORY"),
    GNUNET_SQ_make_try_execute ("PRAGMA synchronous=NORMAL"),
    GNUNET_SQ_make_try_execute ("PRAGMA legacy_file_format=OFF"),
    GNUNET_SQ_make_try_execute ("PRAGMA auto_vacuum=INCREMENTAL"),
    GNUNET_SQ_make_try_execute ("PRAGMA encoding=\"UTF-8\""),
    GNUNET_SQ_make_try_execute ("PRAGMA locking_mode=EXCLUSIVE"),
    GNUNET_SQ_make_try_execute ("PRAGMA journal_mode=WAL"),
    GNUNET_SQ_make_try_execute ("PRAGMA page_size=4092"),
    GNUNET_SQ_make_execute ("CREATE TABLE IF NOT EXISTS ns098records ("
                            " uid INTEGER PRIMARY KEY,"
                            " zone_private_key BLOB NOT NULL,"
                            " pkey BLOB,"
                            " rvalue INT8 NOT NULL,"
                            " record_count INT NOT NULL,"
                            " record_data BLOB NOT NULL,"
                            " label TEXT NOT NULL"
                            ")"),
    GNUNET_SQ_make_try_execute ("CREATE INDEX IF NOT EXISTS ir_pkey_reverse "
                                "ON ns098records (zone_private_key,pkey)"),
    GNUNET_SQ_make_try_execute ("CREATE INDEX IF NOT EXISTS ir_pkey_iter "
                                "ON ns098records (zone_private_key,uid)"),
    GNUNET_SQ_EXECUTE_STATEMENT_END
  };
  struct GNUNET_SQ_PrepareStatement ps[] = {
    GNUNET_SQ_make_prepare ("INSERT INTO ns098records "
                            "(zone_private_key,pkey,rvalue,record_count,record_data,label)"
                            " VALUES (?, ?, ?, ?, ?, ?)",
                            &plugin->store_records),
    GNUNET_SQ_make_prepare ("DELETE FROM ns098records "
                            "WHERE zone_private_key=? AND label=?",
                            &plugin->delete_records),
    GNUNET_SQ_make_prepare ("SELECT uid,record_count,record_data,label"
                            " FROM ns098records"
                            " WHERE zone_private_key=? AND pkey=?",
                            &plugin->zone_to_name),
    GNUNET_SQ_make_prepare ("SELECT uid,record_count,record_data,label"
                            " FROM ns098records"
                            " WHERE zone_private_key=? AND uid > ?"
                            " ORDER BY uid ASC"
                            " LIMIT ?",
                            &plugin->iterate_zone),
    GNUNET_SQ_make_prepare (
      "SELECT uid,record_count,record_data,label,zone_private_key"
      " FROM ns098records"
      " WHERE uid > ?"
      " ORDER BY uid ASC"
      " LIMIT ?",
      &plugin->iterate_all_zones),
    GNUNET_SQ_make_prepare ("SELECT uid,record_count,record_data,label"
                            " FROM ns098records"
                            " WHERE zone_private_key=? AND label=?",
                            &plugin->lookup_label),
    GNUNET_SQ_PREPARE_END
  };

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->cfg,
                                               "namestore-sqlite",
                                               "FILENAME",
                                               &sqlite_filename))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "namestore-sqlite",
                               "FILENAME");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_DISK_file_test (sqlite_filename))
  {
    if (GNUNET_OK !=
        GNUNET_DISK_directory_create_for_file (sqlite_filename))
    {
      GNUNET_break (0);
      GNUNET_free (sqlite_filename);
      return GNUNET_SYSERR;
    }
  }
  /* sqlite_filename should be UTF-8-encoded. If it isn't, it's a bug */
  plugin->fn = sqlite_filename;

  /* Open database and precompile statements */
  if (SQLITE_OK !=
      sqlite3_open (plugin->fn,
                    &plugin->dbh))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Unable to initialize SQLite: %s.\n"),
         sqlite3_errmsg (plugin->dbh));
    return GNUNET_SYSERR;
  }
  GNUNET_break (SQLITE_OK ==
                sqlite3_busy_timeout (plugin->dbh,
                                      BUSY_TIMEOUT_MS));
  if (GNUNET_OK !=
      GNUNET_SQ_exec_statements (plugin->dbh,
                                 es))
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Failed to setup database at `%s'\n"),
         plugin->fn);
    return GNUNET_SYSERR;
  }

  if (GNUNET_OK !=
      GNUNET_SQ_prepare (plugin->dbh,
                         ps))
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Failed to setup database at `%s'\n"),
         plugin->fn);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Shutdown database connection and associate data
 * structures.
 * @param plugin the plugin context (state for this module)
 */
static void
database_shutdown (struct Plugin *plugin)
{
  int result;
  sqlite3_stmt *stmt;

  if (NULL != plugin->store_records)
    sqlite3_finalize (plugin->store_records);
  if (NULL != plugin->delete_records)
    sqlite3_finalize (plugin->delete_records);
  if (NULL != plugin->iterate_zone)
    sqlite3_finalize (plugin->iterate_zone);
  if (NULL != plugin->iterate_all_zones)
    sqlite3_finalize (plugin->iterate_all_zones);
  if (NULL != plugin->zone_to_name)
    sqlite3_finalize (plugin->zone_to_name);
  if (NULL != plugin->lookup_label)
    sqlite3_finalize (plugin->lookup_label);
  result = sqlite3_close (plugin->dbh);
  if (result == SQLITE_BUSY)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ (
           "Tried to close sqlite without finalizing all prepared statements.\n"));
    stmt = sqlite3_next_stmt (plugin->dbh,
                              NULL);
    while (NULL != stmt)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "sqlite",
                       "Closing statement %p\n",
                       stmt);
      result = sqlite3_finalize (stmt);
      if (result != SQLITE_OK)
        GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
                         "sqlite",
                         "Failed to close statement %p: %d\n",
                         stmt,
                         result);
      stmt = sqlite3_next_stmt (plugin->dbh,
                                NULL);
    }
    result = sqlite3_close (plugin->dbh);
  }
  if (SQLITE_OK != result)
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite3_close");

  GNUNET_free_non_null (plugin->fn);
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
namestore_sqlite_store_records (void *cls,
                                const struct
                                GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                                const char *label,
                                unsigned int rd_count,
                                const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Plugin *plugin = cls;
  int n;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  uint64_t rvalue;
  ssize_t data_size;

  memset (&pkey,
          0,
          sizeof(pkey));
  for (unsigned int i = 0; i < rd_count; i++)
    if (GNUNET_GNSRECORD_TYPE_PKEY == rd[i].record_type)
    {
      GNUNET_break (sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey) ==
                    rd[i].data_size);
      GNUNET_memcpy (&pkey,
                     rd[i].data,
                     rd[i].data_size);
      break;
    }
  rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                     UINT64_MAX);
  data_size = GNUNET_GNSRECORD_records_get_size (rd_count,
                                                 rd);
  if (data_size < 0)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (data_size > 64 * 65536)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  {
    /* First delete 'old' records */
    char data[data_size];
    struct GNUNET_SQ_QueryParam dparams[] = {
      GNUNET_SQ_query_param_auto_from_type (zone_key),
      GNUNET_SQ_query_param_string (label),
      GNUNET_SQ_query_param_end
    };
    ssize_t ret;

    ret = GNUNET_GNSRECORD_records_serialize (rd_count,
                                              rd,
                                              data_size,
                                              data);
    if ((ret < 0) ||
        (data_size != ret))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK !=
        GNUNET_SQ_bind (plugin->delete_records,
                        dparams))
    {
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_bind_XXXX");
      GNUNET_SQ_reset (plugin->dbh,
                       plugin->delete_records);
      return GNUNET_SYSERR;
    }
    n = sqlite3_step (plugin->delete_records);
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->delete_records);

    if (0 != rd_count)
    {
      uint32_t rd_count32 = (uint32_t) rd_count;
      struct GNUNET_SQ_QueryParam sparams[] = {
        GNUNET_SQ_query_param_auto_from_type (zone_key),
        GNUNET_SQ_query_param_auto_from_type (&pkey),
        GNUNET_SQ_query_param_uint64 (&rvalue),
        GNUNET_SQ_query_param_uint32 (&rd_count32),
        GNUNET_SQ_query_param_fixed_size (data, data_size),
        GNUNET_SQ_query_param_string (label),
        GNUNET_SQ_query_param_end
      };

      if (GNUNET_OK !=
          GNUNET_SQ_bind (plugin->store_records,
                          sparams))
      {
        LOG_SQLITE (plugin,
                    GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                    "sqlite3_bind_XXXX");
        GNUNET_SQ_reset (plugin->dbh,
                         plugin->store_records);
        return GNUNET_SYSERR;
      }
      n = sqlite3_step (plugin->store_records);
      GNUNET_SQ_reset (plugin->dbh,
                       plugin->store_records);
    }
  }
  switch (n)
  {
  case SQLITE_DONE:
    if (0 != rd_count)
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "sqlite",
                       "Record stored\n");
    else
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "sqlite",
                       "Record deleted\n");
    return GNUNET_OK;

  case SQLITE_BUSY:
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    return GNUNET_NO;

  default:
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    return GNUNET_SYSERR;
  }
}


/**
 * The given 'sqlite' statement has been prepared to be run.
 * It will return a record which should be given to the iterator.
 * Runs the statement and parses the returned record.
 *
 * @param plugin plugin context
 * @param stmt to run (and then clean up)
 * @param zone_key private key of the zone
 * @param limit maximum number of results to fetch
 * @param iter iterator to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
 */
static int
get_records_and_call_iterator (struct Plugin *plugin,
                               sqlite3_stmt *stmt,
                               const struct
                               GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                               uint64_t limit,
                               GNUNET_NAMESTORE_RecordIterator iter,
                               void *iter_cls)
{
  int ret;
  int sret;

  ret = GNUNET_OK;
  for (uint64_t i = 0; i < limit; i++)
  {
    sret = sqlite3_step (stmt);

    if (SQLITE_DONE == sret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Iteration done (no results)\n");
      ret = GNUNET_NO;
      break;
    }
    if (SQLITE_ROW != sret)
    {
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR,
                  "sqlite_step");
      ret = GNUNET_SYSERR;
      break;
    }

    {
      uint64_t seq;
      uint32_t record_count;
      size_t data_size;
      void *data;
      char *label;
      struct GNUNET_CRYPTO_EcdsaPrivateKey zk;
      struct GNUNET_SQ_ResultSpec rs[] = {
        GNUNET_SQ_result_spec_uint64 (&seq),
        GNUNET_SQ_result_spec_uint32 (&record_count),
        GNUNET_SQ_result_spec_variable_size (&data,
                                             &data_size),
        GNUNET_SQ_result_spec_string (&label),
        GNUNET_SQ_result_spec_end
      };
      struct GNUNET_SQ_ResultSpec rsx[] = {
        GNUNET_SQ_result_spec_uint64 (&seq),
        GNUNET_SQ_result_spec_uint32 (&record_count),
        GNUNET_SQ_result_spec_variable_size (&data,
                                             &data_size),
        GNUNET_SQ_result_spec_string (&label),
        GNUNET_SQ_result_spec_auto_from_type (&zk),
        GNUNET_SQ_result_spec_end
      };

      ret = GNUNET_SQ_extract_result (stmt,
                                      (NULL == zone_key)
                                      ? rsx
                                      : rs);
      if ((GNUNET_OK != ret) ||
          (record_count > 64 * 1024))
      {
        /* sanity check, don't stack allocate far too much just
           because database might contain a large value here */
        GNUNET_break (0);
        ret = GNUNET_SYSERR;
        break;
      }
      else
      {
        struct GNUNET_GNSRECORD_Data rd[record_count];

        GNUNET_assert (0 != seq);
        if (GNUNET_OK !=
            GNUNET_GNSRECORD_records_deserialize (data_size,
                                                  data,
                                                  record_count,
                                                  rd))
        {
          GNUNET_break (0);
          ret = GNUNET_SYSERR;
          break;
        }
        else
        {
          if (NULL != zone_key)
            zk = *zone_key;
          if (NULL != iter)
            iter (iter_cls,
                  seq,
                  &zk,
                  label,
                  record_count,
                  rd);
        }
      }
      GNUNET_SQ_cleanup_result (rs);
    }
  }
  GNUNET_SQ_reset (plugin->dbh,
                   stmt);
  return ret;
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
namestore_sqlite_lookup_records (void *cls,
                                 const struct
                                 GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                                 const char *label,
                                 GNUNET_NAMESTORE_RecordIterator iter,
                                 void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_auto_from_type (zone),
    GNUNET_SQ_query_param_string (label),
    GNUNET_SQ_query_param_end
  };

  if (NULL == zone)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->lookup_label,
                      params))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->lookup_label);
    return GNUNET_SYSERR;
  }
  return get_records_and_call_iterator (plugin,
                                        plugin->lookup_label,
                                        zone,
                                        1,
                                        iter,
                                        iter_cls);
}


/**
 * Iterate over the results for a particular key and zone in the
 * datastore.  Will return at most one result to the iterator.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone, NULL to iterate over all zones
 * @param serial serial number to exclude in the list of all matching records
 * @param limit maximum number of results to return
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no more results, #GNUNET_SYSERR on error
 */
static int
namestore_sqlite_iterate_records (void *cls,
                                  const struct
                                  GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                                  uint64_t serial,
                                  uint64_t limit,
                                  GNUNET_NAMESTORE_RecordIterator iter,
                                  void *iter_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  int err;

  if (NULL == zone)
  {
    struct GNUNET_SQ_QueryParam params[] = {
      GNUNET_SQ_query_param_uint64 (&serial),
      GNUNET_SQ_query_param_uint64 (&limit),
      GNUNET_SQ_query_param_end
    };

    stmt = plugin->iterate_all_zones;
    err = GNUNET_SQ_bind (stmt,
                          params);
  }
  else
  {
    struct GNUNET_SQ_QueryParam params[] = {
      GNUNET_SQ_query_param_auto_from_type (zone),
      GNUNET_SQ_query_param_uint64 (&serial),
      GNUNET_SQ_query_param_uint64 (&limit),
      GNUNET_SQ_query_param_end
    };

    stmt = plugin->iterate_zone;
    err = GNUNET_SQ_bind (stmt,
                          params);
  }
  if (GNUNET_OK != err)
  {
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    GNUNET_SQ_reset (plugin->dbh,
                     stmt);
    return GNUNET_SYSERR;
  }
  return get_records_and_call_iterator (plugin,
                                        stmt,
                                        zone,
                                        limit,
                                        iter,
                                        iter_cls);
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
namestore_sqlite_zone_to_name (void *cls,
                               const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                               const struct
                               GNUNET_CRYPTO_EcdsaPublicKey *value_zone,
                               GNUNET_NAMESTORE_RecordIterator iter,
                               void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_auto_from_type (zone),
    GNUNET_SQ_query_param_auto_from_type (value_zone),
    GNUNET_SQ_query_param_end
  };

  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->zone_to_name,
                      params))
  {
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->zone_to_name);
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Performing reverse lookup for `%s'\n",
       GNUNET_GNSRECORD_z2s (value_zone));
  return get_records_and_call_iterator (plugin,
                                        plugin->zone_to_name,
                                        zone,
                                        1,
                                        iter,
                                        iter_cls);
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_NAMESTORE_PluginEnvironment*"
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_namestore_sqlite_init (void *cls)
{
  static struct Plugin plugin;
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_NAMESTORE_PluginFunctions *api;

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin,
          0,
          sizeof(struct Plugin));
  plugin.cfg = cfg;
  if (GNUNET_OK != database_setup (&plugin))
  {
    database_shutdown (&plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_NAMESTORE_PluginFunctions);
  api->cls = &plugin;
  api->store_records = &namestore_sqlite_store_records;
  api->iterate_records = &namestore_sqlite_iterate_records;
  api->zone_to_name = &namestore_sqlite_zone_to_name;
  api->lookup_records = &namestore_sqlite_lookup_records;
  LOG (GNUNET_ERROR_TYPE_INFO,
       _ ("Sqlite database running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_namestore_sqlite_done (void *cls)
{
  struct GNUNET_NAMESTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sqlite plugin is finished\n");
  return NULL;
}


/* end of plugin_namestore_sqlite.c */
