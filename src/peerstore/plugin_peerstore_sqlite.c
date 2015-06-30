/*
 * This file is part of GNUnet
 * Copyright (C) 2013 Christian Grothoff (and other contributing authors)
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
 * @file peerstore/plugin_peerstore_sqlite.c
 * @brief sqlite-based peerstore backend
 * @author Omar Tarabai
 */

#include "platform.h"
#include "gnunet_peerstore_plugin.h"
#include "gnunet_peerstore_service.h"
#include "peerstore.h"
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
#define LOG_SQLITE(db, level, cmd) do { GNUNET_log_from (level, "peerstore-sqlite", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); } while(0)

#define LOG(kind,...) GNUNET_log_from (kind, "peerstore-sqlite", __VA_ARGS__)

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
   * Database filename.
   */
  char *fn;

  /**
   * Native SQLite database handle.
   */
  sqlite3 *dbh;

  /**
   * Precompiled SQL for inserting into peerstoredata
   */
  sqlite3_stmt *insert_peerstoredata;

  /**
   * Precompiled SQL for selecting from peerstoredata
   */
  sqlite3_stmt *select_peerstoredata;

  /**
   * Precompiled SQL for selecting from peerstoredata
   */
  sqlite3_stmt *select_peerstoredata_by_pid;

  /**
   * Precompiled SQL for selecting from peerstoredata
   */
  sqlite3_stmt *select_peerstoredata_by_key;

  /**
   * Precompiled SQL for selecting from peerstoredata
   */
  sqlite3_stmt *select_peerstoredata_by_all;

  /**
   * Precompiled SQL for deleting expired
   * records from peerstoredata
   */
  sqlite3_stmt *expire_peerstoredata;

  /**
   * Precompiled SQL for deleting records
   * with given key
   */
  sqlite3_stmt *delete_peerstoredata;

};

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
peerstore_sqlite_delete_records (void *cls, const char *sub_system,
                                 const struct GNUNET_PeerIdentity *peer,
                                 const char *key)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->delete_peerstoredata;

  if ((SQLITE_OK !=
       sqlite3_bind_text (stmt, 1, sub_system, strlen (sub_system) + 1,
                          SQLITE_STATIC)) ||
      (SQLITE_OK !=
       sqlite3_bind_blob (stmt, 2, peer, sizeof (struct GNUNET_PeerIdentity),
                          SQLITE_STATIC)) ||
      (SQLITE_OK !=
       sqlite3_bind_text (stmt, 3, key, strlen (key) + 1, SQLITE_STATIC)))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else if (SQLITE_DONE != sqlite3_step (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
  }
  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
    return 0;
  }
  return sqlite3_changes (plugin->dbh);
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
peerstore_sqlite_expire_records (void *cls, struct GNUNET_TIME_Absolute now,
                                 GNUNET_PEERSTORE_Continuation cont,
                                 void *cont_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->expire_peerstoredata;

  if (SQLITE_OK !=
      sqlite3_bind_int64 (stmt, 1, (sqlite3_uint64) now.abs_value_us))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else if (SQLITE_DONE != sqlite3_step (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
  }
  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  if (NULL != cont)
  {
    cont (cont_cls, sqlite3_changes (plugin->dbh));
  }
  return GNUNET_OK;
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
peerstore_sqlite_iterate_records (void *cls, const char *sub_system,
                                  const struct GNUNET_PeerIdentity *peer,
                                  const char *key,
                                  GNUNET_PEERSTORE_Processor iter,
                                  void *iter_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  int err = 0;
  int sret;
  struct GNUNET_PEERSTORE_Record *ret;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Executing iterate request on sqlite db.\n");
  if (NULL == peer && NULL == key)
  {
    stmt = plugin->select_peerstoredata;
    err =
        (SQLITE_OK !=
         sqlite3_bind_text (stmt, 1, sub_system, strlen (sub_system) + 1,
                            SQLITE_STATIC));
  }
  else if (NULL == key)
  {
    stmt = plugin->select_peerstoredata_by_pid;
    err =
        (SQLITE_OK !=
         sqlite3_bind_text (stmt, 1, sub_system, strlen (sub_system) + 1,
                            SQLITE_STATIC)) ||
        (SQLITE_OK !=
         sqlite3_bind_blob (stmt, 2, peer, sizeof (struct GNUNET_PeerIdentity),
                            SQLITE_STATIC));
  }
  else if (NULL == peer)
  {
    stmt = plugin->select_peerstoredata_by_key;
    err =
        (SQLITE_OK !=
         sqlite3_bind_text (stmt, 1, sub_system, strlen (sub_system) + 1,
                            SQLITE_STATIC)) ||
        (SQLITE_OK !=
         sqlite3_bind_text (stmt, 2, key, strlen (key) + 1, SQLITE_STATIC));
  }
  else
  {
    stmt = plugin->select_peerstoredata_by_all;
    err =
        (SQLITE_OK !=
         sqlite3_bind_text (stmt, 1, sub_system, strlen (sub_system) + 1,
                            SQLITE_STATIC)) ||
        (SQLITE_OK !=
         sqlite3_bind_blob (stmt, 2, peer, sizeof (struct GNUNET_PeerIdentity),
                            SQLITE_STATIC)) ||
        (SQLITE_OK !=
         sqlite3_bind_text (stmt, 3, key, strlen (key) + 1, SQLITE_STATIC));
  }

  if (err)
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  while (SQLITE_ROW == (sret = sqlite3_step (stmt)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Returning a matched record.\n");
    ret = GNUNET_new (struct GNUNET_PEERSTORE_Record);

    ret->sub_system = (char *) sqlite3_column_text (stmt, 0);
    ret->peer = (struct GNUNET_PeerIdentity *) sqlite3_column_blob (stmt, 1);
    ret->key = (char *) sqlite3_column_text (stmt, 2);
    ret->value = (void *) sqlite3_column_blob (stmt, 3);
    ret->value_size = sqlite3_column_bytes (stmt, 3);
    ret->expiry = GNUNET_new (struct GNUNET_TIME_Absolute);

    ret->expiry->abs_value_us = (uint64_t) sqlite3_column_int64 (stmt, 4);
    if (NULL != iter)
      iter (iter_cls, ret, NULL);
    GNUNET_free (ret->expiry);
    GNUNET_free (ret);
  }
  if (SQLITE_DONE != sret)
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite_step");
    err = 1;
  }
  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
    err = 1;
  }
  if (NULL != iter)
  {
    iter (iter_cls, NULL, err ? "sqlite error" : NULL);
  }
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
peerstore_sqlite_store_record (void *cls, const char *sub_system,
                               const struct GNUNET_PeerIdentity *peer,
                               const char *key, const void *value, size_t size,
                               struct GNUNET_TIME_Absolute expiry,
                               enum GNUNET_PEERSTORE_StoreOption options,
                               GNUNET_PEERSTORE_Continuation cont,
                               void *cont_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->insert_peerstoredata;

  if (GNUNET_PEERSTORE_STOREOPTION_REPLACE == options)
  {
    peerstore_sqlite_delete_records (cls, sub_system, peer, key);
  }
  if (SQLITE_OK !=
      sqlite3_bind_text (stmt, 1, sub_system, strlen (sub_system) + 1,
                         SQLITE_STATIC) ||
      SQLITE_OK != sqlite3_bind_blob (stmt, 2, peer,
                                      sizeof (struct GNUNET_PeerIdentity),
                                      SQLITE_STATIC) ||
      SQLITE_OK != sqlite3_bind_text (stmt, 3, key, strlen (key) + 1,
                                      SQLITE_STATIC) ||
      SQLITE_OK != sqlite3_bind_blob (stmt, 4, value, size, SQLITE_STATIC) ||
      SQLITE_OK != sqlite3_bind_int64 (stmt, 5,
                                       (sqlite3_uint64) expiry.abs_value_us))
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  else if (SQLITE_DONE != sqlite3_step (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
  }
  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  if (NULL != cont)
  {
    cont (cont_cls, GNUNET_OK);
  }
  return GNUNET_OK;
}


/**
 * @brief Prepare a SQL statement
 *
 * @param dbh handle to the database
 * @param sql SQL statement, UTF-8 encoded
 * @return 0 on success
 */
static int
sql_exec (sqlite3 * dbh, const char *sql)
{
  int result;

  result = sqlite3_exec (dbh, sql, NULL, NULL, NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Executed `%s' / %d\n", sql, result);
  if (result != SQLITE_OK)
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Error executing SQL query: %s\n  %s\n"),
         sqlite3_errmsg (dbh), sql);
  return result;
}


/**
 * @brief Prepare a SQL statement
 *
 * @param dbh handle to the database
 * @param sql SQL statement, UTF-8 encoded
 * @param stmt set to the prepared statement
 * @return 0 on success
 */
static int
sql_prepare (sqlite3 * dbh, const char *sql, sqlite3_stmt ** stmt)
{
  char *tail;
  int result;

  result =
      sqlite3_prepare_v2 (dbh, sql, strlen (sql), stmt, (const char **) &tail);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Prepared `%s' / %p: %d\n", sql, *stmt, result);
  if (result != SQLITE_OK)
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Error preparing SQL query: %s\n  %s\n"),
         sqlite3_errmsg (dbh), sql);
  return result;
}


/**
 * sqlite3 custom function for comparison of uint64_t values
 * since it is not supported by default
 */
void
sqlite3_lessthan (sqlite3_context * ctx, int dummy, sqlite3_value ** values)
{
  uint64_t v1;
  uint64_t v2;

  v1 = (uint64_t) sqlite3_value_int64 (values[0]);
  v2 = (uint64_t) sqlite3_value_int64 (values[1]);
  sqlite3_result_int (ctx, v1 < v2);
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
  char *filename;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->cfg, "peerstore-sqlite",
                                               "FILENAME", &filename))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "peerstore-sqlite",
                               "FILENAME");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_DISK_file_test (filename))
  {
    if (GNUNET_OK != GNUNET_DISK_directory_create_for_file (filename))
    {
      GNUNET_break (0);
      GNUNET_free (filename);
      return GNUNET_SYSERR;
    }
  }
  /* filename should be UTF-8-encoded. If it isn't, it's a bug */
  plugin->fn = filename;
  /* Open database and precompile statements */
  if (SQLITE_OK != sqlite3_open (plugin->fn, &plugin->dbh))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Unable to initialize SQLite: %s.\n"),
         sqlite3_errmsg (plugin->dbh));
    return GNUNET_SYSERR;
  }
  sql_exec (plugin->dbh, "PRAGMA temp_store=MEMORY");
  sql_exec (plugin->dbh, "PRAGMA synchronous=OFF");
  sql_exec (plugin->dbh, "PRAGMA legacy_file_format=OFF");
  sql_exec (plugin->dbh, "PRAGMA auto_vacuum=INCREMENTAL");
  sql_exec (plugin->dbh, "PRAGMA encoding=\"UTF-8\"");
  sql_exec (plugin->dbh, "PRAGMA page_size=4096");
  sqlite3_busy_timeout (plugin->dbh, BUSY_TIMEOUT_MS);
  /* Create tables */
  sql_exec (plugin->dbh,
            "CREATE TABLE IF NOT EXISTS peerstoredata (\n"
            "  sub_system TEXT NOT NULL,\n" "  peer_id BLOB NOT NULL,\n"
            "  key TEXT NOT NULL,\n" "  value BLOB NULL,\n"
            "  expiry sqlite3_uint64 NOT NULL" ");");
  sqlite3_create_function (plugin->dbh, "UINT64_LT", 2, SQLITE_UTF8, NULL,
                           &sqlite3_lessthan, NULL, NULL);
  /* Create Indices */
  if (SQLITE_OK !=
      sqlite3_exec (plugin->dbh,
                    "CREATE INDEX IF NOT EXISTS peerstoredata_key_index ON peerstoredata (sub_system, peer_id, key)",
                    NULL, NULL, NULL))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Unable to create indices: %s.\n"),
         sqlite3_errmsg (plugin->dbh));
    return GNUNET_SYSERR;
  }
  /* Prepare statements */

  sql_prepare (plugin->dbh,
               "INSERT INTO peerstoredata (sub_system, peer_id, key, value, expiry) VALUES (?,?,?,?,?);",
               &plugin->insert_peerstoredata);
  sql_prepare (plugin->dbh,
               "SELECT * FROM peerstoredata" " WHERE sub_system = ?",
               &plugin->select_peerstoredata);
  sql_prepare (plugin->dbh,
               "SELECT * FROM peerstoredata" " WHERE sub_system = ?"
               " AND peer_id = ?", &plugin->select_peerstoredata_by_pid);
  sql_prepare (plugin->dbh,
               "SELECT * FROM peerstoredata" " WHERE sub_system = ?"
               " AND key = ?", &plugin->select_peerstoredata_by_key);
  sql_prepare (plugin->dbh,
               "SELECT * FROM peerstoredata" " WHERE sub_system = ?"
               " AND peer_id = ?" " AND key = ?",
               &plugin->select_peerstoredata_by_all);
  sql_prepare (plugin->dbh,
               "DELETE FROM peerstoredata" " WHERE UINT64_LT(expiry, ?)",
               &plugin->expire_peerstoredata);
  sql_prepare (plugin->dbh,
               "DELETE FROM peerstoredata" " WHERE sub_system = ?"
               " AND peer_id = ?" " AND key = ?",
               &plugin->delete_peerstoredata);
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

  while (NULL != (stmt = sqlite3_next_stmt (plugin->dbh, NULL)))
  {
    result = sqlite3_finalize (stmt);
    if (SQLITE_OK != result)
      LOG (GNUNET_ERROR_TYPE_WARNING, "Failed to close statement %p: %d\n",
           stmt, result);
  }
  if (SQLITE_OK != sqlite3_close (plugin->dbh))
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite3_close");
  GNUNET_free_non_null (plugin->fn);
}


/**
 * Entry point for the plugin.
 *
 * @param cls The struct GNUNET_CONFIGURATION_Handle.
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_peerstore_sqlite_init (void *cls)
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
  api->store_record = &peerstore_sqlite_store_record;
  api->iterate_records = &peerstore_sqlite_iterate_records;
  api->expire_records = &peerstore_sqlite_expire_records;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sqlite plugin is running\n");
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls The plugin context (as returned by "init")
 * @return Always NULL
 */
void *
libgnunet_plugin_peerstore_sqlite_done (void *cls)
{
  struct GNUNET_PEERSTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sqlite plugin is finished\n");
  return NULL;
}

/* end of plugin_peerstore_sqlite.c */
