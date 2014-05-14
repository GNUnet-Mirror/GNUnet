/*
 * This file is part of GNUnet
 * (C) 2013 Christian Grothoff (and other contributing authors)
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
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
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

};

/**
 * Iterate over the records given an optional peer id
 * and/or key.
 *
 * @param cls closure (internal context for the plugin)
 * @param sub_system name of sub system
 * @param peer Peer identity (can be NULL)
 * @param key entry key string (can be NULL)
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
peerstore_sqlite_iterate_records (void *cls,
    const char *sub_system,
    const struct GNUNET_PeerIdentity *peer,
    const char *key,
    GNUNET_PEERSTORE_RecordIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  int err = 0;
  int sret;
  const char *ret_sub_system;
  const struct GNUNET_PeerIdentity *ret_peer;
  const char *ret_key;
  const void *ret_value;
  size_t ret_value_size;

  if(NULL == peer && NULL == key)
  {
    stmt = plugin->select_peerstoredata;
    err = (SQLITE_OK != sqlite3_bind_text(stmt, 1, sub_system, strlen(sub_system) + 1, SQLITE_STATIC));
  }
  else if(NULL == key)
  {
    stmt = plugin->select_peerstoredata_by_pid;
    err = (SQLITE_OK != sqlite3_bind_text(stmt, 1, sub_system, strlen(sub_system) + 1, SQLITE_STATIC))
        || (SQLITE_OK != sqlite3_bind_blob(stmt, 2, peer, sizeof(struct GNUNET_PeerIdentity), SQLITE_STATIC));
  }
  else if(NULL == peer)
  {
    stmt = plugin->select_peerstoredata_by_key;
    err = (SQLITE_OK != sqlite3_bind_text(stmt, 1, sub_system, strlen(sub_system) + 1, SQLITE_STATIC))
        || (SQLITE_OK != sqlite3_bind_text(stmt, 3, key, strlen(key) + 1, SQLITE_STATIC));
  }
  else
  {
    stmt = plugin->select_peerstoredata_by_all;
    err = (SQLITE_OK != sqlite3_bind_text(stmt, 1, sub_system, strlen(sub_system) + 1, SQLITE_STATIC))
            || (SQLITE_OK != sqlite3_bind_blob(stmt, 2, peer, sizeof(struct GNUNET_PeerIdentity), SQLITE_STATIC))
            || (SQLITE_OK != sqlite3_bind_text(stmt, 3, key, strlen(key) + 1, SQLITE_STATIC));
  }

  if (err)
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
    "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin,
      GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
      "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  while (SQLITE_ROW == (sret = sqlite3_step (stmt)))
  {
    ret_sub_system = (const char *)sqlite3_column_text(stmt, 0);
    ret_peer = sqlite3_column_blob(stmt, 1);
    ret_key = (const char *)sqlite3_column_text(stmt, 2);
    ret_value = sqlite3_column_blob(stmt, 3);
    ret_value_size = sqlite3_column_bytes(stmt, 3);
    if (NULL != iter)
      iter (iter_cls, ret_sub_system, ret_peer, ret_key, ret_value, ret_value_size);
  }
  if (SQLITE_DONE != sret)
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite_step");
    err = 1;
  }
  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin,
    GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
    "sqlite3_reset");
    err = 1;
  }
  if(err)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}

/**
 * Store a record in the peerstore.
 * Key is the combination of sub system and peer identity.
 * One key can store multiple values.
 *
 * @param cls closure (internal context for the plugin)
 * @param peer peer identity
 * @param sub_system name of the GNUnet sub system responsible
 * @param value value to be stored
 * @param size size of value to be stored
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
peerstore_sqlite_store_record(void *cls,
    const char *sub_system,
    const struct GNUNET_PeerIdentity *peer,
    const char *key,
    const void *value,
    size_t size)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->insert_peerstoredata;

  //FIXME: check if value exists with the same key first

  if(SQLITE_OK != sqlite3_bind_text(stmt, 1, sub_system, strlen(sub_system) + 1, SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_blob(stmt, 2, peer, sizeof(struct GNUNET_PeerIdentity), SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_text(stmt, 3, key, strlen(key) + 1, SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_blob(stmt, 4, value, size, SQLITE_STATIC))
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
sql_exec (sqlite3 *dbh, const char *sql)
{
  int result;

  result = sqlite3_exec (dbh, sql, NULL, NULL, NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Executed `%s' / %d\n", sql, result);
  if (result != SQLITE_OK)
    LOG (GNUNET_ERROR_TYPE_ERROR,
   _("Error executing SQL query: %s\n  %s\n"),
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
sql_prepare (sqlite3 *dbh, const char *sql, sqlite3_stmt **stmt)
{
  char *tail;
  int result;

  result = sqlite3_prepare_v2 (dbh, sql, strlen (sql), stmt,
                               (const char **) &tail);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Prepared `%s' / %p: %d\n", sql, *stmt, result);
  if (result != SQLITE_OK)
    LOG (GNUNET_ERROR_TYPE_ERROR,
   _("Error preparing SQL query: %s\n  %s\n"),
   sqlite3_errmsg (dbh), sql);
  return result;
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
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
             "peerstore-sqlite", "FILENAME");
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
    LOG (GNUNET_ERROR_TYPE_ERROR,
   _("Unable to initialize SQLite: %s.\n"),
   sqlite3_errmsg (plugin->dbh));
    return GNUNET_SYSERR;
  }

  sql_exec (plugin->dbh, "PRAGMA temp_store=MEMORY");
  sql_exec (plugin->dbh, "PRAGMA synchronous=NORMAL");
  sql_exec (plugin->dbh, "PRAGMA legacy_file_format=OFF");
  sql_exec (plugin->dbh, "PRAGMA auto_vacuum=INCREMENTAL");
  sql_exec (plugin->dbh, "PRAGMA encoding=\"UTF-8\"");
  sql_exec (plugin->dbh, "PRAGMA count_changes=OFF");
  sql_exec (plugin->dbh, "PRAGMA page_size=4096");

  sqlite3_busy_timeout (plugin->dbh, BUSY_TIMEOUT_MS);

  /* Create tables */

  sql_exec (plugin->dbh,
      "CREATE TABLE IF NOT EXISTS peerstoredata (\n"
      "  sub_system TEXT NOT NULL,\n"
      "  peer_id BLOB NOT NULL,\n"
      "  key TEXT NOT NULL,\n"
      "  value BLOB NULL"
      ");");

  /* Prepare statements */

  sql_prepare (plugin->dbh,
      "INSERT INTO peerstoredata (sub_system, peer_id, key, value) VALUES (?,?,?,?);",
      &plugin->insert_peerstoredata);
  sql_prepare(plugin->dbh,
      "SELECT peer_id, sub_system, value FROM peerstoredata"
      " WHERE sub_system = ?",
      &plugin->select_peerstoredata);
  sql_prepare(plugin->dbh,
      "SELECT peer_id, sub_system, value FROM peerstoredata"
      " WHERE sub_system = ?"
      " AND peer_id = ?",
      &plugin->select_peerstoredata_by_pid);
  sql_prepare(plugin->dbh,
      "SELECT peer_id, sub_system, value FROM peerstoredata"
      " WHERE sub_system = ?"
      " AND key = ?",
      &plugin->select_peerstoredata_by_key);
  sql_prepare(plugin->dbh,
      "SELECT peer_id, sub_system, value FROM peerstoredata"
      " WHERE sub_system = ?"
      " AND peer_id = ?"
      " AND key = ?",
      &plugin->select_peerstoredata_by_all);

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
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Failed to close statement %p: %d\n", stmt, result);
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
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Sqlite plugin is running\n");
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
