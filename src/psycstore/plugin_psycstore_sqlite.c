 /*
  * This file is part of GNUnet
  * (C) 2009-2013 Christian Grothoff (and other contributing authors)
  *
  * GNUnet is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published
  * by the Free Software Foundation; either version 3, or (at your
  * option) any later version.
  *
  * GNUnet is distributed in the hope that it will be useful, but
  * WITHOUT ANY WARRANTY; without even the implied warranty of
t  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  * General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with GNUnet; see the file COPYING.  If not, write to the
  * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
  * Boston, MA 02111-1307, USA.
  */

/**
 * @file psycstore/plugin_psycstore_sqlite.c
 * @brief sqlite-based psycstore backend
 * @author Gabor X Toth
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_psycstore_plugin.h"
#include "gnunet_psycstore_service.h"
#include "psycstore.h"
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
#define LOG_SQLITE(db, level, cmd) do { GNUNET_log_from (level, "psycstore-sqlite", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); } while(0)

#define LOG(kind,...) GNUNET_log_from (kind, "psycstore-sqlite", __VA_ARGS__)


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
   * Precompiled SQL for channel_key_store()
   */
  sqlite3_stmt *insert_channel_key;

  /**
   * Precompiled SQL for slave_key_store()
   */
  sqlite3_stmt *insert_slave_key;


  /**
   * Precompiled SQL for membership_store()
   */
  sqlite3_stmt *insert_membership;

  /**
   * Precompiled SQL for membership_test()
   */
  sqlite3_stmt *select_membership;


  /**
   * Precompiled SQL for fragment_store()
   */
  sqlite3_stmt *insert_fragment;

  /**
   * Precompiled SQL for fragment_add_flags()
   */
  sqlite3_stmt *update_fragment_flags;

  /**
   * Precompiled SQL for fragment_get()
   */
  sqlite3_stmt *select_fragment;

  /**
   * Precompiled SQL for message_get()
   */
  sqlite3_stmt *select_message;

  /**
   * Precompiled SQL for message_get_fragment()
   */
  sqlite3_stmt *select_message_fragment;

  /**
   * Precompiled SQL for counters_get_master()
   */
  sqlite3_stmt *select_master_counters;

  /**
   * Precompiled SQL for counters_get_slave()
   */
  sqlite3_stmt *select_slave_counters;


  /**
   * Precompiled SQL for state_set()
   */
  sqlite3_stmt *insert_state_current;

  /**
   * Precompiled SQL for state_set()
   */
  sqlite3_stmt *update_state_current;

  /**
   * Precompiled SQL for state_set_signed()
   */
  sqlite3_stmt *update_state_signed;

  /**
   * Precompiled SQL for state_sync()
   */
  sqlite3_stmt *insert_state_sync;

  /**
   * Precompiled SQL for state_sync()
   */
  sqlite3_stmt *delete_state;

  /**
   * Precompiled SQL for state_sync()
   */
  sqlite3_stmt *insert_state_from_sync;

  /**
   * Precompiled SQL for state_sync()
   */
  sqlite3_stmt *delete_state_sync;

  /**
   * Precompiled SQL for state_get()
   */
  sqlite3_stmt *select_state_one;

  /**
   * Precompiled SQL for state_get_all()
   */
  sqlite3_stmt *select_state_prefix;

};


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
 * @brief Prepare a SQL statement
 *
 * @param dbh handle to the database
 * @param zSql SQL statement, UTF-8 encoded
 * @param ppStmt set to the prepared statement
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
      GNUNET_CONFIGURATION_get_value_filename (plugin->cfg, "psycstore-sqlite",
                                               "FILENAME", &filename))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "psycstore-sqlite", "FILENAME");
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
  if (sqlite3_open (plugin->fn, &plugin->dbh) != SQLITE_OK)
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
  sql_exec (plugin->dbh, "PRAGMA locking_mode=EXCLUSIVE");
  sql_exec (plugin->dbh, "PRAGMA count_changes=OFF");
  sql_exec (plugin->dbh, "PRAGMA page_size=4096");

  sqlite3_busy_timeout (plugin->dbh, BUSY_TIMEOUT_MS);

  /* Create tables */

  sql_exec (plugin->dbh,
            "CREATE TABLE IF NOT EXISTS channels ("
            "  id INTEGER PRIMARY KEY,"
            "  pub_key BLOB UNIQUE"
            ");");

  sql_exec (plugin->dbh,
            "CREATE TABLE IF NOT EXISTS slaves ("
            "  id INTEGER PRIMARY KEY,"
            "  pub_key BLOB UNIQUE"
            ");");

  sql_exec (plugin->dbh,
            "CREATE TABLE IF NOT EXISTS membership ("
            "  channel_id INTEGER NOT NULL REFERENCES channels(id),"
            "  slave_id INTEGER NOT NULL REFERENCES slaves(id),"
            "  did_join INTEGER NOT NULL,"
            "  announced_at INTEGER NOT NULL,"
            "  effective_since INTEGER NOT NULL,"
            "  group_generation INTEGER NOT NULL"
            ");");
  sql_exec (plugin->dbh,
            "CREATE INDEX IF NOT EXISTS idx_membership_channel_id_slave_id "
            "ON membership (channel_id, slave_id);");

  sql_exec (plugin->dbh,
            "CREATE TABLE IF NOT EXISTS messages ("
            "  channel_id INTEGER NOT NULL,"
            "  hop_counter INTEGER NOT NULL,"
            "  signature BLOB,"
            "  purpose BLOB,"
            "  fragment_id INTEGER NOT NULL,"
            "  fragment_offset INTEGER NOT NULL,"
            "  message_id INTEGER NOT NULL,"
            "  group_generation INTEGER NOT NULL,"
            "  multicast_flags INTEGER NOT NULL,"
            "  psyc_flags INTEGER NOT NULL,"
            "  data BLOB,"
            "  PRIMARY KEY (channel_id, fragment_id),"
            "  UNIQUE (channel_id, message_id, fragment_offset)"
            ");");

  sql_exec (plugin->dbh,
            "CREATE TABLE IF NOT EXISTS state ("
            "  channel_id INTEGER NOT NULL,"
            "  name TEXT NOT NULL,"
            "  value_current BLOB, "
            "  value_signed BLOB, "
            "  PRIMARY KEY (channel_id, name)"
            ");");

  sql_exec (plugin->dbh,
            "CREATE TABLE IF NOT EXISTS state_sync ("
            "  channel_id INTEGER NOT NULL,"
            "  name TEXT NOT NULL,"
            "  value BLOB, "
            "  PRIMARY KEY (channel_id, name)"
            ");");

  /* Prepare statements */

  sql_prepare (plugin->dbh,
               "INSERT OR IGNORE INTO channels (pub_key) VALUES (?);",
               &plugin->insert_channel_key);

  sql_prepare (plugin->dbh,
               "INSERT OR IGNORE INTO slaves (pub_key) VALUES (?);",
               &plugin->insert_slave_key);

  sql_prepare (plugin->dbh,
               "INSERT INTO membership "
               " (channel_id, slave_id, did_join, announced_at, "
               "  effective_since, group_generation) "
               "VALUES ((SELECT id FROM channels WHERE pub_key = ?), "
               "        (SELECT id FROM slaves WHERE pub_key = ?), "
               "        ?, ?, ?, ?);",
               &plugin->insert_membership);

  sql_prepare (plugin->dbh,
               "SELECT did_join FROM membership "
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?) "
               "      AND slave_id = ? AND effective_since <= ? "
               "ORDER BY announced_at DESC LIMIT 1;",
               &plugin->select_membership);

  sql_prepare (plugin->dbh,
               "INSERT INTO messages "
               " (channel_id, hop_counter, signature, purpose, "
               "  fragment_id, fragment_offset, message_id, "
               "  group_generation, multicast_flags, psyc_flags, data) "
               "VALUES ((SELECT id FROM channels WHERE pub_key = ?), "
               "        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
               &plugin->insert_fragment);

  sql_prepare (plugin->dbh,
               "UPDATE messages "
               "SET multicast_flags = multicast_flags | ?, "
               "    psyc_flags = psyc_flags | ? "
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?) "
               "      AND message_id = ?;",
               &plugin->update_fragment_flags);

  sql_prepare (plugin->dbh,
               "SELECT hop_counter, signature, purpose, "
               "       fragment_offset, message_id, group_generation, "
               "       multicast_flags, psyc_flags, data "
               "FROM messages "
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?) "
               "      AND fragment_id = ?;",
               &plugin->select_fragment);

  sql_prepare (plugin->dbh,
               "SELECT hop_counter, signature, purpose, "
               "       fragment_id, fragment_offset, group_generation, "
               "       multicast_flags, psyc_flags, data "
               "FROM messages "
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?) "
               "      AND message_id = ?;",
               &plugin->select_message);

  sql_prepare (plugin->dbh,
               "SELECT hop_counter, signature, purpose, "
               "       fragment_id, message_id, group_generation, "
               "       multicast_flags, psyc_flags, data "
               "FROM messages "
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?) "
               "      AND message_id = ? AND fragment_offset = ?;",
               &plugin->select_message_fragment);

  sql_prepare (plugin->dbh,
               "SELECT max(fragment_id), max(message_id), max(group_generation) "
               "FROM messages "
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
               &plugin->select_master_counters);

  sql_prepare (plugin->dbh,
               "SELECT max(message_id) "
               "FROM messages "
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?) "
               "      AND psyc_flags & ?;",
               &plugin->select_slave_counters);

  sql_prepare (plugin->dbh,
               "INSERT OR REPLACE INTO state (channel_id, name, value_current) "
               "VALUES ((SELECT id FROM channels WHERE pub_key = ?), ?, ?);",
               &plugin->insert_state_current);

  sql_prepare (plugin->dbh,
               "UPDATE state "
               "SET value_current = ? "
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?) "
               "      AND name = ?;",
               &plugin->update_state_current);

  sql_prepare (plugin->dbh,
               "UPDATE state "
               "SET value_signed = value_current "
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?) ",
               &plugin->update_state_signed);

  sql_prepare (plugin->dbh,
               "INSERT INTO state_sync (channel_id, name, value) "
               "VALUES ((SELECT id FROM channels WHERE pub_key = ?), ?, ?);",
               &plugin->insert_state_sync);

  sql_prepare (plugin->dbh,
               "DELETE FROM state "
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
               &plugin->delete_state);

  sql_prepare (plugin->dbh,
               "INSERT INTO state "
               " (channel_id, name, value_current, value_signed) "
               "SELECT channel_id, name, value, value "
               "FROM state_sync "
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
               &plugin->insert_state_from_sync);

  sql_prepare (plugin->dbh,
               "DELETE FROM state_sync "
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
               &plugin->delete_state_sync);

  sql_prepare (plugin->dbh,
               "SELECT value_current "
               "FROM state "
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?) "
               "      AND name = ?;",
               &plugin->select_state_one);

  sql_prepare (plugin->dbh,
               "SELECT value_current "
               "FROM state "
               "WHERE name LIKE ? OR name LIKE ?;",
               &plugin->select_state_prefix);

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

  if (NULL != plugin->insert_channel_key)
    sqlite3_finalize (plugin->insert_channel_key);

  if (NULL != plugin->insert_slave_key)
    sqlite3_finalize (plugin->insert_slave_key);

  if (NULL != plugin->insert_membership)
    sqlite3_finalize (plugin->insert_membership);

  if (NULL != plugin->select_membership)
    sqlite3_finalize (plugin->select_membership);

  if (NULL != plugin->insert_fragment)
    sqlite3_finalize (plugin->insert_fragment);

  if (NULL != plugin->update_fragment_flags)
    sqlite3_finalize (plugin->update_fragment_flags);

  if (NULL != plugin->select_fragment)
    sqlite3_finalize (plugin->select_fragment);

  if (NULL != plugin->select_message)
    sqlite3_finalize (plugin->select_message);

  if (NULL != plugin->select_message_fragment)
    sqlite3_finalize (plugin->select_message_fragment);

  if (NULL != plugin->select_master_counters)
    sqlite3_finalize (plugin->select_master_counters);

  if (NULL != plugin->select_slave_counters)
    sqlite3_finalize (plugin->select_slave_counters);

  if (NULL != plugin->insert_state_current)
    sqlite3_finalize (plugin->insert_state_current);

  if (NULL != plugin->update_state_current)
    sqlite3_finalize (plugin->update_state_current);

  if (NULL != plugin->update_state_signed)
    sqlite3_finalize (plugin->update_state_signed);

  if (NULL != plugin->insert_state_sync)
    sqlite3_finalize (plugin->insert_state_sync);

  if (NULL != plugin->delete_state)
    sqlite3_finalize (plugin->delete_state);

  if (NULL != plugin->insert_state_from_sync)
    sqlite3_finalize (plugin->insert_state_from_sync);

  if (NULL != plugin->delete_state_sync)
    sqlite3_finalize (plugin->delete_state_sync);

  if (NULL != plugin->select_state_one)
    sqlite3_finalize (plugin->select_state_one);

  if (NULL != plugin->select_state_prefix)
    sqlite3_finalize (plugin->select_state_prefix);

  result = sqlite3_close (plugin->dbh);
  if (result == SQLITE_BUSY)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 _("Tried to close sqlite without finalizing all prepared statements.\n"));
    stmt = sqlite3_next_stmt (plugin->dbh, NULL);
    while (stmt != NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                       "Closing statement %p\n", stmt);
      result = sqlite3_finalize (stmt);
      if (result != SQLITE_OK)
        GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "sqlite",
                         "Failed to close statement %p: %d\n", stmt, result);
      stmt = sqlite3_next_stmt (plugin->dbh, NULL);
    }
    result = sqlite3_close (plugin->dbh);
  }
  if (SQLITE_OK != result)
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite3_close");

  GNUNET_free_non_null (plugin->fn);
}


/** 
 * Store join/leave events for a PSYC channel in order to be able to answer
 * membership test queries later.
 *
 * @see GNUNET_PSYCSTORE_membership_store()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
int
libgnunet_plugin_psycstore_sqlite_membership_store
 (void *cls, 
  const struct GNUNET_HashCode *channel_key,
  const struct GNUNET_HashCode *slave_key,
  int did_join,
  uint64_t announced_at,
  uint64_t effective_since,
  uint64_t group_generation) {


}

/** 
 * Test if a member was admitted to the channel at the given message ID.
 *
 * @see GNUNET_PSYCSTORE_membership_test()
 * 
 * @return #GNUNET_YES if the member was admitted, #GNUNET_NO if not,
 *         #GNUNET_SYSERR if there was en error.
 */
int
libgnunet_plugin_psycstore_sqlite_membership_test
 (void *cls,
  const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
  const struct GNUNET_CRYPTO_EccPublicKey *slave_key,
  uint64_t message_id,
  uint64_t group_generation) {

}

/** 
 * Store a message fragment sent to a channel.
 *
 * @see GNUNET_PSYCSTORE_fragment_store()
 * 
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
int
libgnunet_plugin_psycstore_sqlite_fragment_store
 (void *cls,
  const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
  const struct GNUNET_MULTICAST_MessageHeader *message) {

}

/** 
 * Set additional flags for a given message.
 *
 * @param message_id ID of the message.
 * @param flags Flags to add.
 * 
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
int
libgnunet_plugin_psycstore_sqlite_fragment_add_flags
 (void *cls,
  const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
  uint64_t message_id,
  uint64_t multicast_flags,
  uint64_t psyc_flags) {

}

/** 
 * Retrieve a message fragment by fragment ID.
 *
 * @see GNUNET_PSYCSTORE_fragment_get()
 * 
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
int
libgnunet_plugin_psycstore_sqlite_fragment_get
 (void *cls,
  const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
  uint64_t fragment_id,
  GNUNET_PSYCSTORE_FragmentCallback cb,
  void *cb_cls) {

}

/** 
 * Retrieve all fragments of a message.
 *
 * @see GNUNET_PSYCSTORE_message_get()
 * 
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
int
libgnunet_plugin_psycstore_sqlite_message_get
 (void *cls,
  const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
  uint64_t message_id,
  GNUNET_PSYCSTORE_FragmentCallback cb,
  void *cb_cls) {

}

/** 
 * Retrieve a fragment of message specified by its message ID and fragment
 * offset.
 *
 * @see GNUNET_PSYCSTORE_message_get_fragment()
 * 
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
int
libgnunet_plugin_psycstore_sqlite_message_get_fragment
 (void *cls,
  const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
  uint64_t message_id,
  uint64_t fragment_offset,
  GNUNET_PSYCSTORE_FragmentCallback cb,
  void *cb_cls)
{

}

/** 
 * Retrieve latest values of counters for a channel master.
 *
 * @see GNUNET_PSYCSTORE_counters_get_master()
 * 
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
int
libgnunet_plugin_psycstore_sqlite_counters_get_master
 (void *cls,
  const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
  uint64_t *fragment_id,
  uint64_t *message_id,
  uint64_t *group_generation)
{

}

/** 
 * Retrieve latest values of counters for a channel slave. 
 *
 * @see GNUNET_PSYCSTORE_counters_get_slave()
 * 
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
int
libgnunet_plugin_psycstore_sqlite_counters_get_slave
 (void *cls,
  const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
  uint64_t *max_state_msg_id) {

}

/** 
 * Set a state variable to the given value.
 *
 * @see GNUNET_PSYCSTORE_state_modify()
 * 
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
int
libgnunet_plugin_psycstore_sqlite_state_set
 (struct GNUNET_PSYCSTORE_Handle *h,
  const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
  const char *name,
  size_t value_size,
  const void *value) {

}

/** 
 * Retrieve a state variable by name.
 *
 * @param name Name of the variable to retrieve.
 * @param[out] value_size Size of value.
 * @param[out] value Returned value.
 * 
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
int
libgnunet_plugin_psycstore_sqlite_state_get
 (struct GNUNET_PSYCSTORE_Handle *h,
  const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
  const char *name,
  GNUNET_PSYCSTORE_StateCallback cb,
  void *cb_cls) {

}

/** 
 * Retrieve all state variables for a channel with the given prefix.
 *
 * @see GNUNET_PSYCSTORE_state_get_all()
 * 
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
int
libgnunet_plugin_psycstore_sqlite_state_get_all
 (struct GNUNET_PSYCSTORE_Handle *h,
  const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
  const char *name,
  GNUNET_PSYCSTORE_StateCallback cb,
  void *cb_cls) {

}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_PSYCSTORE_PluginEnvironment*"
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_psycstore_sqlite_init (void *cls)
{
  static struct Plugin plugin;
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_PSYCSTORE_PluginFunctions *api;

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.cfg = cfg;  
  if (GNUNET_OK != database_setup (&plugin))
  {
    database_shutdown (&plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_PSYCSTORE_PluginFunctions);
  api->cls = &plugin;
  api->membership_store = &libgnunet_plugin_psycstore_sqlite_membership_store;
  api->membership_test = &libgnunet_plugin_psycstore_sqlite_membership_test;
  api->fragment_store = &libgnunet_plugin_psycstore_sqlite_fragment_store;
  api->fragment_add_flags = &libgnunet_plugin_psycstore_sqlite_fragment_add_flags;
  api->fragment_get = &libgnunet_plugin_psycstore_sqlite_fragment_get;
  api->message_get = &libgnunet_plugin_psycstore_sqlite_message_get;
  api->message_get_fragment = &libgnunet_plugin_psycstore_sqlite_message_get_fragment;
  api->counters_get_master = &libgnunet_plugin_psycstore_sqlite_counters_get_master;
  api->counters_get_slave = &libgnunet_plugin_psycstore_sqlite_counters_get_slave;
  api->state_set = &libgnunet_plugin_psycstore_sqlite_state_set;
  api->state_get = &libgnunet_plugin_psycstore_sqlite_state_get;
  api->state_get_all = &libgnunet_plugin_psycstore_sqlite_state_get_all;

  LOG (GNUNET_ERROR_TYPE_INFO, 
       _("Sqlite database running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_psycstore_sqlite_done (void *cls)
{
  struct GNUNET_PSYCSTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "sqlite plugin is finished\n");
  return NULL;
}

/* end of plugin_psycstore_sqlite.c */
