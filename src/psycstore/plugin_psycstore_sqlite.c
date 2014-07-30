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
 * @file psycstore/plugin_psycstore_sqlite.c
 * @brief sqlite-based psycstore backend
 * @author Gabor X Toth
 * @author Christian Grothoff
 */

/*
 * FIXME: SQLite3 only supports signed 64-bit integers natively,
 *        thus it can only store 63 bits of the uint64_t's.
 */

#include "platform.h"
#include "gnunet_psycstore_plugin.h"
#include "gnunet_psycstore_service.h"
#include "gnunet_multicast_service.h"
#include "gnunet_crypto_lib.h"
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

#define DEBUG_PSYCSTORE GNUNET_EXTRA_LOGGING

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(db, level, cmd) do { GNUNET_log_from (level, "psycstore-sqlite", _("`%s' failed at %s:%d with error: %s (%d)\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh), sqlite3_errcode(db->dbh)); } while(0)

#define LOG(kind,...) GNUNET_log_from (kind, "psycstore-sqlite", __VA_ARGS__)

enum Transactions {
  TRANSACTION_NONE = 0,
  TRANSACTION_STATE_MODIFY
};

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
   * Current transaction.
   */
  enum Transactions transaction;

  sqlite3_stmt *transaction_begin;

  sqlite3_stmt *transaction_commit;

  sqlite3_stmt *transaction_rollback;

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
   * Precompiled SQL for message_add_flags()
   */
  sqlite3_stmt *update_message_flags;

  /**
   * Precompiled SQL for fragment_get()
   */
  sqlite3_stmt *select_fragments;

  /**
   * Precompiled SQL for fragment_get()
   */
  sqlite3_stmt *select_latest_fragments;

  /**
   * Precompiled SQL for message_get()
   */
  sqlite3_stmt *select_messages;

  /**
   * Precompiled SQL for message_get()
   */
  sqlite3_stmt *select_latest_messages;

  /**
   * Precompiled SQL for message_get_fragment()
   */
  sqlite3_stmt *select_message_fragment;

  /**
   * Precompiled SQL for counters_get_message()
   */
  sqlite3_stmt *select_counters_message;

  /**
   * Precompiled SQL for counters_get_state()
   */
  sqlite3_stmt *select_counters_state;

  /**
   * Precompiled SQL for state_modify_end()
   */
  sqlite3_stmt *update_state_hash_message_id;

  /**
   * Precompiled SQL for state_sync_end()
   */
  sqlite3_stmt *update_max_state_message_id;


  /**
   * Precompiled SQL for message_modify_begin()
   */
  sqlite3_stmt *select_message_state_delta;

  /**
   * Precompiled SQL for state_modify_set()
   */
  sqlite3_stmt *insert_state_current;

  /**
   * Precompiled SQL for state_modify_end()
   */
  sqlite3_stmt *delete_state_empty;

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
   * Precompiled SQL for state_get_signed()
   */
  sqlite3_stmt *select_state_signed;

  /**
   * Precompiled SQL for state_get()
   */
  sqlite3_stmt *select_state_one;

  /**
   * Precompiled SQL for state_get_prefix()
   */
  sqlite3_stmt *select_state_prefix;

};

#if DEBUG_PSYCSTORE

static void
sql_trace (void *cls, const char *sql)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "SQL query:\n%s\n", sql);
}

#endif

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
  if (SQLITE_OK != sqlite3_open (plugin->fn, &plugin->dbh))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 _("Unable to initialize SQLite: %s.\n"),
	 sqlite3_errmsg (plugin->dbh));
    return GNUNET_SYSERR;
  }

#if DEBUG_PSYCSTORE
  sqlite3_trace (plugin->dbh, &sql_trace, NULL);
#endif

  sql_exec (plugin->dbh, "PRAGMA temp_store=MEMORY");
  sql_exec (plugin->dbh, "PRAGMA synchronous=NORMAL");
  sql_exec (plugin->dbh, "PRAGMA legacy_file_format=OFF");
  sql_exec (plugin->dbh, "PRAGMA auto_vacuum=INCREMENTAL");
  sql_exec (plugin->dbh, "PRAGMA encoding=\"UTF-8\"");
#if ! DEBUG_PSYCSTORE
  sql_exec (plugin->dbh, "PRAGMA locking_mode=EXCLUSIVE");
#endif
  sql_exec (plugin->dbh, "PRAGMA count_changes=OFF");
  sql_exec (plugin->dbh, "PRAGMA page_size=4096");

  sqlite3_busy_timeout (plugin->dbh, BUSY_TIMEOUT_MS);

  /* Create tables */

  sql_exec (plugin->dbh,
            "CREATE TABLE IF NOT EXISTS channels (\n"
            "  id INTEGER PRIMARY KEY,\n"
            "  pub_key BLOB UNIQUE,\n"
            "  max_state_message_id INTEGER,\n"
            "  state_hash_message_id INTEGER\n"
            ");");

  sql_exec (plugin->dbh,
            "CREATE TABLE IF NOT EXISTS slaves (\n"
            "  id INTEGER PRIMARY KEY,\n"
            "  pub_key BLOB UNIQUE\n"
            ");");

  sql_exec (plugin->dbh,
            "CREATE TABLE IF NOT EXISTS membership (\n"
            "  channel_id INTEGER NOT NULL REFERENCES channels(id),\n"
            "  slave_id INTEGER NOT NULL REFERENCES slaves(id),\n"
            "  did_join INTEGER NOT NULL,\n"
            "  announced_at INTEGER NOT NULL,\n"
            "  effective_since INTEGER NOT NULL,\n"
            "  group_generation INTEGER NOT NULL\n"
            ");");
  sql_exec (plugin->dbh,
            "CREATE INDEX IF NOT EXISTS idx_membership_channel_id_slave_id "
            "ON membership (channel_id, slave_id);");

  sql_exec (plugin->dbh,
            "CREATE TABLE IF NOT EXISTS messages (\n"
            "  channel_id INTEGER NOT NULL REFERENCES channels(id),\n"
            "  hop_counter INTEGER NOT NULL,\n"
            "  signature BLOB,\n"
            "  purpose BLOB,\n"
            "  fragment_id INTEGER NOT NULL,\n"
            "  fragment_offset INTEGER NOT NULL,\n"
            "  message_id INTEGER NOT NULL,\n"
            "  group_generation INTEGER NOT NULL,\n"
            "  multicast_flags INTEGER NOT NULL,\n"
            "  psycstore_flags INTEGER NOT NULL,\n"
            "  data BLOB,\n"
            "  PRIMARY KEY (channel_id, fragment_id),\n"
            "  UNIQUE (channel_id, message_id, fragment_offset)\n"
            ");");

  sql_exec (plugin->dbh,
            "CREATE TABLE IF NOT EXISTS state (\n"
            "  channel_id INTEGER NOT NULL REFERENCES channels(id),\n"
            "  name TEXT NOT NULL,\n"
            "  value_current BLOB,\n"
            "  value_signed BLOB,\n"
            "  PRIMARY KEY (channel_id, name)\n"
            ");");

  sql_exec (plugin->dbh,
            "CREATE TABLE IF NOT EXISTS state_sync (\n"
            "  channel_id INTEGER NOT NULL REFERENCES channels(id),\n"
            "  name TEXT NOT NULL,\n"
            "  value BLOB,\n"
            "  PRIMARY KEY (channel_id, name)\n"
            ");");

  /* Prepare statements */

  sql_prepare (plugin->dbh, "BEGIN;", &plugin->transaction_begin);

  sql_prepare (plugin->dbh, "COMMIT;", &plugin->transaction_commit);

  sql_prepare (plugin->dbh, "ROLLBACK;", &plugin->transaction_rollback);

  sql_prepare (plugin->dbh,
               "INSERT OR IGNORE INTO channels (pub_key) VALUES (?);",
               &plugin->insert_channel_key);

  sql_prepare (plugin->dbh,
               "INSERT OR IGNORE INTO slaves (pub_key) VALUES (?);",
               &plugin->insert_slave_key);

  sql_prepare (plugin->dbh,
               "INSERT INTO membership\n"
               " (channel_id, slave_id, did_join, announced_at,\n"
               "  effective_since, group_generation)\n"
               "VALUES ((SELECT id FROM channels WHERE pub_key = ?),\n"
               "        (SELECT id FROM slaves WHERE pub_key = ?),\n"
               "        ?, ?, ?, ?);",
               &plugin->insert_membership);

  sql_prepare (plugin->dbh,
               "SELECT did_join FROM membership\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               "      AND slave_id = (SELECT id FROM slaves WHERE pub_key = ?)\n"
               "      AND effective_since <= ? AND did_join = 1\n"
               "ORDER BY announced_at DESC LIMIT 1;",
               &plugin->select_membership);

  sql_prepare (plugin->dbh,
               "INSERT OR IGNORE INTO messages\n"
               " (channel_id, hop_counter, signature, purpose,\n"
               "  fragment_id, fragment_offset, message_id,\n"
               "  group_generation, multicast_flags, psycstore_flags, data)\n"
               "VALUES ((SELECT id FROM channels WHERE pub_key = ?),\n"
               "        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
               &plugin->insert_fragment);

  sql_prepare (plugin->dbh,
               "UPDATE messages\n"
               "SET psycstore_flags = psycstore_flags | ?\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               "      AND message_id = ? AND fragment_offset = 0;",
               &plugin->update_message_flags);

  sql_prepare (plugin->dbh,
               "SELECT hop_counter, signature, purpose, fragment_id,\n"
               "       fragment_offset, message_id, group_generation,\n"
               "       multicast_flags, psycstore_flags, data\n"
               "FROM messages\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               "      AND ? <= fragment_id AND fragment_id <= ?;",
               &plugin->select_fragments);

  sql_prepare (plugin->dbh,
               "SELECT hop_counter, signature, purpose, fragment_id,\n"
               "       fragment_offset, message_id, group_generation,\n"
               "       multicast_flags, psycstore_flags, data\n"
               "FROM messages\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               "      AND ? <= message_id AND message_id <= ?;",
               &plugin->select_messages);

  sql_prepare (plugin->dbh,
               "SELECT * FROM\n"
               "(SELECT hop_counter, signature, purpose, fragment_id,\n"
               "        fragment_offset, message_id, group_generation,\n"
               "        multicast_flags, psycstore_flags, data\n"
               " FROM messages\n"
               " WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               " ORDER BY fragment_id DESC\n"
               " LIMIT ?)\n"
               "ORDER BY fragment_id;",
               &plugin->select_latest_fragments);

  sql_prepare (plugin->dbh,
               "SELECT hop_counter, signature, purpose, fragment_id,\n"
               "       fragment_offset, message_id, group_generation,\n"
               "        multicast_flags, psycstore_flags, data\n"
               "FROM messages\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               "      AND message_id IN\n"
               "      (SELECT message_id\n"
               "       FROM messages\n"
               "       WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               "       ORDER BY message_id\n"
               "       DESC LIMIT ?)\n"
               "ORDER BY fragment_id;",
               &plugin->select_latest_messages);

  sql_prepare (plugin->dbh,
               "SELECT hop_counter, signature, purpose, fragment_id,\n"
               "       fragment_offset, message_id, group_generation,\n"
               "       multicast_flags, psycstore_flags, data\n"
               "FROM messages\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               "      AND message_id = ? AND fragment_offset = ?;",
               &plugin->select_message_fragment);

  sql_prepare (plugin->dbh,
               "SELECT fragment_id, message_id, group_generation\n"
               "FROM messages\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               "ORDER BY fragment_id DESC LIMIT 1;",
               &plugin->select_counters_message);

  sql_prepare (plugin->dbh,
               "SELECT max_state_message_id\n"
               "FROM channels\n"
               "WHERE pub_key = ? AND max_state_message_id IS NOT NULL;",
               &plugin->select_counters_state);

  sql_prepare (plugin->dbh,
               "UPDATE channels\n"
               "SET max_state_message_id = ?\n"
               "WHERE pub_key = ?;",
               &plugin->update_max_state_message_id);

  sql_prepare (plugin->dbh,
               "UPDATE channels\n"
               "SET state_hash_message_id = ?\n"
               "WHERE pub_key = ?;",
               &plugin->update_state_hash_message_id);

  sql_prepare (plugin->dbh,
               "SELECT 1\n"
               "FROM channels AS c\n"
               "LEFT JOIN messages AS m\n"
               "ON c.id = m.channel_id\n"
               "WHERE c.pub_key = ?\n"
               "      AND ((? < c.state_hash_message_id AND c.state_hash_message_id < ?)\n"
               "           OR (m.message_id = ? AND m.psycstore_flags & ?))\n"
               "LIMIT 1;",
               &plugin->select_message_state_delta);

  sql_prepare (plugin->dbh,
               "INSERT OR REPLACE INTO state\n"
               "  (channel_id, name, value_current, value_signed)\n"
               "SELECT new.channel_id, new.name,\n"
               "       new.value_current, old.value_signed\n"
               "FROM (SELECT (SELECT id FROM channels WHERE pub_key = ?)\n"
               "             AS channel_id,\n"
               "             ? AS name, ? AS value_current) AS new\n"
               "LEFT JOIN (SELECT channel_id, name, value_signed\n"
               "           FROM state) AS old\n"
               "ON new.channel_id = old.channel_id AND new.name = old.name;",
               &plugin->insert_state_current);

  sql_prepare (plugin->dbh,
               "DELETE FROM state\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               "      AND (value_current IS NULL OR length(value_current) = 0)\n"
               "      AND (value_signed IS NULL OR length(value_signed) = 0);",
               &plugin->delete_state_empty);

  sql_prepare (plugin->dbh,
               "UPDATE state\n"
               "SET value_signed = value_current\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
               &plugin->update_state_signed);

  sql_prepare (plugin->dbh,
               "DELETE FROM state\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
               &plugin->delete_state);

  sql_prepare (plugin->dbh,
               "INSERT INTO state_sync (channel_id, name, value)\n"
               "VALUES ((SELECT id FROM channels WHERE pub_key = ?), ?, ?);",
               &plugin->insert_state_sync);

  sql_prepare (plugin->dbh,
               "INSERT INTO state\n"
               " (channel_id, name, value_current, value_signed)\n"
               "SELECT channel_id, name, value, value\n"
               "FROM state_sync\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
               &plugin->insert_state_from_sync);

  sql_prepare (plugin->dbh,
               "DELETE FROM state_sync\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
               &plugin->delete_state_sync);

  sql_prepare (plugin->dbh,
               "SELECT value_current\n"
               "FROM state\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               "      AND name = ?;",
               &plugin->select_state_one);

  sql_prepare (plugin->dbh,
               "SELECT name, value_current\n"
               "FROM state\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               "      AND (name = ? OR name LIKE ?);",
               &plugin->select_state_prefix);

  sql_prepare (plugin->dbh,
               "SELECT name, value_signed\n"
               "FROM state\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)"
               "      AND value_signed IS NOT NULL;",
               &plugin->select_state_signed);

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
 * Execute a prepared statement with a @a channel_key argument.
 *
 * @param plugin Plugin handle.
 * @param stmt Statement to execute.
 * @param channel_key Public key of the channel.
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
exec_channel (struct Plugin *plugin, sqlite3_stmt *stmt,
              const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key)
{
  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key), SQLITE_STATIC))
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

  return GNUNET_OK;
}

/**
 * Begin a transaction.
 */
static int
transaction_begin (struct Plugin *plugin, enum Transactions transaction)
{
  sqlite3_stmt *stmt = plugin->transaction_begin;

  if (SQLITE_DONE != sqlite3_step (stmt))
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

  plugin->transaction = transaction;
  return GNUNET_OK;
}


/**
 * Commit current transaction.
 */
static int
transaction_commit (struct Plugin *plugin)
{
  sqlite3_stmt *stmt = plugin->transaction_commit;

  if (SQLITE_DONE != sqlite3_step (stmt))
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

  plugin->transaction = TRANSACTION_NONE;
  return GNUNET_OK;
}


/**
 * Roll back current transaction.
 */
static int
transaction_rollback (struct Plugin *plugin)
{
  sqlite3_stmt *stmt = plugin->transaction_rollback;

  if (SQLITE_DONE != sqlite3_step (stmt))
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
  plugin->transaction = TRANSACTION_NONE;
  return GNUNET_OK;
}


static int
channel_key_store (struct Plugin *plugin,
                   const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key)
{
  sqlite3_stmt *stmt = plugin->insert_channel_key;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key), SQLITE_STATIC))
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

  return GNUNET_OK;
}


static int
slave_key_store (struct Plugin *plugin,
                 const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key)
{
  sqlite3_stmt *stmt = plugin->insert_slave_key;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, slave_key,
                                      sizeof (*slave_key), SQLITE_STATIC))
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

  return GNUNET_OK;
}


/**
 * Store join/leave events for a PSYC channel in order to be able to answer
 * membership test queries later.
 *
 * @see GNUNET_PSYCSTORE_membership_store()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
membership_store (void *cls,
                  const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                  const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                  int did_join,
                  uint64_t announced_at,
                  uint64_t effective_since,
                  uint64_t group_generation)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->insert_membership;

  GNUNET_assert (TRANSACTION_NONE == plugin->transaction);

  if (announced_at > INT64_MAX ||
      effective_since > INT64_MAX ||
      group_generation > INT64_MAX)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  if (GNUNET_OK != channel_key_store (plugin, channel_key)
      || GNUNET_OK != slave_key_store (plugin, slave_key))
    return GNUNET_SYSERR;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key), SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_blob (stmt, 2, slave_key,
                                         sizeof (*slave_key), SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_int (stmt, 3, did_join)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 4, announced_at)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 5, effective_since)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 6, group_generation))
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

  return GNUNET_OK;
}

/**
 * Test if a member was admitted to the channel at the given message ID.
 *
 * @see GNUNET_PSYCSTORE_membership_test()
 *
 * @return #GNUNET_YES if the member was admitted, #GNUNET_NO if not,
 *         #GNUNET_SYSERR if there was en error.
 */
static int
membership_test (void *cls,
                 const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                 const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                 uint64_t message_id)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->select_membership;
  int ret = GNUNET_SYSERR;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key), SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_blob (stmt, 2, slave_key,
                                         sizeof (*slave_key), SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 3, message_id))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else
  {
    switch (sqlite3_step (stmt))
    {
    case SQLITE_DONE:
      ret = GNUNET_NO;
      break;
    case SQLITE_ROW:
      ret = GNUNET_YES;
    }
  }

  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  }

  return ret;
}

/**
 * Store a message fragment sent to a channel.
 *
 * @see GNUNET_PSYCSTORE_fragment_store()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
fragment_store (void *cls,
                const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                const struct GNUNET_MULTICAST_MessageHeader *msg,
                uint32_t psycstore_flags)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->insert_fragment;

  GNUNET_assert (TRANSACTION_NONE == plugin->transaction);

  uint64_t fragment_id = GNUNET_ntohll (msg->fragment_id);
  uint64_t fragment_offset = GNUNET_ntohll (msg->fragment_offset);
  uint64_t message_id = GNUNET_ntohll (msg->message_id);
  uint64_t group_generation = GNUNET_ntohll (msg->group_generation);

  if (fragment_id > INT64_MAX || fragment_offset > INT64_MAX ||
      message_id > INT64_MAX || group_generation > INT64_MAX)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Tried to store fragment with a field > INT64_MAX: "
         "%lu, %lu, %lu, %lu\n", fragment_id, fragment_offset,
         message_id, group_generation);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  if (GNUNET_OK != channel_key_store (plugin, channel_key))
    return GNUNET_SYSERR;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key), SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 2, ntohl (msg->hop_counter) )
      || SQLITE_OK != sqlite3_bind_blob (stmt, 3, (const void *) &msg->signature,
                                         sizeof (msg->signature), SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_blob (stmt, 4, (const void *) &msg->purpose,
                                         sizeof (msg->purpose), SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 5, fragment_id)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 6, fragment_offset)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 7, message_id)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 8, group_generation)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 9, ntohl (msg->flags))
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 10, psycstore_flags)
      || SQLITE_OK != sqlite3_bind_blob (stmt, 11, (const void *) &msg[1],
                                         ntohs (msg->header.size)
                                         - sizeof (*msg), SQLITE_STATIC))
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

  return GNUNET_OK;
}

/**
 * Set additional flags for a given message.
 *
 * They are OR'd with any existing flags set.
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
message_add_flags (void *cls,
                   const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                   uint64_t message_id,
                   uint64_t psycstore_flags)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->update_message_flags;
  int ret = GNUNET_SYSERR;

  if (SQLITE_OK != sqlite3_bind_int64 (stmt, 1, psycstore_flags)
      || SQLITE_OK != sqlite3_bind_blob (stmt, 2, channel_key,
                                         sizeof (*channel_key), SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 3, message_id))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else
  {
    switch (sqlite3_step (stmt))
    {
    case SQLITE_DONE:
      ret = sqlite3_total_changes (plugin->dbh) > 0 ? GNUNET_OK : GNUNET_NO;
      break;
    default:
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_step");
    }
  }

  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
    return GNUNET_SYSERR;
  }

  return ret;
}

static int
fragment_row (sqlite3_stmt *stmt, GNUNET_PSYCSTORE_FragmentCallback cb,
              void *cb_cls)
{
  int data_size = sqlite3_column_bytes (stmt, 9);
  struct GNUNET_MULTICAST_MessageHeader *msg
    = GNUNET_malloc (sizeof (*msg) + data_size);

  msg->header.size = htons (sizeof (*msg) + data_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE);
  msg->hop_counter = htonl ((uint32_t) sqlite3_column_int64 (stmt, 0));
  memcpy (&msg->signature,
          sqlite3_column_blob (stmt, 1),
          sqlite3_column_bytes (stmt, 1));
  memcpy (&msg->purpose,
          sqlite3_column_blob (stmt, 2),
          sqlite3_column_bytes (stmt, 2));
  msg->fragment_id = GNUNET_htonll (sqlite3_column_int64 (stmt, 3));
  msg->fragment_offset = GNUNET_htonll (sqlite3_column_int64 (stmt, 4));
  msg->message_id = GNUNET_htonll (sqlite3_column_int64 (stmt, 5));
  msg->group_generation = GNUNET_htonll (sqlite3_column_int64 (stmt, 6));
  msg->flags = htonl (sqlite3_column_int64 (stmt, 7));
  memcpy (&msg[1], sqlite3_column_blob (stmt, 9), data_size);

  return cb (cb_cls, (void *) msg, sqlite3_column_int64 (stmt, 8));
}


static int
fragment_select (struct Plugin *plugin, sqlite3_stmt *stmt,
                 uint64_t *returned_fragments,
                 GNUNET_PSYCSTORE_FragmentCallback cb, void *cb_cls)
{
  int ret = GNUNET_SYSERR;
  int sql_ret;

  do
  {
    sql_ret = sqlite3_step (stmt);
    switch (sql_ret)
    {
    case SQLITE_DONE:
      if (ret != GNUNET_OK)
        ret = GNUNET_NO;
      break;
    case SQLITE_ROW:
      ret = fragment_row (stmt, cb, cb_cls);
      (*returned_fragments)++;
      if (ret != GNUNET_YES)
        sql_ret = SQLITE_DONE;
      break;
    default:
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_step");
    }
  }
  while (sql_ret == SQLITE_ROW);

  return ret;
}

/**
 * Retrieve a message fragment range by fragment ID.
 *
 * @see GNUNET_PSYCSTORE_fragment_get()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
fragment_get (void *cls,
              const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
              uint64_t first_fragment_id,
              uint64_t last_fragment_id,
              uint64_t *returned_fragments,
              GNUNET_PSYCSTORE_FragmentCallback cb,
              void *cb_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->select_fragments;
  int ret = GNUNET_SYSERR;
  *returned_fragments = 0;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key),
                                      SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 2, first_fragment_id)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 3, last_fragment_id))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else
  {
    ret = fragment_select (plugin, stmt, returned_fragments, cb, cb_cls);
  }

  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  }

  return ret;
}


/**
 * Retrieve a message fragment range by fragment ID.
 *
 * @see GNUNET_PSYCSTORE_fragment_get_latest()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
fragment_get_latest (void *cls,
                     const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                     uint64_t fragment_limit,
                     uint64_t *returned_fragments,
                     GNUNET_PSYCSTORE_FragmentCallback cb,
                     void *cb_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->select_latest_fragments;
  int ret = GNUNET_SYSERR;
  *returned_fragments = 0;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key),
                                      SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 2, fragment_limit))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else
  {
    ret = fragment_select (plugin, stmt, returned_fragments, cb, cb_cls);
  }

  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  }

  return ret;
}


/**
 * Retrieve all fragments of a message ID range.
 *
 * @see GNUNET_PSYCSTORE_message_get()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
message_get (void *cls,
             const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
             uint64_t first_message_id,
             uint64_t last_message_id,
             uint64_t *returned_fragments,
             GNUNET_PSYCSTORE_FragmentCallback cb,
             void *cb_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->select_messages;
  int ret = GNUNET_SYSERR;
  *returned_fragments = 0;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key),
                                      SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 2, first_message_id)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 3, last_message_id))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else
  {
    ret = fragment_select (plugin, stmt, returned_fragments, cb, cb_cls);
  }

  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  }

  return ret;
}


/**
 * Retrieve all fragments of the latest messages.
 *
 * @see GNUNET_PSYCSTORE_message_get_latest()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
message_get_latest (void *cls,
                    const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                    uint64_t message_limit,
                    uint64_t *returned_fragments,
                    GNUNET_PSYCSTORE_FragmentCallback cb,
                    void *cb_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->select_latest_messages;
  int ret = GNUNET_SYSERR;
  *returned_fragments = 0;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key),
                                      SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_blob (stmt, 2, channel_key,
                                         sizeof (*channel_key),
                                         SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 3, message_limit))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else
  {
    ret = fragment_select (plugin, stmt, returned_fragments, cb, cb_cls);
  }

  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  }

  return ret;
}


/**
 * Retrieve a fragment of message specified by its message ID and fragment
 * offset.
 *
 * @see GNUNET_PSYCSTORE_message_get_fragment()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
message_get_fragment (void *cls,
                      const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                      uint64_t message_id,
                      uint64_t fragment_offset,
                      GNUNET_PSYCSTORE_FragmentCallback cb,
                      void *cb_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->select_message_fragment;
  int ret = GNUNET_SYSERR;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key),
                                      SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 2, message_id)
      || SQLITE_OK != sqlite3_bind_int64 (stmt, 3, fragment_offset))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else
  {
    switch (sqlite3_step (stmt))
    {
    case SQLITE_DONE:
      ret = GNUNET_NO;
      break;
    case SQLITE_ROW:
      ret = fragment_row (stmt, cb, cb_cls);
      break;
    default:
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_step");
    }
  }

  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  }

  return ret;
}

/**
 * Retrieve the max. values of message counters for a channel.
 *
 * @see GNUNET_PSYCSTORE_counters_get()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
counters_message_get (void *cls,
                      const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                      uint64_t *max_fragment_id,
                      uint64_t *max_message_id,
                      uint64_t *max_group_generation)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->select_counters_message;
  int ret = GNUNET_SYSERR;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key),
                                      SQLITE_STATIC))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else
  {
    switch (sqlite3_step (stmt))
    {
    case SQLITE_DONE:
      ret = GNUNET_NO;
      break;
    case SQLITE_ROW:
      *max_fragment_id = sqlite3_column_int64 (stmt, 0);
      *max_message_id = sqlite3_column_int64 (stmt, 1);
      *max_group_generation = sqlite3_column_int64 (stmt, 2);
      ret = GNUNET_OK;
      break;
    default:
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_step");
    }
  }

  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  }

  return ret;
}

/**
 * Retrieve the max. values of state counters for a channel.
 *
 * @see GNUNET_PSYCSTORE_counters_get()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
counters_state_get (void *cls,
                    const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                    uint64_t *max_state_message_id)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->select_counters_state;
  int ret = GNUNET_SYSERR;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key),
                                      SQLITE_STATIC))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else
  {
    switch (sqlite3_step (stmt))
    {
    case SQLITE_DONE:
      ret = GNUNET_NO;
      break;
    case SQLITE_ROW:
      *max_state_message_id = sqlite3_column_int64 (stmt, 0);
      ret = GNUNET_OK;
      break;
    default:
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_step");
    }
  }

  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  }

  return ret;
}


/**
 * Set a state variable to the given value.
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
state_set (struct Plugin *plugin, sqlite3_stmt *stmt,
           const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
           const char *name, const void *value, size_t value_size)
{
  int ret = GNUNET_SYSERR;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key), SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_text (stmt, 2, name, -1, SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_blob (stmt, 3, value, value_size,
                                         SQLITE_STATIC))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else
  {
    switch (sqlite3_step (stmt))
    {
    case SQLITE_DONE:
      ret = 0 < sqlite3_total_changes (plugin->dbh) ? GNUNET_OK : GNUNET_NO;
      break;
    default:
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_step");
    }
  }

  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
    return GNUNET_SYSERR;
  }

  return ret;
}


static int
update_message_id (struct Plugin *plugin, sqlite3_stmt *stmt,
                   const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                   uint64_t message_id)
{
  if (SQLITE_OK != sqlite3_bind_int64 (stmt, 1, message_id)
      || SQLITE_OK != sqlite3_bind_blob (stmt, 2, channel_key,
                                         sizeof (*channel_key), SQLITE_STATIC))
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
  return GNUNET_OK;
}


/**
 * Begin modifying current state.
 */
static int
state_modify_begin (void *cls,
                    const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                    uint64_t message_id, uint64_t state_delta)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->select_message_state_delta;

  if (state_delta > 0)
  {
    int ret = GNUNET_SYSERR;
    if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                        sizeof (*channel_key), SQLITE_STATIC)
        || SQLITE_OK != sqlite3_bind_int64 (stmt, 2,
                                            message_id - state_delta)
        || SQLITE_OK != sqlite3_bind_int64 (stmt, 3,
                                            message_id)
        || SQLITE_OK != sqlite3_bind_int64 (stmt, 4,
                                            message_id - state_delta)
        || SQLITE_OK != sqlite3_bind_int64 (stmt, 5,
                                            GNUNET_PSYCSTORE_MESSAGE_STATE_APPLIED))
    {
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_bind");
    }
    else
    {
      switch (sqlite3_step (stmt))
      {
      case SQLITE_DONE:
        ret = GNUNET_NO;
        break;
      case SQLITE_ROW:
        ret = GNUNET_OK;
        break;
      default:
        LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                    "sqlite3_step");
      }
    }
    if (SQLITE_OK != sqlite3_reset (stmt))
    {
      ret = GNUNET_SYSERR;
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
     }
    if (GNUNET_OK != ret)
      return ret;
  }

  if (TRANSACTION_NONE != plugin->transaction)
      if (GNUNET_OK != transaction_rollback (plugin))
          return GNUNET_SYSERR;

  return transaction_begin (plugin, TRANSACTION_STATE_MODIFY);
}


/**
 * Set the current value of state variable.
 *
 * @see GNUNET_PSYCSTORE_state_modify()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
state_modify_set (void *cls,
                  const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                  const char *name, const void *value, size_t value_size)
{
  struct Plugin *plugin = cls;
  GNUNET_assert (TRANSACTION_STATE_MODIFY == plugin->transaction);

  return state_set (plugin, plugin->insert_state_current, channel_key,
                    name, value, value_size);

}


/**
 * End modifying current state.
 */
static int
state_modify_end (void *cls,
                  const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                  uint64_t message_id)
{
  struct Plugin *plugin = cls;
  GNUNET_assert (TRANSACTION_STATE_MODIFY == plugin->transaction);

  return
    GNUNET_OK == exec_channel (plugin, plugin->delete_state_empty, channel_key)
    && GNUNET_OK == update_message_id (plugin,
                                       plugin->update_max_state_message_id,
                                       channel_key, message_id)
    && GNUNET_OK == transaction_commit (plugin)
    ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Begin state synchronization.
 */
static int
state_sync_begin (void *cls,
                  const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key)
{
  struct Plugin *plugin = cls;
  return exec_channel (plugin, plugin->delete_state_sync, channel_key);
}


/**
 * Set the current value of state variable.
 *
 * @see GNUNET_PSYCSTORE_state_modify()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
state_sync_set (void *cls,
                const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                const char *name, const void *value, size_t value_size)
{
  struct Plugin *plugin = cls;
  return state_set (cls, plugin->insert_state_sync, channel_key,
                    name, value, value_size);
}


/**
 * End modifying current state.
 */
static int
state_sync_end (void *cls,
                const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                uint64_t message_id)
{
  struct Plugin *plugin = cls;
  int ret = GNUNET_SYSERR;

  GNUNET_OK == transaction_begin (plugin, TRANSACTION_NONE)
    && GNUNET_OK == exec_channel (plugin, plugin->delete_state, channel_key)
    && GNUNET_OK == exec_channel (plugin, plugin->insert_state_from_sync,
                                  channel_key)
    && GNUNET_OK == exec_channel (plugin, plugin->delete_state_sync,
                                  channel_key)
    && GNUNET_OK == update_message_id (plugin,
                                       plugin->update_state_hash_message_id,
                                       channel_key, message_id)
    && GNUNET_OK == transaction_commit (plugin)
    ? ret = GNUNET_OK
    : transaction_rollback (plugin);
  return ret;
}


/**
 * Reset the state of a channel.
 *
 * @see GNUNET_PSYCSTORE_state_reset()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
state_reset (void *cls, const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key)
{
  struct Plugin *plugin = cls;
  return exec_channel (plugin, plugin->delete_state, channel_key);
}


/**
 * Update signed values of state variables in the state store.
 *
 * @see GNUNET_PSYCSTORE_state_hash_update()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
state_update_signed (void *cls,
                     const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key)
{
  struct Plugin *plugin = cls;
  return exec_channel (plugin, plugin->update_state_signed, channel_key);
}


/**
 * Retrieve a state variable by name.
 *
 * @see GNUNET_PSYCSTORE_state_get()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
state_get (void *cls, const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
           const char *name, GNUNET_PSYCSTORE_StateCallback cb, void *cb_cls)
{
  struct Plugin *plugin = cls;
  int ret = GNUNET_SYSERR;

  sqlite3_stmt *stmt = plugin->select_state_one;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key),
                                      SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_text (stmt, 2, name, -1, SQLITE_STATIC))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else
  {
    switch (sqlite3_step (stmt))
    {
    case SQLITE_DONE:
      ret = GNUNET_NO;
      break;
    case SQLITE_ROW:
      ret = cb (cb_cls, name, sqlite3_column_blob (stmt, 0),
                sqlite3_column_bytes (stmt, 0));
      break;
    default:
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_step");
    }
  }

  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  }

  return ret;
}


/**
 * Retrieve all state variables for a channel with the given prefix.
 *
 * @see GNUNET_PSYCSTORE_state_get_prefix()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
state_get_prefix (void *cls, const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                  const char *name, GNUNET_PSYCSTORE_StateCallback cb,
                  void *cb_cls)
{
  struct Plugin *plugin = cls;
  int ret = GNUNET_SYSERR;

  sqlite3_stmt *stmt = plugin->select_state_prefix;
  size_t name_len = strlen (name);
  char *name_prefix = GNUNET_malloc (name_len + 2);
  memcpy (name_prefix, name, name_len);
  memcpy (name_prefix + name_len, "_%", 2);

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key), SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_text (stmt, 2, name, name_len, SQLITE_STATIC)
      || SQLITE_OK != sqlite3_bind_text (stmt, 3, name_prefix, name_len + 2,
                                         SQLITE_STATIC))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else
  {
    int sql_ret;
    do
    {
      sql_ret = sqlite3_step (stmt);
      switch (sql_ret)
      {
      case SQLITE_DONE:
        if (ret != GNUNET_OK)
          ret = GNUNET_NO;
        break;
      case SQLITE_ROW:
        ret = cb (cb_cls, (const char *) sqlite3_column_text (stmt, 0),
                  sqlite3_column_blob (stmt, 1),
                  sqlite3_column_bytes (stmt, 1));
        if (ret != GNUNET_YES)
          sql_ret = SQLITE_DONE;
        break;
      default:
        LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                    "sqlite3_step");
      }
    }
    while (sql_ret == SQLITE_ROW);
  }

  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  }

  return ret;
}


/**
 * Retrieve all signed state variables for a channel.
 *
 * @see GNUNET_PSYCSTORE_state_get_signed()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
state_get_signed (void *cls,
                  const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                  GNUNET_PSYCSTORE_StateCallback cb, void *cb_cls)
{
  struct Plugin *plugin = cls;
  int ret = GNUNET_SYSERR;

  sqlite3_stmt *stmt = plugin->select_state_signed;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, channel_key,
                                      sizeof (*channel_key), SQLITE_STATIC))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
  }
  else
  {
    int sql_ret;
    do
    {
      sql_ret = sqlite3_step (stmt);
      switch (sql_ret)
      {
      case SQLITE_DONE:
        if (ret != GNUNET_OK)
          ret = GNUNET_NO;
        break;
      case SQLITE_ROW:
        ret = cb (cb_cls, (const char *) sqlite3_column_text (stmt, 0),
                  sqlite3_column_blob (stmt, 1),
                  sqlite3_column_bytes (stmt, 1));
        if (ret != GNUNET_YES)
          sql_ret = SQLITE_DONE;
        break;
      default:
        LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                    "sqlite3_step");
      }
    }
    while (sql_ret == SQLITE_ROW);
  }

  if (SQLITE_OK != sqlite3_reset (stmt))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  }

  return ret;
}


/**
 * Entry point for the plugin.
 *
 * @param cls The struct GNUNET_CONFIGURATION_Handle.
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
  api->membership_store = &membership_store;
  api->membership_test = &membership_test;
  api->fragment_store = &fragment_store;
  api->message_add_flags = &message_add_flags;
  api->fragment_get = &fragment_get;
  api->fragment_get_latest = &fragment_get_latest;
  api->message_get = &message_get;
  api->message_get_latest = &message_get_latest;
  api->message_get_fragment = &message_get_fragment;
  api->counters_message_get = &counters_message_get;
  api->counters_state_get = &counters_state_get;
  api->state_modify_begin = &state_modify_begin;
  api->state_modify_set = &state_modify_set;
  api->state_modify_end = &state_modify_end;
  api->state_sync_begin = &state_sync_begin;
  api->state_sync_set = &state_sync_set;
  api->state_sync_end = &state_sync_end;
  api->state_reset = &state_reset;
  api->state_update_signed = &state_update_signed;
  api->state_get = &state_get;
  api->state_get_prefix = &state_get_prefix;
  api->state_get_signed = &state_get_signed;

  LOG (GNUNET_ERROR_TYPE_INFO, _("SQLite database running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls The plugin context (as returned by "init")
 * @return Always NULL
 */
void *
libgnunet_plugin_psycstore_sqlite_done (void *cls)
{
  struct GNUNET_PSYCSTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "SQLite plugin is finished\n");
  return NULL;
}

/* end of plugin_psycstore_sqlite.c */
