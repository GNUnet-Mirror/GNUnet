/*
 * This file is part of GNUnet
 * Copyright (C) 2013 GNUnet e.V.
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
 * @file psycstore/plugin_psycstore_mysql.c
 * @brief sqlite-based psycstore backend
 * @author Gabor X Toth
 * @author Christian Grothoff
 * @author Christophe Genevey
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
#include "gnunet_psyc_util_lib.h"
#include "psycstore.h"
#include "gnunet_my_lib.h"
#include "gnunet_mysql_lib.h"

#include <sqlite3.h>
#include <mysql/mysql.h>

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
#define LOG_MYSQL(db, level, cmd, stmt) do { GNUNET_log_from (level, "psycstore-mysql", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, mysql_stmt_error (stmt)); } while(0)

#define LOG(kind,...) GNUNET_log_from (kind, "psycstore-mysql", __VA_ARGS__)

enum Transactions {
  TRANSACTION_NONE = 0,
  TRANSACTION_STATE_MODIFY,
  TRANSACTION_STATE_SYNC,
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
    *Handle to talk to Mysql
    */
  struct GNUNET_MYSQL_Context *mc;

  /**
   * Current transaction.
   */
  enum Transactions transaction;

  struct GNUNET_MYSQL_StatementHandle *transaction_begin;

  struct GNUNET_MYSQL_StatementHandle *transaction_commit;

  struct GNUNET_MYSQL_StatementHandle *transaction_rollback;

  /**
   * Precompiled SQL for channel_key_store()
   */
  struct GNUNET_MYSQL_StatementHandle *insert_channel_key;


  /**
   * Precompiled SQL for slave_key_store()
   */
  struct GNUNET_MYSQL_StatementHandle *insert_slave_key;

  /**
   * Precompiled SQL for membership_store()
   */
  struct GNUNET_MYSQL_StatementHandle *insert_membership;

  /**
   * Precompiled SQL for membership_test()
   */
  struct GNUNET_MYSQL_StatementHandle *select_membership;

  /**
   * Precompiled SQL for fragment_store()
   */
  struct GNUNET_MYSQL_StatementHandle *insert_fragment;

  /**
   * Precompiled SQL for message_add_flags()
   */
  struct GNUNET_MYSQL_StatementHandle *update_message_flags;

  /**
   * Precompiled SQL for fragment_get()
   */
  struct GNUNET_MYSQL_StatementHandle *select_fragments;

  /**
   * Precompiled SQL for fragment_get()
   */
  struct GNUNET_MYSQL_StatementHandle *select_latest_fragments;

  /**
   * Precompiled SQL for message_get()
   */
  struct GNUNET_MYSQL_StatementHandle *select_messages;

  /**
   * Precompiled SQL for message_get()
   */
  struct GNUNET_MYSQL_StatementHandle *select_latest_messages;

  /**
   * Precompiled SQL for message_get_fragment()
   */
  struct GNUNET_MYSQL_StatementHandle *select_message_fragment;

  /**
   * Precompiled SQL for counters_get_message()
   */
  struct GNUNET_MYSQL_StatementHandle *select_counters_message;

  /**
   * Precompiled SQL for counters_get_state()
   */
  struct GNUNET_MYSQL_StatementHandle *select_counters_state;

  /**
   * Precompiled SQL for state_modify_end()
   */
  struct GNUNET_MYSQL_StatementHandle *update_state_hash_message_id;

  /**
   * Precompiled SQL for state_sync_end()
   */
  struct GNUNET_MYSQL_StatementHandle *update_max_state_message_id;

  /**
   * Precompiled SQL for state_modify_op()
   */
  struct GNUNET_MYSQL_StatementHandle *insert_state_current;

  /**
   * Precompiled SQL for state_modify_end()
   */
  struct GNUNET_MYSQL_StatementHandle *delete_state_empty;

  /**
   * Precompiled SQL for state_set_signed()
   */
  struct GNUNET_MYSQL_StatementHandle *update_state_signed;

  /**
   * Precompiled SQL for state_sync()
   */
  struct GNUNET_MYSQL_StatementHandle *insert_state_sync;

  /**
   * Precompiled SQL for state_sync()
   */
  struct GNUNET_MYSQL_StatementHandle *delete_state;

  /**
   * Precompiled SQL for state_sync()
   */
  struct GNUNET_MYSQL_StatementHandle *insert_state_from_sync;

  /**
   * Precompiled SQL for state_sync()
   */
  struct GNUNET_MYSQL_StatementHandle *delete_state_sync;

  /**
   * Precompiled SQL for state_get_signed()
   */
  struct GNUNET_MYSQL_StatementHandle *select_state_signed;

  /**
   * Precompiled SQL for state_get()
   */
  struct GNUNET_MYSQL_StatementHandle *select_state_one;

  /**
   * Precompiled SQL for state_get_prefix()
   */
  struct GNUNET_MYSQL_StatementHandle *select_state_prefix;

};

#if DEBUG_PSYCSTORE

static void
sql_trace (void *cls, const char *sql)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "MYSQL query:\n%s\n", sql);
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
mysql_prepare (struct GNUNET_MYSQL_Context *mc,
              const char *sql, 
              struct GNUNET_MYSQL_StatementHandle *stmt)
{
  stmt = GNUNET_MYSQL_statement_prepare (mc,
                                          sql);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Prepared `%s' / %p\n", sql, stmt);
  if(NULL == stmt)
    LOG (GNUNET_ERROR_TYPE_ERROR,
   _("Error preparing SQL query: %s\n  %s\n"),
   mysql_stmt_error (GNUNET_MYSQL_statement_get_stmt (stmt)), sql);

  return 1;
}


/**
 * @brief Prepare a SQL statement
 *
 * @param dbh handle to the database
 * @param sql SQL statement, UTF-8 encoded
 * @return 0 on success
 */
static int
mysql_exec (struct GNUNET_MYSQL_Context *mc,
            struct GNUNET_MYSQL_StatementHandle *sh,
            struct GNUNET_MY_QueryParam *qp)
{
  int result;

  result = GNUNET_MY_exec_prepared (mc, sh, qp);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Executed `GNUNET_MY_exec_prepared`' / %d\n", result);
  if (GNUNET_OK != result)
    LOG (GNUNET_ERROR_TYPE_ERROR,
   _("Error executing SQL query: %s\n"),
   mysql_stmt_error (GNUNET_MYSQL_statement_get_stmt (sh)));
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
      GNUNET_CONFIGURATION_get_value_filename (plugin->cfg, "psycstore-mysql",
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
  plugin->mc = GNUNET_MYSQL_context_create(plugin->cfg, "psycstore-mysql");

  if (NULL == plugin->mc)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
   _("Unable to initialize SQLite: %s.\n"),
    sqlite3_errmsg (plugin->dbh));
    return GNUNET_SYSERR; 
  }
  
/*
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
  sql_exec (plugin->dbh, "PRAGMA page_size=4096");

  sqlite3_busy_timeout (plugin->dbh, BUSY_TIMEOUT_MS);

*/
  /* Create tables */

  GNUNET_MYSQL_statement_run (plugin->mc,
                              "CREATE TABLE IF NOT EXISTS channels (\n"
                              "  id INT PRIMARY KEY,\n"
                              "  pub_key BLOB UNIQUE,\n"
                              "  max_state_message_id INT,\n" // last applied state message ID
                              "  state_hash_message_id INT\n" // last message ID with a state hash
                              ");");

  GNUNET_MYSQL_statement_run (plugin->mc,
                              "CREATE TABLE IF NOT EXISTS slaves (\n"
                              "  id INT PRIMARY KEY,\n"
                              "  pub_key BLOB UNIQUE\n"
                              ");");

  GNUNET_MYSQL_statement_run (plugin->mc,
                              "CREATE TABLE IF NOT EXISTS membership (\n"
                              "  channel_id INT NOT NULL REFERENCES channels(id),\n"
                              "  slave_id INT NOT NULL REFERENCES slaves(id),\n"
                              "  did_join INT NOT NULL,\n"
                              "  announced_at INT NOT NULL,\n"
                              "  effective_since INT NOT NULL,\n"
                              "  group_generation INT NOT NULL\n"
                              ");");

  GNUNET_MYSQL_statement_run (plugin->mc,
                              "CREATE INDEX IF NOT EXISTS idx_membership_channel_id_slave_id "
                              "ON membership (channel_id, slave_id);");

  /** @todo messages table: add method_name column */
  GNUNET_MYSQL_statement_run (plugin->mc,
                              "CREATE TABLE IF NOT EXISTS messages (\n"
                              "  channel_id INT NOT NULL REFERENCES channels(id),\n"
                              "  hop_counter INT NOT NULL,\n"
                              "  signature BLOB,\n"
                              "  purpose BLOB,\n"
                              "  fragment_id INT NOT NULL,\n"
                              "  fragment_offset INT NOT NULL,\n"
                              "  message_id INT NOT NULL,\n"
                              "  group_generation INT NOT NULL,\n"
                              "  multicast_flags INT NOT NULL,\n"
                              "  psycstore_flags INT NOT NULL,\n"
                              "  data BLOB,\n"
                              "  PRIMARY KEY (channel_id, fragment_id),\n"
                              "  UNIQUE (channel_id, message_id, fragment_offset)\n"
                              ");");

  GNUNET_MYSQL_statement_run (plugin->mc,
                              "CREATE TABLE IF NOT EXISTS state (\n"
                              "  channel_id INT NOT NULL REFERENCES channels(id),\n"
                              "  name TEXT NOT NULL,\n"
                              "  value_current BLOB,\n"
                              "  value_signed BLOB,\n"
                              "  PRIMARY KEY (channel_id, name)\n"
                              ");");

  GNUNET_MYSQL_statement_run (plugin->mc,
                              "CREATE TABLE IF NOT EXISTS state_sync (\n"
                              "  channel_id INT NOT NULL REFERENCES channels(id),\n"
                              "  name TEXT NOT NULL,\n"
                              "  value BLOB,\n"
                              "  PRIMARY KEY (channel_id, name)\n"
                              ");");

  /* Prepare statements */
  mysql_prepare (plugin->mc, 
                "BEGIN", 
                plugin->transaction_begin);

  mysql_prepare (plugin->mc, 
                "COMMIT", 
                plugin->transaction_commit);

  mysql_prepare (plugin->mc, 
                "ROLLBACK;", 
                plugin->transaction_rollback);

  mysql_prepare (plugin->mc, 
                "INSERT OR IGNORE INTO channels (pub_key) VALUES (?);", 
                plugin->insert_channel_key);

  mysql_prepare (plugin->mc, 
                "INSERT OR IGNORE INTO slaves (pub_key) VALUES (?);", 
                plugin->insert_slave_key);
 
  mysql_prepare (plugin->mc, 
                "INSERT INTO membership\n"
                " (channel_id, slave_id, did_join, announced_at,\n"
                "  effective_since, group_generation)\n"
                "VALUES ((SELECT id FROM channels WHERE pub_key = ?),\n"
                "        (SELECT id FROM slaves WHERE pub_key = ?),\n"
                "        ?, ?, ?, ?);",
                plugin->insert_membership);

  mysql_prepare (plugin->mc,
                "SELECT did_join FROM membership\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               "      AND slave_id = (SELECT id FROM slaves WHERE pub_key = ?)\n"
               "      AND effective_since <= ? AND did_join = 1\n"
               "ORDER BY announced_at DESC LIMIT 1;",
               plugin->select_membership);

  mysql_prepare (plugin->mc,
                "INSERT OR IGNORE INTO messages\n"
               " (channel_id, hop_counter, signature, purpose,\n"
               "  fragment_id, fragment_offset, message_id,\n"
               "  group_generation, multicast_flags, psycstore_flags, data)\n"
               "VALUES ((SELECT id FROM channels WHERE pub_key = ?),\n"
               "        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                plugin->insert_fragment);

  mysql_prepare (plugin->mc,
                "UPDATE messages\n"
                "SET psycstore_flags = psycstore_flags | ?\n"
                "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
                "      AND message_id = ? AND fragment_offset = 0;",
                plugin->update_message_flags);

  mysql_prepare (plugin->mc,
                  "SELECT hop_counter, signature, purpose, fragment_id,\n"
                  "       fragment_offset, message_id, group_generation,\n"
                  "       multicast_flags, psycstore_flags, data\n"
                  "FROM messages\n"
                  "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
                  "      AND ? <= fragment_id AND fragment_id <= ?;",
               plugin->select_fragments);

  /** @todo select_messages: add method_prefix filter */
  mysql_prepare (plugin->mc,
                "SELECT hop_counter, signature, purpose, fragment_id,\n"
                "       fragment_offset, message_id, group_generation,\n"
                "       multicast_flags, psycstore_flags, data\n"
                "FROM messages\n"
                "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
                "      AND ? <= message_id AND message_id <= ?"
                "LIMIT ?;",
                plugin->select_messages);

  mysql_prepare (plugin->mc,
                "SELECT * FROM\n"
                "(SELECT hop_counter, signature, purpose, fragment_id,\n"
                "        fragment_offset, message_id, group_generation,\n"
                "        multicast_flags, psycstore_flags, data\n"
                " FROM messages\n"
                " WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
                " ORDER BY fragment_id DESC\n"
                " LIMIT ?)\n"
                "ORDER BY fragment_id;",
                plugin->select_latest_fragments);

  /** @todo select_latest_messages: add method_prefix filter */
  mysql_prepare (plugin->mc,
                "SELECT hop_counter, signature, purpose, fragment_id,\n"
                "       fragment_offset, message_id, group_generation,\n"
                "        multicast_flags, psycstore_flags, data\n"
                "FROM messages\n"
                "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
                "      AND message_id IN\n"
                "      (SELECT message_id\n"
                "       FROM messages\n"
                "       WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
                "       GROUP BY message_id\n"
                "       ORDER BY message_id\n"
                "       DESC LIMIT ?)\n"
                "ORDER BY fragment_id;",
               plugin->select_latest_messages);

  mysql_prepare (plugin->mc,
                "SELECT hop_counter, signature, purpose, fragment_id,\n"
                "       fragment_offset, message_id, group_generation,\n"
                "       multicast_flags, psycstore_flags, data\n"
                "FROM messages\n"
                "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
                "      AND message_id = ? AND fragment_offset = ?;",
                plugin->select_message_fragment);

  mysql_prepare (plugin->mc,
                "SELECT fragment_id, message_id, group_generation\n"
               "FROM messages\n"
               "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
               "ORDER BY fragment_id DESC LIMIT 1;",
               plugin->select_counters_message);

  mysql_prepare (plugin->mc,
                "SELECT max_state_message_id\n"
                "FROM channels\n"
                "WHERE pub_key = ? AND max_state_message_id IS NOT NULL;",
               plugin->select_counters_state);

  mysql_prepare (plugin->mc,
                "UPDATE channels\n"
                "SET max_state_message_id = ?\n"
                "WHERE pub_key = ?;",
               plugin->update_max_state_message_id);

  mysql_prepare (plugin->mc,
                "UPDATE channels\n"
                "SET state_hash_message_id = ?\n"
                "WHERE pub_key = ?;",
                plugin->update_state_hash_message_id);

  mysql_prepare (plugin->mc,
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
                plugin->insert_state_current);

  mysql_prepare (plugin->mc,
                "DELETE FROM state\n"
                "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
                "      AND (value_current IS NULL OR length(value_current) = 0)\n"
                "      AND (value_signed IS NULL OR length(value_signed) = 0);",
               plugin->delete_state_empty);

  mysql_prepare (plugin->mc,
                "UPDATE state\n"
                "SET value_signed = value_current\n"
                "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
                plugin->update_state_signed);

  mysql_prepare (plugin->mc,
                "DELETE FROM state\n"
                "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
                plugin->delete_state);

  mysql_prepare (plugin->mc,
                "INSERT INTO state_sync (channel_id, name, value)\n"
                "VALUES ((SELECT id FROM channels WHERE pub_key = ?), ?, ?);",
                plugin->insert_state_sync);

  mysql_prepare (plugin->mc,
                "INSERT INTO state\n"
                " (channel_id, name, value_current, value_signed)\n"
                "SELECT channel_id, name, value, value\n"
                "FROM state_sync\n"
                "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
                plugin->insert_state_from_sync);

  mysql_prepare (plugin->mc,
                "DELETE FROM state_sync\n"
                "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
                plugin->delete_state_sync);

  mysql_prepare (plugin->mc,
                "SELECT value_current\n"
                "FROM state\n"
                "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
                "      AND name = ?;",
                plugin->select_state_one);

  mysql_prepare (plugin->mc,
                "SELECT name, value_current\n"
                "FROM state\n"
                "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
                "      AND (name = ? OR substr(name, 1, ?) = ? || '_');",
                plugin->select_state_prefix);

  mysql_prepare (plugin->mc,
                "SELECT name, value_signed\n"
                "FROM state\n"
                "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)"
                "      AND value_signed IS NOT NULL;",
                plugin->select_state_signed);

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
  
  //MYSQL_STMT *stmt;

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
exec_channel (struct Plugin *plugin, struct GNUNET_MYSQL_StatementHandle *stmt,
              const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key)
{
  MYSQL_STMT * statement = NULL;
  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  if (NULL == statement)
  {
     LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql statement invalide", statement);
    return GNUNET_SYSERR;
  }

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_end
  };

  if(GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc,
                                          stmt,
                                          params))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql exec_channel", stmt); 
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
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
  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->transaction_begin;
  MYSQL_STMT * statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  if (NULL == statement)
  {
     LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql statement invalide", statement);
    return GNUNET_SYSERR;
  }

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc,
                                            stmt,
                                            params))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql extract_result", statement);
    return GNUNET_SYSERR; 
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
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
  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->transaction_commit;
  MYSQL_STMT *statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  if (NULL == statement)
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql statement invalide", statement);
    return GNUNET_SYSERR; 
  }

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared( plugin->mc,
                                            stmt,
                                            params))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql extract_result", statement);
    return GNUNET_SYSERR; 
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
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
  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->transaction_rollback;
  MYSQL_STMT* statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);
  if (NULL == statement)
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql statement invalide", statement);
    return GNUNET_SYSERR; 
  }

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc,
                                            stmt,
                                            params))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql extract_result", statement);
    return GNUNET_SYSERR;  
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
  }

  plugin->transaction = TRANSACTION_NONE;
  return GNUNET_OK;
}


static int
channel_key_store (struct Plugin *plugin,
                   const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key)
{
  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->insert_channel_key;

  MYSQL_STMT *statement = NULL;
  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  if(NULL == statement)
  {
   LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql statement invalide", statement);
    return GNUNET_SYSERR;  
  }

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc,
                                            stmt,
                                            params))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql extract_result", statement);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
  }

  return GNUNET_OK;
}


static int
slave_key_store (struct Plugin *plugin,
                 const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key)
{
  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->insert_slave_key;

  MYSQL_STMT *statement = NULL;
  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  if(NULL == statement)
  {
   LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql statement invalide", statement);
    return GNUNET_SYSERR;  
  }

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_auto_from_type (slave_key),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared( plugin->mc,
                                            stmt,
                                            params))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql extract_result", statement);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
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
sqlite_membership_store (void *cls,
                         const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                         const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                         int did_join,
                         uint64_t announced_at,
                         uint64_t effective_since,
                         uint64_t group_generation)
{
  struct Plugin *plugin = cls;
  
  uint32_t idid_join = (uint32_t)did_join;
  uint64_t iannounced_at = (uint64_t)announced_at;
  uint64_t ieffective_since = (uint64_t)effective_since;
  uint64_t igroup_generation = (uint64_t)group_generation;

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->insert_membership;
  MYSQL_STMT *statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

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

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_auto_from_type (slave_key),
    GNUNET_MY_query_param_uint32 (&idid_join),
    GNUNET_MY_query_param_uint64 (&iannounced_at),
    GNUNET_MY_query_param_uint64 (&ieffective_since),
    GNUNET_MY_query_param_uint64 (&igroup_generation),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc,
                                            stmt,
                                            params))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql extract_result", statement);
    return GNUNET_SYSERR; 
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
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

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->select_membership;
  MYSQL_STMT *statement = NULL;
  
  uint32_t did_join = 0;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  if(NULL == statement)
  {
   LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql statement invalide", statement);
    return GNUNET_SYSERR;  
  }

  int ret = GNUNET_SYSERR;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_auto_from_type (slave_key),
    GNUNET_MY_query_param_uint64 (&message_id),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_MY_exec_prepared (plugin->mc,
                              stmt,
                              params_select))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql execute prepared", statement);
    return GNUNET_SYSERR; 
  }

  struct GNUNET_MY_ResultSpec results_select[] = {
    GNUNET_MY_result_spec_uint32 (&did_join),
    GNUNET_MY_result_spec_end
  };

  if (GNUNET_OK != GNUNET_MY_extract_result (stmt,
                                results_select))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql extract_result", statement);
    return GNUNET_SYSERR; 
  }

  if(0 != did_join)
  {
    ret = GNUNET_YES;
  }
  else
  {
    ret = GNUNET_NO;
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
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
  
  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->insert_fragment;
  MYSQL_STMT *statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

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

  struct GNUNET_MY_QueryParam params_insert[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_uint32 (msg->hop_counter),
    GNUNET_MY_query_param_auto_from_type (&msg->signature),
    GNUNET_MY_query_param_auto_from_type (&msg->purpose),
    GNUNET_MY_query_param_uint64 (&fragment_id),
    GNUNET_MY_query_param_uint64 (&fragment_offset),
    GNUNET_MY_query_param_uint64 (&message_id),
    GNUNET_MY_query_param_uint64 (&group_generation),
    GNUNET_MY_query_param_uint32 ( msg->flags),
    GNUNET_MY_query_param_uint32 (&psycstore_flags),
    GNUNET_MY_query_param_auto_from_type (&msg[1]),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_MY_exec_prepared (plugin->mc,
                              stmt,
                              params_insert))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql execute prepared", statement);
    return GNUNET_SYSERR;    
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
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

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->update_message_flags;
  MYSQL_STMT *statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  int ret = GNUNET_SYSERR;

  struct GNUNET_MY_QueryParam params_update[] = {
    GNUNET_MY_query_param_uint64 (&psycstore_flags),
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_uint64 (&message_id),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc,
                                            stmt,
                                            params_update))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql execute prepared", statement);
    return GNUNET_SYSERR;   
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
  }

  return ret;
}

/** Extract result from statement **/
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

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->select_fragments;
  MYSQL_STMT *statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);
  if (NULL == statement)
  {
   LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql get_stmt", statement);
    return GNUNET_SYSERR;  
  }

  int ret = GNUNET_SYSERR;
  *returned_fragments = 0;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_uint64 (&first_fragment_id),
    GNUNET_MY_query_param_uint64 (&last_fragment_id),
    GNUNET_MY_query_param_end
  };

  ret = fragment_select (plugin, stmt, returned_fragments, cb, cb_cls);

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
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

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->select_latest_fragments;
  MYSQL_STMT * statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  int ret = GNUNET_SYSERR;
  *returned_fragments = 0;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_uint64 (&fragment_limit),
    GNUNET_MY_query_param_end
  };

  ret = fragment_select (plugin, stmt, returned_fragments, cb, cb_cls);

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
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
             uint64_t fragment_limit,
             uint64_t *returned_fragments,
             GNUNET_PSYCSTORE_FragmentCallback cb,
             void *cb_cls)
{
  struct Plugin *plugin = cls;

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->select_messages;
  MYSQL_STMT *statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  int ret = GNUNET_SYSERR;
  *returned_fragments = 0;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_uint64 (&first_message_id),
    GNUNET_MY_query_param_uint64 (&last_message_id),
    GNUNET_MY_query_param_uint64 (&fragment_limit),
    GNUNET_MY_query_param_end
  };

  ret = fragment_select (plugin, stmt, returned_fragments, cb, cb_cls);

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
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

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->select_latest_messages;
  MYSQL_STMT *statement;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  int ret = GNUNET_SYSERR;
  *returned_fragments = 0;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_uint64 (&message_limit),
    GNUNET_MY_query_param_end
  };

  ret = fragment_select (plugin, stmt, returned_fragments, cb, cb_cls);

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
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

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->select_message_fragment;
  MYSQL_STMT *statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  int ret = GNUNET_SYSERR;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_uint64 (&message_id),
    GNUNET_MY_query_param_uint64 (&fragment_offset),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc,
                                            stmt,
                                            params_select))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql execute prepared", statement);
    return GNUNET_SYSERR;    
  }

  ret = fragment_row (stmt, cb, cb_cls);

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
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
  
  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->select_counters_message;
  MYSQL_STMT *statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);
  if (NULL == statement)
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql get statement", statement);
    return GNUNET_SYSERR;
  }  

  int ret = GNUNET_SYSERR;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc,
                                            stmt,
                                            params_select))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql execute prepared", statement);
    return GNUNET_SYSERR;
  }

  struct GNUNET_MY_ResultSpec results_select[] = {
    GNUNET_MY_result_spec_uint64 (max_fragment_id),
    GNUNET_MY_result_spec_uint64 (max_message_id),
    GNUNET_MY_result_spec_uint64 (max_group_generation),
    GNUNET_MY_result_spec_end
  };

  ret = GNUNET_MY_extract_result (stmt,
                                  results_select);

  if (GNUNET_OK != ret)
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql extract_result", statement);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
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

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->select_counters_state;
  MYSQL_STMT *statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);
  if (NULL == statement)
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql get_stmt", statement);
    return GNUNET_SYSERR; 
  }

  int ret = GNUNET_SYSERR;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc,
                                            stmt,
                                            params_select))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql execute prepared", statement);
    return GNUNET_SYSERR;
  }

  struct GNUNET_MY_ResultSpec results_select[] = {
    GNUNET_MY_result_spec_uint64 (max_state_message_id),
    GNUNET_MY_result_spec_end
  };

  ret = GNUNET_MY_extract_result (stmt,
                                  results_select);

  if (GNUNET_OK != ret)
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql extract_result", statement);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
  }  

  return ret;
}


/**
 * Assign a value to a state variable.
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
state_assign (struct Plugin *plugin, struct GNUNET_MYSQL_StatementHandle *stmt,
              const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
              const char *name, const void *value, size_t value_size)
{
  int ret = GNUNET_SYSERR;

  MYSQL_STMT *statement = NULL;
  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  if (NULL == statement)
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql get_stmt", statement);
    return GNUNET_SYSERR;
  }

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_string (name),
    GNUNET_MY_query_param_auto_from_type (value_size),
    GNUNET_MY_query_param_end
  };

  ret = GNUNET_MY_exec_prepared (plugin->mc,
                                            stmt,
                                            params);

  if (GNUNET_OK != ret)
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql execute prepared", statement);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
  }    

  return ret;
}


static int
update_message_id (struct Plugin *plugin, struct GNUNET_MYSQL_StatementHandle *stmt,
                   const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                   uint64_t message_id)
{
  MYSQL_STMT *statement = NULL;
  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  if (NULL == statement)
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql get_stmt", statement);
    return GNUNET_SYSERR;
  }

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_uint64 (&message_id),
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc,
                                            stmt,
                                            params))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql execute prepared", statement);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
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

  if (state_delta > 0)
  {
    /**
     * We can only apply state modifiers in the current message if modifiers in
     * the previous stateful message (message_id - state_delta) were already
     * applied.
     */

    uint64_t max_state_message_id = 0;
    int ret = counters_state_get (plugin, channel_key, &max_state_message_id);
    switch (ret)
    {
    case GNUNET_OK:
    case GNUNET_NO: // no state yet
      ret = GNUNET_OK;
      break;
    default:
      return ret;
    }

    if (max_state_message_id < message_id - state_delta)
      return GNUNET_NO; /* some stateful messages not yet applied */
    else if (message_id - state_delta < max_state_message_id)
      return GNUNET_NO; /* changes already applied */
  }

  if (TRANSACTION_NONE != plugin->transaction)
  {
    /** @todo FIXME: wait for other transaction to finish  */
    return GNUNET_SYSERR;
  }
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
state_modify_op (void *cls,
                 const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                 enum GNUNET_PSYC_Operator op,
                 const char *name, const void *value, size_t value_size)
{
  struct Plugin *plugin = cls;
  GNUNET_assert (TRANSACTION_STATE_MODIFY == plugin->transaction);

  switch (op)
  {
  case GNUNET_PSYC_OP_ASSIGN:
    return state_assign (plugin, plugin->insert_state_current, channel_key,
                         name, value, value_size);

  default: /** @todo implement more state operations */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
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
 * Assign current value of a state variable.
 *
 * @see GNUNET_PSYCSTORE_state_modify()
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
state_sync_assign (void *cls,
                const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                const char *name, const void *value, size_t value_size)
{
  struct Plugin *plugin = cls;
  return state_assign (cls, plugin->insert_state_sync, channel_key,
                       name, value, value_size);
}


/**
 * End modifying current state.
 */
static int
state_sync_end (void *cls,
                const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                uint64_t max_state_message_id,
                uint64_t state_hash_message_id)
{
  struct Plugin *plugin = cls;
  int ret = GNUNET_SYSERR;

  if (TRANSACTION_NONE != plugin->transaction)
  {
    /** @todo FIXME: wait for other transaction to finish  */
    return GNUNET_SYSERR;
  }

  GNUNET_OK == transaction_begin (plugin, TRANSACTION_STATE_SYNC)
    && GNUNET_OK == exec_channel (plugin, plugin->delete_state, channel_key)
    && GNUNET_OK == exec_channel (plugin, plugin->insert_state_from_sync,
                                  channel_key)
    && GNUNET_OK == exec_channel (plugin, plugin->delete_state_sync,
                                  channel_key)
    && GNUNET_OK == update_message_id (plugin,
                                       plugin->update_state_hash_message_id,
                                       channel_key, state_hash_message_id)
    && GNUNET_OK == update_message_id (plugin,
                                       plugin->update_max_state_message_id,
                                       channel_key, max_state_message_id)
    && GNUNET_OK == transaction_commit (plugin)
    ? ret = GNUNET_OK
    : transaction_rollback (plugin);
  return ret;
}


/**
 * Delete the whole state.
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

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->select_state_one;
  MYSQL_STMT *statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_string (name),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc,
                                            stmt,
                                            params_select))
  {

  }

  ret = cb (cb_cls, name, sqlite3_column_blob (stmt, 0),
                sqlite3_column_bytes (stmt, 0));

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
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

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->select_state_prefix;
  MYSQL_STMT *statement = NULL;
  statement = GNUNET_MYSQL_statement_get_stmt (stmt);

  if (NULL == statement)
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql get_stmt", statement);
    return GNUNET_SYSERR;
  }

  uint32_t name_len = (uint32_t) strlen (name);

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_string (name),
    GNUNET_MY_query_param_uint32 (&name_len),
    GNUNET_MY_query_param_string (name),
    GNUNET_MY_query_param_end
  };

  int sql_ret;

  sql_ret = GNUNET_MY_exec_prepared (plugin->mc,
                                    stmt,
                                    params_select);

  if (GNUNET_OK != sql_ret)
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql exec_prepared", statement);
    return GNUNET_SYSERR;
  }

  ret = cb (cb_cls, (const char *) sqlite3_column_text (stmt, 0),
                  sqlite3_column_blob (stmt, 1),
                  sqlite3_column_bytes (stmt, 1));

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
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

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->select_state_signed;
  MYSQL_STMT *statement = NULL;

  statement = GNUNET_MYSQL_statement_get_stmt (stmt);
  if (NULL == statement)
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql get_stmt", statement);
    return GNUNET_SYSERR; 
  }

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_end
  };

  int sql_ret;

  sql_ret = GNUNET_MY_exec_prepared (plugin->mc,
                                      stmt,
                                      params_select);

  if (GNUNET_OK != sql_ret)
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_exec_prepared", statement);
    return GNUNET_SYSERR;
  }

  ret = cb (cb_cls, (const char *) sqlite3_column_text (stmt, 0),
                  sqlite3_column_blob (stmt, 1),
                  sqlite3_column_bytes (stmt, 1));

  if (0 != mysql_stmt_reset (statement))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", statement);
    return GNUNET_SYSERR; 
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
  api->membership_store = &sqlite_membership_store;
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
  api->state_modify_op = &state_modify_op;
  api->state_modify_end = &state_modify_end;
  api->state_sync_begin = &state_sync_begin;
  api->state_sync_assign = &state_sync_assign;
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

/* end of plugin_psycstore_mysql.c */
