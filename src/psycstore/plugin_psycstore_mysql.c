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
 * @brief mysql-based psycstore backend
 * @author Gabor X Toth
 * @author Christian Grothoff
 * @author Christophe Genevey
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
#define LOG_MYSQL(db, level, cmd, stmt)                                 \
  do {                                                                  \
    GNUNET_log_from (level, "psycstore-mysql",                          \
                     _("`%s' failed at %s:%d with error: %s\n"),        \
                     cmd, __FILE__, __LINE__,                           \
                     mysql_stmt_error (GNUNET_MYSQL_statement_get_stmt(stmt))); \
  } while (0)

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
   * MySQL context.
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
mysql_trace (void *cls, const char *sql)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG, "MYSQL query:\n%s\n", sql);
}

#endif


/**
 * @brief Prepare a SQL statement
 *
 * @param dbh handle to the database
 * @param sql SQL statement, UTF-8 encoded
 * @param stmt set to the prepared statement
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
mysql_prepare (struct GNUNET_MYSQL_Context *mc,
              const char *sql,
              struct GNUNET_MYSQL_StatementHandle **stmt)
{
  *stmt = GNUNET_MYSQL_statement_prepare (mc,
                                          sql);

  if (NULL == *stmt)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Error preparing SQL query: %s\n  %s\n"),
         mysql_stmt_error (GNUNET_MYSQL_statement_get_stmt (*stmt)),
         sql);
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Prepared `%s' / %p\n",
       sql,
       stmt);
  return GNUNET_OK;
}


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
  /* Open database and precompile statements */
  plugin->mc = GNUNET_MYSQL_context_create (plugin->cfg,
                                            "psycstore-mysql");

  if (NULL == plugin->mc)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Unable to initialize Mysql.\n"));
    return GNUNET_SYSERR;
  }

#define STMT_RUN(sql) \
  if (GNUNET_OK != \
      GNUNET_MYSQL_statement_run (plugin->mc, \
                                  sql)) \
  { \
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, \
                _("Failed to run SQL statement `%s'\n"), \
                sql); \
    return GNUNET_SYSERR; \
  }

  /* Create tables */
  STMT_RUN ("CREATE TABLE IF NOT EXISTS channels (\n"
            " id INT AUTO_INCREMENT,\n"
            " pub_key BLOB,\n"
            " max_state_message_id INT,\n"
            " state_hash_message_id INT,\n"
            " PRIMARY KEY(id),\n"
            " UNIQUE KEY(pub_key(5))\n"
            ");");

  STMT_RUN ("CREATE TABLE IF NOT EXISTS slaves (\n"
            " id INT AUTO_INCREMENT,\n"
            " pub_key BLOB,\n"
            " PRIMARY KEY(id),\n"
            " UNIQUE KEY(pub_key(5))\n"
            ");");

  STMT_RUN ("CREATE TABLE IF NOT EXISTS membership (\n"
            "  channel_id INT NOT NULL REFERENCES channels(id),\n"
            "  slave_id INT NOT NULL REFERENCES slaves(id),\n"
            "  did_join INT NOT NULL,\n"
            "  announced_at BIGINT UNSIGNED NOT NULL,\n"
            "  effective_since BIGINT UNSIGNED NOT NULL,\n"
            "  group_generation BIGINT UNSIGNED NOT NULL\n"
            ");");

/*** FIX because IF NOT EXISTS doesn't work ***/
  GNUNET_MYSQL_statement_run (plugin->mc,
                              "CREATE INDEX idx_membership_channel_id_slave_id "
                              "ON membership (channel_id, slave_id);");

  /** @todo messages table: add method_name column */
  STMT_RUN ("CREATE TABLE IF NOT EXISTS messages (\n"
            "  channel_id INT NOT NULL REFERENCES channels(id),\n"
            "  hop_counter BIGINT UNSIGNED NOT NULL,\n"
            "  signature BLOB,\n"
            "  purpose BLOB,\n"
            "  fragment_id BIGINT UNSIGNED NOT NULL,\n"
            "  fragment_offset BIGINT UNSIGNED NOT NULL,\n"
                              "  message_id BIGINT UNSIGNED NOT NULL,\n"
            "  group_generation BIGINT UNSIGNED NOT NULL,\n"
            "  multicast_flags BIGINT UNSIGNED NOT NULL,\n"
            "  psycstore_flags BIGINT UNSIGNED NOT NULL,\n"
            "  data BLOB,\n"
            "  PRIMARY KEY (channel_id, fragment_id),\n"
            "  UNIQUE KEY(channel_id, message_id, fragment_offset)\n"
            ");");

  STMT_RUN ("CREATE TABLE IF NOT EXISTS state (\n"
            "  channel_id INT NOT NULL REFERENCES channels(id),\n"
            "  name TEXT NOT NULL,\n"
            "  value_current BLOB,\n"
            "  value_signed BLOB,\n"
            "  PRIMARY KEY (channel_id, name(5))\n"
            ");");

  STMT_RUN ("CREATE TABLE IF NOT EXISTS state_sync (\n"
            "  channel_id INT NOT NULL REFERENCES channels(id),\n"
            "  name TEXT NOT NULL,\n"
            "  value BLOB,\n"
            "  PRIMARY KEY (channel_id, name(5))\n"
            ");");
#undef STMT_RUN

  /* Prepare statements */
#define PREP(stmt,handle)                                    \
  if (GNUNET_OK != mysql_prepare (plugin->mc, stmt, handle)) \
  { \
    GNUNET_break (0); \
    return GNUNET_SYSERR; \
  }
  PREP ("BEGIN",
        &plugin->transaction_begin);
  PREP ("COMMIT",
        &plugin->transaction_commit);
  PREP ("ROLLBACK;",
        &plugin->transaction_rollback);
  PREP ("INSERT IGNORE INTO channels (pub_key) VALUES (?);",
        &plugin->insert_channel_key);
  PREP ("INSERT IGNORE INTO slaves (pub_key) VALUES (?);",
        &plugin->insert_slave_key);
  PREP ("INSERT INTO membership\n"
        " (channel_id, slave_id, did_join, announced_at,\n"
        "  effective_since, group_generation)\n"
        "VALUES ((SELECT id FROM channels WHERE pub_key = ?),\n"
        "        (SELECT id FROM slaves WHERE pub_key = ?),\n"
        "        ?, ?, ?, ?);",
        &plugin->insert_membership);
  PREP ("SELECT did_join FROM membership\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
        "      AND slave_id = (SELECT id FROM slaves WHERE pub_key = ?)\n"
        "      AND effective_since <= ? AND did_join = 1\n"
        "ORDER BY announced_at DESC LIMIT 1;",
        &plugin->select_membership);

  PREP ("INSERT IGNORE INTO messages\n"
        " (channel_id, hop_counter, signature, purpose,\n"
        "  fragment_id, fragment_offset, message_id,\n"
        "  group_generation, multicast_flags, psycstore_flags, data)\n"
        "VALUES ((SELECT id FROM channels WHERE pub_key = ?),\n"
        "        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        &plugin->insert_fragment);

  PREP ("UPDATE messages\n"
        "SET psycstore_flags = psycstore_flags | ?\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
        "      AND message_id = ? AND fragment_offset = 0;",
        &plugin->update_message_flags);

  PREP ("SELECT hop_counter, signature, purpose, fragment_id,\n"
        "       fragment_offset, message_id, group_generation,\n"
        "       multicast_flags, psycstore_flags, data\n"
        "FROM messages\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
        "      AND ? <= fragment_id AND fragment_id <= ? LIMIT 1;",
        &plugin->select_fragments);

  /** @todo select_messages: add method_prefix filter */
  PREP ("SELECT hop_counter, signature, purpose, fragment_id,\n"
        "       fragment_offset, message_id, group_generation,\n"
        "       multicast_flags, psycstore_flags, data\n"
        "FROM messages\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
        "      AND ? <= message_id AND message_id <= ?\n"
        "LIMIT ?;",
        &plugin->select_messages);

  PREP ("SELECT * FROM\n"
        "(SELECT hop_counter, signature, purpose, fragment_id,\n"
        "        fragment_offset, message_id, group_generation,\n"
        "        multicast_flags, psycstore_flags, data\n"
        " FROM messages\n"
        " WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
        " ORDER BY fragment_id DESC\n"
        " LIMIT ?)\n"
        "ORDER BY fragment_id;",
        &plugin->select_latest_fragments);

  /** @todo select_latest_messages: add method_prefix filter */
  PREP ("SELECT hop_counter, signature, purpose, fragment_id,\n"
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
        &plugin->select_latest_messages);

  PREP ("SELECT hop_counter, signature, purpose, fragment_id,\n"
        "       fragment_offset, message_id, group_generation,\n"
        "       multicast_flags, psycstore_flags, data\n"
        "FROM messages\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
        "      AND message_id = ? AND fragment_offset = ?;",
        &plugin->select_message_fragment);

  PREP ("SELECT fragment_id, message_id, group_generation\n"
        "FROM messages\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
        "ORDER BY fragment_id DESC LIMIT 1;",
        &plugin->select_counters_message);

  PREP ("SELECT max_state_message_id\n"
        "FROM channels\n"
        "WHERE pub_key = ? AND max_state_message_id IS NOT NULL;",
        &plugin->select_counters_state);

  PREP ("UPDATE channels\n"
        "SET max_state_message_id = ?\n"
        "WHERE pub_key = ?;",
        &plugin->update_max_state_message_id);

  PREP ("UPDATE channels\n"
        "SET state_hash_message_id = ?\n"
        "WHERE pub_key = ?;",
        &plugin->update_state_hash_message_id);

  PREP ("REPLACE INTO state\n"
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

  PREP ("DELETE FROM state\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
        "      AND (value_current IS NULL OR length(value_current) = 0)\n"
        "      AND (value_signed IS NULL OR length(value_signed) = 0);",
        &plugin->delete_state_empty);

  PREP ("UPDATE state\n"
        "SET value_signed = value_current\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
        &plugin->update_state_signed);

  PREP ("DELETE FROM state\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
        &plugin->delete_state);

  PREP ("INSERT INTO state_sync (channel_id, name, value)\n"
        "VALUES ((SELECT id FROM channels WHERE pub_key = ?), ?, ?);",
        &plugin->insert_state_sync);

  PREP ("INSERT INTO state\n"
        " (channel_id, name, value_current, value_signed)\n"
        "SELECT channel_id, name, value, value\n"
        "FROM state_sync\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
        &plugin->insert_state_from_sync);

  PREP ("DELETE FROM state_sync\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?);",
        &plugin->delete_state_sync);

  PREP ("SELECT value_current\n"
        "FROM state\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
        "      AND name = ?;",
        &plugin->select_state_one);

  PREP ("SELECT name, value_current\n"
        "FROM state\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)\n"
        "      AND (name = ? OR substr(name, 1, ?) = ? || '_');",
        &plugin->select_state_prefix);

  PREP ("SELECT name, value_signed\n"
        "FROM state\n"
        "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = ?)"
        "      AND value_signed IS NOT NULL;",
        &plugin->select_state_signed);
#undef PREP

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
  GNUNET_MYSQL_context_destroy (plugin->mc);
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
  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql exec_channel", stmt);
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql exexc_prepared", stmt);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt(stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql exec_prepared", stmt);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql exec_prepared", stmt);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql exec_prepared", stmt);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


static int
slave_key_store (struct Plugin *plugin,
                 const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key)
{
  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->insert_slave_key;

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_auto_from_type (slave_key),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql exec_prepared", stmt);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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
mysql_membership_store (void *cls,
                         const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                         const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                         int did_join,
                         uint64_t announced_at,
                         uint64_t effective_since,
                         uint64_t group_generation)
{
  struct Plugin *plugin = cls;

  uint32_t idid_join = (uint32_t)did_join;

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->insert_membership;

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
    GNUNET_MY_query_param_uint64 (&announced_at),
    GNUNET_MY_query_param_uint64 (&effective_since),
    GNUNET_MY_query_param_uint64 (&group_generation),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql exec_prepared", stmt);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  uint32_t did_join = 0;

  int ret = GNUNET_SYSERR;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_auto_from_type (slave_key),
    GNUNET_MY_query_param_uint64 (&message_id),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params_select))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql execute prepared", stmt);
    return GNUNET_SYSERR;
  }

  struct GNUNET_MY_ResultSpec results_select[] = {
    GNUNET_MY_result_spec_uint32 (&did_join),
    GNUNET_MY_result_spec_end
  };

  switch(GNUNET_MY_extract_result (stmt,
                                results_select))
  {
    case GNUNET_NO:
      ret = GNUNET_NO;
      break;
    case GNUNET_OK:
      ret = GNUNET_YES;
      break;
    default:
      LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql extract_result", stmt);
      return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  GNUNET_assert (TRANSACTION_NONE == plugin->transaction);

  uint64_t fragment_id = GNUNET_ntohll (msg->fragment_id);

  uint64_t fragment_offset = GNUNET_ntohll (msg->fragment_offset);
  uint64_t message_id = GNUNET_ntohll (msg->message_id);
  uint64_t group_generation = GNUNET_ntohll (msg->group_generation);

  uint64_t hop_counter = ntohl(msg->hop_counter);
  uint64_t flags = ntohl(msg->flags);

  if (fragment_id > INT64_MAX || fragment_offset > INT64_MAX ||
      message_id > INT64_MAX || group_generation > INT64_MAX)
  {
    LOG(GNUNET_ERROR_TYPE_ERROR,
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
    GNUNET_MY_query_param_uint64 (&hop_counter),
    GNUNET_MY_query_param_auto_from_type (&msg->signature),
    GNUNET_MY_query_param_auto_from_type (&msg->purpose),
    GNUNET_MY_query_param_uint64 (&fragment_id),
    GNUNET_MY_query_param_uint64 (&fragment_offset),
    GNUNET_MY_query_param_uint64 (&message_id),
    GNUNET_MY_query_param_uint64 (&group_generation),
    GNUNET_MY_query_param_uint64 (&flags),
    GNUNET_MY_query_param_uint32 (&psycstore_flags),
    GNUNET_MY_query_param_fixed_size (&msg[1], ntohs (msg->header.size)
                                                  - sizeof (*msg)),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params_insert))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql execute prepared", stmt);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  int sql_ret;
  int ret = GNUNET_SYSERR;

  struct GNUNET_MY_QueryParam params_update[] = {
    GNUNET_MY_query_param_uint64 (&psycstore_flags),
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_uint64 (&message_id),
    GNUNET_MY_query_param_end
  };

  sql_ret = GNUNET_MY_exec_prepared (plugin->mc, stmt, params_update);
  switch (sql_ret)
  {
    case GNUNET_OK:
      ret = GNUNET_OK;
      break;

    default:
       LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql execute prepared", stmt);
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
    return GNUNET_SYSERR;
  }

  return ret;
}


static int
fragment_row (struct GNUNET_MYSQL_StatementHandle *stmt,
              GNUNET_PSYCSTORE_FragmentCallback cb,
              void *cb_cls,
              uint64_t *returned_fragments)
{

  uint32_t hop_counter;
  void *signature = NULL;
  void *purpose = NULL;
  size_t signature_size;
  size_t purpose_size;
  uint64_t fragment_id;
  uint64_t fragment_offset;
  uint64_t message_id;
  uint64_t group_generation;
  uint64_t flags;
  void *buf;
  size_t buf_size;
  int ret = GNUNET_SYSERR;
  int sql_ret;
  struct GNUNET_MULTICAST_MessageHeader *mp;
  uint64_t msg_flags;
  struct GNUNET_MY_ResultSpec results[] = {
    GNUNET_MY_result_spec_uint32 (&hop_counter),
    GNUNET_MY_result_spec_variable_size (&signature, &signature_size),
    GNUNET_MY_result_spec_variable_size (&purpose, &purpose_size),
    GNUNET_MY_result_spec_uint64 (&fragment_id),
    GNUNET_MY_result_spec_uint64 (&fragment_offset),
    GNUNET_MY_result_spec_uint64 (&message_id),
    GNUNET_MY_result_spec_uint64 (&group_generation),
    GNUNET_MY_result_spec_uint64 (&msg_flags),
    GNUNET_MY_result_spec_uint64 (&flags),
    GNUNET_MY_result_spec_variable_size (&buf,
                                         &buf_size),
    GNUNET_MY_result_spec_end
  };

  do
    {
      sql_ret = GNUNET_MY_extract_result (stmt,
                                          results);
      switch (sql_ret)
        {
        case GNUNET_NO:
          if (ret != GNUNET_OK)
            ret = GNUNET_NO;
          break;

        case GNUNET_YES:
          mp = GNUNET_malloc (sizeof (*mp) + buf_size);

          mp->header.size = htons (sizeof (*mp) + buf_size);
          mp->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE);
          mp->hop_counter = htonl (hop_counter);
          GNUNET_memcpy (&mp->signature,
                         signature,
                         signature_size);
          GNUNET_memcpy (&mp->purpose,
                         purpose,
                         purpose_size);
          mp->fragment_id = GNUNET_htonll (fragment_id);
          mp->fragment_offset = GNUNET_htonll (fragment_offset);
          mp->message_id = GNUNET_htonll (message_id);
          mp->group_generation = GNUNET_htonll (group_generation);
          mp->flags = htonl(msg_flags);

          GNUNET_memcpy (&mp[1],
                         buf,
                         buf_size);
          ret = cb (cb_cls, mp, (enum GNUNET_PSYCSTORE_MessageFlags) flags);
          if (NULL != returned_fragments)
            (*returned_fragments)++;
          GNUNET_MY_cleanup_result (results);
          break;

        default:
          LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                    "mysql extract_result", stmt);
        }
    }
  while (GNUNET_YES == sql_ret);

  return ret;
}


static int
fragment_select (struct Plugin *plugin,
                 struct GNUNET_MYSQL_StatementHandle *stmt,
                 struct GNUNET_MY_QueryParam *params,
                 uint64_t *returned_fragments,
                 GNUNET_PSYCSTORE_FragmentCallback cb,
                 void *cb_cls)
{
  int ret = GNUNET_SYSERR;
  int sql_ret;

  sql_ret = GNUNET_MY_exec_prepared (plugin->mc, stmt, params);
  switch (sql_ret)
    {
    case GNUNET_NO:
      if (ret != GNUNET_OK)
        ret = GNUNET_NO;
      break;

    case GNUNET_YES:
      ret = fragment_row (stmt, cb, cb_cls, returned_fragments);
      break;

    default:
      LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                 "mysql exec_prepared", stmt);
    }
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
  int ret = GNUNET_SYSERR;
  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_uint64 (&first_fragment_id),
    GNUNET_MY_query_param_uint64 (&last_fragment_id),
    GNUNET_MY_query_param_end
  };

  *returned_fragments = 0;
  ret = fragment_select (plugin, stmt, params_select, returned_fragments, cb, cb_cls);

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  int ret = GNUNET_SYSERR;
  *returned_fragments = 0;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_uint64 (&fragment_limit),
    GNUNET_MY_query_param_end
  };

  ret = fragment_select (plugin, stmt, params_select, returned_fragments, cb, cb_cls);

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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
  int ret;
  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_uint64 (&first_message_id),
    GNUNET_MY_query_param_uint64 (&last_message_id),
    GNUNET_MY_query_param_uint64 (&fragment_limit),
    GNUNET_MY_query_param_end
  };

  *returned_fragments = 0;
  ret = fragment_select (plugin, stmt, params_select, returned_fragments, cb, cb_cls);

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  int ret = GNUNET_SYSERR;
  *returned_fragments = 0;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_uint64 (&message_limit),
    GNUNET_MY_query_param_end
  };

  ret = fragment_select (plugin, stmt, params_select, returned_fragments, cb, cb_cls);

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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
  int sql_ret;
  int ret = GNUNET_SYSERR;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_uint64 (&message_id),
    GNUNET_MY_query_param_uint64 (&fragment_offset),
    GNUNET_MY_query_param_end
  };

  sql_ret = GNUNET_MY_exec_prepared (plugin->mc, stmt, params_select);
  switch (sql_ret)
  {
    case GNUNET_NO:
      ret = GNUNET_NO;
      break;

    case GNUNET_OK:
      ret = fragment_row (stmt, cb, cb_cls, NULL);
      break;

    default:
      LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql execute prepared", stmt);
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  int ret = GNUNET_SYSERR;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params_select))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql execute prepared", stmt);
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
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql extract_result", stmt);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  int ret = GNUNET_SYSERR;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params_select))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql execute prepared", stmt);
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
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql extract_result", stmt);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_string (name),
    GNUNET_MY_query_param_auto_from_type (value),
    GNUNET_MY_query_param_end
  };

  ret = GNUNET_MY_exec_prepared (plugin->mc, stmt, params);
  if (GNUNET_OK != ret)
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql exec_prepared", stmt);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
    return GNUNET_SYSERR;
  }

  return ret;
}


static int
update_message_id (struct Plugin *plugin, struct GNUNET_MYSQL_StatementHandle *stmt,
                   const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                   uint64_t message_id)
{
  struct GNUNET_MY_QueryParam params[] = {
    GNUNET_MY_query_param_uint64 (&message_id),
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc,
                                            stmt,
                                            params))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql execute prepared", stmt);
    return GNUNET_SYSERR;
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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
  int sql_ret ;

  struct GNUNET_MYSQL_StatementHandle *stmt = plugin->select_state_one;

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_string (name),
    GNUNET_MY_query_param_end
  };

  void *value_current = NULL;
  size_t value_size = 0;

  struct GNUNET_MY_ResultSpec results[] = {
    GNUNET_MY_result_spec_variable_size (&value_current, &value_size),
    GNUNET_MY_result_spec_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params_select))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql exec_prepared", stmt);
  }
  else
  {
    sql_ret = GNUNET_MY_extract_result (stmt, results);
    switch (sql_ret)
    {
    case GNUNET_NO:
      ret = GNUNET_NO;
      break;
    case GNUNET_YES:
      ret = cb (cb_cls, name, value_current,
                value_size);
      break;
    default:
      LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql extract_result", stmt);
    }
  }

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  uint32_t name_len = (uint32_t) strlen (name);

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_string (name),
    GNUNET_MY_query_param_uint32 (&name_len),
    GNUNET_MY_query_param_string (name),
    GNUNET_MY_query_param_end
  };

  char *name2 = "";
  void *value_current = NULL;
  size_t value_size = 0;

  struct GNUNET_MY_ResultSpec results[] = {
    GNUNET_MY_result_spec_string (&name2),
    GNUNET_MY_result_spec_variable_size (&value_current, &value_size),
    GNUNET_MY_result_spec_end
  };

  int sql_ret;

  do
  {
    if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params_select))
    {
      LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql exec_prepared", stmt);
      break;
    }
    sql_ret = GNUNET_MY_extract_result (stmt, results);
    switch (sql_ret)
    {
      case GNUNET_NO:
        if (ret != GNUNET_OK)
          ret = GNUNET_NO;
        break;

      case GNUNET_YES:
        ret = cb (cb_cls, (const char *) name2,
                  value_current,
                  value_size);

        if (ret != GNUNET_YES)
          sql_ret = GNUNET_NO;
        break;

      default:
        LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql extract_result", stmt);
    }
  }
  while (sql_ret == GNUNET_YES);

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_auto_from_type (channel_key),
    GNUNET_MY_query_param_end
  };

  int sql_ret;

  char *name = "";
  void *value_signed = NULL;
  size_t value_size = 0;

  struct GNUNET_MY_ResultSpec results[] = {
    GNUNET_MY_result_spec_string (&name),
    GNUNET_MY_result_spec_variable_size (&value_signed, &value_size),
    GNUNET_MY_result_spec_end
  };

  do
  {
    if (GNUNET_OK != GNUNET_MY_exec_prepared (plugin->mc, stmt, params_select))
    {
      LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "mysql exec_prepared", stmt);
      break;
    }
    sql_ret = GNUNET_MY_extract_result (stmt, results);
    switch (sql_ret)
    {
      case GNUNET_NO:
        if (ret != GNUNET_OK)
          ret = GNUNET_NO;
        break;
      case GNUNET_YES:
        ret = cb (cb_cls, (const char *) name,
                  value_signed,
                  value_size);

        if (ret != GNUNET_YES)
            sql_ret = GNUNET_NO;
        break;
      default:
         LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql extract_result", stmt);
    }
  }
  while (sql_ret == GNUNET_YES);

  if (0 != mysql_stmt_reset (GNUNET_MYSQL_statement_get_stmt (stmt)))
  {
    LOG_MYSQL(plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
              "mysql_stmt_reset", stmt);
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
libgnunet_plugin_psycstore_mysql_init (void *cls)
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
  api->membership_store = &mysql_membership_store;
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

  LOG (GNUNET_ERROR_TYPE_INFO, _("Mysql database running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls The plugin context (as returned by "init")
 * @return Always NULL
 */
void *
libgnunet_plugin_psycstore_mysql_done (void *cls)
{
  struct GNUNET_PSYCSTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Mysql plugin is finished\n");
  return NULL;
}

/* end of plugin_psycstore_mysql.c */
