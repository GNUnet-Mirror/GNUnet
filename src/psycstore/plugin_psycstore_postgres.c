/*
 * This file is part of GNUnet
 * Copyright (C) 2016 GNUnet e.V.
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
 * @file psycstore/plugin_psycstore_postgres.c
 * @brief PostgresQL-based psycstore backend
 * @author Daniel Golle
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
#include "gnunet_postgres_lib.h"
#include "gnunet_pq_lib.h"

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

#define LOG(kind,...) GNUNET_log_from (kind, "psycstore-postgres", __VA_ARGS__)

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
   * Native Postgres database handle.
   */
  PGconn *dbh;

  enum Transactions transaction;

  void *cls;
};


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
  /* Open database and precompile statements */
  plugin->dbh = GNUNET_POSTGRES_connect (plugin->cfg,
                                         "psycstore-postgres");
  if (NULL == plugin->dbh)
    return GNUNET_SYSERR;

  /* Create tables */
  if ((GNUNET_OK !=
         GNUNET_POSTGRES_exec(plugin->dbh,
                              "CREATE TABLE IF NOT EXISTS channels (\n"
                              " id SERIAL,\n"
                              " pub_key BYTEA,\n"
                              " max_state_message_id INT,\n"
                              " state_hash_message_id INT,\n"
                              " PRIMARY KEY(id)\n"
                              ")" "WITH OIDS")) ||

      (GNUNET_OK !=
         GNUNET_POSTGRES_exec(plugin->dbh,
                              "CREATE UNIQUE INDEX IF NOT EXISTS channel_pub_key_idx \n"
                              " ON channels (substring(pub_key from 1 for 5)\n"
                              ")")) ||

      (GNUNET_OK !=
         GNUNET_POSTGRES_exec(plugin->dbh,
                              "CREATE OR REPLACE FUNCTION get_chan_id(BYTEA) RETURNS INTEGER AS \n"
                              " 'SELECT id FROM channels WHERE pub_key=$1;' LANGUAGE SQL STABLE \n"
                              "RETURNS NULL ON NULL INPUT")) ||

      (GNUNET_OK !=
         GNUNET_POSTGRES_exec(plugin->dbh,
                              "CREATE TABLE IF NOT EXISTS slaves (\n"
                              " id SERIAL,\n"
                              " pub_key BYTEA,\n"
                              " PRIMARY KEY(id)\n"
                              ")" "WITH OIDS")) ||

      (GNUNET_OK !=
         GNUNET_POSTGRES_exec(plugin->dbh,
                              "CREATE UNIQUE INDEX IF NOT EXISTS slaves_pub_key_idx \n"
                              " ON slaves (substring(pub_key from 1 for 5)\n"
                              ")")) ||

      (GNUNET_OK !=
         GNUNET_POSTGRES_exec(plugin->dbh,
                              "CREATE OR REPLACE FUNCTION get_slave_id(BYTEA) RETURNS INTEGER AS \n"
                              " 'SELECT id FROM slaves WHERE pub_key=$1;' LANGUAGE SQL STABLE \n"
                              "RETURNS NULL ON NULL INPUT")) ||

      (GNUNET_OK !=
         GNUNET_POSTGRES_exec(plugin->dbh,
                              "CREATE TABLE IF NOT EXISTS membership (\n"
                              "  channel_id INT NOT NULL REFERENCES channels(id),\n"
                              "  slave_id INT NOT NULL REFERENCES slaves(id),\n"
                              "  did_join INT NOT NULL,\n"
                              "  announced_at BIGINT NOT NULL,\n"
                              "  effective_since BIGINT NOT NULL,\n"
                              "  group_generation BIGINT NOT NULL\n"
                              ")" "WITH OIDS")) ||

      (GNUNET_OK !=
         GNUNET_POSTGRES_exec(plugin->dbh,
                              "CREATE INDEX IF NOT EXISTS idx_membership_channel_id_slave_id "
                              "ON membership (channel_id, slave_id)")) ||

  /** @todo messages table: add method_name column */
      (GNUNET_OK !=
         GNUNET_POSTGRES_exec(plugin->dbh,
                              "CREATE TABLE IF NOT EXISTS messages (\n"
                              "  channel_id INT NOT NULL REFERENCES channels(id),\n"
                              "  hop_counter BIGINT NOT NULL,\n"
                              "  signature BYTEA,\n"
                              "  purpose BYTEA,\n"
                              "  fragment_id BIGINT NOT NULL,\n"
                              "  fragment_offset BIGINT NOT NULL,\n"
                              "  message_id BIGINT NOT NULL,\n"
                              "  group_generation BIGINT NOT NULL,\n"
                              "  multicast_flags BIGINT NOT NULL,\n"
                              "  psycstore_flags BIGINT NOT NULL,\n"
                              "  data BYTEA,\n"
                              "  PRIMARY KEY (channel_id, fragment_id),\n"
                              "  UNIQUE (channel_id, message_id, fragment_offset)\n"
                              ")" "WITH OIDS")) ||

      (GNUNET_OK !=
         GNUNET_POSTGRES_exec(plugin->dbh,
                              "CREATE TABLE IF NOT EXISTS state (\n"
                              "  channel_id INT NOT NULL REFERENCES channels(id),\n"
                              "  name TEXT NOT NULL,\n"
                              "  value_current BYTEA,\n"
                              "  value_signed BYTEA\n"
                              ")" "WITH OIDS")) ||

      (GNUNET_OK !=
         GNUNET_POSTGRES_exec(plugin->dbh,
                              "CREATE UNIQUE INDEX IF NOT EXISTS state_uniq_idx \n"
                              " ON state (channel_id, substring(name from 1 for 5)\n"
                              ")")) ||

      (GNUNET_OK !=
         GNUNET_POSTGRES_exec(plugin->dbh,
                              "CREATE TABLE IF NOT EXISTS state_sync (\n"
                              "  channel_id INT NOT NULL REFERENCES channels(id),\n"
                              "  name TEXT NOT NULL,\n"
                              "  value BYTEA,\n"
                              "  PRIMARY KEY (channel_id)\n"
                              ")" "WITH OIDS")) ||

      (GNUNET_OK !=
         GNUNET_POSTGRES_exec(plugin->dbh,
                              "CREATE UNIQUE INDEX IF NOT EXISTS state_sync_name_idx \n"
                              " ON state_sync (substring(name from 1 for 5)\n"
                              ")")))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }


  /* Prepare statements */
  if ((GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                           "transaction_begin",
                           "BEGIN", 0)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                           "transaction_commit",
                           "COMMIT", 0)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                           "transaction_rollback",
                           "ROLLBACK", 0)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                           "insert_channel_key",
                           "INSERT INTO channels (pub_key) VALUES ($1)"
                           " ON CONFLICT DO NOTHING", 1)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                           "insert_slave_key",
                           "INSERT INTO slaves (pub_key) VALUES ($1)"
                           " ON CONFLICT DO NOTHING", 1)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                           "insert_membership",
                           "INSERT INTO membership\n"
                           " (channel_id, slave_id, did_join, announced_at,\n"
                           "  effective_since, group_generation)\n"
                           "VALUES (get_chan_id($1),\n"
                           "        get_slave_id($2),\n"
                           "        $3, $4, $5, $6)", 6)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                           "select_membership",
                           "SELECT did_join FROM membership\n"
                           "WHERE channel_id = get_chan_id($1)\n"
                           "      AND slave_id = get_slave_id($2)\n"
                           "      AND effective_since <= $3 AND did_join = 1\n"
                           "ORDER BY announced_at DESC LIMIT 1", 3)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                           "insert_fragment",
                           "INSERT INTO messages\n"
                           " (channel_id, hop_counter, signature, purpose,\n"
                           "  fragment_id, fragment_offset, message_id,\n"
                           "  group_generation, multicast_flags, psycstore_flags, data)\n"
                           "VALUES (get_chan_id($1),\n"
                           "        $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
                           "ON CONFLICT DO NOTHING", 11)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                           "update_message_flags",
                           "UPDATE messages\n"
                           "SET psycstore_flags = psycstore_flags | $1\n"
                           "WHERE channel_id = get_chan_id($2) \n"
                           "      AND message_id = $3 AND fragment_offset = 0", 3)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                           "select_fragments",
                           "SELECT hop_counter, signature, purpose, fragment_id,\n"
                           "       fragment_offset, message_id, group_generation,\n"
                           "       multicast_flags, psycstore_flags, data\n"
                           "FROM messages\n"
                           "WHERE channel_id = get_chan_id($1) \n"
                           "      AND $2 <= fragment_id AND fragment_id <= $3", 3)) ||

      /** @todo select_messages: add method_prefix filter */
      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "select_messages",
                "SELECT hop_counter, signature, purpose, fragment_id,\n"
                "       fragment_offset, message_id, group_generation,\n"
                "       multicast_flags, psycstore_flags, data\n"
                "FROM messages\n"
                "WHERE channel_id = get_chan_id($1) \n"
                "      AND $2 <= message_id AND message_id <= $3"
                "LIMIT $4;", 4)) ||

      /** @todo select_latest_messages: add method_prefix filter */
      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "select_latest_fragments",
                "SELECT  rev.hop_counter AS hop_counter,\n"
                "        rev.signature AS signature,\n"
                "        rev.purpose AS purpose,\n"
                "        rev.fragment_id AS fragment_id,\n"
                "        rev.fragment_offset AS fragment_offset,\n"
                "        rev.message_id AS message_id,\n"
                "        rev.group_generation AS group_generation,\n"
                "        rev.multicast_flags AS multicast_flags,\n"
                "        rev.psycstore_flags AS psycstore_flags,\n"
                "        rev.data AS data\n"
                " FROM\n"
                " (SELECT hop_counter, signature, purpose, fragment_id,\n"
                "        fragment_offset, message_id, group_generation,\n"
                "        multicast_flags, psycstore_flags, data \n"
                "  FROM messages\n"
                "  WHERE channel_id = get_chan_id($1) \n"
                "  ORDER BY fragment_id DESC\n"
                "  LIMIT $2) AS rev\n"
                " ORDER BY rev.fragment_id;", 2)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "select_latest_messages",
                "SELECT hop_counter, signature, purpose, fragment_id,\n"
                "       fragment_offset, message_id, group_generation,\n"
                "        multicast_flags, psycstore_flags, data\n"
                "FROM messages\n"
                "WHERE channel_id = get_chan_id($1)\n"
                "      AND message_id IN\n"
                "      (SELECT message_id\n"
                "       FROM messages\n"
                "       WHERE channel_id = get_chan_id($2) \n"
                "       GROUP BY message_id\n"
                "       ORDER BY message_id\n"
                "       DESC LIMIT $3)\n"
                "ORDER BY fragment_id", 3)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "select_message_fragment",
                "SELECT hop_counter, signature, purpose, fragment_id,\n"
                "       fragment_offset, message_id, group_generation,\n"
                "       multicast_flags, psycstore_flags, data\n"
                "FROM messages\n"
                "WHERE channel_id = get_chan_id($1) \n"
                "      AND message_id = $2 AND fragment_offset = $3", 3)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "select_counters_message",
                "SELECT fragment_id, message_id, group_generation\n"
                "FROM messages\n"
                "WHERE channel_id = get_chan_id($1)\n"
                "ORDER BY fragment_id DESC LIMIT 1", 1)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "select_counters_state",
                "SELECT max_state_message_id\n"
                "FROM channels\n"
                "WHERE pub_key = $1 AND max_state_message_id IS NOT NULL", 1)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "update_max_state_message_id",
                "UPDATE channels\n"
                "SET max_state_message_id = $1\n"
                "WHERE pub_key = $2", 2)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "update_state_hash_message_id",
                "UPDATE channels\n"
                "SET state_hash_message_id = $1\n"
                "WHERE pub_key = $2", 2)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "insert_state_current",
                "INSERT INTO state\n"
                "  (channel_id, name, value_current, value_signed)\n"
                "SELECT new.channel_id, new.name,\n"
                "       new.value_current, old.value_signed\n"
                "FROM (SELECT get_chan_id($1) AS channel_id,\n"
                "             $2::TEXT AS name, $3::BYTEA AS value_current) AS new\n"
                "LEFT JOIN (SELECT channel_id, name, value_signed\n"
                "           FROM state) AS old\n"
                "ON new.channel_id = old.channel_id AND new.name = old.name\n"
                "ON CONFLICT ( channel_id, substring(name from 1 for 5) )\n"
                "   DO UPDATE SET value_current = EXCLUDED.value_current,\n"
                "                 value_signed = EXCLUDED.value_signed", 3)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "delete_state_empty",
                "DELETE FROM state\n"
                "WHERE channel_id = (SELECT id FROM channels WHERE pub_key = $1)\n"
                "      AND (value_current IS NULL OR length(value_current) = 0)\n"
                "      AND (value_signed IS NULL OR length(value_signed) = 0)", 1)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "update_state_signed",
                "UPDATE state\n"
                "SET value_signed = value_current\n"
                "WHERE channel_id = get_chan_id($1) ", 1)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "delete_state",
                "DELETE FROM state\n"
                "WHERE channel_id = get_chan_id($1) ", 1)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "insert_state_sync",
                "INSERT INTO state_sync (channel_id, name, value)\n"
                "VALUES (get_chan_id($1), $2, $3)", 3)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "insert_state_from_sync",
                "INSERT INTO state\n"
                " (channel_id, name, value_current, value_signed)\n"
                "SELECT channel_id, name, value, value\n"
                "FROM state_sync\n"
                "WHERE channel_id = get_chan_id($1)", 1)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "delete_state_sync",
                "DELETE FROM state_sync\n"
                "WHERE channel_id = get_chan_id($1)", 1)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "select_state_one",
                "SELECT value_current\n"
                "FROM state\n"
                "WHERE channel_id = get_chan_id($1)\n"
                "      AND name = $2", 2)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "select_state_prefix",
                "SELECT name, value_current\n"
                "FROM state\n"
                "WHERE channel_id = get_chan_id($1)\n"
                "      AND (name = $2 OR substr(name, 1, $3) = $4 || '_')", 4)) ||

      (GNUNET_OK != GNUNET_POSTGRES_prepare (plugin->dbh,
                "select_state_signed",
                "SELECT name, value_signed\n"
                "FROM state\n"
                "WHERE channel_id = get_chan_id($1)\n"
                "      AND value_signed IS NOT NULL", 1)))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
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
  PQfinish (plugin->dbh);
  plugin->dbh = NULL;
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
exec_channel (struct Plugin *plugin, const char *stmt,
              const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key)
{
  PGresult *ret;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_end
  };

  ret = GNUNET_PQ_exec_prepared (plugin->dbh, stmt, params);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    ret,
                                    PGRES_COMMAND_OK,
                                    "PQexecPrepared", stmt))
    return GNUNET_SYSERR;

  PQclear (ret);

  return GNUNET_OK;
}


/**
 * Begin a transaction.
 */
static int
transaction_begin (struct Plugin *plugin, enum Transactions transaction)
{
  PGresult *ret;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_end
  };

  ret = GNUNET_PQ_exec_prepared (plugin->dbh, "transaction_begin", params);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    ret,
                                    PGRES_COMMAND_OK,
                                    "PQexecPrepared", "transaction_begin"))
  {
    return GNUNET_SYSERR;
  }

  plugin->transaction = transaction;
  PQclear (ret);
  return GNUNET_OK;
}


/**
 * Commit current transaction.
 */
static int
transaction_commit (struct Plugin *plugin)
{
  PGresult *ret;

  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_end
  };

  ret = GNUNET_PQ_exec_prepared (plugin->dbh, "transaction_commit", params);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    ret,
                                    PGRES_COMMAND_OK,
                                    "PQexecPrepared", "transaction_commit"))
  {
    return GNUNET_SYSERR;
  }

  PQclear (ret);
  plugin->transaction = TRANSACTION_NONE;
  return GNUNET_OK;
}


/**
 * Roll back current transaction.
 */
static int
transaction_rollback (struct Plugin *plugin)
{
  PGresult *ret;

  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_end
  };

  ret = GNUNET_PQ_exec_prepared (plugin->dbh, "transaction_rollback", params);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    ret,
                                    PGRES_COMMAND_OK,
                                    "PQexecPrepared", "transaction_rollback"))
  {
    return GNUNET_SYSERR;
  }

  PQclear (ret);
  plugin->transaction = TRANSACTION_NONE;
  return GNUNET_OK;
}


static int
channel_key_store (struct Plugin *plugin,
                   const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key)
{
  PGresult *ret;

  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_end
  };

  ret = GNUNET_PQ_exec_prepared (plugin->dbh, "insert_channel_key", params);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    ret,
                                    PGRES_COMMAND_OK,
                                    "PQexecPrepared", "insert_channel_key"))
  {
    return GNUNET_SYSERR;
  }

  PQclear (ret);
  return GNUNET_OK;
}


static int
slave_key_store (struct Plugin *plugin,
                 const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key)
{
  PGresult *ret;

  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (slave_key),
    GNUNET_PQ_query_param_end
  };

  ret = GNUNET_PQ_exec_prepared (plugin->dbh, "insert_slave_key", params);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    ret,
                                    PGRES_COMMAND_OK,
                                    "PQexecPrepared", "insert_slave_key"))
  {
    return GNUNET_SYSERR;
  }

  PQclear (ret);
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
postgres_membership_store (void *cls,
                           const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                           const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                           int did_join,
                           uint64_t announced_at,
                           uint64_t effective_since,
                           uint64_t group_generation)
{
  PGresult *ret;
  struct Plugin *plugin = cls;

  uint32_t idid_join = (uint32_t)did_join;

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

  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_auto_from_type (slave_key),
    GNUNET_PQ_query_param_uint32 (&idid_join),
    GNUNET_PQ_query_param_uint64 (&announced_at),
    GNUNET_PQ_query_param_uint64 (&effective_since),
    GNUNET_PQ_query_param_uint64 (&group_generation),
    GNUNET_PQ_query_param_end
  };

  ret = GNUNET_PQ_exec_prepared (plugin->dbh, "insert_slave_key", params);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    ret,
                                    PGRES_COMMAND_OK,
                                    "PQexecPrepared", "insert_slave_key"))
  {
    return GNUNET_SYSERR;
  }

  PQclear (ret);
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
  PGresult *res;
  struct Plugin *plugin = cls;

  uint32_t did_join = 0;

  int ret = GNUNET_SYSERR;

  struct GNUNET_PQ_QueryParam params_select[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_auto_from_type (slave_key),
    GNUNET_PQ_query_param_uint64 (&message_id),
    GNUNET_PQ_query_param_end
  };

  res = GNUNET_PQ_exec_prepared (plugin->dbh, "select_membership", params_select);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    res,
                                    PGRES_COMMAND_OK,
                                    "PQexecPrepared", "select_membership"))
  {
    return GNUNET_SYSERR;
  }

  struct GNUNET_PQ_ResultSpec results_select[] = {
    GNUNET_PQ_result_spec_uint32 ("did_join", &did_join),
    GNUNET_PQ_result_spec_end
  };

  switch(GNUNET_PQ_extract_result (res, results_select, 0))
  {
    case GNUNET_OK:
      ret = GNUNET_YES;
      break;
    default:
      ret = GNUNET_NO;
      break;
  }

  PQclear (res);

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
  PGresult *res;
  struct Plugin *plugin = cls;

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

  struct GNUNET_PQ_QueryParam params_insert[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_uint64 (&hop_counter),
    GNUNET_PQ_query_param_auto_from_type (&msg->signature),
    GNUNET_PQ_query_param_auto_from_type (&msg->purpose),
    GNUNET_PQ_query_param_uint64 (&fragment_id),
    GNUNET_PQ_query_param_uint64 (&fragment_offset),
    GNUNET_PQ_query_param_uint64 (&message_id),
    GNUNET_PQ_query_param_uint64 (&group_generation),
    GNUNET_PQ_query_param_uint64 (&flags),
    GNUNET_PQ_query_param_uint32 (&psycstore_flags),
    GNUNET_PQ_query_param_fixed_size (&msg[1], ntohs (msg->header.size)
                                                  - sizeof (*msg)),
    GNUNET_PQ_query_param_end
  };

  res = GNUNET_PQ_exec_prepared (plugin->dbh, "insert_fragment", params_insert);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    res,
                                    PGRES_COMMAND_OK,
                                    "PQexecPrepared", "insert_fragment"))
    return GNUNET_SYSERR;

  PQclear (res);
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
  PGresult *res;
  struct Plugin *plugin = cls;

  int ret = GNUNET_SYSERR;

  struct GNUNET_PQ_QueryParam params_update[] = {
    GNUNET_PQ_query_param_uint64 (&psycstore_flags),
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_uint64 (&message_id),
    GNUNET_PQ_query_param_end
  };

  res = GNUNET_PQ_exec_prepared (plugin->dbh, "update_message_flags", params_update);
  if (GNUNET_OK != GNUNET_POSTGRES_check_result (plugin->dbh,
                                      res,
                                      PGRES_COMMAND_OK,
                                      "PQexecPrepared", "update_message_flags"))
    return ret;

  PQclear (res);
  return ret;
}


static int
fragment_row (struct Plugin *plugin,
              const char *stmt,
              PGresult *res,
              GNUNET_PSYCSTORE_FragmentCallback cb,
              void *cb_cls)
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
  struct GNUNET_MULTICAST_MessageHeader *mp;

  uint64_t msg_flags;
  unsigned int cnt;

  struct GNUNET_PQ_ResultSpec results[] = {
    GNUNET_PQ_result_spec_uint32 ("hop_counter", &hop_counter),
    GNUNET_PQ_result_spec_variable_size ("signature", &signature, &signature_size),
    GNUNET_PQ_result_spec_variable_size ("purpose", &purpose, &purpose_size),
    GNUNET_PQ_result_spec_uint64 ("fragment_id", &fragment_id),
    GNUNET_PQ_result_spec_uint64 ("fragment_offset", &fragment_offset),
    GNUNET_PQ_result_spec_uint64 ("message_id", &message_id),
    GNUNET_PQ_result_spec_uint64 ("group_generation", &group_generation),
    GNUNET_PQ_result_spec_uint64 ("msg_flags", &msg_flags),
    GNUNET_PQ_result_spec_uint64 ("flags", &flags),
    GNUNET_PQ_result_spec_variable_size ("data", &buf,
                                         &buf_size),
    GNUNET_PQ_result_spec_end
  };

  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, res, PGRES_TUPLES_OK,
                                    "PQexecPrepared",
                                    stmt))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failing fragment lookup (postgres error)\n");
    return GNUNET_SYSERR;
  }

  cnt = PQntuples (res);
  if (cnt == 0)
  {
    ret = GNUNET_NO;
  }
  else
  {
    if (GNUNET_OK != GNUNET_PQ_extract_result(res, results, 0)) {
      PQclear (res);
      return GNUNET_SYSERR;
    }

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
    GNUNET_PQ_cleanup_result(results);
    ret = cb (cb_cls, mp, (enum GNUNET_PSYCSTORE_MessageFlags) flags);
  }

  PQclear (res);
  return ret;
}


static int
fragment_select (struct Plugin *plugin, const char *stmt,
                 struct GNUNET_PQ_QueryParam *params,
                 uint64_t *returned_fragments,
                 GNUNET_PSYCSTORE_FragmentCallback cb, void *cb_cls)
{
  PGresult *res;
  int ret = GNUNET_SYSERR;

  // FIXME
  if (NULL == plugin->dbh || NULL == stmt || NULL == params)
  {
    fprintf(stderr, "%p %p %p\n", plugin->dbh, stmt, params);
    return GNUNET_SYSERR;
  }

  res = GNUNET_PQ_exec_prepared (plugin->dbh, stmt, params);
  if (GNUNET_YES ==
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    res,
                                    PGRES_COMMAND_OK,
                                    "PQexecPrepared", stmt))
  {
    if (PQntuples (res) == 0)
      ret = GNUNET_NO;
    else
    {
      ret = fragment_row (plugin, stmt, res, cb, cb_cls);
      (*returned_fragments)++;
    }
    PQclear (res);
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
  *returned_fragments = 0;

  struct GNUNET_PQ_QueryParam params_select[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_uint64 (&first_fragment_id),
    GNUNET_PQ_query_param_uint64 (&last_fragment_id),
    GNUNET_PQ_query_param_end
  };

  return fragment_select (plugin, "select_fragments", params_select, returned_fragments, cb, cb_cls);
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

  *returned_fragments = 0;

  struct GNUNET_PQ_QueryParam params_select[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_uint64 (&fragment_limit),
    GNUNET_PQ_query_param_end
  };

  return fragment_select (plugin, "select_latest_fragments", params_select, returned_fragments, cb, cb_cls);
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
  *returned_fragments = 0;

  struct GNUNET_PQ_QueryParam params_select[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_uint64 (&first_message_id),
    GNUNET_PQ_query_param_uint64 (&last_message_id),
    GNUNET_PQ_query_param_uint64 (&fragment_limit),
    GNUNET_PQ_query_param_end
  };

  return fragment_select (plugin, "select_messages", params_select, returned_fragments, cb, cb_cls);
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
  *returned_fragments = 0;

  struct GNUNET_PQ_QueryParam params_select[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_uint64 (&message_limit),
    GNUNET_PQ_query_param_end
  };

  return fragment_select (plugin, "select_latest_messages", params_select, returned_fragments, cb, cb_cls);
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
  PGresult *res;
  struct Plugin *plugin = cls;
  int ret = GNUNET_SYSERR;
  const char *stmt = "select_message_fragment";

  struct GNUNET_PQ_QueryParam params_select[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_uint64 (&message_id),
    GNUNET_PQ_query_param_uint64 (&fragment_offset),
    GNUNET_PQ_query_param_end
  };

  res = GNUNET_PQ_exec_prepared (plugin->dbh, stmt, params_select);
  if (GNUNET_OK == GNUNET_POSTGRES_check_result (plugin->dbh,
                                      res,
                                      PGRES_COMMAND_OK,
                                      "PQexecPrepared", stmt))
  {
    if (PQntuples (res) == 0)
      ret = GNUNET_NO;
    else
      ret = fragment_row (plugin, stmt, res, cb, cb_cls);

    PQclear (res);
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
  PGresult *res;
  struct Plugin *plugin = cls;

  const char *stmt = "select_counters_message";

  struct GNUNET_PQ_QueryParam params_select[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_end
  };

  res = GNUNET_PQ_exec_prepared (plugin->dbh, stmt, params_select);
  if (GNUNET_OK != GNUNET_POSTGRES_check_result (plugin->dbh,
                                      res,
                                      PGRES_COMMAND_OK,
                                      "PQexecPrepared", stmt))
  {
    return GNUNET_SYSERR;
  }

  struct GNUNET_PQ_ResultSpec results_select[] = {
    GNUNET_PQ_result_spec_uint64 ("max_fragment_id", max_fragment_id),
    GNUNET_PQ_result_spec_uint64 ("max_message_id", max_message_id),
    GNUNET_PQ_result_spec_uint64 ("max_group_generation", max_group_generation),
    GNUNET_PQ_result_spec_end
  };

  if (GNUNET_OK != GNUNET_PQ_extract_result (res,
                                  results_select, 0))
  {
    PQclear (res);
    return GNUNET_SYSERR;
  }

  GNUNET_PQ_cleanup_result(results_select);
  PQclear (res);

  return GNUNET_OK;
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
  PGresult *res;
  struct Plugin *plugin = cls;

  const char *stmt = "select_counters_state";

  int ret = GNUNET_SYSERR;

  struct GNUNET_PQ_QueryParam params_select[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_end
  };

  res = GNUNET_PQ_exec_prepared (plugin->dbh, stmt, params_select);
  if (GNUNET_OK != GNUNET_POSTGRES_check_result (plugin->dbh,
                                      res,
                                      PGRES_COMMAND_OK,
                                      "PQexecPrepared", stmt))
  {
    return GNUNET_SYSERR;
  }

  struct GNUNET_PQ_ResultSpec results_select[] = {
    GNUNET_PQ_result_spec_uint64 ("max_state_message_id", max_state_message_id),
    GNUNET_PQ_result_spec_end
  };

  ret = GNUNET_PQ_extract_result (res,
                                  results_select, 0);

  if (GNUNET_OK != ret)
  {
    PQclear (res);
    return GNUNET_SYSERR;
  }

  GNUNET_PQ_cleanup_result(results_select);
  PQclear (res);

  return ret;
}


/**
 * Assign a value to a state variable.
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
state_assign (struct Plugin *plugin, const char *stmt,
              const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
              const char *name, const void *value, size_t value_size)
{
  PGresult *res;

  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_string (name),
    GNUNET_PQ_query_param_auto_from_type (value),
    GNUNET_PQ_query_param_end
  };

  res = GNUNET_PQ_exec_prepared (plugin->dbh, stmt, params);
  if (GNUNET_OK != GNUNET_POSTGRES_check_result (plugin->dbh,
                                      res,
                                      PGRES_COMMAND_OK,
                                      "PQexecPrepared", stmt))
  {
    return GNUNET_SYSERR;
  }

  PQclear (res);

  return GNUNET_OK;
}


static int
update_message_id (struct Plugin *plugin, const char *stmt,
                   const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                   uint64_t message_id)
{
  PGresult *res;

  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_uint64 (&message_id),
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_end
  };

  res = GNUNET_PQ_exec_prepared (plugin->dbh, stmt, params);
  if (GNUNET_OK != GNUNET_POSTGRES_check_result (plugin->dbh,
                                      res,
                                      PGRES_COMMAND_OK,
                                      "PQexecPrepared", stmt))
  {
    return GNUNET_SYSERR;
  }

  PQclear (res);

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
    return state_assign (plugin, "insert_state_current", channel_key,
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
    GNUNET_OK == exec_channel (plugin, "delete_state_empty", channel_key)
    && GNUNET_OK == update_message_id (plugin,
                                       "update_max_state_message_id",
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
  return exec_channel (plugin, "delete_state_sync", channel_key);
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
  return state_assign (plugin, "insert_state_sync", channel_key,
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
    && GNUNET_OK == exec_channel (plugin, "delete_state", channel_key)
    && GNUNET_OK == exec_channel (plugin, "insert_state_from_sync",
                                  channel_key)
    && GNUNET_OK == exec_channel (plugin, "delete_state_sync",
                                  channel_key)
    && GNUNET_OK == update_message_id (plugin,
                                       "update_state_hash_message_id",
                                       channel_key, state_hash_message_id)
    && GNUNET_OK == update_message_id (plugin,
                                       "update_max_state_message_id",
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
  return exec_channel (plugin, "delete_state", channel_key);
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
  return exec_channel (plugin, "update_state_signed", channel_key);
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
  PGresult *res;

  struct Plugin *plugin = cls;
  int ret = GNUNET_SYSERR;

  const char *stmt = "select_state_one";

  struct GNUNET_PQ_QueryParam params_select[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_string (name),
    GNUNET_PQ_query_param_end
  };

  void *value_current = NULL;
  size_t value_size = 0;

  struct GNUNET_PQ_ResultSpec results[] = {
    GNUNET_PQ_result_spec_variable_size ("value_current", &value_current, &value_size),
    GNUNET_PQ_result_spec_end
  };

  res = GNUNET_PQ_exec_prepared (plugin->dbh, stmt, params_select);
  if (GNUNET_OK != GNUNET_POSTGRES_check_result (plugin->dbh,
                                      res,
                                      PGRES_COMMAND_OK,
                                      "PQexecPrepared", stmt))
  {
    return GNUNET_SYSERR;
  }

  if (PQntuples (res) == 0)
  {
    PQclear (res);
    ret = GNUNET_NO;
  }

  ret = GNUNET_PQ_extract_result (res,
                                  results, 0);

  if (GNUNET_OK != ret)
  {
    PQclear (res);
    return GNUNET_SYSERR;
  }

  ret = cb (cb_cls, name, value_current,
            value_size);

  GNUNET_PQ_cleanup_result(results);
  PQclear (res);

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
  PGresult *res;
  struct Plugin *plugin = cls;
  int ret = GNUNET_SYSERR;

  const char *stmt = "select_state_prefix";

  uint32_t name_len = (uint32_t) strlen (name);

  struct GNUNET_PQ_QueryParam params_select[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_string (name),
    GNUNET_PQ_query_param_uint32 (&name_len),
    GNUNET_PQ_query_param_string (name),
    GNUNET_PQ_query_param_end
  };

  char *name2 = "";
  void *value_current = NULL;
  size_t value_size = 0;

  struct GNUNET_PQ_ResultSpec results[] = {
    GNUNET_PQ_result_spec_string ("name", &name2),
    GNUNET_PQ_result_spec_variable_size ("value_current", &value_current, &value_size),
    GNUNET_PQ_result_spec_end
  };

  do
  {
    res = GNUNET_PQ_exec_prepared (plugin->dbh, stmt, params_select);
    if (GNUNET_OK != GNUNET_POSTGRES_check_result (plugin->dbh,
                                      res,
                                      PGRES_COMMAND_OK,
                                      "PQexecPrepared", stmt))
    {
      break;
    }

    if (PQntuples (res) == 0)
    {
      PQclear (res);
      ret = GNUNET_NO;
      break;
    }

    if (GNUNET_OK != GNUNET_PQ_extract_result (res, results, 0))
    {
      PQclear (res);
      break;
    }

    ret = cb (cb_cls, (const char *) name2,
              value_current,
              value_size);
    GNUNET_PQ_cleanup_result(results);
  }
  while (ret == GNUNET_YES);

  PQclear (res);

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
  PGresult *res;
  struct Plugin *plugin = cls;
  int ret = GNUNET_SYSERR;

  const char *stmt = "select_state_signed";

  struct GNUNET_PQ_QueryParam params_select[] = {
    GNUNET_PQ_query_param_auto_from_type (channel_key),
    GNUNET_PQ_query_param_end
  };

  char *name = "";
  void *value_signed = NULL;
  size_t value_size = 0;

  struct GNUNET_PQ_ResultSpec results[] = {
    GNUNET_PQ_result_spec_string ("name", &name),
    GNUNET_PQ_result_spec_variable_size ("value_signed", &value_signed, &value_size),
    GNUNET_PQ_result_spec_end
  };

  do
  {
    res = GNUNET_PQ_exec_prepared (plugin->dbh, stmt, params_select);
    if (GNUNET_OK != GNUNET_POSTGRES_check_result (plugin->dbh,
                                      res,
                                      PGRES_COMMAND_OK,
                                      "PQexecPrepared", stmt))
    {
      break;
    }

    if (PQntuples (res) == 0)
    {
      PQclear (res);
      ret = GNUNET_NO;
      break;
    }

    if (GNUNET_OK != GNUNET_PQ_extract_result (res, results, 0))
    {
      PQclear (res);
      break;
    }

    ret = cb (cb_cls, (const char *) name,
              value_signed,
              value_size);

    GNUNET_PQ_cleanup_result(results);
  }
  while (ret == GNUNET_YES);

  PQclear (res);

  return ret;
}


/**
 * Entry point for the plugin.
 *
 * @param cls The struct GNUNET_CONFIGURATION_Handle.
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_psycstore_postgres_init (void *cls)
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
  api->membership_store = &postgres_membership_store;
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

  LOG (GNUNET_ERROR_TYPE_INFO, _("Postgres database running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls The plugin context (as returned by "init")
 * @return Always NULL
 */
void *
libgnunet_plugin_psycstore_postgres_done (void *cls)
{
  struct GNUNET_PSYCSTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Postgres plugin has finished\n");
  return NULL;
}

/* end of plugin_psycstore_postgres.c */
