 /*
  * This file is part of GNUnet
  * Copyright (C) 2009, 2011, 2017 GNUnet e.V.
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
 * @file datastore/plugin_datastore_sqlite.c
 * @brief sqlite-based datastore backend
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_datastore_plugin.h"
#include "gnunet_sq_lib.h"
#include <sqlite3.h>


/**
 * We allocate items on the stack at times.  To prevent a stack
 * overflow, we impose a limit on the maximum size for the data per
 * item.  64k should be enough.
 */
#define MAX_ITEM_SIZE 65536

/**
 * After how many ms "busy" should a DB operation fail for good?
 * A low value makes sure that we are more responsive to requests
 * (especially PUTs).  A high value guarantees a higher success
 * rate (SELECTs in iterate can take several seconds despite LIMIT=1).
 *
 * The default value of 250ms should ensure that users do not experience
 * huge latencies while at the same time allowing operations to succeed
 * with reasonable probability.
 */
#define BUSY_TIMEOUT_MS 250


/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(db, level, cmd) do { GNUNET_log_from (level, "sqlite", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); } while(0)


/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE_MSG(db, msg, level, cmd) do { GNUNET_log_from (level, "sqlite", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); GNUNET_asprintf(msg, _("`%s' failed at %s:%u with error: %s"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); } while(0)



/**
 * Context for all functions in this plugin.
 */
struct Plugin
{
  /**
   * Our execution environment.
   */
  struct GNUNET_DATASTORE_PluginEnvironment *env;

  /**
   * Database filename.
   */
  char *fn;

  /**
   * Native SQLite database handle.
   */
  sqlite3 *dbh;

  /**
   * Precompiled SQL for remove_key.
   */
  sqlite3_stmt *remove;

  /**
   * Precompiled SQL for deletion.
   */
  sqlite3_stmt *delRow;

  /**
   * Precompiled SQL for update.
   */
  sqlite3_stmt *update;

  /**
   * Get maximum repl value in database.
   */
  sqlite3_stmt *maxRepl;

  /**
   * Precompiled SQL for replication decrement.
   */
  sqlite3_stmt *updRepl;

  /**
   * Precompiled SQL for replication selection.
   */
  sqlite3_stmt *selRepl;

  /**
   * Precompiled SQL for expiration selection.
   */
  sqlite3_stmt *selExpi;

  /**
   * Precompiled SQL for expiration selection.
   */
  sqlite3_stmt *selZeroAnon;

  /**
   * Precompiled SQL for insertion.
   */
  sqlite3_stmt *insertContent;

  /**
   * Precompiled SQL for selection
   */
  sqlite3_stmt *get[8];

  /**
   * Should the database be dropped on shutdown?
   */
  int drop_on_shutdown;

};


/**
 * @brief Prepare a SQL statement
 *
 * @param dbh handle to the database
 * @param zSql SQL statement, UTF-8 encoded
 * @param ppStmt set to the prepared statement
 * @return 0 on success
 */
static int
sq_prepare (sqlite3 *dbh,
            const char *zSql,
            sqlite3_stmt **ppStmt)
{
  char *dummy;
  int result;

  result = sqlite3_prepare_v2 (dbh,
                               zSql,
                               strlen (zSql),
                               ppStmt,
                               (const char **) &dummy);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "sqlite",
                   "Prepared `%s' / %p: %d\n",
                   zSql,
                   *ppStmt,
                   result);
  return result;
}


/**
 * Create our database indices.
 *
 * @param dbh handle to the database
 */
static void
create_indices (sqlite3 * dbh)
{
  /* create indices */
  if (0 !=
      (SQLITE_OK !=
       sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS idx_hash ON gn091 (hash)",
                     NULL, NULL, NULL)) +
      (SQLITE_OK !=
       sqlite3_exec (dbh,
                     "CREATE INDEX IF NOT EXISTS idx_anon_type ON gn091 (anonLevel ASC,type)",
                     NULL, NULL, NULL)) +
      (SQLITE_OK !=
       sqlite3_exec (dbh,
                     "CREATE INDEX IF NOT EXISTS idx_expire ON gn091 (expire ASC)",
                     NULL, NULL, NULL)) +
      (SQLITE_OK !=
       sqlite3_exec (dbh,
                     "CREATE INDEX IF NOT EXISTS idx_repl_rvalue ON gn091 (repl,rvalue)",
                     NULL, NULL, NULL)) )
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "sqlite",
                     "Failed to create indices: %s\n", sqlite3_errmsg (dbh));
}


#if 0
#define CHECK(a) GNUNET_break(a)
#define ENULL NULL
#else
#define ENULL &e
#define ENULL_DEFINED 1
#define CHECK(a) if (! (a)) { GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "%s\n", e); sqlite3_free(e); }
#endif


/**
 * Initialize the database connections and associated
 * data structures (create tables and indices
 * as needed as well).
 *
 * @param cfg our configuration
 * @param plugin the plugin context (state for this module)
 * @return #GNUNET_OK on success
 */
static int
database_setup (const struct GNUNET_CONFIGURATION_Handle *cfg,
                struct Plugin *plugin)
{
  sqlite3_stmt *stmt;
  char *afsdir;
#if ENULL_DEFINED
  char *e;
#endif

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               "datastore-sqlite",
                                               "FILENAME",
                                               &afsdir))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "datastore-sqlite",
                               "FILENAME");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_DISK_file_test (afsdir))
  {
    if (GNUNET_OK !=
        GNUNET_DISK_directory_create_for_file (afsdir))
    {
      GNUNET_break (0);
      GNUNET_free (afsdir);
      return GNUNET_SYSERR;
    }
    /* database is new or got deleted, reset payload to zero! */
    if (NULL != plugin->env->duc)
      plugin->env->duc (plugin->env->cls,
                        0);
  }
  /* afsdir should be UTF-8-encoded. If it isn't, it's a bug */
  plugin->fn = afsdir;

  /* Open database and precompile statements */
  if (SQLITE_OK !=
      sqlite3_open (plugin->fn, &plugin->dbh))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "sqlite",
                     _("Unable to initialize SQLite: %s.\n"),
                     sqlite3_errmsg (plugin->dbh));
    return GNUNET_SYSERR;
  }
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA temp_store=MEMORY", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA synchronous=OFF", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA legacy_file_format=OFF", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA auto_vacuum=INCREMENTAL", NULL,
                       NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA locking_mode=EXCLUSIVE", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA page_size=4096", NULL, NULL,
                       ENULL));

  CHECK (SQLITE_OK ==
         sqlite3_busy_timeout (plugin->dbh, BUSY_TIMEOUT_MS));


  /* We have to do it here, because otherwise precompiling SQL might fail */
  CHECK (SQLITE_OK ==
         sq_prepare (plugin->dbh,
                     "SELECT 1 FROM sqlite_master WHERE tbl_name = 'gn091'",
                     &stmt));

  /* FIXME: SQLite does not have unsigned integers! This is ok for the type column because
   * we only test equality on it and can cast it to/from uint32_t. For repl, prio, and anonLevel
   * we do math or inequality tests, so we can't handle the entire range of uint32_t.
   * This will also cause problems for expiration times after 294247-01-10-04:00:54 UTC.
   */
  if ( (SQLITE_DONE ==
        sqlite3_step (stmt)) &&
       (SQLITE_OK !=
        sqlite3_exec (plugin->dbh,
                      "CREATE TABLE gn091 ("
                      "  repl INT4 NOT NULL DEFAULT 0,"
                      "  type INT4 NOT NULL DEFAULT 0,"
                      "  prio INT4 NOT NULL DEFAULT 0,"
                      "  anonLevel INT4 NOT NULL DEFAULT 0,"
                      "  expire INT8 NOT NULL DEFAULT 0,"
                      "  rvalue INT8 NOT NULL,"
                      "  hash TEXT NOT NULL DEFAULT '',"
                      "  vhash TEXT NOT NULL DEFAULT '',"
                      "  value BLOB NOT NULL DEFAULT '')",
                      NULL,
                      NULL,
                      NULL)) )
  {
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite3_exec");
    sqlite3_finalize (stmt);
    return GNUNET_SYSERR;
  }
  sqlite3_finalize (stmt);
  create_indices (plugin->dbh);

#define RESULT_COLUMNS "repl, type, prio, anonLevel, expire, hash, value, _ROWID_"
  if ( (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "UPDATE gn091 "
                    "SET prio = prio + ?, "
                    "repl = repl + ?, "
                    "expire = MAX(expire, ?) "
                    "WHERE hash = ? AND vhash = ?",
                    &plugin->update)) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "UPDATE gn091 " "SET repl = MAX (0, repl - 1) WHERE _ROWID_ = ?",
                    &plugin->updRepl)) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT " RESULT_COLUMNS " FROM gn091 "
                    "WHERE repl=?2 AND " " (rvalue>=?1 OR "
                    "  NOT EXISTS (SELECT 1 FROM gn091 "
                    "WHERE repl=?2 AND rvalue>=?1 LIMIT 1) ) "
                    "ORDER BY rvalue ASC LIMIT 1",
                    &plugin->selRepl)) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT MAX(repl) FROM gn091",
                    &plugin->maxRepl)) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT " RESULT_COLUMNS " FROM gn091 "
                    "WHERE NOT EXISTS (SELECT 1 FROM gn091 WHERE expire < ?1 LIMIT 1) OR (expire < ?1) "
                    "ORDER BY expire ASC LIMIT 1",
                    &plugin->selExpi)) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT " RESULT_COLUMNS " FROM gn091 "
                    "WHERE _ROWID_ >= ? AND "
                    "anonLevel = 0 AND "
                    "type = ? "
                    "ORDER BY _ROWID_ ASC LIMIT 1",
                    &plugin->selZeroAnon)) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "INSERT INTO gn091 (repl, type, prio, anonLevel, expire, rvalue, hash, vhash, value) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    &plugin->insertContent)) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT " RESULT_COLUMNS " FROM gn091 "
                    "WHERE _ROWID_ >= ?1 "
                    "ORDER BY _ROWID_ ASC LIMIT 1",
                    &plugin->get[0])) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT " RESULT_COLUMNS " FROM gn091 "
                    "WHERE _ROWID_ >= ?1 AND "
                    "type = ?4 "
                    "ORDER BY _ROWID_ ASC LIMIT 1",
                    &plugin->get[1])) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT " RESULT_COLUMNS " FROM gn091 "
                    "WHERE _ROWID_ >= ?1 AND "
                    "hash = ?3 "
                    "ORDER BY _ROWID_ ASC LIMIT 1",
                    &plugin->get[2])) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT " RESULT_COLUMNS " FROM gn091 "
                    "WHERE _ROWID_ >= ?1 AND "
                    "hash = ?3 AND "
                    "type = ?4 "
                    "ORDER BY _ROWID_ ASC LIMIT 1",
                    &plugin->get[3])) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT " RESULT_COLUMNS " FROM gn091 "
                    "WHERE _ROWID_ >= ?1 AND "
                    "rvalue >= ?2 "
                    "ORDER BY _ROWID_ ASC LIMIT 1",
                    &plugin->get[4])) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT " RESULT_COLUMNS " FROM gn091 "
                    "WHERE _ROWID_ >= ?1 AND "
                    "rvalue >= ?2 AND "
                    "type = ?4 "
                    "ORDER BY _ROWID_ ASC LIMIT 1",
                    &plugin->get[5])) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT " RESULT_COLUMNS " FROM gn091 "
                    "WHERE _ROWID_ >= ?1 AND "
                    "rvalue >= ?2 AND "
                    "hash = ?3 "
                    "ORDER BY _ROWID_ ASC LIMIT 1",
                    &plugin->get[6])) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT " RESULT_COLUMNS " FROM gn091 "
                    "WHERE _ROWID_ >= ?1 AND "
                    "rvalue >= ?2 AND "
                    "hash = ?3 AND "
                    "type = ?4 "
                    "ORDER BY _ROWID_ ASC LIMIT 1",
                    &plugin->get[7])) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "DELETE FROM gn091 WHERE _ROWID_ = ?",
                    &plugin->delRow)) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "DELETE FROM gn091 "
                    "WHERE hash = ? AND "
                    "value = ? ",
                    &plugin->remove)) ||
       false)
  {
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR,
                "precompiling");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Shutdown database connection and associate data
 * structures.
 *
 * @param plugin the plugin context (state for this module)
 */
static void
database_shutdown (struct Plugin *plugin)
{
  int result;
#if SQLITE_VERSION_NUMBER >= 3007000
  sqlite3_stmt *stmt;
#endif

  if (NULL != plugin->remove)
    sqlite3_finalize (plugin->remove);
  if (NULL != plugin->delRow)
    sqlite3_finalize (plugin->delRow);
  if (NULL != plugin->update)
    sqlite3_finalize (plugin->update);
  if (NULL != plugin->updRepl)
    sqlite3_finalize (plugin->updRepl);
  if (NULL != plugin->selRepl)
    sqlite3_finalize (plugin->selRepl);
  if (NULL != plugin->maxRepl)
    sqlite3_finalize (plugin->maxRepl);
  if (NULL != plugin->selExpi)
    sqlite3_finalize (plugin->selExpi);
  if (NULL != plugin->selZeroAnon)
    sqlite3_finalize (plugin->selZeroAnon);
  if (NULL != plugin->insertContent)
    sqlite3_finalize (plugin->insertContent);
  for (int i = 0; i < 8; ++i)
    if (NULL != plugin->get[i])
      sqlite3_finalize (plugin->get[i]);
  result = sqlite3_close (plugin->dbh);
#if SQLITE_VERSION_NUMBER >= 3007000
  if (result == SQLITE_BUSY)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
                     "sqlite",
                     _("Tried to close sqlite without finalizing all prepared statements.\n"));
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
#endif
  if (SQLITE_OK != result)
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite3_close");
  GNUNET_free_non_null (plugin->fn);
}


/**
 * Delete the database entry with the given
 * row identifier.
 *
 * @param plugin the plugin context (state for this module)
 * @param rid the ID of the row to delete
 */
static int
delete_by_rowid (struct Plugin *plugin,
                 uint64_t rid)
{
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_uint64 (&rid),
    GNUNET_SQ_query_param_end
  };

  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->delRow,
                      params))
    return GNUNET_SYSERR;
  if (SQLITE_DONE != sqlite3_step (plugin->delRow))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->delRow);
    return GNUNET_SYSERR;
  }
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->delRow);
  return GNUNET_OK;
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure
 * @param key key for the item
 * @param absent true if the key was not found in the bloom filter
 * @param size number of bytes in @a data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param cont continuation called with success or failure status
 * @param cont_cls continuation closure
 */
static void
sqlite_plugin_put (void *cls,
                   const struct GNUNET_HashCode *key,
                   bool absent,
                   uint32_t size,
                   const void *data,
                   enum GNUNET_BLOCK_Type type,
                   uint32_t priority,
                   uint32_t anonymity,
                   uint32_t replication,
                   struct GNUNET_TIME_Absolute expiration,
                   PluginPutCont cont,
                   void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_HashCode vhash;
  char *msg = NULL;

  GNUNET_CRYPTO_hash (data,
                      size,
                      &vhash);

  if (!absent)
  {
    struct GNUNET_SQ_QueryParam params[] = {
      GNUNET_SQ_query_param_uint32 (&priority),
      GNUNET_SQ_query_param_uint32 (&replication),
      GNUNET_SQ_query_param_absolute_time (&expiration),
      GNUNET_SQ_query_param_auto_from_type (key),
      GNUNET_SQ_query_param_auto_from_type (&vhash),
      GNUNET_SQ_query_param_end
    };

    if (GNUNET_OK !=
        GNUNET_SQ_bind (plugin->update,
                        params))
    {
      cont (cont_cls,
            key,
            size,
            GNUNET_SYSERR,
            _("sqlite bind failure"));
      return;
    }
    if (SQLITE_DONE != sqlite3_step (plugin->update))
    {
      LOG_SQLITE_MSG (plugin, &msg, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                      "sqlite3_step");
      cont (cont_cls,
            key,
            size,
            GNUNET_SYSERR,
            msg);
      GNUNET_free_non_null (msg);
      return;
    }
    int changes = sqlite3_changes (plugin->dbh);
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->update);
    if (0 != changes)
    {
      cont (cont_cls,
            key,
            size,
            GNUNET_NO,
            NULL);
      return;
    }
  }

  uint64_t rvalue;
  uint32_t type32 = (uint32_t) type;
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_uint32 (&replication),
    GNUNET_SQ_query_param_uint32 (&type32),
    GNUNET_SQ_query_param_uint32 (&priority),
    GNUNET_SQ_query_param_uint32 (&anonymity),
    GNUNET_SQ_query_param_absolute_time (&expiration),
    GNUNET_SQ_query_param_uint64 (&rvalue),
    GNUNET_SQ_query_param_auto_from_type (key),
    GNUNET_SQ_query_param_auto_from_type (&vhash),
    GNUNET_SQ_query_param_fixed_size (data, size),
    GNUNET_SQ_query_param_end
  };
  int n;
  int ret;
  sqlite3_stmt *stmt;

  if (size > MAX_ITEM_SIZE)
  {
    cont (cont_cls, key, size, GNUNET_SYSERR, _("Data too large"));
    return;
  }
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                   "Storing in database block with type %u/key `%s'/priority %u/expiration in %s (%s).\n",
                   type,
                   GNUNET_h2s (key),
                   priority,
                   GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining (expiration),
							   GNUNET_YES),
                   GNUNET_STRINGS_absolute_time_to_string (expiration));
  stmt = plugin->insertContent;
  rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX);
  if (GNUNET_OK !=
      GNUNET_SQ_bind (stmt,
                      params))
  {
    cont (cont_cls, key, size, GNUNET_SYSERR, NULL);
    return;
  }
  n = sqlite3_step (stmt);
  switch (n)
  {
  case SQLITE_DONE:
    if (NULL != plugin->env->duc)
      plugin->env->duc (plugin->env->cls,
                        size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                     "Stored new entry (%u bytes)\n",
                     size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
    ret = GNUNET_OK;
    break;
  case SQLITE_BUSY:
    GNUNET_break (0);
    LOG_SQLITE_MSG (plugin, &msg, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                    "sqlite3_step");
    ret = GNUNET_SYSERR;
    break;
  default:
    LOG_SQLITE_MSG (plugin, &msg, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                    "sqlite3_step");
    GNUNET_SQ_reset (plugin->dbh,
                     stmt);
    database_shutdown (plugin);
    database_setup (plugin->env->cfg, plugin);
    cont (cont_cls, key, size, GNUNET_SYSERR, msg);
    GNUNET_free_non_null(msg);
    return;
  }
  GNUNET_SQ_reset (plugin->dbh,
                   stmt);
  cont (cont_cls, key, size, ret, msg);
  GNUNET_free_non_null(msg);
}


/**
 * Execute statement that gets a row and call the callback
 * with the result.  Resets the statement afterwards.
 *
 * @param plugin the plugin
 * @param stmt the statement
 * @param proc processor to call
 * @param proc_cls closure for @a proc
 */
static void
execute_get (struct Plugin *plugin,
             sqlite3_stmt *stmt,
             PluginDatumProcessor proc,
             void *proc_cls)
{
  int n;
  struct GNUNET_TIME_Absolute expiration;
  uint32_t replication;
  uint32_t type;
  uint32_t priority;
  uint32_t anonymity;
  uint64_t rowid;
  void *value;
  size_t value_size;
  struct GNUNET_HashCode key;
  int ret;
  struct GNUNET_SQ_ResultSpec rs[] = {
    GNUNET_SQ_result_spec_uint32 (&replication),
    GNUNET_SQ_result_spec_uint32 (&type),
    GNUNET_SQ_result_spec_uint32 (&priority),
    GNUNET_SQ_result_spec_uint32 (&anonymity),
    GNUNET_SQ_result_spec_absolute_time (&expiration),
    GNUNET_SQ_result_spec_auto_from_type (&key),
    GNUNET_SQ_result_spec_variable_size (&value,
                                         &value_size),
    GNUNET_SQ_result_spec_uint64 (&rowid),
    GNUNET_SQ_result_spec_end
  };

  n = sqlite3_step (stmt);
  switch (n)
  {
  case SQLITE_ROW:
    if (GNUNET_OK !=
        GNUNET_SQ_extract_result (stmt,
                                  rs))
    {
      GNUNET_break (0);
      break;
    }
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     "sqlite",
                     "Found reply in database with expiration %s\n",
                     GNUNET_STRINGS_absolute_time_to_string (expiration));
    ret = proc (proc_cls,
                &key,
                value_size,
                value,
                type,
                priority,
                anonymity,
                replication,
                expiration,
                rowid);
    GNUNET_SQ_cleanup_result (rs);
    GNUNET_SQ_reset (plugin->dbh,
                     stmt);
    if ( (GNUNET_NO == ret) &&
         (GNUNET_OK == delete_by_rowid (plugin,
                                        rowid)) &&
         (NULL != plugin->env->duc) )
      plugin->env->duc (plugin->env->cls,
                        -(value_size + GNUNET_DATASTORE_ENTRY_OVERHEAD));
    return;
  case SQLITE_DONE:
    /* database must be empty */
    break;
  case SQLITE_BUSY:
  case SQLITE_ERROR:
  case SQLITE_MISUSE:
  default:
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    if (SQLITE_OK !=
        sqlite3_reset (stmt))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    GNUNET_break (0);
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    database_shutdown (plugin);
    database_setup (plugin->env->cfg,
                    plugin);
    return;
  }
  GNUNET_SQ_reset (plugin->dbh,
                   stmt);
  proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
}


/**
 * Select a subset of the items in the datastore and call
 * the given processor for the item.
 *
 * @param cls our plugin context
 * @param next_uid return the result with lowest uid >= next_uid
 * @param type entries of which type should be considered?
 *        Must not be zero (ANY).
 * @param proc function to call on the matching value;
 *        will be called with NULL if no value matches
 * @param proc_cls closure for @a proc
 */
static void
sqlite_plugin_get_zero_anonymity (void *cls,
                                  uint64_t next_uid,
                                  enum GNUNET_BLOCK_Type type,
                                  PluginDatumProcessor proc,
                                  void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_uint64 (&next_uid),
    GNUNET_SQ_query_param_uint32 (&type),
    GNUNET_SQ_query_param_end
  };

  GNUNET_assert (type != GNUNET_BLOCK_TYPE_ANY);
  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->selZeroAnon,
                      params))
  {
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  execute_get (plugin, plugin->selZeroAnon, proc, proc_cls);
}


/**
 * Get results for a particular key in the datastore.
 *
 * @param cls closure
 * @param next_uid return the result with lowest uid >= next_uid
 * @param random if true, return a random result instead of using next_uid
 * @param key maybe NULL (to match all entries)
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param proc function to call on the matching value;
 *        will be called with NULL if nothing matches
 * @param proc_cls closure for @a proc
 */
static void
sqlite_plugin_get_key (void *cls,
                       uint64_t next_uid,
                       bool random,
                       const struct GNUNET_HashCode *key,
                       enum GNUNET_BLOCK_Type type,
                       PluginDatumProcessor proc,
                       void *proc_cls)
{
  struct Plugin *plugin = cls;
  uint64_t rvalue;
  int use_rvalue = random;
  uint32_t type32 = (uint32_t) type;
  int use_type = GNUNET_BLOCK_TYPE_ANY != type;
  int use_key = NULL != key;
  sqlite3_stmt *stmt = plugin->get[use_rvalue * 4 + use_key * 2 + use_type];
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_uint64 (&next_uid),
    GNUNET_SQ_query_param_uint64 (&rvalue),
    GNUNET_SQ_query_param_auto_from_type (key),
    GNUNET_SQ_query_param_uint32 (&type32),
    GNUNET_SQ_query_param_end
  };

  if (! use_type)
    memset (&params[3], 0, sizeof (struct GNUNET_SQ_QueryParam));
  if (! use_key)
    memset (&params[2], 0, sizeof (struct GNUNET_SQ_QueryParam));
  if (random)
  {
    rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                       UINT64_MAX);
    next_uid = 0;
  }
  else
    rvalue = 0;

  if (GNUNET_OK !=
      GNUNET_SQ_bind (stmt,
                      params))
  {
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  execute_get (plugin,
               stmt,
               proc,
               proc_cls);
}


/**
 * Context for #repl_proc() function.
 */
struct ReplCtx
{

  /**
   * Function to call for the result (or the NULL).
   */
  PluginDatumProcessor proc;

  /**
   * Closure for @e proc.
   */
  void *proc_cls;

  /**
   * UID to use.
   */
  uint64_t uid;

  /**
   * Yes if UID was set.
   */
  int have_uid;
};


/**
 * Wrapper for the processor for #sqlite_plugin_get_replication().
 * Decrements the replication counter and calls the original
 * processor.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in @a data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 * @return #GNUNET_OK for normal return,
 *         #GNUNET_NO to delete the item
 */
static int
repl_proc (void *cls,
           const struct GNUNET_HashCode *key,
           uint32_t size,
           const void *data,
           enum GNUNET_BLOCK_Type type,
           uint32_t priority,
           uint32_t anonymity,
           uint32_t replication,
           struct GNUNET_TIME_Absolute expiration,
           uint64_t uid)
{
  struct ReplCtx *rc = cls;
  int ret;

  if (GNUNET_SYSERR == rc->have_uid)
    rc->have_uid = GNUNET_NO;
  ret = rc->proc (rc->proc_cls,
                  key,
                  size,
                  data,
                  type,
                  priority,
                  anonymity,
                  replication,
                  expiration,
                  uid);
  if (NULL != key)
  {
    rc->uid = uid;
    rc->have_uid = GNUNET_YES;
  }
  return ret;
}


/**
 * Get a random item for replication.  Returns a single random item
 * from those with the highest replication counters.  The item's
 * replication counter is decremented by one IF it was positive before.
 * Call @a proc with all values ZERO or NULL if the datastore is empty.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for @a proc
 */
static void
sqlite_plugin_get_replication (void *cls,
                               PluginDatumProcessor proc,
                               void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct ReplCtx rc;
  uint64_t rvalue;
  uint32_t repl;
  struct GNUNET_SQ_QueryParam params_sel_repl[] = {
    GNUNET_SQ_query_param_uint64 (&rvalue),
    GNUNET_SQ_query_param_uint32 (&repl),
    GNUNET_SQ_query_param_end
  };
  struct GNUNET_SQ_QueryParam params_upd_repl[] = {
    GNUNET_SQ_query_param_uint64 (&rc.uid),
    GNUNET_SQ_query_param_end
  };

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "datastore-sqlite",
                   "Getting random block based on replication order.\n");
  if (SQLITE_ROW !=
      sqlite3_step (plugin->maxRepl))
  {
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->maxRepl);
    /* DB empty */
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  repl = sqlite3_column_int (plugin->maxRepl,
                             0);
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->maxRepl);
  rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                     UINT64_MAX);
  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->selRepl,
                      params_sel_repl))
  {
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  rc.have_uid = GNUNET_SYSERR;
  rc.proc = proc;
  rc.proc_cls = proc_cls;
  execute_get (plugin,
               plugin->selRepl,
               &repl_proc,
               &rc);
  if (GNUNET_YES == rc.have_uid)
  {
    if (GNUNET_OK !=
        GNUNET_SQ_bind (plugin->updRepl,
                        params_upd_repl))
    {
      proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
    if (SQLITE_DONE !=
        sqlite3_step (plugin->updRepl))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_step");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->updRepl);
  }
  if (GNUNET_SYSERR == rc.have_uid)
  {
    /* proc was not called at all so far, do it now. */
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
  }
}


/**
 * Get a random item that has expired or has low priority.
 * Call @a proc with all values ZERO or NULL if the datastore is empty.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for @a proc
 */
static void
sqlite_plugin_get_expiration (void *cls, PluginDatumProcessor proc,
                              void *proc_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_absolute_time (&now),
    GNUNET_SQ_query_param_end
  };

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "sqlite",
                   "Getting random block based on expiration and priority order.\n");
  now = GNUNET_TIME_absolute_get ();
  stmt = plugin->selExpi;
  if (GNUNET_OK !=
      GNUNET_SQ_bind (stmt,
                      params))
  {
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  execute_get (plugin, stmt, proc, proc_cls);
}


/**
 * Get all of the keys in the datastore.
 *
 * @param cls closure
 * @param proc function to call on each key
 * @param proc_cls closure for @a proc
 */
static void
sqlite_plugin_get_keys (void *cls,
			PluginKeyProcessor proc,
			void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_HashCode key;
  struct GNUNET_SQ_ResultSpec results[] = {
    GNUNET_SQ_result_spec_auto_from_type (&key),
    GNUNET_SQ_result_spec_end
  };
  sqlite3_stmt *stmt;
  int ret;

  GNUNET_assert (NULL != proc);
  if (SQLITE_OK !=
      sq_prepare (plugin->dbh,
                  "SELECT hash FROM gn091",
                  &stmt))
  {
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite_prepare");
    proc (proc_cls,
          NULL,
          0);
    return;
  }
  while (SQLITE_ROW == (ret = sqlite3_step (stmt)))
  {
    if (GNUNET_OK ==
        GNUNET_SQ_extract_result (stmt,
                                  results))
      proc (proc_cls,
            &key,
            1);
    else
      GNUNET_break (0);
  }
  if (SQLITE_DONE != ret)
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite_step");
  sqlite3_finalize (stmt);
  proc (proc_cls,
        NULL,
        0);
}


/**
 * Drop database.
 *
 * @param cls our plugin context
 */
static void
sqlite_plugin_drop (void *cls)
{
  struct Plugin *plugin = cls;

  plugin->drop_on_shutdown = GNUNET_YES;
}


/**
 * Remove a particular key in the datastore.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param cont continuation called with success or failure status
 * @param cont_cls continuation closure for @a cont
 */
static void
sqlite_plugin_remove_key (void *cls,
                          const struct GNUNET_HashCode *key,
                          uint32_t size,
                          const void *data,
                          PluginRemoveCont cont,
                          void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_auto_from_type (key),
    GNUNET_SQ_query_param_fixed_size (data, size),
    GNUNET_SQ_query_param_end
  };

  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->remove,
                      params))
  {
    cont (cont_cls,
          key,
          size,
          GNUNET_SYSERR,
          "bind failed");
    return;
  }
  if (SQLITE_DONE != sqlite3_step (plugin->remove))
  {
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->remove);
    cont (cont_cls,
          key,
          size,
          GNUNET_SYSERR,
          "sqlite3_step failed");
    return;
  }
  int changes = sqlite3_changes (plugin->dbh);
  GNUNET_SQ_reset (plugin->dbh,
                   plugin->remove);
  if (0 == changes)
  {
    cont (cont_cls,
          key,
          size,
          GNUNET_NO,
          NULL);
    return;
  }
  if (NULL != plugin->env->duc)
    plugin->env->duc (plugin->env->cls,
                      -(size + GNUNET_DATASTORE_ENTRY_OVERHEAD));
  cont (cont_cls,
        key,
        size,
        GNUNET_OK,
        NULL);
}


/**
 * Get an estimate of how much space the database is
 * currently using.
 *
 * @param cls the `struct Plugin`
 * @return the size of the database on disk (estimate)
 */
static void
sqlite_plugin_estimate_size (void *cls,
                             unsigned long long *estimate)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  uint64_t pages;
  uint64_t page_size;

#if ENULL_DEFINED
  char *e;
#endif

  if (NULL == estimate)
    return;
  if (SQLITE_VERSION_NUMBER < 3006000)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
                     "datastore-sqlite",
                     _("sqlite version to old to determine size, assuming zero\n"));
    *estimate = 0;
    return;
  }
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "VACUUM",
                       NULL,
                       NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA auto_vacuum=INCREMENTAL",
                       NULL,
                       NULL, ENULL));
  CHECK (SQLITE_OK ==
         sq_prepare (plugin->dbh,
                     "PRAGMA page_count",
                     &stmt));
  if (SQLITE_ROW == sqlite3_step (stmt))
    pages = sqlite3_column_int64 (stmt,
                                  0);
  else
    pages = 0;
  sqlite3_finalize (stmt);
  CHECK (SQLITE_OK ==
         sq_prepare (plugin->dbh,
                     "PRAGMA page_size",
                     &stmt));
  CHECK (SQLITE_ROW ==
         sqlite3_step (stmt));
  page_size = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Using sqlite page utilization to estimate payload (%llu pages of size %llu bytes)\n"),
              (unsigned long long) pages,
              (unsigned long long) page_size);
  *estimate = pages * page_size;
}


/**
 * Entry point for the plugin.
 *
 * @param cls the `struct GNUNET_DATASTORE_PluginEnvironment *`
 * @return NULL on error, othrewise the plugin context
 */
void *
libgnunet_plugin_datastore_sqlite_init (void *cls)
{
  static struct Plugin plugin;
  struct GNUNET_DATASTORE_PluginEnvironment *env = cls;
  struct GNUNET_DATASTORE_PluginFunctions *api;

  if (NULL != plugin.env)
    return NULL;                /* can only initialize once! */
  memset (&plugin,
          0,
          sizeof (struct Plugin));
  plugin.env = env;
  if (GNUNET_OK != database_setup (env->cfg, &plugin))
  {
    database_shutdown (&plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_DATASTORE_PluginFunctions);
  api->cls = &plugin;
  api->estimate_size = &sqlite_plugin_estimate_size;
  api->put = &sqlite_plugin_put;
  api->get_key = &sqlite_plugin_get_key;
  api->get_replication = &sqlite_plugin_get_replication;
  api->get_expiration = &sqlite_plugin_get_expiration;
  api->get_zero_anonymity = &sqlite_plugin_get_zero_anonymity;
  api->get_keys = &sqlite_plugin_get_keys;
  api->drop = &sqlite_plugin_drop;
  api->remove_key = &sqlite_plugin_remove_key;
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                   "sqlite",
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
libgnunet_plugin_datastore_sqlite_done (void *cls)
{
  char *fn;
  struct GNUNET_DATASTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "sqlite",
                   "sqlite plugin is done\n");
  fn = NULL;
  if (plugin->drop_on_shutdown)
    fn = GNUNET_strdup (plugin->fn);
  database_shutdown (plugin);
  plugin->env = NULL;
  GNUNET_free (api);
  if (NULL != fn)
  {
    if (0 != UNLINK (fn))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                "unlink",
                                fn);
    GNUNET_free (fn);
  }
  return NULL;
}

/* end of plugin_datastore_sqlite.c */
