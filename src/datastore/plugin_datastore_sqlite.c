 /*
  * This file is part of GNUnet
  * (C) 2009, 2011 Christian Grothoff (and other contributing authors)
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
 * @file datastore/plugin_datastore_sqlite.c
 * @brief sqlite-based datastore backend
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_datastore_plugin.h"
#include <sqlite3.h>

/**
 * Enable or disable logging debug messages.
 */
#define DEBUG_SQLITE GNUNET_EXTRA_LOGGING

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
#define LOG_SQLITE(db, msg, level, cmd) do { GNUNET_log_from (level, "sqlite", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); if (msg != NULL) GNUNET_asprintf(msg, _("`%s' failed at %s:%u with error: %s"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); } while(0)



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
   * Precompiled SQL for deletion.
   */
  sqlite3_stmt *delRow;

  /**
   * Precompiled SQL for update.
   */
  sqlite3_stmt *updPrio;

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
sq_prepare (sqlite3 * dbh, const char *zSql, sqlite3_stmt ** ppStmt)
{
  char *dummy;
  int result;

  result =
      sqlite3_prepare_v2 (dbh, zSql, strlen (zSql), ppStmt,
                          (const char **) &dummy);
#if DEBUG_SQLITE && 0
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                   "Prepared `%s' / %p: %d\n", zSql, *ppStmt, result);
#endif
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
  if ((SQLITE_OK !=
       sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS idx_hash ON gn090 (hash)",
                     NULL, NULL, NULL)) ||
      (SQLITE_OK !=
       sqlite3_exec (dbh,
                     "CREATE INDEX IF NOT EXISTS idx_hash_vhash ON gn090 (hash,vhash)",
                     NULL, NULL, NULL)) ||
      (SQLITE_OK !=
       sqlite3_exec (dbh,
                     "CREATE INDEX IF NOT EXISTS idx_expire_repl ON gn090 (expire ASC,repl DESC)",
                     NULL, NULL, NULL)) ||
      (SQLITE_OK !=
       sqlite3_exec (dbh,
                     "CREATE INDEX IF NOT EXISTS idx_comb ON gn090 (anonLevel ASC,expire ASC,prio,type,hash)",
                     NULL, NULL, NULL)) ||
      (SQLITE_OK !=
       sqlite3_exec (dbh,
                     "CREATE INDEX IF NOT EXISTS idx_anon_type_hash ON gn090 (anonLevel ASC,type,hash)",
                     NULL, NULL, NULL)) ||
      (SQLITE_OK !=
       sqlite3_exec (dbh,
                     "CREATE INDEX IF NOT EXISTS idx_expire ON gn090 (expire ASC)",
                     NULL, NULL, NULL)) ||
      (SQLITE_OK !=
       sqlite3_exec (dbh,
                     "CREATE INDEX IF NOT EXISTS idx_repl_rvalue ON gn090 (repl,rvalue)",
                     NULL, NULL, NULL)) ||
      (SQLITE_OK !=
       sqlite3_exec (dbh,
                     "CREATE INDEX IF NOT EXISTS idx_repl ON gn090 (repl DESC)",
                     NULL, NULL, NULL)))
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "sqlite",
                     "Failed to create indices: %s\n", sqlite3_errmsg (dbh));
}


#if 0
#define CHECK(a) GNUNET_break(a)
#define ENULL NULL
#else
#define ENULL &e
#define ENULL_DEFINED 1
#define CHECK(a) if (! a) { GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "%s\n", e); sqlite3_free(e); }
#endif


/**
 * Initialize the database connections and associated
 * data structures (create tables and indices
 * as needed as well).
 *
 * @param cfg our configuration
 * @param plugin the plugin context (state for this module)
 * @return GNUNET_OK on success
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
      GNUNET_CONFIGURATION_get_value_filename (cfg, "datastore-sqlite",
                                               "FILENAME", &afsdir))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "sqlite",
                     _
                     ("Option `%s' in section `%s' missing in configuration!\n"),
                     "FILENAME", "datastore-sqlite");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_DISK_file_test (afsdir))
  {
    if (GNUNET_OK != GNUNET_DISK_directory_create_for_file (afsdir))
    {
      GNUNET_break (0);
      GNUNET_free (afsdir);
      return GNUNET_SYSERR;
    }
    /* database is new or got deleted, reset payload to zero! */
    plugin->env->duc (plugin->env->cls, 0);
  }
#ifdef ENABLE_NLS
  plugin->fn =
      GNUNET_STRINGS_to_utf8 (afsdir, strlen (afsdir), nl_langinfo (CODESET));
#else
  plugin->fn = GNUNET_STRINGS_to_utf8 (afsdir, strlen (afsdir), "UTF-8");       /* good luck */
#endif
  GNUNET_free (afsdir);

  /* Open database and precompile statements */
  if (sqlite3_open (plugin->fn, &plugin->dbh) != SQLITE_OK)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "sqlite",
                     _("Unable to initialize SQLite: %s.\n"),
                     sqlite3_errmsg (plugin->dbh));
    return GNUNET_SYSERR;
  }
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA temp_store=MEMORY", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA synchronous=OFF", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA legacy_file_format=OFF", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA auto_vacuum=INCREMENTAL", NULL,
                       NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA locking_mode=EXCLUSIVE", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA count_changes=OFF", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA page_size=4092", NULL, NULL,
                       ENULL));

  CHECK (SQLITE_OK == sqlite3_busy_timeout (plugin->dbh, BUSY_TIMEOUT_MS));


  /* We have to do it here, because otherwise precompiling SQL might fail */
  CHECK (SQLITE_OK ==
         sq_prepare (plugin->dbh,
                     "SELECT 1 FROM sqlite_master WHERE tbl_name = 'gn090'",
                     &stmt));
  if ((sqlite3_step (stmt) == SQLITE_DONE) &&
      (sqlite3_exec
       (plugin->dbh,
        "CREATE TABLE gn090 (" "  repl INT4 NOT NULL DEFAULT 0,"
        "  type INT4 NOT NULL DEFAULT 0," "  prio INT4 NOT NULL DEFAULT 0,"
        "  anonLevel INT4 NOT NULL DEFAULT 0,"
        "  expire INT8 NOT NULL DEFAULT 0," "  rvalue INT8 NOT NULL,"
        "  hash TEXT NOT NULL DEFAULT ''," "  vhash TEXT NOT NULL DEFAULT '',"
        "  value BLOB NOT NULL DEFAULT '')", NULL, NULL, NULL) != SQLITE_OK))
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_exec");
    sqlite3_finalize (stmt);
    return GNUNET_SYSERR;
  }
  sqlite3_finalize (stmt);
  create_indices (plugin->dbh);

  if ((sq_prepare
       (plugin->dbh,
        "UPDATE gn090 "
        "SET prio = prio + ?, expire = MAX(expire,?) WHERE _ROWID_ = ?",
        &plugin->updPrio) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "UPDATE gn090 " "SET repl = MAX (0, repl - 1) WHERE _ROWID_ = ?",
        &plugin->updRepl) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT type,prio,anonLevel,expire,hash,value,_ROWID_ " "FROM gn090 "
#if SQLITE_VERSION_NUMBER >= 3007000
        "INDEXED BY idx_repl_rvalue "
#endif
        "WHERE repl=?2 AND " " (rvalue>=?1 OR "
        "  NOT EXISTS (SELECT 1 FROM gn090 "
#if SQLITE_VERSION_NUMBER >= 3007000
        "INDEXED BY idx_repl_rvalue "
#endif
        "WHERE repl=?2 AND rvalue>=?1 LIMIT 1) ) "
        "ORDER BY rvalue ASC LIMIT 1", &plugin->selRepl) != SQLITE_OK) ||
      (sq_prepare (plugin->dbh, "SELECT MAX(repl) FROM gn090"
#if SQLITE_VERSION_NUMBER >= 3007000
                   " INDEXED BY idx_repl_rvalue"
#endif
                   "", &plugin->maxRepl) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT type,prio,anonLevel,expire,hash,value,_ROWID_ " "FROM gn090 "
#if SQLITE_VERSION_NUMBER >= 3007000
        "INDEXED BY idx_expire "
#endif
        "WHERE NOT EXISTS (SELECT 1 FROM gn090 WHERE expire < ?1 LIMIT 1) OR (expire < ?1) "
        "ORDER BY expire ASC LIMIT 1", &plugin->selExpi) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT type,prio,anonLevel,expire,hash,value,_ROWID_ " "FROM gn090 "
#if SQLITE_VERSION_NUMBER >= 3007000
        "INDEXED BY idx_anon_type_hash "
#endif
        "WHERE (anonLevel = 0 AND type=?1) "
        "ORDER BY hash DESC LIMIT 1 OFFSET ?2",
        &plugin->selZeroAnon) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "INSERT INTO gn090 (repl, type, prio, anonLevel, expire, rvalue, hash, vhash, value) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &plugin->insertContent) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh, "DELETE FROM gn090 WHERE _ROWID_ = ?",
        &plugin->delRow) != SQLITE_OK))
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR, "precompiling");
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

#if SQLITE_VERSION_NUMBER >= 3007000
  sqlite3_stmt *stmt;
#endif

  if (plugin->delRow != NULL)
    sqlite3_finalize (plugin->delRow);
  if (plugin->updPrio != NULL)
    sqlite3_finalize (plugin->updPrio);
  if (plugin->updRepl != NULL)
    sqlite3_finalize (plugin->updRepl);
  if (plugin->selRepl != NULL)
    sqlite3_finalize (plugin->selRepl);
  if (plugin->maxRepl != NULL)
    sqlite3_finalize (plugin->maxRepl);
  if (plugin->selExpi != NULL)
    sqlite3_finalize (plugin->selExpi);
  if (plugin->selZeroAnon != NULL)
    sqlite3_finalize (plugin->selZeroAnon);
  if (plugin->insertContent != NULL)
    sqlite3_finalize (plugin->insertContent);
  result = sqlite3_close (plugin->dbh);
#if SQLITE_VERSION_NUMBER >= 3007000
  if (result == SQLITE_BUSY)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "sqlite",
                     _
                     ("Tried to close sqlite without finalizing all prepared statements.\n"));
    stmt = sqlite3_next_stmt (plugin->dbh, NULL);
    while (stmt != NULL)
    {
#if DEBUG_SQLITE
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                       "Closing statement %p\n", stmt);
#endif
      result = sqlite3_finalize (stmt);
      if (result != SQLITE_OK)
        GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "sqlite",
                         "Failed to close statement %p: %d\n", stmt, result);
      stmt = sqlite3_next_stmt (plugin->dbh, NULL);
    }
    result = sqlite3_close (plugin->dbh);
  }
#endif
  if (SQLITE_OK != result)
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_close");

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
delete_by_rowid (struct Plugin *plugin, unsigned long long rid)
{
  if (SQLITE_OK != sqlite3_bind_int64 (plugin->delRow, 1, rid))
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->delRow))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  if (SQLITE_DONE != sqlite3_step (plugin->delRow))
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    if (SQLITE_OK != sqlite3_reset (plugin->delRow))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  if (SQLITE_OK != sqlite3_reset (plugin->delRow))
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  return GNUNET_OK;
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure
 * @param key key for the item
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param msg set to an error message
 * @return GNUNET_OK on success
 */
static int
sqlite_plugin_put (void *cls, const GNUNET_HashCode * key, uint32_t size,
                   const void *data, enum GNUNET_BLOCK_Type type,
                   uint32_t priority, uint32_t anonymity, uint32_t replication,
                   struct GNUNET_TIME_Absolute expiration, char **msg)
{
  struct Plugin *plugin = cls;
  int n;
  int ret;
  sqlite3_stmt *stmt;
  GNUNET_HashCode vhash;
  uint64_t rvalue;

  if (size > MAX_ITEM_SIZE)
    return GNUNET_SYSERR;
#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                   "Storing in database block with type %u/key `%s'/priority %u/expiration in %llu ms (%lld).\n",
                   type, GNUNET_h2s (key), priority,
                   (unsigned long long)
                   GNUNET_TIME_absolute_get_remaining (expiration).rel_value,
                   (long long) expiration.abs_value);
#endif
  GNUNET_CRYPTO_hash (data, size, &vhash);
  stmt = plugin->insertContent;
  rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX);
  if ((SQLITE_OK != sqlite3_bind_int (stmt, 1, replication)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 2, type)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 3, priority)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 4, anonymity)) ||
      (SQLITE_OK != sqlite3_bind_int64 (stmt, 5, expiration.abs_value)) ||
      (SQLITE_OK != sqlite3_bind_int64 (stmt, 6, rvalue)) ||
      (SQLITE_OK !=
       sqlite3_bind_blob (stmt, 7, key, sizeof (GNUNET_HashCode),
                          SQLITE_TRANSIENT)) ||
      (SQLITE_OK !=
       sqlite3_bind_blob (stmt, 8, &vhash, sizeof (GNUNET_HashCode),
                          SQLITE_TRANSIENT)) ||
      (SQLITE_OK != sqlite3_bind_blob (stmt, 9, data, size, SQLITE_TRANSIENT)))
  {
    LOG_SQLITE (plugin, msg, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  n = sqlite3_step (stmt);
  switch (n)
  {
  case SQLITE_DONE:
    plugin->env->duc (plugin->env->cls, size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
#if DEBUG_SQLITE
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                     "Stored new entry (%u bytes)\n",
                     size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
#endif
    ret = GNUNET_OK;
    break;
  case SQLITE_BUSY:
    GNUNET_break (0);
    LOG_SQLITE (plugin, msg, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    ret = GNUNET_SYSERR;
    break;
  default:
    LOG_SQLITE (plugin, msg, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    database_shutdown (plugin);
    database_setup (plugin->env->cfg, plugin);
    return GNUNET_SYSERR;
  }
  if (SQLITE_OK != sqlite3_reset (stmt))
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  return ret;
}


/**
 * Update the priority for a particular key in the datastore.  If
 * the expiration time in value is different than the time found in
 * the datastore, the higher value should be kept.  For the
 * anonymity level, the lower value is to be used.  The specified
 * priority should be added to the existing priority, ignoring the
 * priority in value.
 *
 * Note that it is possible for multiple values to match this put.
 * In that case, all of the respective values are updated.
 *
 * @param cls the plugin context (state for this module)
 * @param uid unique identifier of the datum
 * @param delta by how much should the priority
 *     change?  If priority + delta < 0 the
 *     priority should be set to 0 (never go
 *     negative).
 * @param expire new expiration time should be the
 *     MAX of any existing expiration time and
 *     this value
 * @param msg set to an error message
 * @return GNUNET_OK on success
 */
static int
sqlite_plugin_update (void *cls, uint64_t uid, int delta,
                      struct GNUNET_TIME_Absolute expire, char **msg)
{
  struct Plugin *plugin = cls;
  int n;

  if ((SQLITE_OK != sqlite3_bind_int (plugin->updPrio, 1, delta)) ||
      (SQLITE_OK != sqlite3_bind_int64 (plugin->updPrio, 2, expire.abs_value))
      || (SQLITE_OK != sqlite3_bind_int64 (plugin->updPrio, 3, uid)))
  {
    LOG_SQLITE (plugin, msg, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->updPrio))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;

  }
  n = sqlite3_step (plugin->updPrio);
  if (SQLITE_OK != sqlite3_reset (plugin->updPrio))
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  switch (n)
  {
  case SQLITE_DONE:
#if DEBUG_SQLITE
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite", "Block updated\n");
#endif
    return GNUNET_OK;
  case SQLITE_BUSY:
    LOG_SQLITE (plugin, msg, GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    return GNUNET_NO;
  default:
    LOG_SQLITE (plugin, msg, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    return GNUNET_SYSERR;
  }
}


/**
 * Execute statement that gets a row and call the callback
 * with the result.  Resets the statement afterwards.
 *
 * @param plugin the plugin
 * @param stmt the statement
 * @param proc processor to call
 * @param proc_cls closure for 'proc'
 */
static void
execute_get (struct Plugin *plugin, sqlite3_stmt * stmt,
             PluginDatumProcessor proc, void *proc_cls)
{
  int n;
  struct GNUNET_TIME_Absolute expiration;
  unsigned long long rowid;
  unsigned int size;
  int ret;

  n = sqlite3_step (stmt);
  switch (n)
  {
  case SQLITE_ROW:
    size = sqlite3_column_bytes (stmt, 5);
    rowid = sqlite3_column_int64 (stmt, 6);
    if (sqlite3_column_bytes (stmt, 4) != sizeof (GNUNET_HashCode))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "sqlite",
                       _
                       ("Invalid data in database.  Trying to fix (by deletion).\n"));
      if (SQLITE_OK != sqlite3_reset (stmt))
        LOG_SQLITE (plugin, NULL,
                    GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                    "sqlite3_reset");
      if (GNUNET_OK == delete_by_rowid (plugin, rowid))
        plugin->env->duc (plugin->env->cls,
                          -(size + GNUNET_DATASTORE_ENTRY_OVERHEAD));
      break;
    }
    expiration.abs_value = sqlite3_column_int64 (stmt, 3);
#if DEBUG_SQLITE
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                     "Found reply in database with expiration %llu\n",
                     (unsigned long long) expiration.abs_value);
#endif
    ret = proc (proc_cls, sqlite3_column_blob (stmt, 4) /* key */ ,
                size, sqlite3_column_blob (stmt, 5) /* data */ ,
                sqlite3_column_int (stmt, 0) /* type */ ,
                sqlite3_column_int (stmt, 1) /* priority */ ,
                sqlite3_column_int (stmt, 2) /* anonymity */ ,
                expiration, rowid);
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    if ((GNUNET_NO == ret) && (GNUNET_OK == delete_by_rowid (plugin, rowid)))
      plugin->env->duc (plugin->env->cls,
                        -(size + GNUNET_DATASTORE_ENTRY_OVERHEAD));
    return;
  case SQLITE_DONE:
    /* database must be empty */
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    break;
  case SQLITE_BUSY:
  case SQLITE_ERROR:
  case SQLITE_MISUSE:
  default:
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    GNUNET_break (0);
    database_shutdown (plugin);
    database_setup (plugin->env->cfg, plugin);
    break;
  }
  if (SQLITE_OK != sqlite3_reset (stmt))
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
}



/**
 * Select a subset of the items in the datastore and call
 * the given processor for the item.
 *
 * @param cls our plugin context
 * @param offset offset of the result (modulo num-results);
 *               specific ordering does not matter for the offset
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param proc function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param proc_cls closure for proc
 */
static void
sqlite_plugin_get_zero_anonymity (void *cls, uint64_t offset,
                                  enum GNUNET_BLOCK_Type type,
                                  PluginDatumProcessor proc, void *proc_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;

  GNUNET_assert (type != GNUNET_BLOCK_TYPE_ANY);
  stmt = plugin->selZeroAnon;
  if ((SQLITE_OK != sqlite3_bind_int (stmt, 1, type)) ||
      (SQLITE_OK != sqlite3_bind_int64 (stmt, 2, offset)))
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  execute_get (plugin, stmt, proc, proc_cls);
}



/**
 * Get results for a particular key in the datastore.
 *
 * @param cls closure
 * @param offset offset (mod count).
 * @param key key to match, never NULL
 * @param vhash hash of the value, maybe NULL (to
 *        match all values that have the right key).
 *        Note that for DBlocks there is no difference
 *        betwen key and vhash, but for other blocks
 *        there may be!
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param proc function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param proc_cls closure for proc
 */
static void
sqlite_plugin_get_key (void *cls, uint64_t offset, const GNUNET_HashCode * key,
                       const GNUNET_HashCode * vhash,
                       enum GNUNET_BLOCK_Type type, PluginDatumProcessor proc,
                       void *proc_cls)
{
  struct Plugin *plugin = cls;
  int ret;
  int total;
  int limit_off;
  unsigned int sqoff;
  sqlite3_stmt *stmt;
  char scratch[256];

  GNUNET_assert (proc != NULL);
  GNUNET_assert (key != NULL);
  GNUNET_snprintf (scratch, sizeof (scratch),
                   "SELECT count(*) FROM gn090 WHERE hash=?%s%s",
                   vhash == NULL ? "" : " AND vhash=?",
                   type == 0 ? "" : " AND type=?");
  if (sq_prepare (plugin->dbh, scratch, &stmt) != SQLITE_OK)
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite_prepare");
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  sqoff = 1;
  ret =
      sqlite3_bind_blob (stmt, sqoff++, key, sizeof (GNUNET_HashCode),
                         SQLITE_TRANSIENT);
  if ((vhash != NULL) && (ret == SQLITE_OK))
    ret =
        sqlite3_bind_blob (stmt, sqoff++, vhash, sizeof (GNUNET_HashCode),
                           SQLITE_TRANSIENT);
  if ((type != 0) && (ret == SQLITE_OK))
    ret = sqlite3_bind_int (stmt, sqoff++, type);
  if (SQLITE_OK != ret)
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite_bind");
    sqlite3_finalize (stmt);
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  ret = sqlite3_step (stmt);
  if (ret != SQLITE_ROW)
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite_step");
    sqlite3_finalize (stmt);
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  total = sqlite3_column_int (stmt, 0);
  sqlite3_finalize (stmt);
  if (0 == total)
  {
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  limit_off = (int) (offset % total);
  if (limit_off < 0)
    limit_off += total;
  GNUNET_snprintf (scratch, sizeof (scratch),
                   "SELECT type, prio, anonLevel, expire, hash, value, _ROWID_ "
                   "FROM gn090 WHERE hash=?%s%s "
                   "ORDER BY _ROWID_ ASC LIMIT 1 OFFSET ?",
                   vhash == NULL ? "" : " AND vhash=?",
                   type == 0 ? "" : " AND type=?");
  if (sq_prepare (plugin->dbh, scratch, &stmt) != SQLITE_OK)
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite_prepare");
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  sqoff = 1;
  ret =
      sqlite3_bind_blob (stmt, sqoff++, key, sizeof (GNUNET_HashCode),
                         SQLITE_TRANSIENT);
  if ((vhash != NULL) && (ret == SQLITE_OK))
    ret =
        sqlite3_bind_blob (stmt, sqoff++, vhash, sizeof (GNUNET_HashCode),
                           SQLITE_TRANSIENT);
  if ((type != 0) && (ret == SQLITE_OK))
    ret = sqlite3_bind_int (stmt, sqoff++, type);
  if (ret == SQLITE_OK)
    ret = sqlite3_bind_int64 (stmt, sqoff++, limit_off);
  if (ret != SQLITE_OK)
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite_bind");
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  execute_get (plugin, stmt, proc, proc_cls);
  sqlite3_finalize (stmt);
}



/**
 * Context for 'repl_proc' function.
 */
struct ReplCtx
{

  /**
   * Function to call for the result (or the NULL).
   */
  PluginDatumProcessor proc;

  /**
   * Closure for proc.
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
 * Wrapper for the processor for 'sqlite_plugin_replication_get'.
 * Decrements the replication counter and calls the original
 * processor.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 *
 * @return GNUNET_OK for normal return,
 *         GNUNET_NO to delete the item
 */
static int
repl_proc (void *cls, const GNUNET_HashCode * key, uint32_t size,
           const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
           uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
           uint64_t uid)
{
  struct ReplCtx *rc = cls;
  int ret;

  ret =
      rc->proc (rc->proc_cls, key, size, data, type, priority, anonymity,
                expiration, uid);
  if (key != NULL)
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
 * Call 'proc' with all values ZERO or NULL if the datastore is empty.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for proc
 */
static void
sqlite_plugin_get_replication (void *cls, PluginDatumProcessor proc,
                               void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct ReplCtx rc;
  uint64_t rvalue;
  uint32_t repl;
  sqlite3_stmt *stmt;

#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                   "Getting random block based on replication order.\n");
#endif
  rc.have_uid = GNUNET_NO;
  rc.proc = proc;
  rc.proc_cls = proc_cls;
  stmt = plugin->maxRepl;
  if (SQLITE_ROW != sqlite3_step (stmt))
  {
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    /* DB empty */
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  repl = sqlite3_column_int (stmt, 0);
  if (SQLITE_OK != sqlite3_reset (stmt))
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  stmt = plugin->selRepl;
  rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX);
  if (SQLITE_OK != sqlite3_bind_int64 (stmt, 1, rvalue))
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  if (SQLITE_OK != sqlite3_bind_int (stmt, 2, repl))
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  execute_get (plugin, stmt, &repl_proc, &rc);
  if (GNUNET_YES == rc.have_uid)
  {
    if (SQLITE_OK != sqlite3_bind_int64 (plugin->updRepl, 1, rc.uid))
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_bind_XXXX");
      if (SQLITE_OK != sqlite3_reset (plugin->updRepl))
        LOG_SQLITE (plugin, NULL,
                    GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                    "sqlite3_reset");
      return;
    }
    if (SQLITE_DONE != sqlite3_step (plugin->updRepl))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_step");
    if (SQLITE_OK != sqlite3_reset (plugin->updRepl))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
  }
}



/**
 * Get a random item that has expired or has low priority.
 * Call 'proc' with all values ZERO or NULL if the datastore is empty.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for proc
 */
static void
sqlite_plugin_get_expiration (void *cls, PluginDatumProcessor proc,
                              void *proc_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  struct GNUNET_TIME_Absolute now;

#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                   "Getting random block based on expiration and priority order.\n");
#endif
  now = GNUNET_TIME_absolute_get ();
  stmt = plugin->selExpi;
  if (SQLITE_OK != sqlite3_bind_int64 (stmt, 1, now.abs_value))
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  execute_get (plugin, stmt, proc, proc_cls);
}



/**
 * Get all of the keys in the datastore.
 *
 * @param cls closure
 * @param proc function to call on each key
 * @param proc_cls closure for proc
 */
static void
sqlite_plugin_get_keys (void *cls,
			PluginKeyProcessor proc,
			void *proc_cls)
{
  struct Plugin *plugin = cls;
  const GNUNET_HashCode *key;
  sqlite3_stmt *stmt;
  int ret;

  GNUNET_assert (proc != NULL);
  if (sq_prepare (plugin->dbh, "SELECT hash FROM gn090", &stmt) != SQLITE_OK)
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite_prepare");
    return;
  }
  while (SQLITE_ROW == (ret = sqlite3_step (stmt)))
  {
    key = sqlite3_column_blob (stmt, 1);
    if (sizeof (GNUNET_HashCode) == sqlite3_column_bytes (stmt, 1))
      proc (proc_cls, key, 1);
  }
  if (SQLITE_DONE != ret)
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite_step");
  sqlite3_finalize (stmt);
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
 * Get an estimate of how much space the database is
 * currently using.
 *
 * @param cls the 'struct Plugin'
 * @return the size of the database on disk (estimate)
 */
static unsigned long long
sqlite_plugin_estimate_size (void *cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  uint64_t pages;
  uint64_t page_size;

#if ENULL_DEFINED
  char *e;
#endif

  if (SQLITE_VERSION_NUMBER < 3006000)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "datastore-sqlite",
                     _
                     ("sqlite version to old to determine size, assuming zero\n"));
    return 0;
  }
  CHECK (SQLITE_OK == sqlite3_exec (plugin->dbh, "VACUUM", NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA auto_vacuum=INCREMENTAL", NULL,
                       NULL, ENULL));
  CHECK (SQLITE_OK == sq_prepare (plugin->dbh, "PRAGMA page_count", &stmt));
  if (SQLITE_ROW == sqlite3_step (stmt))
    pages = sqlite3_column_int64 (stmt, 0);
  else
    pages = 0;
  sqlite3_finalize (stmt);
  CHECK (SQLITE_OK == sq_prepare (plugin->dbh, "PRAGMA page_size", &stmt));
  CHECK (SQLITE_ROW == sqlite3_step (stmt));
  page_size = sqlite3_column_int64 (stmt, 0);
  sqlite3_finalize (stmt);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _
              ("Using sqlite page utilization to estimate payload (%llu pages of size %llu bytes)\n"),
              (unsigned long long) pages, (unsigned long long) page_size);
  return pages * page_size;
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_DATASTORE_PluginEnvironment*"
 * @return NULL on error, othrewise the plugin context
 */
void *
libgnunet_plugin_datastore_sqlite_init (void *cls)
{
  static struct Plugin plugin;
  struct GNUNET_DATASTORE_PluginEnvironment *env = cls;
  struct GNUNET_DATASTORE_PluginFunctions *api;

  if (plugin.env != NULL)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.env = env;
  if (GNUNET_OK != database_setup (env->cfg, &plugin))
  {
    database_shutdown (&plugin);
    return NULL;
  }
  api = GNUNET_malloc (sizeof (struct GNUNET_DATASTORE_PluginFunctions));
  api->cls = &plugin;
  api->estimate_size = &sqlite_plugin_estimate_size;
  api->put = &sqlite_plugin_put;
  api->update = &sqlite_plugin_update;
  api->get_key = &sqlite_plugin_get_key;
  api->get_replication = &sqlite_plugin_get_replication;
  api->get_expiration = &sqlite_plugin_get_expiration;
  api->get_zero_anonymity = &sqlite_plugin_get_zero_anonymity;
  api->get_keys = &sqlite_plugin_get_keys;
  api->drop = &sqlite_plugin_drop;
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "sqlite",
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

#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                   "sqlite plugin is done\n");
#endif

  fn = NULL;
  if (plugin->drop_on_shutdown)
    fn = GNUNET_strdup (plugin->fn);
#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                   "Shutting down database\n");
#endif
  database_shutdown (plugin);
  plugin->env = NULL;
  GNUNET_free (api);
  if (fn != NULL)
  {
    if (0 != UNLINK (fn))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", fn);
    GNUNET_free (fn);
  }
#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                   "sqlite plugin is finished\n");
#endif
  return NULL;
}

/* end of plugin_datastore_sqlite.c */
