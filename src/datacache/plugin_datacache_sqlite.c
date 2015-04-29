/*
     This file is part of GNUnet
     Copyright (C) 2006, 2009, 2015 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file datacache/plugin_datacache_sqlite.c
 * @brief sqlite for an implementation of a database backend for the datacache
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_datacache_plugin.h"
#include <sqlite3.h>

#define LOG(kind,...) GNUNET_log_from (kind, "datacache-sqlite", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind,op,fn) GNUNET_log_from_strerror_file (kind, "datacache-sqlite", op, fn)


/**
 * How much overhead do we assume per entry in the
 * datacache?
 */
#define OVERHEAD (sizeof(struct GNUNET_HashCode) + 32)

/**
 * Context for all functions in this plugin.
 */
struct Plugin
{
  /**
   * Our execution environment.
   */
  struct GNUNET_DATACACHE_PluginEnvironment *env;

  /**
   * Handle to the sqlite database.
   */
  sqlite3 *dbh;

  /**
   * Filename used for the DB.
   */
  char *fn;

  /**
   * Number of key-value pairs in the database.
   */
  unsigned int num_items;
};


/**
 * Log an error message at log-level @a level that indicates
 * a failure of the command @a cmd with the error from the database @a db
 *
 * @param db database handle
 * @param level log level
 * @param cmd failed command
 */
#define LOG_SQLITE(db, level, cmd) do { LOG (level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db)); } while(0)


/**
 * Execute SQL statement.
 *
 * @param db database handle
 * @param cmd SQL command to execute
 */
#define SQLITE3_EXEC(db, cmd) do { emsg = NULL; if (SQLITE_OK != sqlite3_exec(db, cmd, NULL, NULL, &emsg)) { LOG (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, _("`%s' failed at %s:%d with error: %s\n"), "sqlite3_exec", __FILE__, __LINE__, emsg); sqlite3_free(emsg); } } while(0)


/**
 * @brief Prepare a SQL statement
 *
 * @param dbh database handle
 * @param zsql SQL statement text
 * @param[out] ppStmt set to the prepared statement
 * @return 0 on success
 */
static int
sq_prepare (sqlite3 *dbh,
            const char *zSql,    /* SQL statement, UTF-8 encoded */
            sqlite3_stmt **ppStmt)
{                               /* OUT: Statement handle */
  char *dummy;

  return sqlite3_prepare (dbh,
                          zSql, strlen (zSql),
                          ppStmt,
                          (const char **) &dummy);
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure (our `struct Plugin`)
 * @param key key to store @a data under
 * @param size number of bytes in @a data
 * @param data data to store
 * @param type type of the value
 * @param discard_time when to discard the value in any case
 * @param path_info_len number of entries in @a path_info
 * @param path_info array of peers that have processed the request
 * @return 0 if duplicate, -1 on error, number of bytes used otherwise
 */
static ssize_t
sqlite_plugin_put (void *cls,
		   const struct GNUNET_HashCode *key,
		   size_t size,
                   const char *data,
		   enum GNUNET_BLOCK_Type type,
                   struct GNUNET_TIME_Absolute discard_time,
		   unsigned int path_info_len,
		   const struct GNUNET_PeerIdentity *path_info)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  int64_t dval;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing PUT of %u bytes with key `%4s' and expiration %s\n",
       (unsigned int) size,
       GNUNET_h2s (key),
       GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining (discard_time), GNUNET_YES));
  dval = (int64_t) discard_time.abs_value_us;
  if (dval < 0)
    dval = INT64_MAX;
  if (sq_prepare
      (plugin->dbh,
       "INSERT INTO ds090 (type, expire, key, value, path) VALUES (?, ?, ?, ?, ?)",
       &stmt) != SQLITE_OK)
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sq_prepare");
    return -1;
  }
  if ((SQLITE_OK != sqlite3_bind_int (stmt, 1, type)) ||
      (SQLITE_OK != sqlite3_bind_int64 (stmt, 2, dval)) ||
      (SQLITE_OK !=
       sqlite3_bind_blob (stmt, 3,
			  key, sizeof (struct GNUNET_HashCode),
                          SQLITE_TRANSIENT)) ||
      (SQLITE_OK != sqlite3_bind_blob (stmt, 4,
				       data, size,
				       SQLITE_TRANSIENT)) ||
      (SQLITE_OK != sqlite3_bind_blob (stmt, 5,
				       path_info,
				       path_info_len * sizeof (struct GNUNET_PeerIdentity),
				       SQLITE_TRANSIENT)))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_xxx");
    sqlite3_finalize (stmt);
    return -1;
  }
  if (SQLITE_DONE != sqlite3_step (stmt))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    sqlite3_finalize (stmt);
    return -1;
  }
  plugin->num_items++;
  if (SQLITE_OK != sqlite3_finalize (stmt))
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_finalize");
  return size + OVERHEAD;
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure (our `struct Plugin`)
 * @param key
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found
 */
static unsigned int
sqlite_plugin_get (void *cls,
                   const struct GNUNET_HashCode *key,
                   enum GNUNET_BLOCK_Type type,
                   GNUNET_DATACACHE_Iterator iter,
                   void *iter_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Absolute exp;
  unsigned int size;
  const char *dat;
  unsigned int cnt;
  unsigned int off;
  unsigned int total;
  unsigned int psize;
  char scratch[256];
  int64_t ntime;
  const struct GNUNET_PeerIdentity *path;

  now = GNUNET_TIME_absolute_get ();
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing GET for key `%4s'\n",
       GNUNET_h2s (key));
  if (sq_prepare
      (plugin->dbh,
       "SELECT count(*) FROM ds090 WHERE key=? AND type=? AND expire >= ?",
       &stmt) != SQLITE_OK)
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sq_prepare");
    return 0;
  }
  ntime = (int64_t) now.abs_value_us;
  GNUNET_assert (ntime >= 0);
  if ((SQLITE_OK !=
       sqlite3_bind_blob (stmt, 1, key, sizeof (struct GNUNET_HashCode),
                          SQLITE_TRANSIENT)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 2, type)) ||
      (SQLITE_OK != sqlite3_bind_int64 (stmt, 3, now.abs_value_us)))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_xxx");
    sqlite3_finalize (stmt);
    return 0;
  }

  if (SQLITE_ROW != sqlite3_step (stmt))
  {
    LOG_SQLITE (plugin->dbh, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite_step");
    sqlite3_finalize (stmt);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "No content found when processing GET for key `%4s'\n",
         GNUNET_h2s (key));
    return 0;
  }
  total = sqlite3_column_int (stmt, 0);
  sqlite3_finalize (stmt);
  if ((0 == total) || (NULL == iter))
  {
    if (0 == total)
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "No content found when processing GET for key `%4s'\n",
           GNUNET_h2s (key));
    return total;
  }

  cnt = 0;
  off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, total);
  while (cnt < total)
  {
    off = (off + 1) % total;
    GNUNET_snprintf (scratch, sizeof (scratch),
                     "SELECT value,expire,path FROM ds090 WHERE key=? AND type=? AND expire >= ? LIMIT 1 OFFSET %u",
                     off);
    if (sq_prepare (plugin->dbh, scratch, &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (plugin->dbh,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sq_prepare");
      return cnt;
    }
    if ((SQLITE_OK !=
         sqlite3_bind_blob (stmt, 1,
                            key,
                            sizeof (struct GNUNET_HashCode),
                            SQLITE_TRANSIENT)) ||
        (SQLITE_OK != sqlite3_bind_int (stmt, 2, type)) ||
        (SQLITE_OK != sqlite3_bind_int64 (stmt, 3, now.abs_value_us)))
    {
      LOG_SQLITE (plugin->dbh,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_bind_xxx");
      sqlite3_finalize (stmt);
      return cnt;
    }
    if (sqlite3_step (stmt) != SQLITE_ROW)
      break;
    size = sqlite3_column_bytes (stmt, 0);
    dat = sqlite3_column_blob (stmt, 0);
    exp.abs_value_us = sqlite3_column_int64 (stmt, 1);
    psize = sqlite3_column_bytes (stmt, 2);
    if (0 != psize % sizeof (struct GNUNET_PeerIdentity))
    {
      GNUNET_break (0);
      psize = 0;
    }
    psize /= sizeof (struct GNUNET_PeerIdentity);
    if (0 != psize)
      path = sqlite3_column_blob (stmt, 2);
    else
      path = NULL;
    ntime = (int64_t) exp.abs_value_us;
    if (ntime == INT64_MAX)
      exp = GNUNET_TIME_UNIT_FOREVER_ABS;
    cnt++;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Found %u-byte result when processing GET for key `%4s'\n",
         (unsigned int) size,
         GNUNET_h2s (key));
    if (GNUNET_OK != iter (iter_cls,
                           key,
                           size,
                           dat,
                           type,
                           exp,
                           psize,
                           path))
    {
      sqlite3_finalize (stmt);
      break;
    }
    sqlite3_finalize (stmt);
  }
  return cnt;
}


/**
 * Delete the entry with the lowest expiration value
 * from the datacache right now.
 *
 * @param cls closure (our `struct Plugin`)
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
sqlite_plugin_del (void *cls)
{
  struct Plugin *plugin = cls;
  unsigned long long rowid;
  unsigned int dsize;
  sqlite3_stmt *stmt;
  sqlite3_stmt *dstmt;
  struct GNUNET_HashCode hc;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing DEL\n");
  stmt = NULL;
  dstmt = NULL;
  if (SQLITE_OK !=
      sq_prepare (plugin->dbh,
                  "SELECT _ROWID_,key,value FROM ds090 ORDER BY expire ASC LIMIT 1",
                  &stmt))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sq_prepare");
    if (stmt != NULL)
      (void) sqlite3_finalize (stmt);
    return GNUNET_SYSERR;
  }
  if (SQLITE_ROW != sqlite3_step (stmt))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    (void) sqlite3_finalize (stmt);
    return GNUNET_SYSERR;
  }
  rowid = sqlite3_column_int64 (stmt, 0);
  GNUNET_assert (sqlite3_column_bytes (stmt, 1) == sizeof (struct GNUNET_HashCode));
  memcpy (&hc, sqlite3_column_blob (stmt, 1), sizeof (struct GNUNET_HashCode));
  dsize = sqlite3_column_bytes (stmt, 2);
  if (SQLITE_OK != sqlite3_finalize (stmt))
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
  if (SQLITE_OK !=
      sq_prepare (plugin->dbh,
                  "DELETE FROM ds090 WHERE _ROWID_=?", &dstmt))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sq_prepare");
    if (stmt != NULL)
      (void) sqlite3_finalize (stmt);
    return GNUNET_SYSERR;
  }
  if (SQLITE_OK != sqlite3_bind_int64 (dstmt, 1, rowid))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind");
    (void) sqlite3_finalize (dstmt);
    return GNUNET_SYSERR;
  }
  if (SQLITE_DONE != sqlite3_step (dstmt))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    (void) sqlite3_finalize (dstmt);
    return GNUNET_SYSERR;
  }
  plugin->num_items--;
  plugin->env->delete_notify (plugin->env->cls,
                              &hc,
                              dsize + OVERHEAD);
  if (SQLITE_OK != sqlite3_finalize (dstmt))
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_finalize");
  return GNUNET_OK;
}


/**
 * Obtain a random key-value pair from the datacache.
 *
 * @param cls closure (our `struct Plugin`)
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found, zero (datacache empty) or one
 */
static unsigned int
sqlite_plugin_get_random (void *cls,
                          GNUNET_DATACACHE_Iterator iter,
                          void *iter_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  struct GNUNET_TIME_Absolute exp;
  unsigned int size;
  const char *dat;
  unsigned int off;
  unsigned int psize;
  unsigned int type;
  char scratch[256];
  int64_t ntime;
  const struct GNUNET_PeerIdentity *path;
  const struct GNUNET_HashCode *key;

  if (0 == plugin->num_items)
    return 0;
  if (NULL == iter)
    return 1;
  off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                  plugin->num_items);
  GNUNET_snprintf (scratch,
                   sizeof (scratch),
                   "SELECT value,expire,path,key,type FROM ds090 ORDER BY key LIMIT 1 OFFSET %u",
                   off);
  if (SQLITE_OK !=
      sq_prepare (plugin->dbh, scratch, &stmt))
  {
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sq_prepare");
    return 0;
  }
  if (SQLITE_ROW != sqlite3_step (stmt))
  {
    GNUNET_break (0);
    sqlite3_finalize (stmt);
    return 0;
  }
  size = sqlite3_column_bytes (stmt, 0);
  dat = sqlite3_column_blob (stmt, 0);
  exp.abs_value_us = sqlite3_column_int64 (stmt, 1);
  psize = sqlite3_column_bytes (stmt, 2);
  if (0 != psize % sizeof (struct GNUNET_PeerIdentity))
  {
    GNUNET_break (0);
    psize = 0;
  }
  psize /= sizeof (struct GNUNET_PeerIdentity);
  if (0 != psize)
    path = sqlite3_column_blob (stmt, 2);
  else
    path = NULL;

  GNUNET_assert (sizeof (struct GNUNET_HashCode) ==
                 sqlite3_column_bytes (stmt, 3));
  key = sqlite3_column_blob (stmt, 3);
  type = sqlite3_column_int (stmt, 4);

  ntime = (int64_t) exp.abs_value_us;
  if (ntime == INT64_MAX)
    exp = GNUNET_TIME_UNIT_FOREVER_ABS;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Found %u-byte result with key %s when processing GET-RANDOM\n",
       (unsigned int) size,
       GNUNET_h2s (key));
  (void) iter (iter_cls,
               key,
               size,
               dat,
               type,
               exp,
               psize,
               path);
  sqlite3_finalize (stmt);
  return 1;
}


/**
 * Entry point for the plugin.
 *
 * @param cls closure (the `struct GNUNET_DATACACHE_PluginEnvironment`)
 * @return the plugin's closure (our `struct Plugin`)
 */
void *
libgnunet_plugin_datacache_sqlite_init (void *cls)
{
  struct GNUNET_DATACACHE_PluginEnvironment *env = cls;
  struct GNUNET_DATACACHE_PluginFunctions *api;
  struct Plugin *plugin;
  char *fn;
  char *fn_utf8;
  sqlite3 *dbh;
  char *emsg;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
					    "datacache-sqlite",
					    "IN_MEMORY"))
  {
    if (SQLITE_OK != sqlite3_open (":memory:", &dbh))
      return NULL;
    fn_utf8 = NULL;
  }
  else
  {
    fn = GNUNET_DISK_mktemp ("gnunet-datacache");
    if (fn == NULL)
      {
	GNUNET_break (0);
	return NULL;
      }
    /* fn should be UTF-8-encoded. If it isn't, it's a bug. */
    fn_utf8 = GNUNET_strdup (fn);
    if (SQLITE_OK != sqlite3_open (fn_utf8, &dbh))
    {
      GNUNET_free (fn);
      GNUNET_free (fn_utf8);
      return NULL;
    }
    GNUNET_free (fn);
  }

  SQLITE3_EXEC (dbh, "PRAGMA temp_store=MEMORY");
  SQLITE3_EXEC (dbh, "PRAGMA locking_mode=EXCLUSIVE");
  SQLITE3_EXEC (dbh, "PRAGMA journal_mode=OFF");
  SQLITE3_EXEC (dbh, "PRAGMA synchronous=OFF");
  SQLITE3_EXEC (dbh, "PRAGMA page_size=4092");
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
					    "datacache-sqlite",
					    "IN_MEMORY"))
    SQLITE3_EXEC (dbh, "PRAGMA sqlite_temp_store=3");

  SQLITE3_EXEC (dbh,
                "CREATE TABLE ds090 (" "  type INTEGER NOT NULL DEFAULT 0,"
                "  expire INTEGER NOT NULL DEFAULT 0,"
                "  key BLOB NOT NULL DEFAULT '',"
                "  value BLOB NOT NULL DEFAULT '',"
		"  path BLOB DEFAULT '')");
  SQLITE3_EXEC (dbh, "CREATE INDEX idx_hashidx ON ds090 (key,type,expire)");
  SQLITE3_EXEC (dbh, "CREATE INDEX idx_expire ON ds090 (expire)");
  plugin = GNUNET_new (struct Plugin);
  plugin->env = env;
  plugin->dbh = dbh;
  plugin->fn = fn_utf8;
  api = GNUNET_new (struct GNUNET_DATACACHE_PluginFunctions);
  api->cls = plugin;
  api->get = &sqlite_plugin_get;
  api->put = &sqlite_plugin_put;
  api->del = &sqlite_plugin_del;
  api->get_random = &sqlite_plugin_get_random;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Sqlite datacache running\n");
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls closure (our `struct Plugin`)
 * @return NULL
 */
void *
libgnunet_plugin_datacache_sqlite_done (void *cls)
{
  struct GNUNET_DATACACHE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  int result;

#if SQLITE_VERSION_NUMBER >= 3007000
  sqlite3_stmt *stmt;
#endif

#if !WINDOWS || defined(__CYGWIN__)
  if ( (NULL != plugin->fn) &&
       (0 != UNLINK (plugin->fn)) )
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING,
                       "unlink",
                       plugin->fn);
  GNUNET_free_non_null (plugin->fn);
#endif
  result = sqlite3_close (plugin->dbh);
#if SQLITE_VERSION_NUMBER >= 3007000
  if (SQLITE_BUSY == result)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Tried to close sqlite without finalizing all prepared statements.\n"));
    stmt = sqlite3_next_stmt (plugin->dbh, NULL);
    while (NULL != stmt)
    {
      result = sqlite3_finalize (stmt);
      if (result != SQLITE_OK)
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Failed to close statement %p: %d\n",
             stmt,
             result);
      stmt = sqlite3_next_stmt (plugin->dbh, NULL);
    }
    result = sqlite3_close (plugin->dbh);
  }
#endif
  if (SQLITE_OK != result)
    LOG_SQLITE (plugin->dbh,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite3_close");

#if WINDOWS && !defined(__CYGWIN__)
  if ( (NULL != plugin->fn) &&
       (0 != UNLINK (plugin->fn)) )
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING,
                       "unlink",
                       plugin->fn);
  GNUNET_free_non_null (plugin->fn);
#endif
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}



/* end of plugin_datacache_sqlite.c */
