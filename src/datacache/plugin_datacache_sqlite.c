/*
     This file is part of GNUnet
     (C) 2006, 2009 Christian Grothoff (and other contributing authors)

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

#define DEBUG_DATACACHE_SQLITE GNUNET_NO

/**
 * How much overhead do we assume per entry in the
 * datacache?
 */
#define OVERHEAD (sizeof(GNUNET_HashCode) + 32)

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
};


/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(db, level, cmd) do { GNUNET_log(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db)); } while(0)


#define SQLITE3_EXEC(db, cmd) do { emsg = NULL; if (SQLITE_OK != sqlite3_exec(db, cmd, NULL, NULL, &emsg)) { GNUNET_log(GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, _("`%s' failed at %s:%d with error: %s\n"), "sqlite3_exec", __FILE__, __LINE__, emsg); sqlite3_free(emsg); } } while(0)


/**
 * @brief Prepare a SQL statement
 */
static int
sq_prepare (sqlite3 * dbh, const char *zSql,    /* SQL statement, UTF-8 encoded */
            sqlite3_stmt ** ppStmt)
{                               /* OUT: Statement handle */
  char *dummy;
  return sqlite3_prepare (dbh,
                          zSql,
                          strlen (zSql), ppStmt, (const char **) &dummy);
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure (our "struct Plugin")
 * @param key key to store data under
 * @param size number of bytes in data
 * @param data data to store
 * @param type type of the value
 * @param discard_time when to discard the value in any case
 * @return 0 on error, number of bytes used otherwise
 */
static size_t 
sqlite_plugin_put (void *cls,
		   const GNUNET_HashCode * key,
		   size_t size,
		   const char *data,
		   enum GNUNET_BLOCK_Type type,
		   struct GNUNET_TIME_Absolute discard_time)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  int64_t dval;

#if DEBUG_DATACACHE_SQLITE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing `%s' of %u bytes with key `%4s' and expiration %llums\n",
	      "PUT",
	      (unsigned int) size,
	      GNUNET_h2s (key),
	      (unsigned long long) GNUNET_TIME_absolute_get_remaining (discard_time).rel_value);
#endif
  dval = (int64_t) discard_time.abs_value;
  if (dval < 0)    
    dval = INT64_MAX;    
  if (sq_prepare (plugin->dbh,
                  "INSERT INTO ds090 "
                  "(type, expire, key, value) "
                  "VALUES (?, ?, ?, ?)", &stmt) != SQLITE_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  _("`%s' failed at %s:%d with error: %s\n"),
		  "sq_prepare", __FILE__, __LINE__, 
		  sqlite3_errmsg (plugin->dbh));
      return 0;
    }
  if ( (SQLITE_OK != sqlite3_bind_int (stmt, 1, type)) ||
       (SQLITE_OK != sqlite3_bind_int64 (stmt, 2, dval)) ||
       (SQLITE_OK != sqlite3_bind_blob (stmt, 3, key, sizeof (GNUNET_HashCode),
					SQLITE_TRANSIENT)) ||
       (SQLITE_OK != sqlite3_bind_blob (stmt, 4, data, size, SQLITE_TRANSIENT)))
    {
      LOG_SQLITE (plugin->dbh,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, 
		  "sqlite3_bind_xxx");
      sqlite3_finalize (stmt);
      return 0;
    }
  if (SQLITE_DONE != sqlite3_step (stmt))
    {
      LOG_SQLITE (plugin->dbh,
		  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, 
		  "sqlite3_step");
      sqlite3_finalize (stmt);
      return 0;
    }
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
 * @param cls closure (our "struct Plugin")
 * @param key
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for iter
 * @return the number of results found
 */
static unsigned int 
sqlite_plugin_get (void *cls,
		   const GNUNET_HashCode * key,
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
  char scratch[256];
  int64_t ntime;

  now = GNUNET_TIME_absolute_get ();
#if DEBUG_DATACACHE_SQLITE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing `%s' for key `%4s'\n",
	      "GET",
	      GNUNET_h2s (key));
#endif
  if (sq_prepare (plugin->dbh,
                  "SELECT count(*) FROM ds090 WHERE key=? AND type=? AND expire >= ?",
                  &stmt) != SQLITE_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  _("`%s' failed at %s:%d with error: %s\n"),
		  "sq_prepare", __FILE__, __LINE__, 
		  sqlite3_errmsg (plugin->dbh));
      return 0;
    }
  ntime = (int64_t) now.abs_value;
  GNUNET_assert (ntime >= 0);
  if ( (SQLITE_OK != 
	sqlite3_bind_blob (stmt, 1, key, sizeof (GNUNET_HashCode),
			   SQLITE_TRANSIENT)) ||
       (SQLITE_OK != 
	sqlite3_bind_int (stmt, 2, type)) ||
       (SQLITE_OK !=
	sqlite3_bind_int64 (stmt, 3, now.abs_value)) )	
    {
      LOG_SQLITE (plugin->dbh,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, 
		  "sqlite3_bind_xxx");
      sqlite3_finalize (stmt);
      return 0;
    }

  if (SQLITE_ROW != sqlite3_step (stmt))
    {
      LOG_SQLITE (plugin->dbh,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, 
		  "sqlite_step");
      sqlite3_finalize (stmt);
      return 0;
    }
  total = sqlite3_column_int (stmt, 0);
  sqlite3_finalize (stmt);
  if ( (total == 0) || (iter == NULL) )
    return total;    

  cnt = 0;
  off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, total);
  while (cnt < total)
    {
      off = (off + 1) % total;
      GNUNET_snprintf (scratch, 
		       sizeof(scratch),
                       "SELECT value,expire FROM ds090 WHERE key=? AND type=? AND expire >= ? LIMIT 1 OFFSET %u",
                       off);
      if (sq_prepare (plugin->dbh, scratch, &stmt) != SQLITE_OK)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		      _("`%s' failed at %s:%d with error: %s\n"),
		      "sq_prepare", __FILE__, __LINE__,
		      sqlite3_errmsg (plugin->dbh));
          return cnt;
        }
      if ( (SQLITE_OK !=
	    sqlite3_bind_blob (stmt, 1, key, sizeof (GNUNET_HashCode),
			       SQLITE_TRANSIENT)) ||
	   (SQLITE_OK !=
	    sqlite3_bind_int (stmt, 2, type)) ||
	   (SQLITE_OK != 
	    sqlite3_bind_int64 (stmt, 3, now.abs_value)) )
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
      exp.abs_value = sqlite3_column_int64 (stmt, 1);
      ntime = (int64_t) exp.abs_value;
      if (ntime == INT64_MAX)
	exp = GNUNET_TIME_UNIT_FOREVER_ABS;
      cnt++;
      if (GNUNET_OK != iter (iter_cls,
			     exp,
			     key, 
			     size,
			     dat,
			     type))
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
 * @param cls closure (our "struct Plugin")
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */ 
static int 
sqlite_plugin_del (void *cls)
{
  struct Plugin *plugin = cls;
  unsigned int dsize;
  unsigned int dtype;
  sqlite3_stmt *stmt;
  sqlite3_stmt *dstmt;
  char blob[65536];
  GNUNET_HashCode hc;

#if DEBUG_DATACACHE_SQLITE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Processing `%s'\n",
	      "DEL");
#endif
  stmt = NULL;
  dstmt = NULL;
  if (sq_prepare (plugin->dbh,
                   "SELECT type, key, value FROM ds090 ORDER BY expire ASC LIMIT 1",
                   &stmt) != SQLITE_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  _("`%s' failed at %s:%d with error: %s\n"),
		  "sq_prepare", __FILE__, __LINE__, sqlite3_errmsg (plugin->dbh));
      if (stmt != NULL)
        (void) sqlite3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  if (SQLITE_ROW != sqlite3_step (stmt))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  _("`%s' failed at %s:%d with error: %s\n"),
		  "sqlite3_step", __FILE__, __LINE__,
		  sqlite3_errmsg (plugin->dbh));
      (void) sqlite3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  dtype = sqlite3_column_int (stmt, 0);
  GNUNET_break (sqlite3_column_bytes (stmt, 1) == sizeof (GNUNET_HashCode));
  dsize = sqlite3_column_bytes (stmt, 2);
  GNUNET_assert (dsize <= sizeof (blob));
  memcpy (blob, sqlite3_column_blob (stmt, 2), dsize);
  memcpy (&hc, sqlite3_column_blob (stmt, 1), sizeof (GNUNET_HashCode));
  if (SQLITE_OK != sqlite3_finalize (stmt))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		_("`%s' failed at %s:%d with error: %s\n"),
		"sqlite3_step", __FILE__, __LINE__,
		sqlite3_errmsg (plugin->dbh));    
  if (sq_prepare (plugin->dbh,
		  "DELETE FROM ds090 "
		  "WHERE key=? AND value=? AND type=?",
		  &dstmt) != SQLITE_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  _("`%s' failed at %s:%d with error: %s\n"),
		  "sq_prepare", __FILE__, __LINE__, sqlite3_errmsg (plugin->dbh));
      if (stmt != NULL)
        (void) sqlite3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  if ( (SQLITE_OK !=
	sqlite3_bind_blob (dstmt,
			   1, &hc,
			   sizeof (GNUNET_HashCode),
			   SQLITE_TRANSIENT)) ||
       (SQLITE_OK !=
	sqlite3_bind_blob (dstmt,
			   2, blob,
			   dsize,
			   SQLITE_TRANSIENT)) ||
       (SQLITE_OK != 
	sqlite3_bind_int (dstmt, 3, dtype)) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  _("`%s' failed at %s:%d with error: %s\n"),
		  "sqlite3_bind", __FILE__, __LINE__,
		  sqlite3_errmsg (plugin->dbh));    
      (void) sqlite3_finalize (dstmt);
      return GNUNET_SYSERR;
    }
  if (sqlite3_step (dstmt) != SQLITE_DONE)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  _("`%s' failed at %s:%d with error: %s\n"),
		  "sqlite3_step", __FILE__, __LINE__,
		  sqlite3_errmsg (plugin->dbh));    
      (void) sqlite3_finalize (dstmt);
      return GNUNET_SYSERR;
    }
  plugin->env->delete_notify (plugin->env->cls,
			      &hc,
			      dsize + OVERHEAD);
  if (SQLITE_OK != sqlite3_finalize (dstmt))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		_("`%s' failed at %s:%d with error: %s\n"),
		"sqlite3_finalize", __FILE__, __LINE__,
		sqlite3_errmsg (plugin->dbh));    
  return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 *
 * @param cls closure (the "struct GNUNET_DATACACHE_PluginEnvironmnet")
 * @return the plugin's closure (our "struct Plugin")
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

  fn = GNUNET_DISK_mktemp ("gnunet-datacache");
  if (fn == NULL)
    {
      GNUNET_break (0);
      return NULL;
    }
#ifdef ENABLE_NLS
  fn_utf8 = GNUNET_STRINGS_to_utf8 (fn, strlen (fn), nl_langinfo (CODESET));
#else
  /* good luck */
  fn_utf8 = GNUNET_STRINGS_to_utf8 (fn, strlen (fn), "UTF-8");
#endif
  if (SQLITE_OK != sqlite3_open (fn_utf8, &dbh))
    {
      GNUNET_free (fn);
      GNUNET_free (fn_utf8);
      return NULL;
    }
  GNUNET_free (fn);

  SQLITE3_EXEC (dbh, "PRAGMA temp_store=MEMORY");
  SQLITE3_EXEC (dbh, "PRAGMA locking_mode=EXCLUSIVE");
  SQLITE3_EXEC (dbh, "PRAGMA journal_mode=OFF");
  SQLITE3_EXEC (dbh, "PRAGMA synchronous=OFF");
  SQLITE3_EXEC (dbh, "PRAGMA count_changes=OFF");
  SQLITE3_EXEC (dbh, "PRAGMA page_size=4092");
  SQLITE3_EXEC (dbh,
                "CREATE TABLE ds090 ("
                "  type INTEGER NOT NULL DEFAULT 0,"
                "  expire INTEGER NOT NULL DEFAULT 0,"
                "  key BLOB NOT NULL DEFAULT '',"
                "  value BLOB NOT NULL DEFAULT '')");
  SQLITE3_EXEC (dbh, "CREATE INDEX idx_hashidx ON ds090 (key,type,expire)");
  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  plugin->dbh = dbh;
  plugin->fn = fn_utf8;
  api = GNUNET_malloc (sizeof (struct GNUNET_DATACACHE_PluginFunctions));
  api->cls = plugin;
  api->get = &sqlite_plugin_get;
  api->put = &sqlite_plugin_put;
  api->del = &sqlite_plugin_del;
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                   "sqlite", _("Sqlite datacache running\n"));
  return api;
}
// explain SELECT type FROM gn090 WHERE NOT EXISTS (SELECT 1 from gn090 WHERE expire < 42 LIMIT 1) OR expire < 42 ORDER BY repl DESC, Random() LIMIT 1;


/**
 * Exit point from the plugin.
 *
 * @param cls closure (our "struct Plugin")
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
  if (0 != UNLINK (plugin->fn))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
			      "unlink", 
			      plugin->fn);
  GNUNET_free (plugin->fn);
#endif
  result = sqlite3_close (plugin->dbh);
#if SQLITE_VERSION_NUMBER >= 3007000
  if (result == SQLITE_BUSY)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, 
		       "sqlite",
		       _("Tried to close sqlite without finalizing all prepared statements.\n"));
      stmt = sqlite3_next_stmt(plugin->dbh, NULL); 
      while (stmt != NULL)
        {
#if DEBUG_SQLITE
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			   "sqlite", "Closing statement %p\n", stmt);
#endif
          result = sqlite3_finalize(stmt);
#if DEBUG_SQLITE
          if (result != SQLITE_OK)
	    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			     "sqlite",
			     "Failed to close statement %p: %d\n", stmt, result);
#endif
	  stmt = sqlite3_next_stmt(plugin->dbh, NULL);
        }
      result = sqlite3_close(plugin->dbh);
    }
#endif
  if (SQLITE_OK != result)
    LOG_SQLITE (plugin->dbh,
		GNUNET_ERROR_TYPE_ERROR, 
		"sqlite3_close");

#if WINDOWS && !defined(__CYGWIN__)
  if (0 != UNLINK (plugin->fn))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
			      "unlink", 
			      plugin->fn);
  GNUNET_free (plugin->fn);
#endif
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}



/* end of plugin_datacache_sqlite.c */

