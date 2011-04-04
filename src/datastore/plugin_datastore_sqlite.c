 /*
     This file is part of GNUnet
     (C) 2009, 2011 Christian Grothoff (and other contributing authors)

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
#define DEBUG_SQLITE GNUNET_NO

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
   * Precompiled SQL for insertion.
   */
  sqlite3_stmt *insertContent;

  /**
   * Closure of the 'next_task' (must be freed if 'next_task' is cancelled).
   */
  struct NextContext *next_task_nc;

  /**
   * Pending task with scheduler for running the next request.
   */
  GNUNET_SCHEDULER_TaskIdentifier next_task;

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
sq_prepare (sqlite3 * dbh, 
	    const char *zSql,
            sqlite3_stmt ** ppStmt)
{
  char *dummy;
  int result;

  result = sqlite3_prepare_v2 (dbh,
			       zSql,
			       strlen (zSql), 
			       ppStmt,
			       (const char **) &dummy);
#if DEBUG_SQLITE && 0
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "sqlite",
                   "Prepared `%s' / %p: %d\n",
		   zSql,
		   *ppStmt, 
		   result);
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
  sqlite3_exec (dbh,
                "CREATE INDEX idx_hash ON gn090 (hash)", NULL, NULL, NULL);
  sqlite3_exec (dbh, "CREATE INDEX idx_prio ON gn090 (prio)", NULL, NULL,
                NULL);
  sqlite3_exec (dbh, "CREATE INDEX idx_expire_prio ON gn090 (expire,prio)", NULL, NULL,
                NULL);
  sqlite3_exec (dbh,
                "CREATE INDEX idx_hash_vhash ON gn090 (hash,vhash)", NULL,
                NULL, NULL);
  sqlite3_exec (dbh, "CREATE INDEX idx_comb ON gn090 (prio,expire,anonLevel,hash)",
                NULL, NULL, NULL);
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
      GNUNET_CONFIGURATION_get_value_filename (cfg,
					       "datastore-sqlite",
					       "FILENAME",
					       &afsdir))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
		       "sqlite",
		       _("Option `%s' in section `%s' missing in configuration!\n"),
		       "FILENAME",
		       "datastore-sqlite");
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
  plugin->fn = GNUNET_STRINGS_to_utf8 (afsdir, strlen (afsdir),
				       nl_langinfo (CODESET));
#else
  plugin->fn = GNUNET_STRINGS_to_utf8 (afsdir, strlen (afsdir),
				       "UTF-8");   /* good luck */
#endif
  GNUNET_free (afsdir);
  
  /* Open database and precompile statements */
  if (sqlite3_open (plugin->fn, &plugin->dbh) != SQLITE_OK)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
		       "sqlite",
		       _("Unable to initialize SQLite: %s.\n"),
		       sqlite3_errmsg (plugin->dbh));
      return GNUNET_SYSERR;
    }
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA temp_store=MEMORY", NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA synchronous=OFF", NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA auto_vacuum=INCREMENTAL", NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA count_changes=OFF", NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, 
		       "PRAGMA page_size=4092", NULL, NULL, ENULL));

  CHECK (SQLITE_OK == sqlite3_busy_timeout (plugin->dbh, BUSY_TIMEOUT_MS));


  /* We have to do it here, because otherwise precompiling SQL might fail */
  CHECK (SQLITE_OK ==
         sq_prepare (plugin->dbh,
                     "SELECT 1 FROM sqlite_master WHERE tbl_name = 'gn090'",
                     &stmt));
  if ( (sqlite3_step (stmt) == SQLITE_DONE) &&
       (sqlite3_exec (plugin->dbh,
		      "CREATE TABLE gn090 ("
		      "  repl INT4 NOT NULL DEFAULT 0,"
		      "  type INT4 NOT NULL DEFAULT 0,"
		      "  prio INT4 NOT NULL DEFAULT 0,"
		      "  anonLevel INT4 NOT NULL DEFAULT 0,"
		      "  expire INT8 NOT NULL DEFAULT 0,"
		      "  hash TEXT NOT NULL DEFAULT '',"
		      "  vhash TEXT NOT NULL DEFAULT '',"
		      "  value BLOB NOT NULL DEFAULT '')", NULL, NULL,
		      NULL) != SQLITE_OK) )
    {
      LOG_SQLITE (plugin, NULL,
		  GNUNET_ERROR_TYPE_ERROR, 
		  "sqlite3_exec");
      sqlite3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  sqlite3_finalize (stmt);
  create_indices (plugin->dbh);

  CHECK (SQLITE_OK ==
         sq_prepare (plugin->dbh,
                     "SELECT 1 FROM sqlite_master WHERE tbl_name = 'gn071'",
                     &stmt));
  if ( (sqlite3_step (stmt) == SQLITE_DONE) &&
       (sqlite3_exec (plugin->dbh,
		      "CREATE TABLE gn071 ("
		      "  key TEXT NOT NULL DEFAULT '',"
		      "  value INTEGER NOT NULL DEFAULT 0)", NULL, NULL,
		      NULL) != SQLITE_OK) )
    {
      LOG_SQLITE (plugin, NULL,
		  GNUNET_ERROR_TYPE_ERROR, "sqlite3_exec");
      sqlite3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  sqlite3_finalize (stmt);

  if ((sq_prepare (plugin->dbh,
                   "UPDATE gn090 SET prio = prio + ?, expire = MAX(expire,?) WHERE "
                   "_ROWID_ = ?",
                   &plugin->updPrio) != SQLITE_OK) ||
      (sq_prepare (plugin->dbh,
                   "UPDATE gn090 SET repl = MAX (0, repl - 1) WHERE "
                   "_ROWID_ = ?",
                   &plugin->updRepl) != SQLITE_OK) ||
      (sq_prepare (plugin->dbh,
		   "SELECT type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn090 WHERE (expire > ?1) "
		   " ORDER BY repl DESC, Random() LIMIT 1",
                   &plugin->selRepl) != SQLITE_OK) ||
      (sq_prepare (plugin->dbh,
		   "SELECT type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn090 WHERE (expire < ?1) "
		   " OR NOT EXISTS (SELECT 1 from gn090 WHERE (expire < ?1)) "
		   " ORDER BY prio ASC LIMIT 1",
                   &plugin->selExpi) != SQLITE_OK) ||
      (sq_prepare (plugin->dbh,
                   "INSERT INTO gn090 (repl, type, prio, "
                   "anonLevel, expire, hash, vhash, value) VALUES "
                   "(?, ?, ?, ?, ?, ?, ?, ?)",
                   &plugin->insertContent) != SQLITE_OK) ||
      (sq_prepare (plugin->dbh,
                   "DELETE FROM gn090 WHERE _ROWID_ = ?",
                   &plugin->delRow) != SQLITE_OK))
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR, "precompiling");
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
  if (plugin->selExpi != NULL)
    sqlite3_finalize (plugin->selExpi);
  if (plugin->insertContent != NULL)
    sqlite3_finalize (plugin->insertContent);
  result = sqlite3_close(plugin->dbh);
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
      LOG_SQLITE (plugin, NULL,
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
delete_by_rowid (struct Plugin* plugin, 
		 unsigned long long rid)
{
  sqlite3_bind_int64 (plugin->delRow, 1, rid);
  if (SQLITE_DONE != sqlite3_step (plugin->delRow))
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR |
                  GNUNET_ERROR_TYPE_BULK, "sqlite3_step");
      if (SQLITE_OK != sqlite3_reset (plugin->delRow))
          LOG_SQLITE (plugin, NULL,
                      GNUNET_ERROR_TYPE_ERROR |
                      GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
      return GNUNET_SYSERR;
    }
  if (SQLITE_OK != sqlite3_reset (plugin->delRow))
    LOG_SQLITE (plugin, NULL,
		GNUNET_ERROR_TYPE_ERROR |
		GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
  return GNUNET_OK;
}


/**
 * Context for the universal iterator.
 */
struct NextContext;

/**
 * Type of a function that will prepare
 * the next iteration.
 *
 * @param cls closure
 * @param nc the next context; NULL for the last
 *         call which gives the callback a chance to
 *         clean up the closure
 * @return GNUNET_OK on success, GNUNET_NO if there are
 *         no more values, GNUNET_SYSERR on error
 */
typedef int (*PrepareFunction)(void *cls,
			       struct NextContext *nc);


/**
 * Context we keep for the "next request" callback.
 */
struct NextContext
{
  /**
   * Internal state.
   */ 
  struct Plugin *plugin;

  /**
   * Function to call on the next value.
   */
  PluginIterator iter;

  /**
   * Closure for iter.
   */
  void *iter_cls;

  /**
   * Function to call to prepare the next
   * iteration.
   */
  PrepareFunction prep;

  /**
   * Closure for prep.
   */
  void *prep_cls;

  /**
   * Statement that the iterator will get the data
   * from (updated or set by prep).
   */ 
  sqlite3_stmt *stmt;

  /**
   * Row ID of the last result.
   */
  unsigned long long last_rowid;

  /**
   * Key of the last result.
   */
  GNUNET_HashCode lastKey;  

  /**
   * Priority of the last value visited.
   */ 
  unsigned int lastPriority; 

  /**
   * Number of results processed so far.
   */
  unsigned int count;

  /**
   * Set to GNUNET_YES if we must stop now.
   */
  int end_it;
};


/**
 * Continuation of "sqlite_next_request".
 *
 * @param cls the 'struct NextContext*'
 * @param tc the task context (unused)
 */
static void 
sqlite_next_request_cont (void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NextContext * nc = cls;
  struct Plugin *plugin;
  unsigned long long rowid;
  int ret;
  unsigned int size;
  unsigned int hsize;
  uint32_t anonymity;
  uint32_t priority;
  enum GNUNET_BLOCK_Type type;
  const GNUNET_HashCode *key;
  struct GNUNET_TIME_Absolute expiration;
  
  plugin = nc->plugin;
  plugin->next_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->next_task_nc = NULL;
  if ( (GNUNET_YES == nc->end_it) ||
       (GNUNET_OK != (nc->prep(nc->prep_cls,
			       nc))) )
    {
#if DEBUG_SQLITE
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "sqlite",
		       "Iteration completes after %u results\n",
		       nc->count);
#endif
    END:
      nc->iter (nc->iter_cls, 
		NULL, NULL, 0, NULL, 0, 0, 0, 
		GNUNET_TIME_UNIT_ZERO_ABS, 0);
      nc->prep (nc->prep_cls, NULL);
      GNUNET_free (nc);
      return;
    }

  type = sqlite3_column_int (nc->stmt, 0);
  priority = sqlite3_column_int (nc->stmt, 1);
  anonymity = sqlite3_column_int (nc->stmt, 2);
  expiration.abs_value = sqlite3_column_int64 (nc->stmt, 3);
  hsize = sqlite3_column_bytes (nc->stmt, 4);
  key = sqlite3_column_blob (nc->stmt, 4);
  size = sqlite3_column_bytes (nc->stmt, 5);
  rowid = sqlite3_column_int64 (nc->stmt, 6);
  if (hsize != sizeof (GNUNET_HashCode))
    {
      GNUNET_break (0);
      if (SQLITE_OK != sqlite3_reset (nc->stmt))
	LOG_SQLITE (plugin, NULL,
		    GNUNET_ERROR_TYPE_ERROR |
		    GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
      if (GNUNET_OK == delete_by_rowid (plugin, rowid))
	plugin->env->duc (plugin->env->cls,
			  - (size + GNUNET_DATASTORE_ENTRY_OVERHEAD));      
      goto END;
    }
#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "sqlite",
		   "Iterator returns value with type %u/key `%s'/priority %u/expiration %llu (%lld).\n",
		   type, 
		   GNUNET_h2s(key),
		   priority,
		   (unsigned long long) GNUNET_TIME_absolute_get_remaining (expiration).rel_value,
		   (long long) expiration.abs_value);
#endif
  if (size > MAX_ITEM_SIZE)
    {
      GNUNET_break (0);
      if (SQLITE_OK != sqlite3_reset (nc->stmt))
	LOG_SQLITE (plugin, NULL,
		    GNUNET_ERROR_TYPE_ERROR |
		    GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
      if (GNUNET_OK == delete_by_rowid (plugin, rowid))
	plugin->env->duc (plugin->env->cls,
			  - (size + GNUNET_DATASTORE_ENTRY_OVERHEAD)); 
      goto END;
    }
  {
    char data[size];
    
    memcpy (data, sqlite3_column_blob (nc->stmt, 5), size);
    nc->count++;
    nc->last_rowid = rowid;
    nc->lastPriority = priority;
    nc->lastKey = *key;
    if (SQLITE_OK != sqlite3_reset (nc->stmt))
      LOG_SQLITE (plugin, NULL,
		  GNUNET_ERROR_TYPE_ERROR |
		  GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
    ret = nc->iter (nc->iter_cls, nc,
		    &nc->lastKey,
		    size, data,
		    type, priority,
		    anonymity, expiration,
		    rowid);
  }
  switch (ret)
    {
    case GNUNET_SYSERR:
      nc->end_it = GNUNET_YES;
      break;
    case GNUNET_NO:
      if (GNUNET_OK == delete_by_rowid (plugin, rowid))
	{
#if DEBUG_SQLITE
	  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			   "sqlite",
			   "Removed entry %llu (%u bytes)\n",
			   (unsigned long long) rowid,
			   size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
#endif
	  plugin->env->duc (plugin->env->cls,
			    - (size + GNUNET_DATASTORE_ENTRY_OVERHEAD));
	}
      break;
    case GNUNET_YES:
      break;
    default:
      GNUNET_break (0);
    }
}


/**
 * Function invoked on behalf of a "PluginIterator" asking the
 * database plugin to call the iterator with the next item.
 *
 * @param next_cls whatever argument was given
 *        to the PluginIterator as "next_cls".
 * @param end_it set to GNUNET_YES if we
 *        should terminate the iteration early
 *        (iterator should be still called once more
 *         to signal the end of the iteration).
 */
static void 
sqlite_next_request (void *next_cls,
		     int end_it)
{
  struct NextContext * nc= next_cls;

  if (GNUNET_YES == end_it)
    nc->end_it = GNUNET_YES;
  nc->plugin->next_task_nc = nc;
  nc->plugin->next_task = GNUNET_SCHEDULER_add_now (&sqlite_next_request_cont,
						    nc);
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
sqlite_plugin_put (void *cls,
		   const GNUNET_HashCode *key,
		   uint32_t size,
		   const void *data,
		   enum GNUNET_BLOCK_Type type,
		   uint32_t priority,
		   uint32_t anonymity,
		   uint32_t replication,
		   struct GNUNET_TIME_Absolute expiration,
		   char ** msg)
{
  struct Plugin *plugin = cls;
  int n;
  int ret;
  sqlite3_stmt *stmt;
  GNUNET_HashCode vhash;

  if (size > MAX_ITEM_SIZE)
    return GNUNET_SYSERR;
#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "sqlite",
		   "Storing in database block with type %u/key `%s'/priority %u/expiration %llu (%lld).\n",
		   type, 
		   GNUNET_h2s(key),
		   priority,
		   (unsigned long long) GNUNET_TIME_absolute_get_remaining (expiration).rel_value,
		   (long long) expiration.abs_value);
#endif
  GNUNET_CRYPTO_hash (data, size, &vhash);
  stmt = plugin->insertContent;
  if ((SQLITE_OK != sqlite3_bind_int (stmt, 1, replication)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 2, type)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 3, priority)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 4, anonymity)) ||
      (SQLITE_OK != sqlite3_bind_int64 (stmt, 5, expiration.abs_value)) ||
      (SQLITE_OK !=
       sqlite3_bind_blob (stmt, 6, key, sizeof (GNUNET_HashCode),
                          SQLITE_TRANSIENT)) ||
      (SQLITE_OK !=
       sqlite3_bind_blob (stmt, 7, &vhash, sizeof (GNUNET_HashCode),
                          SQLITE_TRANSIENT))
      || (SQLITE_OK !=
          sqlite3_bind_blob (stmt, 8, data, size,
                             SQLITE_TRANSIENT)))
    {
      LOG_SQLITE (plugin,
		  msg,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "sqlite3_bind_XXXX");
      if (SQLITE_OK != sqlite3_reset (stmt))
        LOG_SQLITE (plugin, NULL,
                    GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
      return GNUNET_SYSERR;
    }
  n = sqlite3_step (stmt);
  switch (n)
    {
    case SQLITE_DONE:
      plugin->env->duc (plugin->env->cls,
			size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
#if DEBUG_SQLITE
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "sqlite",
		       "Stored new entry (%u bytes)\n",
		       size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
#endif
      ret = GNUNET_OK;
      break;
    case SQLITE_BUSY:      
      GNUNET_break (0);
      LOG_SQLITE (plugin, msg,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, 
		  "sqlite3_step");
      ret = GNUNET_SYSERR;
      break;
    default:
      LOG_SQLITE (plugin, msg,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, 
		  "sqlite3_step");
      if (SQLITE_OK != sqlite3_reset (stmt))
	LOG_SQLITE (plugin, NULL,
		    GNUNET_ERROR_TYPE_ERROR |
		    GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
      database_shutdown (plugin);
      database_setup (plugin->env->cfg,
		      plugin);
      return GNUNET_SYSERR;    
    }
  if (SQLITE_OK != sqlite3_reset (stmt))
    LOG_SQLITE (plugin, NULL,
		GNUNET_ERROR_TYPE_ERROR |
		GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
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
sqlite_plugin_update (void *cls,
		      uint64_t uid,
		      int delta, struct GNUNET_TIME_Absolute expire,
		      char **msg)
{
  struct Plugin *plugin = cls;
  int n;

  sqlite3_bind_int (plugin->updPrio, 1, delta);
  sqlite3_bind_int64 (plugin->updPrio, 2, expire.abs_value);
  sqlite3_bind_int64 (plugin->updPrio, 3, uid);
  n = sqlite3_step (plugin->updPrio);
  sqlite3_reset (plugin->updPrio);
  switch (n)
    {
    case SQLITE_DONE:
#if DEBUG_SQLITE
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "sqlite",
		       "Block updated\n");
#endif
      return GNUNET_OK;
    case SQLITE_BUSY:
      LOG_SQLITE (plugin, msg,
		  GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_step");
      return GNUNET_NO;
    default:
      LOG_SQLITE (plugin, msg,
		  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_step");
      return GNUNET_SYSERR;
    }
}


/**
 * Internal context for an iteration.
 */
struct ZeroIterContext
{
  /**
   * First iterator statement for zero-anonymity iteration.
   */
  sqlite3_stmt *stmt_1;

  /**
   * Second iterator statement for zero-anonymity iteration.
   */
  sqlite3_stmt *stmt_2;

  /**
   * Desired type for blocks returned by this iterator.
   */
  enum GNUNET_BLOCK_Type type;
};


/**
 * Prepare our SQL query to obtain the next record from the database.
 *
 * @param cls our "struct ZeroIterContext"
 * @param nc NULL to terminate the iteration, otherwise our context for
 *           getting the next result.
 * @return GNUNET_OK on success, GNUNET_NO if there are no more results,
 *         GNUNET_SYSERR on error (or end of iteration)
 */
static int
zero_iter_next_prepare (void *cls,
			struct NextContext *nc)
{
  struct ZeroIterContext *ic = cls;
  struct Plugin *plugin;
  int ret;

  if (nc == NULL)
    {
#if DEBUG_SQLITE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Asked to clean up iterator state.\n");
#endif
      sqlite3_finalize (ic->stmt_1);
      sqlite3_finalize (ic->stmt_2);
      return GNUNET_SYSERR;
    }
  plugin = nc->plugin;

  /* first try iter 1 */
#if DEBUG_SQLITE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Restricting to results larger than the last priority %u and key `%s'\n",
	      nc->lastPriority,
	      GNUNET_h2s (&nc->lastKey));
#endif
  if ( (SQLITE_OK != sqlite3_bind_int (ic->stmt_1, 1, nc->lastPriority)) ||
       (SQLITE_OK != sqlite3_bind_blob (ic->stmt_1, 2, 
					&nc->lastKey, 
					sizeof (GNUNET_HashCode),
					SQLITE_TRANSIENT)) )
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "sqlite3_bind_XXXX");
      if (SQLITE_OK != sqlite3_reset (ic->stmt_1))
	LOG_SQLITE (plugin, NULL,
		    GNUNET_ERROR_TYPE_ERROR | 
		    GNUNET_ERROR_TYPE_BULK, 
		    "sqlite3_reset");  
      return GNUNET_SYSERR;
    }
  if (SQLITE_ROW == (ret = sqlite3_step (ic->stmt_1)))
    {      
#if DEBUG_SQLITE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Result found using iterator 1\n");
#endif
      nc->stmt = ic->stmt_1;
      return GNUNET_OK;
    }
  if (ret != SQLITE_DONE)
    {
      LOG_SQLITE (plugin, NULL,
		  GNUNET_ERROR_TYPE_ERROR |
		  GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_step");
      if (SQLITE_OK != sqlite3_reset (ic->stmt_1))
	LOG_SQLITE (plugin, NULL,
		    GNUNET_ERROR_TYPE_ERROR | 
		    GNUNET_ERROR_TYPE_BULK, 
		    "sqlite3_reset");  
      return GNUNET_SYSERR;
    }
  if (SQLITE_OK != sqlite3_reset (ic->stmt_1))
    LOG_SQLITE (plugin, NULL,
		GNUNET_ERROR_TYPE_ERROR | 
		GNUNET_ERROR_TYPE_BULK, 
		"sqlite3_reset");  

  /* now try iter 2 */
  if (SQLITE_OK != sqlite3_bind_int (ic->stmt_2, 1, nc->lastPriority))
    {
      LOG_SQLITE (plugin, NULL,		  
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "sqlite3_bind_XXXX");
      return GNUNET_SYSERR;
    }
  if (SQLITE_ROW == (ret = sqlite3_step (ic->stmt_2))) 
    {
#if DEBUG_SQLITE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Result found using iterator 2\n");
#endif
      nc->stmt = ic->stmt_2;
      return GNUNET_OK;
    }
  if (ret != SQLITE_DONE)
    {
      LOG_SQLITE (plugin, NULL,
		  GNUNET_ERROR_TYPE_ERROR |
		  GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_step");
      if (SQLITE_OK != sqlite3_reset (ic->stmt_2))
	LOG_SQLITE (plugin, NULL,
		    GNUNET_ERROR_TYPE_ERROR |
		    GNUNET_ERROR_TYPE_BULK,
		    "sqlite3_reset");
      return GNUNET_SYSERR;
    }
  if (SQLITE_OK != sqlite3_reset (ic->stmt_2))
    LOG_SQLITE (plugin, NULL,
		GNUNET_ERROR_TYPE_ERROR |
		GNUNET_ERROR_TYPE_BULK,
		"sqlite3_reset");
#if DEBUG_SQLITE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "No result found using either iterator\n");
#endif
  return GNUNET_NO;
}


/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param cls our plugin context
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
sqlite_plugin_iter_zero_anonymity (void *cls,
				   enum GNUNET_BLOCK_Type type,
				   PluginIterator iter,
				   void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_TIME_Absolute now;
  struct NextContext *nc;
  struct ZeroIterContext *ic;
  sqlite3_stmt *stmt_1;
  sqlite3_stmt *stmt_2;
  char *q;

  now = GNUNET_TIME_absolute_get ();
  GNUNET_asprintf (&q, 
		   "SELECT type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn090 "
		   "WHERE (prio = ?1 AND expire > %llu AND anonLevel = 0 AND hash < ?2) "
		   "ORDER BY hash DESC LIMIT 1",
		   (unsigned long long) now.abs_value);
  if (sq_prepare (plugin->dbh, q, &stmt_1) != SQLITE_OK)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR |
                  GNUNET_ERROR_TYPE_BULK, "sqlite3_prepare_v2");
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      GNUNET_free (q);
      return;
    }
  GNUNET_free (q);
  GNUNET_asprintf (&q, 
		   "SELECT type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn090 "
		   "WHERE (prio < ?1 AND expire > %llu AND anonLevel = 0) "
		   "ORDER BY prio DESC, hash DESC LIMIT 1",
		   (unsigned long long) now.abs_value);
  if (sq_prepare (plugin->dbh, q, &stmt_2) != SQLITE_OK)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR |
                  GNUNET_ERROR_TYPE_BULK, "sqlite3_prepare_v2");
      sqlite3_finalize (stmt_1);
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      GNUNET_free (q);
      return;
    }
  GNUNET_free (q);
  nc = GNUNET_malloc (sizeof(struct NextContext) + 
		      sizeof(struct ZeroIterContext));
  nc->plugin = plugin;
  nc->iter = iter;
  nc->iter_cls = iter_cls;
  nc->stmt = NULL;
  ic = (struct ZeroIterContext*) &nc[1];
  ic->stmt_1 = stmt_1;
  ic->stmt_2 = stmt_2;
  ic->type = type;
  nc->prep = &zero_iter_next_prepare;
  nc->prep_cls = ic;
  nc->lastPriority = INT32_MAX;
  memset (&nc->lastKey, 255, sizeof (GNUNET_HashCode));
  sqlite_next_request (nc, GNUNET_NO);
}


/**
 * Closure for 'all_next_prepare'.
 */
struct IterateAllContext
{

  /**
   * Offset for the current result.
   */
  unsigned int off;

  /**
   * Requested block type.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Our prepared statement.
   */
  sqlite3_stmt *stmt;
};


/**
 * Call sqlite using the already prepared query to get
 * the next result.
 *
 * @param cls context with the prepared query (of type 'struct IterateAllContext')
 * @param nc generic context with the prepared query
 * @return GNUNET_OK on success, GNUNET_SYSERR on error, GNUNET_NO if
 *        there are no more results 
 */
static int
all_next_prepare (void *cls,
		  struct NextContext *nc)
{
  struct IterateAllContext *iac = cls;
  struct Plugin *plugin;
  int ret;  
  unsigned int sqoff;

  if (nc == NULL)
    {
#if DEBUG_SQLITE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Asked to clean up iterator state.\n");
#endif
      if (NULL != iac->stmt)
	{
	  sqlite3_finalize (iac->stmt);
	  iac->stmt = NULL;
	}
      return GNUNET_SYSERR;
    }
  plugin = nc->plugin;
  sqoff = 1;
  ret = SQLITE_OK;
  if (iac->type != 0)
    ret = sqlite3_bind_int (nc->stmt, sqoff++, iac->type);
  if (SQLITE_OK == ret)
    ret = sqlite3_bind_int64 (nc->stmt, sqoff++, iac->off++);
  if (ret != SQLITE_OK)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "sqlite3_bind_XXXX");
      return GNUNET_SYSERR;
    }
  ret = sqlite3_step (nc->stmt);
  switch (ret)
    {
    case SQLITE_ROW:
      return GNUNET_OK;  
    case SQLITE_DONE:
      return GNUNET_NO;
    default:
      LOG_SQLITE (plugin, NULL,
		  GNUNET_ERROR_TYPE_ERROR |
		  GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_step");
      return GNUNET_SYSERR;
    }
}


/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param cls our plugin context
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
sqlite_plugin_iter_all_now (void *cls,
			    enum GNUNET_BLOCK_Type type,
			    PluginIterator iter,
			    void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct NextContext *nc;
  struct IterateAllContext *iac;
  sqlite3_stmt *stmt;
  const char *q;

  if (type == 0)
    q = "SELECT type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn090 ORDER BY _ROWID_ ASC LIMIT 1 OFFSET ?";
  else
    q = "SELECT type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn090 WHERE type=? ORDER BY _ROWID_ ASC LIMIT 1 OFFSET ?";
  if (sq_prepare (plugin->dbh, q, &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR |
                  GNUNET_ERROR_TYPE_BULK, "sqlite3_prepare_v2");
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  nc = GNUNET_malloc (sizeof(struct NextContext) + 
		      sizeof(struct IterateAllContext));
  iac = (struct IterateAllContext*) &nc[1];
  nc->plugin = plugin;
  nc->iter = iter;
  nc->iter_cls = iter_cls;
  nc->stmt = stmt;
  nc->prep = &all_next_prepare;
  nc->prep_cls = iac;
  iac->off = 0;
  iac->type = type;
  iac->stmt = stmt; /* alias used for freeing at the end */
  sqlite_next_request (nc, GNUNET_NO);
}


/**
 * Context for get_next_prepare.
 */
struct GetNextContext
{

  /**
   * Our prepared statement.
   */
  sqlite3_stmt *stmt;

  /**
   * Plugin handle.
   */
  struct Plugin *plugin;

  /**
   * Key for the query.
   */
  GNUNET_HashCode key;

  /**
   * Vhash for the query.
   */
  GNUNET_HashCode vhash;

  /**
   * Expected total number of results.
   */
  unsigned int total;

  /**
   * Offset to add for the selected result.
   */
  unsigned int off;

  /**
   * Is vhash set?
   */
  int have_vhash;

  /**
   * Desired block type.
   */
  enum GNUNET_BLOCK_Type type;

};


/**
 * Prepare the stmt in 'nc' for the next round of execution, selecting the
 * next return value.
 *
 * @param cls our "struct GetNextContext*"
 * @param nc the general context
 * @return GNUNET_YES if there are more results, 
 *         GNUNET_NO if there are no more results,
 *         GNUNET_SYSERR on internal error
 */
static int
get_next_prepare (void *cls,
		  struct NextContext *nc)
{
  struct GetNextContext *gnc = cls;
  int ret;
  int limit_off;
  unsigned int sqoff;

  if (nc == NULL)
    {
      sqlite3_finalize (gnc->stmt);
      return GNUNET_SYSERR;
    }
  if (nc->count == gnc->total)
    return GNUNET_NO;
  if (nc->count + gnc->off == gnc->total)
    nc->last_rowid = 0;
  if (nc->count == 0)
    limit_off = gnc->off;
  else
    limit_off = 0;
  sqlite3_reset (nc->stmt);
  sqoff = 1;
  ret = sqlite3_bind_blob (nc->stmt,
			   sqoff++,
			   &gnc->key, 
			   sizeof (GNUNET_HashCode),
			   SQLITE_TRANSIENT);
  if ((gnc->have_vhash) && (ret == SQLITE_OK))
    ret = sqlite3_bind_blob (nc->stmt,
			     sqoff++,
			     &gnc->vhash,
			     sizeof (GNUNET_HashCode), SQLITE_TRANSIENT);
  if ((gnc->type != 0) && (ret == SQLITE_OK))
    ret = sqlite3_bind_int (nc->stmt, sqoff++, gnc->type);
  if (ret == SQLITE_OK)
    ret = sqlite3_bind_int64 (nc->stmt, sqoff++, limit_off);
  if (ret != SQLITE_OK)
    return GNUNET_SYSERR;
#if DEBUG_SQLITE 
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "sqlite",
                   "Preparing to GET for key `%s' with type %d at offset %u\n",
		   GNUNET_h2s (&gnc->key),
		   gnc->type,
		   limit_off);
#endif
  ret = sqlite3_step (nc->stmt);
  switch (ret)
    {
    case SQLITE_ROW:
      return GNUNET_OK;  
    case SQLITE_DONE:
      return GNUNET_NO;
    default:
      LOG_SQLITE (gnc->plugin, NULL,
		  GNUNET_ERROR_TYPE_ERROR |
		  GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_step");
      return GNUNET_SYSERR;
    }
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure
 * @param key key to match, never NULL
 * @param vhash hash of the value, maybe NULL (to
 *        match all values that have the right key).
 *        Note that for DBlocks there is no difference
 *        betwen key and vhash, but for other blocks
 *        there may be!
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
sqlite_plugin_get (void *cls,
		   const GNUNET_HashCode *key,
		   const GNUNET_HashCode *vhash,
		   enum GNUNET_BLOCK_Type type,
		   PluginIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct GetNextContext *gnc;
  struct NextContext *nc;
  int ret;
  int total;
  sqlite3_stmt *stmt;
  char scratch[256];
  unsigned int sqoff;

  GNUNET_assert (iter != NULL);
  GNUNET_assert (key != NULL);
  GNUNET_snprintf (scratch, sizeof (scratch),
                   "SELECT count(*) FROM gn090 WHERE hash=?%s%s",
                   vhash == NULL ? "" : " AND vhash=?",
                   type  == 0    ? "" : " AND type=?");
  if (sq_prepare (plugin->dbh, scratch, &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "sqlite_prepare");
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  sqoff = 1;
  ret = sqlite3_bind_blob (stmt, sqoff++,
                           key, sizeof (GNUNET_HashCode), SQLITE_TRANSIENT);
  if ((vhash != NULL) && (ret == SQLITE_OK))
    ret = sqlite3_bind_blob (stmt, sqoff++,
                             vhash,
                             sizeof (GNUNET_HashCode), SQLITE_TRANSIENT);
  if ((type != 0) && (ret == SQLITE_OK))
    ret = sqlite3_bind_int (stmt, sqoff++, type);
  if (SQLITE_OK != ret)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR, "sqlite_bind");
      sqlite3_finalize (stmt);
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  ret = sqlite3_step (stmt);
  if (ret != SQLITE_ROW)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR| GNUNET_ERROR_TYPE_BULK, 
		  "sqlite_step");
      sqlite3_finalize (stmt);
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  total = sqlite3_column_int (stmt, 0);
  sqlite3_finalize (stmt);
  if (0 == total)
    {
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  GNUNET_snprintf (scratch, sizeof (scratch),
                   "SELECT type, prio, anonLevel, expire, hash, value, _ROWID_ "
                   "FROM gn090 WHERE hash=?%s%s "
                   "ORDER BY _ROWID_ ASC LIMIT 1 OFFSET ?",
                   vhash == NULL ? "" : " AND vhash=?",
                   type == 0 ? "" : " AND type=?");

  if (sq_prepare (plugin->dbh, scratch, &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR |
                  GNUNET_ERROR_TYPE_BULK, "sqlite_prepare");
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  nc = GNUNET_malloc (sizeof(struct NextContext) + 
		      sizeof(struct GetNextContext));
  nc->plugin = plugin;
  nc->iter = iter;
  nc->iter_cls = iter_cls;
  nc->stmt = stmt;
  gnc = (struct GetNextContext*) &nc[1];
  gnc->total = total;
  gnc->type = type;
  gnc->key = *key;
  gnc->plugin = plugin;
  gnc->stmt = stmt; /* alias used for freeing at the end! */
  if (NULL != vhash)
    {
      gnc->have_vhash = GNUNET_YES;
      gnc->vhash = *vhash;
    }
  gnc->off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, total);
  nc->prep = &get_next_prepare;
  nc->prep_cls = gnc;
  sqlite_next_request (nc, GNUNET_NO);
}


/**
 * Execute statement that gets a row and call the callback
 * with the result.  Resets the statement afterwards.
 *
 * @param plugin the plugin
 * @param stmt the statement
 * @param iter iterator to call
 * @param iter_cls closure for 'iter'
 */
static void
execute_get (struct Plugin *plugin,
	     sqlite3_stmt *stmt,
	     PluginIterator iter, void *iter_cls)
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
	  GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, 
			   "sqlite",
			   _("Invalid data in database.  Trying to fix (by deletion).\n"));
	  if (SQLITE_OK != sqlite3_reset (stmt))
	    LOG_SQLITE (plugin, NULL,
			GNUNET_ERROR_TYPE_ERROR |
			GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
	  if (GNUNET_OK == delete_by_rowid (plugin, rowid))
	    plugin->env->duc (plugin->env->cls,
			      - (size + GNUNET_DATASTORE_ENTRY_OVERHEAD));	  
	  break;
	}
      expiration.abs_value = sqlite3_column_int64 (stmt, 3);
      ret = iter (iter_cls,
		  NULL,
		  sqlite3_column_blob (stmt, 4) /* key */,
		  size,
		  sqlite3_column_blob (stmt, 5) /* data */, 
		  sqlite3_column_int (stmt, 0) /* type */,
		  sqlite3_column_int (stmt, 1) /* priority */,
		  sqlite3_column_int (stmt, 2) /* anonymity */,
		  expiration,
		  rowid);
      if (SQLITE_OK != sqlite3_reset (stmt))
	LOG_SQLITE (plugin, NULL,
		    GNUNET_ERROR_TYPE_ERROR |
		    GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
      if ( (GNUNET_NO == ret) &&
	   (GNUNET_OK == delete_by_rowid (plugin, rowid)) )
	plugin->env->duc (plugin->env->cls,
			  - (size + GNUNET_DATASTORE_ENTRY_OVERHEAD));	
      return;
    case SQLITE_DONE:
      /* database must be empty */
      if (SQLITE_OK != sqlite3_reset (stmt))
	LOG_SQLITE (plugin, NULL,
		    GNUNET_ERROR_TYPE_ERROR |
		    GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
      break;
    case SQLITE_BUSY:    
    case SQLITE_ERROR:
    case SQLITE_MISUSE:
    default:
      LOG_SQLITE (plugin, NULL,
		  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, 
		  "sqlite3_step");
      if (SQLITE_OK != sqlite3_reset (stmt))
	LOG_SQLITE (plugin, NULL,
		    GNUNET_ERROR_TYPE_ERROR |
		    GNUNET_ERROR_TYPE_BULK,
		    "sqlite3_reset");
      GNUNET_break (0);
      database_shutdown (plugin);
      database_setup (plugin->env->cfg,
		      plugin);
      break;
    }
  iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, 	    
	GNUNET_TIME_UNIT_ZERO_ABS, 0);
}


/**
 * Get a random item for replication.  Returns a single, not expired, random item
 * from those with the highest replication counters.  The item's 
 * replication counter is decremented by one IF it was positive before.
 * Call 'iter' with all values ZERO or NULL if the datastore is empty.
 *
 * @param cls closure
 * @param iter function to call the value (once only).
 * @param iter_cls closure for iter
 */
static void
sqlite_plugin_replication_get (void *cls,
			       PluginIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  struct GNUNET_TIME_Absolute now;

#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "sqlite",
		   "Getting random block based on replication order.\n");
#endif
  stmt = plugin->selRepl;
  now = GNUNET_TIME_absolute_get ();
  if (SQLITE_OK != sqlite3_bind_int64 (stmt, 1, now.abs_value))
    {
      LOG_SQLITE (plugin, NULL,		  
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "sqlite3_bind_XXXX");
      if (SQLITE_OK != sqlite3_reset (stmt))
        LOG_SQLITE (plugin, NULL,
                    GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, 
	    GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  execute_get (plugin, stmt, iter, iter_cls);
}



/**
 * Get a random item that has expired or has low priority.
 * Call 'iter' with all values ZERO or NULL if the datastore is empty.
 *
 * @param cls closure
 * @param iter function to call the value (once only).
 * @param iter_cls closure for iter
 */
static void
sqlite_plugin_expiration_get (void *cls,
			      PluginIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  struct GNUNET_TIME_Absolute now;

#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "sqlite",
		   "Getting random block based on expiration and priority order.\n");
#endif
  now = GNUNET_TIME_absolute_get ();
  stmt = plugin->selExpi;
  if (SQLITE_OK != sqlite3_bind_int64 (stmt, 1, now.abs_value))
    {
      LOG_SQLITE (plugin, NULL,		  
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "sqlite3_bind_XXXX");
      if (SQLITE_OK != sqlite3_reset (stmt))
        LOG_SQLITE (plugin, NULL,
                    GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, 
	    GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  execute_get (plugin, stmt, iter, iter_cls);
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
sqlite_plugin_get_size (void *cls)
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
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
		       "datastore-sqlite",
		       _("sqlite version to old to determine size, assuming zero\n"));
      return 0;
    }
  if (SQLITE_OK !=
      sqlite3_exec (plugin->dbh,
		    "VACUUM", NULL, NULL, ENULL))
    abort ();
  CHECK (SQLITE_OK ==
	 sqlite3_exec (plugin->dbh,
		       "VACUUM", NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
	 sqlite3_exec (plugin->dbh,
		       "PRAGMA auto_vacuum=INCREMENTAL", NULL, NULL, ENULL));
  CHECK (SQLITE_OK ==
	 sq_prepare (plugin->dbh,
		     "PRAGMA page_count",
		     &stmt));
  if (SQLITE_ROW ==
      sqlite3_step (stmt))
    pages = sqlite3_column_int64 (stmt, 0);
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
  return  pages * page_size;
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
    return NULL; /* can only initialize once! */
  memset (&plugin, 0, sizeof(struct Plugin));
  plugin.env = env;
  if (GNUNET_OK !=
      database_setup (env->cfg, &plugin))
    {
      database_shutdown (&plugin);
      return NULL;
    }
  api = GNUNET_malloc (sizeof (struct GNUNET_DATASTORE_PluginFunctions));
  api->cls = &plugin;
  api->get_size = &sqlite_plugin_get_size;
  api->put = &sqlite_plugin_put;
  api->next_request = &sqlite_next_request;
  api->get = &sqlite_plugin_get;
  api->replication_get = &sqlite_plugin_replication_get;
  api->expiration_get = &sqlite_plugin_expiration_get;
  api->update = &sqlite_plugin_update;
  api->iter_zero_anonymity = &sqlite_plugin_iter_zero_anonymity;
  api->iter_all_now = &sqlite_plugin_iter_all_now;
  api->drop = &sqlite_plugin_drop;
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                   "sqlite", _("Sqlite database running\n"));
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
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "sqlite",
		   "sqlite plugin is doneing\n");
#endif

  if (plugin->next_task != GNUNET_SCHEDULER_NO_TASK)
    {
#if DEBUG_SQLITE
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "sqlite",
		       "Canceling next task\n");
#endif
      GNUNET_SCHEDULER_cancel (plugin->next_task);
      plugin->next_task = GNUNET_SCHEDULER_NO_TASK;
#if DEBUG_SQLITE
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "sqlite",
		       "Prep'ing next task\n");
#endif
      plugin->next_task_nc->prep (plugin->next_task_nc->prep_cls, NULL);
      GNUNET_free (plugin->next_task_nc);
      plugin->next_task_nc = NULL;
    }
  fn = NULL;
  if (plugin->drop_on_shutdown)
    fn = GNUNET_strdup (plugin->fn);
#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "sqlite",
		   "Shutting down database\n");
#endif
  database_shutdown (plugin);
  plugin->env = NULL; 
  GNUNET_free (api);
  if (fn != NULL)
    {
      if (0 != UNLINK(fn))
	GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
				  "unlink",
				  fn);
      GNUNET_free (fn);
    }
#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "sqlite",
		   "sqlite plugin is finished doneing\n");
#endif
  return NULL;
}

/* end of plugin_datastore_sqlite.c */
