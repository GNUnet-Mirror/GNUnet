 /*
     This file is part of GNUnet
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
#include "gnunet_statistics_service.h"
#include "plugin_datastore.h"
#include <sqlite3.h>

#define DEBUG_SQLITE GNUNET_YES

/**
 * After how many payload-changing operations
 * do we sync our statistics?
 */
#define MAX_STAT_SYNC_LAG 50

#define QUOTA_STAT_NAME gettext_noop ("# bytes used in file-sharing datastore")

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(db, msg, level, cmd) do { GNUNET_log_from (level, "sqlite", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); if (msg != NULL) GNUNET_asprintf(msg, _("`%s' failed at %s:%u with error: %s"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); } while(0)

#define SELECT_IT_LOW_PRIORITY_1 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (prio = ? AND hash > ?) "\
  "ORDER BY hash ASC LIMIT 1"

#define SELECT_IT_LOW_PRIORITY_2 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (prio > ?) "\
  "ORDER BY prio ASC, hash ASC LIMIT 1"

#define SELECT_IT_NON_ANONYMOUS_1 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (prio = ? AND hash < ? AND anonLevel = 0 AND expire > %llu) "\
  " ORDER BY hash DESC LIMIT 1"

#define SELECT_IT_NON_ANONYMOUS_2 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (prio < ? AND anonLevel = 0 AND expire > %llu)"\
  " ORDER BY prio DESC, hash DESC LIMIT 1"

#define SELECT_IT_EXPIRATION_TIME_1 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (expire = ? AND hash > ?) "\
  " ORDER BY hash ASC LIMIT 1"

#define SELECT_IT_EXPIRATION_TIME_2 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (expire > ?) "\
  " ORDER BY expire ASC, hash ASC LIMIT 1"

#define SELECT_IT_MIGRATION_ORDER_1 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (expire = ? AND hash < ?) "\
  " ORDER BY hash DESC LIMIT 1"

#define SELECT_IT_MIGRATION_ORDER_2 \
  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080 WHERE (expire < ? AND expire > %llu) "\
  " ORDER BY expire DESC, hash DESC LIMIT 1"

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
   * Precompiled SQL for update.
   */
  sqlite3_stmt *updPrio;

  /**
   * Precompiled SQL for insertion.
   */
  sqlite3_stmt *insertContent;

  /**
   * Handle to the statistics service.
   */
  struct GNUNET_STATISTICS_Handle *statistics;

  /**
   * Handle for pending get request.
   */
  struct GNUNET_STATISTICS_GetHandle *stat_get;

  /**
   * Closure of the 'next_task' (must be freed if 'next_task' is cancelled).
   */
  struct NextContext *next_task_nc;

  /**
   * Pending task with scheduler for running the next request.
   */
  GNUNET_SCHEDULER_TaskIdentifier next_task;
  
  /**
   * How much data are we currently storing
   * in the database?
   */
  unsigned long long payload;

  /**
   * Number of updates that were made to the
   * payload value since we last synchronized
   * it with the statistics service.
   */
  unsigned int lastSync;

  /**
   * Should the database be dropped on shutdown?
   */
  int drop_on_shutdown;

  /**
   * Did we get an answer from statistics?
   */
  int stats_worked;
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
sq_prepare (sqlite3 * dbh, const char *zSql,
            sqlite3_stmt ** ppStmt)
{
  char *dummy;
  return sqlite3_prepare (dbh,
                          zSql,
                          strlen (zSql), ppStmt, (const char **) &dummy);
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
                "CREATE INDEX idx_hash ON gn080 (hash)", NULL, NULL, NULL);
  sqlite3_exec (dbh,
                "CREATE INDEX idx_hash_vhash ON gn080 (hash,vhash)", NULL,
                NULL, NULL);
  sqlite3_exec (dbh, "CREATE INDEX idx_prio ON gn080 (prio)", NULL, NULL,
                NULL);
  sqlite3_exec (dbh, "CREATE INDEX idx_expire ON gn080 (expire)", NULL, NULL,
                NULL);
  sqlite3_exec (dbh, "CREATE INDEX idx_comb3 ON gn080 (prio,anonLevel)", NULL,
                NULL, NULL);
  sqlite3_exec (dbh, "CREATE INDEX idx_comb4 ON gn080 (prio,hash,anonLevel)",
                NULL, NULL, NULL);
  sqlite3_exec (dbh, "CREATE INDEX idx_comb7 ON gn080 (expire,hash)", NULL,
                NULL, NULL);
}



#if 1
#define CHECK(a) GNUNET_break(a)
#define ENULL NULL
#else
#define ENULL &e
#define ENULL_DEFINED 1
#define CHECK(a) if (! a) { GNUNET_log(GNUNET_ERROR_TYPE_ERRROR, "%s\n", e); sqlite3_free(e); }
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
      if (plugin->stat_get != NULL)
	{
	  GNUNET_STATISTICS_get_cancel (plugin->stat_get);
	  plugin->stat_get = NULL;
	}
      plugin->payload = 0;
    }
  plugin->fn = GNUNET_STRINGS_to_utf8 (afsdir, strlen (afsdir),
#ifdef ENABLE_NLS
					      nl_langinfo (CODESET)
#else
					      "UTF-8"   /* good luck */
#endif
					      );
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
                     "SELECT 1 FROM sqlite_master WHERE tbl_name = 'gn080'",
                     &stmt));
  if ( (sqlite3_step (stmt) == SQLITE_DONE) &&
       (sqlite3_exec (plugin->dbh,
		      "CREATE TABLE gn080 ("
		      "  size INT4 NOT NULL DEFAULT 0,"
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
                   "UPDATE gn080 SET prio = prio + ?, expire = MAX(expire,?) WHERE "
                   "_ROWID_ = ?",
                   &plugin->updPrio) != SQLITE_OK) ||
      (sq_prepare (plugin->dbh,
                   "INSERT INTO gn080 (size, type, prio, "
                   "anonLevel, expire, hash, vhash, value) VALUES "
                   "(?, ?, ?, ?, ?, ?, ?, ?)",
                   &plugin->insertContent) != SQLITE_OK))
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR, "precompiling");
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}


/**
 * Synchronize our utilization statistics with the 
 * statistics service.
 * @param plugin the plugin context (state for this module)
 */
static void 
sync_stats (struct Plugin *plugin)
{
  GNUNET_STATISTICS_set (plugin->statistics,
			 QUOTA_STAT_NAME,
			 plugin->payload,
			 GNUNET_YES);
  plugin->lastSync = 0;
}


/**
 * Shutdown database connection and associate data
 * structures.
 * @param plugin the plugin context (state for this module)
 */
static void
database_shutdown (struct Plugin *plugin)
{
  if (plugin->lastSync > 0)
    sync_stats (plugin);
  if (plugin->updPrio != NULL)
    sqlite3_finalize (plugin->updPrio);
  if (plugin->insertContent != NULL)
    sqlite3_finalize (plugin->insertContent);
  sqlite3_close (plugin->dbh);
  GNUNET_free_non_null (plugin->fn);
}


/**
 * Get an estimate of how much space the database is
 * currently using.
 *
 * @param cls our plugin context
 * @return number of bytes used on disk
 */
static unsigned long long sqlite_plugin_get_size (void *cls)
{
  struct Plugin *plugin = cls;
  return plugin->payload;
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
  sqlite3_stmt *stmt;

  if (sq_prepare (plugin->dbh,
                  "DELETE FROM gn080 WHERE _ROWID_ = ?", &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR |
                  GNUNET_ERROR_TYPE_BULK, "sq_prepare");
      return GNUNET_SYSERR;
    }
  sqlite3_bind_int64 (stmt, 1, rid);
  if (SQLITE_DONE != sqlite3_step (stmt))
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR |
                  GNUNET_ERROR_TYPE_BULK, "sqlite3_step");
      sqlite3_finalize (stmt);
      return GNUNET_SYSERR;
    }
  sqlite3_finalize (stmt);
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
   * Expiration time of the last value visited.
   */
  struct GNUNET_TIME_Absolute lastExpiration;

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
 * @param cls the next context
 * @param tc the task context (unused)
 */
static void 
sqlite_next_request_cont (void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NextContext * nc = cls;
  struct Plugin *plugin;
  unsigned long long rowid;
  sqlite3_stmt *stmtd;
  int ret;
  unsigned int type;
  unsigned int size;
  unsigned int priority;
  unsigned int anonymity;
  struct GNUNET_TIME_Absolute expiration;
  const GNUNET_HashCode *key;
  const void *data;
  
  plugin = nc->plugin;
  plugin->next_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->next_task_nc = NULL;
  if ( (GNUNET_YES == nc->end_it) ||
       (GNUNET_OK != (nc->prep(nc->prep_cls,
			       nc))) )
    {
    END:
      nc->iter (nc->iter_cls, 
		NULL, NULL, 0, NULL, 0, 0, 0, 
		GNUNET_TIME_UNIT_ZERO_ABS, 0);
      nc->prep (nc->prep_cls, NULL);
      GNUNET_free (nc);
      return;
    }

  rowid = sqlite3_column_int64 (nc->stmt, 7);
  nc->last_rowid = rowid;
  type = sqlite3_column_int (nc->stmt, 1);
  size = sqlite3_column_bytes (nc->stmt, 6);
  if (sqlite3_column_bytes (nc->stmt, 5) != sizeof (GNUNET_HashCode))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, 
		       "sqlite",
		       _("Invalid data in database.  Trying to fix (by deletion).\n"));
      if (SQLITE_OK != sqlite3_reset (nc->stmt))
        LOG_SQLITE (nc->plugin, NULL,
                    GNUNET_ERROR_TYPE_ERROR |
                    GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
      if (sq_prepare
          (nc->plugin->dbh,
           "DELETE FROM gn080 WHERE NOT LENGTH(hash) = ?",
           &stmtd) != SQLITE_OK)
        {
          LOG_SQLITE (nc->plugin, NULL,
                      GNUNET_ERROR_TYPE_ERROR |
                      GNUNET_ERROR_TYPE_BULK, 
		      "sq_prepare");
          goto END;
        }

      if (SQLITE_OK != sqlite3_bind_int (stmtd, 1, sizeof (GNUNET_HashCode)))
        LOG_SQLITE (nc->plugin, NULL,
                    GNUNET_ERROR_TYPE_ERROR |
                    GNUNET_ERROR_TYPE_BULK, "sqlite3_bind_int");
      if (SQLITE_DONE != sqlite3_step (stmtd))
        LOG_SQLITE (nc->plugin, NULL,
                    GNUNET_ERROR_TYPE_ERROR |
                    GNUNET_ERROR_TYPE_BULK, "sqlite3_step");
      if (SQLITE_OK != sqlite3_finalize (stmtd))
        LOG_SQLITE (nc->plugin, NULL,
                    GNUNET_ERROR_TYPE_ERROR |
                    GNUNET_ERROR_TYPE_BULK, "sqlite3_finalize");
      goto END;
    }

  priority = sqlite3_column_int (nc->stmt, 2);
  anonymity = sqlite3_column_int (nc->stmt, 3);
  expiration.value = sqlite3_column_int64 (nc->stmt, 4);
  key = sqlite3_column_blob (nc->stmt, 5);
  nc->lastPriority = priority;
  nc->lastExpiration = expiration;
  memcpy (&nc->lastKey, key, sizeof(GNUNET_HashCode));
  data = sqlite3_column_blob (nc->stmt, 6);
  nc->count++;
  ret = nc->iter (nc->iter_cls,
		  nc,
		  key,
		  size,
		  data, 
		  type,
		  priority,
		  anonymity,
		  expiration,
		  rowid);
  if (ret == GNUNET_SYSERR)
    {
      nc->end_it = GNUNET_YES;
      return;
    }
#if DEBUG_SQLITE
  if (ret == GNUNET_NO)
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		     "sqlite",
		     "Asked to remove entry %llu (%u bytes)\n",
		     (unsigned long long) rowid,
		     size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
#endif
  if ( (ret == GNUNET_NO) &&
       (GNUNET_OK == delete_by_rowid (plugin, rowid)) )
    {
      if (plugin->payload >= size + GNUNET_DATASTORE_ENTRY_OVERHEAD)
	plugin->payload -= (size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
      else
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Datastore payload inaccurate, please fix and restart!\n"));
      plugin->lastSync++; 
#if DEBUG_SQLITE
      if (ret == GNUNET_NO)
	GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			 "sqlite",
			 "Removed entry %llu (%u bytes), new payload is %llu\n",
			 (unsigned long long) rowid,
			 size + GNUNET_DATASTORE_ENTRY_OVERHEAD,
			 plugin->payload);
#endif
      if (plugin->lastSync >= MAX_STAT_SYNC_LAG)
	sync_stats (plugin);
    }
}


/**
 * Function invoked on behalf of a "PluginIterator"
 * asking the database plugin to call the iterator
 * with the next item.
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
  nc->plugin->next_task = GNUNET_SCHEDULER_add_now (nc->plugin->env->sched,
						    &sqlite_next_request_cont,
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
 * @param expiration expiration time for the content
 * @param msg set to an error message
 * @return GNUNET_OK on success
 */
static int
sqlite_plugin_put (void *cls,
		   const GNUNET_HashCode * key,
		   uint32_t size,
		   const void *data,
		   enum GNUNET_BLOCK_Type type,
		   uint32_t priority,
		   uint32_t anonymity,
		   struct GNUNET_TIME_Absolute expiration,
		   char ** msg)
{
  struct Plugin *plugin = cls;
  int n;
  sqlite3_stmt *stmt;
  GNUNET_HashCode vhash;

#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "sqlite",
		   "Storing in database block with type %u/key `%s'/priority %u/expiration %llu (%lld).\n",
		   type, 
		   GNUNET_h2s(key),
		   priority,
		   (unsigned long long) GNUNET_TIME_absolute_get_remaining (expiration).value,
		   (long long) expiration.value);
#endif
  GNUNET_CRYPTO_hash (data, size, &vhash);
  stmt = plugin->insertContent;
  if ((SQLITE_OK != sqlite3_bind_int (stmt, 1, size)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 2, type)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 3, priority)) ||
      (SQLITE_OK != sqlite3_bind_int (stmt, 4, anonymity)) ||
      (SQLITE_OK != sqlite3_bind_int64 (stmt, 5, (sqlite3_int64) expiration.value)) ||
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
  if (n != SQLITE_DONE)
    {
      if (n == SQLITE_BUSY)
        {
	  LOG_SQLITE (plugin, msg,
		      GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "sqlite3_step");
          sqlite3_reset (stmt);
          GNUNET_break (0);
          return GNUNET_NO;
        }
      LOG_SQLITE (plugin, msg,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "sqlite3_step");
      sqlite3_reset (stmt);
      database_shutdown (plugin);
      database_setup (plugin->env->cfg,
		      plugin);
      return GNUNET_SYSERR;
    }
  if (SQLITE_OK != sqlite3_reset (stmt))
    LOG_SQLITE (plugin, NULL,
                GNUNET_ERROR_TYPE_ERROR |
                GNUNET_ERROR_TYPE_BULK, "sqlite3_reset");
  plugin->lastSync++;
  plugin->payload += size + GNUNET_DATASTORE_ENTRY_OVERHEAD;
#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "sqlite",
		   "Stored new entry (%u bytes), new payload is %llu\n",
		   size + GNUNET_DATASTORE_ENTRY_OVERHEAD,
		   plugin->payload);
#endif
  if (plugin->lastSync >= MAX_STAT_SYNC_LAG)
    sync_stats (plugin);
  return GNUNET_OK;
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
  sqlite3_bind_int64 (plugin->updPrio, 2, expire.value);
  sqlite3_bind_int64 (plugin->updPrio, 3, uid);
  n = sqlite3_step (plugin->updPrio);
  if (n != SQLITE_DONE)
    LOG_SQLITE (plugin, msg,
		GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_step");
#if DEBUG_SQLITE
  else
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		     "sqlite",
		     "Block updated\n");
#endif
  sqlite3_reset (plugin->updPrio);

  if (n == SQLITE_BUSY)
    return GNUNET_NO;
  return n == SQLITE_DONE ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Internal context for an iteration.
 */
struct IterContext
{
  /**
   * FIXME.
   */
  sqlite3_stmt *stmt_1;

  /**
   * FIXME.
   */
  sqlite3_stmt *stmt_2;

  /**
   * FIXME.
   */
  int is_asc;

  /**
   * FIXME.
   */
  int is_prio;

  /**
   * FIXME.
   */
  int is_migr;

  /**
   * FIXME.
   */
  int limit_nonanonymous;

  /**
   * Desired type for blocks returned by this iterator.
   */
  enum GNUNET_BLOCK_Type type;
};


/**
 * Prepare our SQL query to obtain the next record from the database.
 *
 * @param cls our "struct IterContext"
 * @param nc NULL to terminate the iteration, otherwise our context for
 *           getting the next result.
 * @return GNUNET_OK on success, GNUNET_NO if there are no more results,
 *         GNUNET_SYSERR on error (or end of iteration)
 */
static int
iter_next_prepare (void *cls,
		   struct NextContext *nc)
{
  struct IterContext *ic = cls;
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
  sqlite3_reset (ic->stmt_1);
  sqlite3_reset (ic->stmt_2);
  plugin = nc->plugin;
  if (ic->is_prio)
    {
#if DEBUG_SQLITE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Restricting to results larger than the last priority %u\n",
		  nc->lastPriority);
#endif
      sqlite3_bind_int (ic->stmt_1, 1, nc->lastPriority);
      sqlite3_bind_int (ic->stmt_2, 1, nc->lastPriority);
    }
  else
    {
#if DEBUG_SQLITE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Restricting to results larger than the last expiration %llu\n",
		  (unsigned long long) nc->lastExpiration.value);
#endif
      sqlite3_bind_int64 (ic->stmt_1, 1, nc->lastExpiration.value);
      sqlite3_bind_int64 (ic->stmt_2, 1, nc->lastExpiration.value);
    }
#if DEBUG_SQLITE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Restricting to results larger than the last key `%s'\n",
	      GNUNET_h2s(&nc->lastKey));
#endif
  sqlite3_bind_blob (ic->stmt_1, 2, 
		     &nc->lastKey, 
		     sizeof (GNUNET_HashCode),
		     SQLITE_TRANSIENT);
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
      return GNUNET_SYSERR;
    }
  if (SQLITE_OK != sqlite3_reset (ic->stmt_1))
    LOG_SQLITE (plugin, NULL,
		GNUNET_ERROR_TYPE_ERROR | 
		GNUNET_ERROR_TYPE_BULK, 
		"sqlite3_reset");
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
 * Call a method for each key in the database and
 * call the callback method on it.
 *
 * @param plugin our plugin context
 * @param type entries of which type should be considered?
 * @param is_asc are we iterating in ascending order?
 * @param is_prio are we iterating by priority (otherwise by expiration)
 * @param is_migr are we iterating in migration order?
 * @param limit_nonanonymous are we restricting results to those with anonymity
 *              level zero?
 * @param stmt_str_1 first SQL statement to execute
 * @param stmt_str_2 SQL statement to execute to get "more" results (inner iteration)
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
basic_iter (struct Plugin *plugin,
	    enum GNUNET_BLOCK_Type type,
	    int is_asc,
	    int is_prio,
	    int is_migr,
	    int limit_nonanonymous,
	    const char *stmt_str_1,
	    const char *stmt_str_2,
	    PluginIterator iter,
	    void *iter_cls)
{
  struct NextContext *nc;
  struct IterContext *ic;
  sqlite3_stmt *stmt_1;
  sqlite3_stmt *stmt_2;

#if DEBUG_SQLITE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "At %llu, using queries `%s' and `%s'\n",
	      (unsigned long long) GNUNET_TIME_absolute_get ().value,
	      stmt_str_1,
	      stmt_str_2);
#endif
  if (sq_prepare (plugin->dbh, stmt_str_1, &stmt_1) != SQLITE_OK)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR |
                  GNUNET_ERROR_TYPE_BULK, "sqlite3_prepare");
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  if (sq_prepare (plugin->dbh, stmt_str_2, &stmt_2) != SQLITE_OK)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR |
                  GNUNET_ERROR_TYPE_BULK, "sqlite3_prepare");
      sqlite3_finalize (stmt_1);
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  nc = GNUNET_malloc (sizeof(struct NextContext) + 
		      sizeof(struct IterContext));
  nc->plugin = plugin;
  nc->iter = iter;
  nc->iter_cls = iter_cls;
  nc->stmt = NULL;
  ic = (struct IterContext*) &nc[1];
  ic->stmt_1 = stmt_1;
  ic->stmt_2 = stmt_2;
  ic->type = type;
  ic->is_asc = is_asc;
  ic->is_prio = is_prio;
  ic->is_migr = is_migr;
  ic->limit_nonanonymous = limit_nonanonymous;
  nc->prep = &iter_next_prepare;
  nc->prep_cls = ic;
  if (is_asc)
    {
      nc->lastPriority = 0;
      nc->lastExpiration.value = 0;
      memset (&nc->lastKey, 0, sizeof (GNUNET_HashCode));
    }
  else
    {
      nc->lastPriority = 0x7FFFFFFF;
      nc->lastExpiration.value = 0x7FFFFFFFFFFFFFFFLL;
      memset (&nc->lastKey, 255, sizeof (GNUNET_HashCode));
    }
  sqlite_next_request (nc, GNUNET_NO);
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
sqlite_plugin_iter_low_priority (void *cls,
				 enum GNUNET_BLOCK_Type type,
				 PluginIterator iter,
				 void *iter_cls)
{
  basic_iter (cls,
	      type, 
	      GNUNET_YES, GNUNET_YES, 
	      GNUNET_NO, GNUNET_NO,
	      SELECT_IT_LOW_PRIORITY_1,
	      SELECT_IT_LOW_PRIORITY_2, 
	      iter, iter_cls);
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
  struct GNUNET_TIME_Absolute now;
  char *q1;
  char *q2;

  now = GNUNET_TIME_absolute_get ();
  GNUNET_asprintf (&q1, SELECT_IT_NON_ANONYMOUS_1,
		   (unsigned long long) now.value);
  GNUNET_asprintf (&q2, SELECT_IT_NON_ANONYMOUS_2,
		   (unsigned long long) now.value);
  basic_iter (cls,
	      type, 
	      GNUNET_NO, GNUNET_YES, 
	      GNUNET_NO, GNUNET_YES,
	      q1,
	      q2,
	      iter, iter_cls);
  GNUNET_free (q1);
  GNUNET_free (q2);
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
sqlite_plugin_iter_ascending_expiration (void *cls,
					 enum GNUNET_BLOCK_Type type,
					 PluginIterator iter,
					 void *iter_cls)
{
  struct GNUNET_TIME_Absolute now;
  char *q1;
  char *q2;

  now = GNUNET_TIME_absolute_get ();
  GNUNET_asprintf (&q1, SELECT_IT_EXPIRATION_TIME_1,
		   (unsigned long long) 0*now.value);
  GNUNET_asprintf (&q2, SELECT_IT_EXPIRATION_TIME_2,
		   (unsigned long long) 0*now.value);
  basic_iter (cls,
	      type, 
	      GNUNET_YES, GNUNET_NO, 
	      GNUNET_NO, GNUNET_NO,
	      q1, q2,
	      iter, iter_cls);
  GNUNET_free (q1);
  GNUNET_free (q2);
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
sqlite_plugin_iter_migration_order (void *cls,
				    enum GNUNET_BLOCK_Type type,
				    PluginIterator iter,
				    void *iter_cls)
{
  struct GNUNET_TIME_Absolute now;
  char *q;

  now = GNUNET_TIME_absolute_get ();
  GNUNET_asprintf (&q, SELECT_IT_MIGRATION_ORDER_2,
		   (unsigned long long) now.value);
  basic_iter (cls,
	      type, 
	      GNUNET_NO, GNUNET_NO, 
	      GNUNET_YES, GNUNET_NO,
	      SELECT_IT_MIGRATION_ORDER_1,
	      q,
	      iter, iter_cls);
  GNUNET_free (q);
}


/**
 * Call sqlite using the already prepared query to get
 * the next result.
 *
 * @param cls not used
 * @param nc context with the prepared query
 * @return GNUNET_OK on success, GNUNET_SYSERR on error, GNUNET_NO if
 *        there are no more results 
 */
static int
all_next_prepare (void *cls,
		  struct NextContext *nc)
{
  struct Plugin *plugin;
  int ret;

  if (nc == NULL)
    {
#if DEBUG_SQLITE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Asked to clean up iterator state.\n");
#endif
      return GNUNET_SYSERR;
    }
  plugin = nc->plugin;
  if (SQLITE_ROW == (ret = sqlite3_step (nc->stmt)))
    {      
      return GNUNET_OK;
    }
  if (ret != SQLITE_DONE)
    {
      LOG_SQLITE (plugin, NULL,
		  GNUNET_ERROR_TYPE_ERROR |
		  GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_step");
      return GNUNET_SYSERR;
    }
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
sqlite_plugin_iter_all_now (void *cls,
			    enum GNUNET_BLOCK_Type type,
			    PluginIterator iter,
			    void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct NextContext *nc;
  sqlite3_stmt *stmt;

  if (sq_prepare (plugin->dbh, 
		  "SELECT size,type,prio,anonLevel,expire,hash,value,_ROWID_ FROM gn080",
		  &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR |
                  GNUNET_ERROR_TYPE_BULK, "sqlite3_prepare");
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  nc = GNUNET_malloc (sizeof(struct NextContext));
  nc->plugin = plugin;
  nc->iter = iter;
  nc->iter_cls = iter_cls;
  nc->stmt = stmt;
  nc->prep = &all_next_prepare;
  nc->prep_cls = NULL;
  sqlite_next_request (nc, GNUNET_NO);
}


/**
 * FIXME.
 */
struct GetNextContext
{

  /**
   * FIXME.
   */
  int total;

  /**
   * FIXME.
   */
  int off;

  /**
   * FIXME.
   */
  int have_vhash;

  /**
   * FIXME.
   */
  unsigned int type;

  /**
   * FIXME.
   */
  sqlite3_stmt *stmt;

  /**
   * FIXME.
   */
  GNUNET_HashCode key;

  /**
   * FIXME.
   */
  GNUNET_HashCode vhash;
};



/**
 * FIXME.
 *
 * @param cls our "struct GetNextContext*"
 * @param nc FIXME
 * @return GNUNET_YES if there are more results, 
 *         GNUNET_NO if there are no more results,
 *         GNUNET_SYSERR on internal error
 */
static int
get_next_prepare (void *cls,
		  struct NextContext *nc)
{
  struct GetNextContext *gnc = cls;
  int sqoff;
  int ret;
  int limit_off;

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
  sqoff = 1;
  sqlite3_reset (nc->stmt);
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
    ret = sqlite3_bind_int64 (nc->stmt, sqoff++, nc->last_rowid + 1);
  if (ret == SQLITE_OK)
    ret = sqlite3_bind_int (nc->stmt, sqoff++, limit_off);
  if (ret != SQLITE_OK)
    return GNUNET_SYSERR;
  if (SQLITE_ROW != sqlite3_step (nc->stmt))
    return GNUNET_NO;
  return GNUNET_OK;
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure
 * @param key maybe NULL (to match all entries)
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
		   const GNUNET_HashCode * key,
		   const GNUNET_HashCode * vhash,
		   enum GNUNET_BLOCK_Type type,
		   PluginIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct GetNextContext *gpc;
  struct NextContext *nc;
  int ret;
  int total;
  sqlite3_stmt *stmt;
  char scratch[256];
  int sqoff;

  GNUNET_assert (iter != NULL);
  if (key == NULL)
    {
      sqlite_plugin_iter_low_priority (cls, type, iter, iter_cls);
      return;
    }
  GNUNET_snprintf (scratch, sizeof (scratch),
                   "SELECT count(*) FROM gn080 WHERE hash=:1%s%s",
                   vhash == NULL ? "" : " AND vhash=:2",
                   type == 0 ? "" : (vhash ==
                                     NULL) ? " AND type=:2" : " AND type=:3");
  if (sq_prepare (plugin->dbh, scratch, &stmt) != SQLITE_OK)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK, "sqlite_prepare");
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  sqoff = 1;
  ret = sqlite3_bind_blob (stmt,
                           sqoff++,
                           key, sizeof (GNUNET_HashCode), SQLITE_TRANSIENT);
  if ((vhash != NULL) && (ret == SQLITE_OK))
    ret = sqlite3_bind_blob (stmt,
                             sqoff++,
                             vhash,
                             sizeof (GNUNET_HashCode), SQLITE_TRANSIENT);
  if ((type != 0) && (ret == SQLITE_OK))
    ret = sqlite3_bind_int (stmt, sqoff++, type);
  if (SQLITE_OK != ret)
    {
      LOG_SQLITE (plugin, NULL,
                  GNUNET_ERROR_TYPE_ERROR, "sqlite_bind");
      sqlite3_reset (stmt);
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
      sqlite3_reset (stmt);
      sqlite3_finalize (stmt);
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  total = sqlite3_column_int (stmt, 0);
  sqlite3_reset (stmt);
  sqlite3_finalize (stmt);
  if (0 == total)
    {
      iter (iter_cls, NULL, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }

  GNUNET_snprintf (scratch, sizeof (scratch),
                   "SELECT size, type, prio, anonLevel, expire, hash, value, _ROWID_ "
                   "FROM gn080 WHERE hash=:1%s%s AND _ROWID_ >= :%d "
                   "ORDER BY _ROWID_ ASC LIMIT 1 OFFSET :d",
                   vhash == NULL ? "" : " AND vhash=:2",
                   type == 0 ? "" : (vhash ==
                                     NULL) ? " AND type=:2" : " AND type=:3",
                   sqoff, sqoff + 1);
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
  gpc = (struct GetNextContext*) &nc[1];
  gpc->total = total;
  gpc->type = type;
  gpc->key = *key;
  gpc->stmt = stmt; /* alias used for freeing at the end! */
  if (NULL != vhash)
    {
      gpc->have_vhash = GNUNET_YES;
      gpc->vhash = *vhash;
    }
  gpc->off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, total);
  nc->prep = &get_next_prepare;
  nc->prep_cls = gpc;
  sqlite_next_request (nc, GNUNET_NO);
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
 * Callback function to process statistic values.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
process_stat_in (void *cls,
		 const char *subsystem,
		 const char *name,
		 uint64_t value,
		 int is_persistent)
{
  struct Plugin *plugin = cls;

  plugin->stats_worked = GNUNET_YES;
  plugin->payload += value;
#if DEBUG_SQLITE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "sqlite",
		   "Notification from statistics about existing payload (%llu), new payload is %llu\n",
		   value,
		   plugin->payload);
#endif
  return GNUNET_OK;
}


static void
process_stat_done (void *cls,
		   int success)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  uint64_t pages;
  uint64_t page_size;

  plugin->stat_get = NULL;
  if (plugin->stats_worked == GNUNET_NO)
    {
      CHECK (SQLITE_OK ==
	     sq_prepare (plugin->dbh,
			 "VACUUM;",
			 &stmt));
      sqlite3_step (stmt);
      sqlite3_finalize (stmt);
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
      plugin->payload = pages * page_size;
    }
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
  plugin.statistics = GNUNET_STATISTICS_create (env->sched,
						"ds-sqlite",
						env->cfg);
  plugin.stat_get = GNUNET_STATISTICS_get (plugin.statistics,
					   "ds-sqlite",
					   QUOTA_STAT_NAME,
					   GNUNET_TIME_UNIT_SECONDS,
					   &process_stat_done,
					   &process_stat_in,
					   &plugin);
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
  api->update = &sqlite_plugin_update;
  api->iter_low_priority = &sqlite_plugin_iter_low_priority;
  api->iter_zero_anonymity = &sqlite_plugin_iter_zero_anonymity;
  api->iter_ascending_expiration = &sqlite_plugin_iter_ascending_expiration;
  api->iter_migration_order = &sqlite_plugin_iter_migration_order;
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

  if (plugin->stat_get != NULL)
    {
      GNUNET_STATISTICS_get_cancel (plugin->stat_get);
      plugin->stat_get = NULL;
    }
  if (plugin->next_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->env->sched,
			       plugin->next_task);
      plugin->next_task = GNUNET_SCHEDULER_NO_TASK;
      plugin->next_task_nc->prep (plugin->next_task_nc->prep_cls, NULL);
      GNUNET_free (plugin->next_task_nc);
      plugin->next_task_nc = NULL;
    }
  fn = NULL;
  if (plugin->drop_on_shutdown)
    fn = GNUNET_strdup (plugin->fn);
  database_shutdown (plugin);
  GNUNET_STATISTICS_destroy (plugin->statistics,
			     GNUNET_NO);
  plugin->env = NULL; 
  plugin->payload = 0;
  GNUNET_free (api);
  if (fn != NULL)
    {
      if (0 != UNLINK(fn))
	GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
				  "unlink",
				  fn);
      GNUNET_free (fn);
    }
  return NULL;
}

/* end of plugin_datastore_sqlite.c */
