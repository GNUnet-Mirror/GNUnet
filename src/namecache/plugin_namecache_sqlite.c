 /*
  * This file is part of GNUnet
  * Copyright (C) 2009-2013 Christian Grothoff (and other contributing authors)
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
 * @file namecache/plugin_namecache_sqlite.c
 * @brief sqlite-based namecache backend
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_namecache_plugin.h"
#include "gnunet_namecache_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "namecache.h"
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


/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(db, level, cmd) do { GNUNET_log_from (level, "namecache-sqlite", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); } while(0)

#define LOG(kind,...) GNUNET_log_from (kind, "namecache-sqlite", __VA_ARGS__)


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
   * Precompiled SQL for caching a block
   */
  sqlite3_stmt *cache_block;

  /**
   * Precompiled SQL for deleting an older block
   */
  sqlite3_stmt *delete_block;

  /**
   * Precompiled SQL for looking up a block
   */
  sqlite3_stmt *lookup_block;

  /**
   * Precompiled SQL for removing expired blocks
   */
  sqlite3_stmt *expire_blocks;


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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Prepared `%s' / %p: %d\n", zSql, *ppStmt, result);
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
  if ( (SQLITE_OK !=
	sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS ir_query_hash ON ns096blocks (query,expiration_time)",
		      NULL, NULL, NULL)) ||
       (SQLITE_OK !=
	sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS ir_block_expiration ON ns096blocks (expiration_time)",
		      NULL, NULL, NULL)) )
    LOG (GNUNET_ERROR_TYPE_ERROR,
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
 * @param plugin the plugin context (state for this module)
 * @return #GNUNET_OK on success
 */
static int
database_setup (struct Plugin *plugin)
{
  sqlite3_stmt *stmt;
  char *afsdir;
#if ENULL_DEFINED
  char *e;
#endif

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->cfg, "namecache-sqlite",
                                               "FILENAME", &afsdir))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "namecache-sqlite", "FILENAME");
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
  }
  /* afsdir should be UTF-8-encoded. If it isn't, it's a bug */
  plugin->fn = afsdir;

  /* Open database and precompile statements */
  if (sqlite3_open (plugin->fn, &plugin->dbh) != SQLITE_OK)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 _("Unable to initialize SQLite: %s.\n"),
	 sqlite3_errmsg (plugin->dbh));
    return GNUNET_SYSERR;
  }
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA temp_store=MEMORY", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA synchronous=NORMAL", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA legacy_file_format=OFF", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA auto_vacuum=INCREMENTAL", NULL,
                       NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA encoding=\"UTF-8\"", NULL,
                       NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA locking_mode=EXCLUSIVE", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA page_size=4092", NULL, NULL,
                       ENULL));

  CHECK (SQLITE_OK == sqlite3_busy_timeout (plugin->dbh, BUSY_TIMEOUT_MS));


  /* Create tables */
  CHECK (SQLITE_OK ==
         sq_prepare (plugin->dbh,
                     "SELECT 1 FROM sqlite_master WHERE tbl_name = 'ns096blocks'",
                     &stmt));
  if ((sqlite3_step (stmt) == SQLITE_DONE) &&
      (sqlite3_exec
       (plugin->dbh,
        "CREATE TABLE ns096blocks ("
        " query BLOB NOT NULL DEFAULT '',"
        " block BLOB NOT NULL DEFAULT '',"
        " expiration_time INT8 NOT NULL DEFAULT 0"
	")",
	NULL, NULL, NULL) != SQLITE_OK))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite3_exec");
    sqlite3_finalize (stmt);
    return GNUNET_SYSERR;
  }
  sqlite3_finalize (stmt);
  create_indices (plugin->dbh);

  if ((sq_prepare
       (plugin->dbh,
        "INSERT INTO ns096blocks (query,block,expiration_time) VALUES (?, ?, ?)",
        &plugin->cache_block) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "DELETE FROM ns096blocks WHERE expiration_time<?",
        &plugin->expire_blocks) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "DELETE FROM ns096blocks WHERE query=? AND expiration_time<=?",
        &plugin->delete_block) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT block FROM ns096blocks WHERE query=? ORDER BY expiration_time DESC LIMIT 1",
        &plugin->lookup_block) != SQLITE_OK)
      )
  {
    LOG_SQLITE (plugin,GNUNET_ERROR_TYPE_ERROR, "precompiling");
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
  sqlite3_stmt *stmt;

  if (NULL != plugin->cache_block)
    sqlite3_finalize (plugin->cache_block);
  if (NULL != plugin->lookup_block)
    sqlite3_finalize (plugin->lookup_block);
  if (NULL != plugin->expire_blocks)
    sqlite3_finalize (plugin->expire_blocks);
  if (NULL != plugin->delete_block)
    sqlite3_finalize (plugin->delete_block);
  result = sqlite3_close (plugin->dbh);
  if (result == SQLITE_BUSY)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 _("Tried to close sqlite without finalizing all prepared statements.\n"));
    stmt = sqlite3_next_stmt (plugin->dbh, NULL);
    while (stmt != NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite",
                       "Closing statement %p\n", stmt);
      result = sqlite3_finalize (stmt);
      if (result != SQLITE_OK)
        GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "sqlite",
                         "Failed to close statement %p: %d\n", stmt, result);
      stmt = sqlite3_next_stmt (plugin->dbh, NULL);
    }
    result = sqlite3_close (plugin->dbh);
  }
  if (SQLITE_OK != result)
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite3_close");

  GNUNET_free_non_null (plugin->fn);
}


/**
 * Removes any expired block.
 *
 * @param plugin the plugin
 */
static void
namecache_sqlite_expire_blocks (struct Plugin *plugin)
{
  struct GNUNET_TIME_Absolute now;
  int n;

  now = GNUNET_TIME_absolute_get ();
  if (SQLITE_OK != sqlite3_bind_int64 (plugin->expire_blocks,
				       1, now.abs_value_us))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->expire_blocks))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return;
  }
  n = sqlite3_step (plugin->expire_blocks);
  if (SQLITE_OK != sqlite3_reset (plugin->expire_blocks))
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  switch (n)
  {
  case SQLITE_DONE:
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite", "Records expired\n");
    return;
  case SQLITE_BUSY:
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    return;
  default:
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    return;
  }
}


/**
 * Cache a block in the datastore.
 *
 * @param cls closure (internal context for the plugin)
 * @param block block to cache
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
namecache_sqlite_cache_block (void *cls,
			      const struct GNUNET_GNSRECORD_Block *block)
{
  struct Plugin *plugin = cls;
  struct GNUNET_HashCode query;
  struct GNUNET_TIME_Absolute expiration;
  int64_t dval;
  size_t block_size;
  int n;

  namecache_sqlite_expire_blocks (plugin);
  GNUNET_CRYPTO_hash (&block->derived_key,
		      sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
		      &query);
  expiration = GNUNET_TIME_absolute_ntoh (block->expiration_time);
  dval = (int64_t) expiration.abs_value_us;
  if (dval < 0)
    dval = INT64_MAX;
  block_size = ntohl (block->purpose.size) +
    sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
    sizeof (struct GNUNET_CRYPTO_EcdsaSignature);
  if (block_size > 64 * 65536)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  /* delete old version of the block */
  if ( (SQLITE_OK !=
        sqlite3_bind_blob (plugin->delete_block, 1,
                           &query, sizeof (struct GNUNET_HashCode),
                           SQLITE_STATIC)) ||
       (SQLITE_OK !=
        sqlite3_bind_int64 (plugin->delete_block,
                            2, dval)) )
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->delete_block))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  n = sqlite3_step (plugin->delete_block);
  switch (n)
  {
  case SQLITE_DONE:
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite", "Old block deleted\n");
    break;
  case SQLITE_BUSY:
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    break;
  default:
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_step");
    break;
  }
  if (SQLITE_OK != sqlite3_reset (plugin->delete_block))
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_reset");

  /* insert new version of the block */
  if ((SQLITE_OK !=
       sqlite3_bind_blob (plugin->cache_block, 1,
			  &query, sizeof (struct GNUNET_HashCode),
			  SQLITE_STATIC)) ||
      (SQLITE_OK !=
       sqlite3_bind_blob (plugin->cache_block, 2,
			  block, block_size,
			  SQLITE_STATIC)) ||
      (SQLITE_OK !=
       sqlite3_bind_int64 (plugin->cache_block, 3,
			   dval)))
  {
    LOG_SQLITE (plugin,
		GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->cache_block))
      LOG_SQLITE (plugin,
		  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_reset");
    return GNUNET_SYSERR;

  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Caching block under derived key `%s'\n",
	      GNUNET_h2s_full (&query));
  n = sqlite3_step (plugin->cache_block);
  if (SQLITE_OK != sqlite3_reset (plugin->cache_block))
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_reset");
  switch (n)
  {
  case SQLITE_DONE:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Record stored\n");
    return GNUNET_OK;
  case SQLITE_BUSY:
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_step");
    return GNUNET_NO;
  default:
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_step");
    return GNUNET_SYSERR;
  }
}


/**
 * Get the block for a particular zone and label in the
 * datastore.  Will return at most one result to the iterator.
 *
 * @param cls closure (internal context for the plugin)
 * @param query hash of public key derived from the zone and the label
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
 */
static int
namecache_sqlite_lookup_block (void *cls,
			       const struct GNUNET_HashCode *query,
			       GNUNET_NAMECACHE_BlockCallback iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  int ret;
  int sret;
  size_t block_size;
  const struct GNUNET_GNSRECORD_Block *block;

  if (SQLITE_OK != sqlite3_bind_blob (plugin->lookup_block, 1,
				      query, sizeof (struct GNUNET_HashCode),
				      SQLITE_STATIC))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->lookup_block))
      LOG_SQLITE (plugin,
		  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  ret = GNUNET_NO;
  if (SQLITE_ROW == (sret = sqlite3_step (plugin->lookup_block)))
  {
    block = sqlite3_column_blob (plugin->lookup_block, 0);
    block_size = sqlite3_column_bytes (plugin->lookup_block, 0);
    if ( (block_size < sizeof (struct GNUNET_GNSRECORD_Block)) ||
	 (ntohl (block->purpose.size) +
	  sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
	  sizeof (struct GNUNET_CRYPTO_EcdsaSignature) != block_size) )
    {
      GNUNET_break (0);
      ret = GNUNET_SYSERR;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Found block under derived key `%s'\n",
		  GNUNET_h2s_full (query));
      iter (iter_cls, block);
      ret = GNUNET_YES;
    }
  }
  else
  {
    if (SQLITE_DONE != sret)
    {
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite_step");
      ret = GNUNET_SYSERR;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "No block found under derived key `%s'\n",
		  GNUNET_h2s_full (query));
    }
  }
  if (SQLITE_OK != sqlite3_reset (plugin->lookup_block))
    LOG_SQLITE (plugin,
		GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_reset");
  return ret;
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_NAMECACHE_PluginEnvironment*"
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_namecache_sqlite_init (void *cls)
{
  static struct Plugin plugin;
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_NAMECACHE_PluginFunctions *api;

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.cfg = cfg;
  if (GNUNET_OK != database_setup (&plugin))
  {
    database_shutdown (&plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_NAMECACHE_PluginFunctions);
  api->cls = &plugin;
  api->cache_block = &namecache_sqlite_cache_block;
  api->lookup_block = &namecache_sqlite_lookup_block;
  LOG (GNUNET_ERROR_TYPE_INFO,
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
libgnunet_plugin_namecache_sqlite_done (void *cls)
{
  struct GNUNET_NAMECACHE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sqlite plugin is finished\n");
  return NULL;
}

/* end of plugin_namecache_sqlite.c */
