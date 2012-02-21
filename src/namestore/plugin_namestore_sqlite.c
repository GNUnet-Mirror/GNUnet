 /*
  * This file is part of GNUnet
  * (C) 2009, 2011, 2012 Christian Grothoff (and other contributing authors)
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
 * @file namestore/plugin_namestore_sqlite.c
 * @brief sqlite-based namestore backend
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_namestore_plugin.h"
#include <sqlite3.h>

/**
 * After how many ms "busy" should a DB operation fail for good?
 * A low value makes sure that we are more responsive to requests
 * (especially PUTs).  A high value guarantees a higher success
 * rate (SELECTs in iterate can take several seconds despite LIMIT=1).
 *
 * The default value of 1s should ensure that users do not experience
 * huge latencies while at the same time allowing operations to succeed
 * with reasonable probability.
 */
#define BUSY_TIMEOUT_MS 1000


/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_SQLITE(db, msg, level, cmd) do { GNUNET_log_from (level, "namestore-sqlite", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); if (msg != NULL) GNUNET_asprintf(msg, _("`%s' failed at %s:%u with error: %s"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); } while(0)

#define LOG(kind,...) GNUNET_log_from (kind, "namestore-sqlite", __VA_ARGS__)


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
   * Precompiled SQL for put record
   */
  sqlite3_stmt *put_record;

  /**
   * Precompiled SQL for put node
   */
  sqlite3_stmt *put_node;

  /**
   * Precompiled SQL for put signature
   */
  sqlite3_stmt *put_signature;

  /**
   * Precompiled SQL for iterate records
   */
  sqlite3_stmt *iterate_records;

  /**
   * Precompiled SQL for get node
   */
  sqlite3_stmt *get_node;

  /**
   * Precompiled SQL for get signature
   */
  sqlite3_stmt *get_signature;

  /**
   * Precompiled SQL for delete zone
   */
  sqlite3_stmt *delete_zone_records;

  /**
   * Precompiled SQL for delete zone
   */
  sqlite3_stmt *delete_zone_nodes;

  /**
   * Precompiled SQL for delete zone
   */
  sqlite3_stmt *delete_zone_signatures;

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
  if (SQLITE_OK !=
      sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS ir_zone_name_hash ON ns090records (zone_hash,record_name_hash)",
		    NULL, NULL, NULL))
    LOG (GNUNET_ERROR_TYPE_ERROR, 
	 "Failed to create indices: %s\n", sqlite3_errmsg (dbh));


  if (SQLITE_OK !=
      sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS in_zone_location ON ns090nodes (zone_hash,zone_revision,node_location_depth,node_location_offset DESC)",
		    NULL, NULL, NULL))
    LOG (GNUNET_ERROR_TYPE_ERROR, 
	 "Failed to create indices: %s\n", sqlite3_errmsg (dbh));


  if (SQLITE_OK !=
      sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS is_zone ON ns090signatures (zone_hash)",
		    NULL, NULL, NULL))
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
 * @return GNUNET_OK on success
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
      GNUNET_CONFIGURATION_get_value_filename (plugin->cfg, "namestore-sqlite",
                                               "FILENAME", &afsdir))
    {
    LOG (GNUNET_ERROR_TYPE_ERROR, 
	 _ ("Option `%s' in section `%s' missing in configuration!\n"),
	 "FILENAME", "namestore-sqlite");
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
         sqlite3_exec (plugin->dbh, "PRAGMA locking_mode=EXCLUSIVE", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA count_changes=OFF", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh, "PRAGMA page_size=4092", NULL, NULL,
                       ENULL));

  CHECK (SQLITE_OK == sqlite3_busy_timeout (plugin->dbh, BUSY_TIMEOUT_MS));


  /* Create tables */
  CHECK (SQLITE_OK ==
         sq_prepare (plugin->dbh,
                     "SELECT 1 FROM sqlite_master WHERE tbl_name = 'ns090records'",
                     &stmt));
  if ((sqlite3_step (stmt) == SQLITE_DONE) &&
      (sqlite3_exec
       (plugin->dbh,
        "CREATE TABLE ns090records (" 
        " zone_hash TEXT NOT NULL DEFAULT ''," 
        " zone_revision INT4 NOT NULL DEFAULT 0," 
        " record_name_hash TEXT NOT NULL DEFAULT ''," 
        " record_name TEXT NOT NULL DEFAULT ''," 
	" record_type INT4 NOT NULL DEFAULT 0,"
        " node_location_depth INT4 NOT NULL DEFAULT 0," 
        " node_location_offset INT8 NOT NULL DEFAULT 0," 
        " record_expiration_time INT8 NOT NULL DEFAULT 0," 
	" record_flags INT4 NOT NULL DEFAULT 0,"
        " record_value BLOB NOT NULL DEFAULT ''"
	")", 
	NULL, NULL, NULL) != SQLITE_OK))
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_exec");
    sqlite3_finalize (stmt);
    return GNUNET_SYSERR;
  }
  sqlite3_finalize (stmt);

  CHECK (SQLITE_OK ==
         sq_prepare (plugin->dbh,
                     "SELECT 1 FROM sqlite_master WHERE tbl_name = 'ns090nodes'",
                     &stmt));
  if ((sqlite3_step (stmt) == SQLITE_DONE) &&
      (sqlite3_exec
       (plugin->dbh,
        "CREATE TABLE ns090nodes (" 
        " zone_hash TEXT NOT NULL DEFAULT ''," 
        " zone_revision INT4 NOT NULL DEFAULT 0," 
        " node_location_depth INT4 NOT NULL DEFAULT 0," 
        " node_location_offset INT8 NOT NULL DEFAULT 0," 
        " node_parent_offset INT8 NOT NULL DEFAULT 0," 
        " node_hashcodes BLOB NOT NULL DEFAULT ''"
	")", 
	NULL, NULL, NULL) != SQLITE_OK))
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_exec");
    sqlite3_finalize (stmt);
    return GNUNET_SYSERR;
  }
  sqlite3_finalize (stmt);


  CHECK (SQLITE_OK ==
         sq_prepare (plugin->dbh,
                     "SELECT 1 FROM sqlite_master WHERE tbl_name = 'ns090signatures'",
                     &stmt));
  if ((sqlite3_step (stmt) == SQLITE_DONE) &&
      (sqlite3_exec
       (plugin->dbh,
        "CREATE TABLE ns090signatures (" 
        " zone_hash TEXT NOT NULL DEFAULT ''," 
        " zone_revision INT4 NOT NULL DEFAULT 0," 
        " zone_time INT8 NOT NULL DEFAULT 0," 
        " zone_root_hash TEXT NOT NULL DEFAULT 0," 
        " zone_root_depth INT4 NOT NULL DEFAULT 0," 
        " zone_public_key BLOB NOT NULL DEFAULT 0," 
        " zone_signature BLOB NOT NULL DEFAULT 0" 
	")", 
	NULL, NULL, NULL) != SQLITE_OK))
  {
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_exec");
    sqlite3_finalize (stmt);
    return GNUNET_SYSERR;
  }
  sqlite3_finalize (stmt);


  create_indices (plugin->dbh);

  if ((sq_prepare
       (plugin->dbh,
        "INSERT INTO ns090records (zone_hash, zone_revision, record_name_hash, record_name, "
	"record_type, node_location_depth, node_location_offset, "
	"record_expiration_time, record_flags, record_value) VALUES "
	"(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &plugin->put_record) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "INSERT INTO ns090nodes (zone_hash, zone_revision, "
	"node_location_depth, node_location_offset, node_parent_offset, node_hashcodes) "
	"VALUES (?, ?, ?, ?, ?, ?)",
        &plugin->put_node) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "INSERT INTO ns090signatures (zone_hash, zone_revision, zone_time, zone_root_hash, "
	"zone_root_depth, zone_public_key, zone_signature) "
	"VALUES (?, ?, ?, ?, ?, ?)",
        &plugin->put_signature) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT zone_revision,record_name,record_type,node_location_depth,node_location_offset,record_expiration_time,record_flags,record_value "
	"FROM ns090records WHERE zone_hash=? AND record_name_hash=?",
        &plugin->iterate_records) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT node_parent_offset,node_hashcodes FROM ns090nodes "
	"WHERE zone_hash=? AND zone_revision=? AND node_location_depth=? AND node_location_offset<=? ORDER BY node_location_offset DESC LIMIT 1",
        &plugin->get_node) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT zone_revision,zone_time,zone_root_hash,zone_root_depth,zone_public_key,zone_signature "
	"FROM ns090signatures WHERE zone_hash=?",
        &plugin->get_signature) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "DELETE FROM gn090records WHERE zone_hash=?",
        &plugin->delete_zone_records) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "DELETE FROM gn090nodes WHERE zone_hash=?",
        &plugin->delete_zone_nodes) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "DELETE FROM gn090signatures WHERE zone_hash=?",
        &plugin->delete_zone_signatures) != SQLITE_OK) )
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
  sqlite3_stmt *stmt;

  if (NULL != plugin->put_record)
    sqlite3_finalize (plugin->put_record);
  if (NULL != plugin->put_node)
    sqlite3_finalize (plugin->put_node);
  if (NULL != plugin->put_signature)
    sqlite3_finalize (plugin->put_signature);
  if (NULL != plugin->iterate_records)
    sqlite3_finalize (plugin->iterate_records);
  if (NULL != plugin->get_node)
    sqlite3_finalize (plugin->get_node);
  if (NULL != plugin->get_signature)
    sqlite3_finalize (plugin->get_signature);
  if (NULL != plugin->delete_zone_records)
    sqlite3_finalize (plugin->delete_zone_records);
  if (NULL != plugin->delete_zone_nodes)
    sqlite3_finalize (plugin->delete_zone_nodes);
  if (NULL != plugin->delete_zone_signatures)
    sqlite3_finalize (plugin->delete_zone_signatures);
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
    LOG_SQLITE (plugin, NULL, GNUNET_ERROR_TYPE_ERROR, "sqlite3_close");

  GNUNET_free_non_null (plugin->fn);
}


/**
 * Store a record in the datastore.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param loc location of the signature for the record
 * @param expiration expiration time for the content
 * @param flags flags for the content
 * @param data_size number of bytes in data
 * @param data value, semantics depend on 'record_type' (see RFCs for DNS and 
 *             GNS specification for GNS extensions)
 * @return GNUNET_OK on success
 */
static int 
namestore_sqlite_put_record (void *cls, 
			     const GNUNET_HashCode *zone,
			     const char *name,
			     uint32_t record_type,
			     const struct GNUNET_NAMESTORE_SignatureLocation *loc,
			     struct GNUNET_TIME_Absolute expiration,
			     enum GNUNET_NAMESTORE_RecordFlags flags,
			     size_t data_size,
			     const void *data)
{
#if 0
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
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite", "Block updated\n");
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
#endif
  return GNUNET_SYSERR;
}


/**
 * Store a Merkle tree node in the datastore.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone
 * @param loc location in the B-tree
 * @param ploc parent's location in the B-tree (must have depth = loc.depth - 1), NULL for root
 * @param num_entries number of entries at this node in the B-tree
 * @param entries the 'num_entries' entries to store (hashes over the
 *                records)
 * @return GNUNET_OK on success
 */
static int 
namestore_sqlite_put_node (void *cls, 
			   const GNUNET_HashCode *zone,
			   const struct GNUNET_NAMESTORE_SignatureLocation *loc,
			   const struct GNUNET_NAMESTORE_SignatureLocation *ploc,
			   unsigned int num_entries,
			   const GNUNET_HashCode *entries)
{
  return GNUNET_SYSERR;
}
  

/**
 * Store a zone signature in the datastore.  If a signature for the zone with a
 * lower depth exists, the old signature is removed.  If a signature for an
 * older revision of the zone exists, this will delete all records, nodes
 * and signatures for the older revision of the zone.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone_key public key of the zone
 * @param loc location in the B-tree (top of the tree, offset 0, depth at 'maximum')
 * @param top_sig signature at the top, NULL if 'loc.depth > 0'
 * @param root_hash top level hash that is signed
 * @param zone_time time the zone was signed
 * @return GNUNET_OK on success
 */
static int
namestore_sqlite_put_signature (void *cls, 
				const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
				const struct GNUNET_NAMESTORE_SignatureLocation *loc,
				const struct GNUNET_CRYPTO_RsaSignature *top_sig,
				const GNUNET_HashCode *root_hash,
				struct GNUNET_TIME_Absolute zone_time)
{
  return GNUNET_SYSERR;
}
  
  
/**
 * Iterate over the results for a particular key and zone in the
 * datastore.  Will only query the latest revision known for the
 * zone (as adding a new zone revision will cause the plugin to
 * delete all records from previous revisions).
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone
 * @param name_hash hash of name, NULL to iterate over all records of the zone
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for iter
 * @return the number of results found
 */
static unsigned int 
namestore_sqlite_iterate_records (void *cls, 
				  const GNUNET_HashCode *zone,
				  const GNUNET_HashCode *name_hash,
				  GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
#if 0
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
                          -(size + GNUNET_NAMESTORE_ENTRY_OVERHEAD));
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
                        -(size + GNUNET_NAMESTORE_ENTRY_OVERHEAD));
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

#endif
  return 0;
}

 
/**
 * Get a particular node from the signature tree.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone
 * @param loc location of the node in the signature tree
 * @param cb function to call with the result
 * @param cb_cls closure for cont
 */
static void
namestore_sqlite_get_node (void *cls, 
			   const GNUNET_HashCode *zone,
			   const struct GNUNET_NAMESTORE_SignatureLocation *loc,
			   GNUNET_NAMESTORE_NodeCallback cb, void *cb_cls)
{
}


/**
 * Get the current signature for a zone.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone
 * @param cb function to call with the result
 * @param cb_cls closure for cont
 */
static void 
namestore_sqlite_get_signature (void *cls, 
				const GNUNET_HashCode *zone,
				GNUNET_NAMESTORE_SignatureCallback cb, void *cb_cls)
{
}


/**
 * Delete an entire zone (all revisions, all records, all nodes,
 * all signatures).  Not used in normal operation.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone zone to delete
 */
static void 
namestore_sqlite_delete_zone (void *cls,
			      const GNUNET_HashCode *zone)
{
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_NAMESTORE_PluginEnvironment*"
 * @return NULL on error, othrewise the plugin context
 */
void *
libgnunet_plugin_namestore_sqlite_init (void *cls)
{
  static struct Plugin plugin;
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_NAMESTORE_PluginFunctions *api;

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.cfg = cfg;  
  if (GNUNET_OK != database_setup (&plugin))
  {
    database_shutdown (&plugin);
    return NULL;
  }
  api = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_PluginFunctions));
  api->cls = &plugin;
  api->put_record = &namestore_sqlite_put_record;
  api->put_node = &namestore_sqlite_put_node;
  api->put_signature = &namestore_sqlite_put_signature;
  api->iterate_records = &namestore_sqlite_iterate_records;
  api->get_node = &namestore_sqlite_get_node;
  api->get_signature = &namestore_sqlite_get_signature;
  api->delete_zone = &namestore_sqlite_delete_zone;
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
libgnunet_plugin_namestore_sqlite_done (void *cls)
{
  struct GNUNET_NAMESTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "sqlite plugin is done\n");
  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "sqlite plugin is finished\n");
  return NULL;
}

/* end of plugin_namestore_sqlite.c */
