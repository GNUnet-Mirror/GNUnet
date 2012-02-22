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
#define LOG_SQLITE(db, level, cmd) do { GNUNET_log_from (level, "namestore-sqlite", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); } while(0)

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
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite3_exec");
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
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite3_exec");
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
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite3_exec");
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
	"VALUES (?, ?, ?, ?, ?, ?, ?)",
        &plugin->put_signature) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT zone_revision,record_name,record_type,node_location_depth,node_location_offset,record_expiration_time,record_flags,record_value "
	"FROM ns090records WHERE zone_hash=? AND record_name_hash=?",
        &plugin->iterate_records) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT node_parent_offset,node_location_offset,node_hashcodes FROM ns090nodes "
	"WHERE zone_hash=? AND zone_revision=? AND node_location_depth=? AND node_location_offset<=? ORDER BY node_location_offset DESC LIMIT 1",
        &plugin->get_node) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT zone_revision,zone_time,zone_root_hash,zone_root_depth,zone_public_key,zone_signature "
	"FROM ns090signatures WHERE zone_hash=?",
        &plugin->get_signature) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "DELETE FROM ns090records WHERE zone_hash=?",
        &plugin->delete_zone_records) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "DELETE FROM ns090nodes WHERE zone_hash=?",
        &plugin->delete_zone_nodes) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "DELETE FROM ns090signatures WHERE zone_hash=?",
        &plugin->delete_zone_signatures) != SQLITE_OK) )
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
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite3_close");

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
  struct Plugin *plugin = cls;
  int n;
  GNUNET_HashCode nh;
  size_t name_len;

  name_len = strlen (name);
  GNUNET_CRYPTO_hash (name, name_len, &nh);
  if ((SQLITE_OK != sqlite3_bind_blob (plugin->put_record, 1, zone, sizeof (GNUNET_HashCode), SQLITE_STATIC)) ||
      (SQLITE_OK != sqlite3_bind_int64 (plugin->put_record, 2, loc->revision)) ||
      (SQLITE_OK != sqlite3_bind_blob (plugin->put_record, 3, &nh, sizeof (GNUNET_HashCode), SQLITE_STATIC)) ||
      (SQLITE_OK != sqlite3_bind_text (plugin->put_record, 4, name, name_len, SQLITE_STATIC)) ||
      (SQLITE_OK != sqlite3_bind_int (plugin->put_record, 5, record_type)) ||
      (SQLITE_OK != sqlite3_bind_int (plugin->put_record, 6, loc->depth)) ||
      (SQLITE_OK != sqlite3_bind_int64 (plugin->put_record, 7, loc->offset)) ||
      (SQLITE_OK != sqlite3_bind_int64 (plugin->put_record, 8, expiration.abs_value)) ||
      (SQLITE_OK != sqlite3_bind_int (plugin->put_record, 9, flags)) ||
      (SQLITE_OK != sqlite3_bind_blob (plugin->put_record, 10, data, data_size, SQLITE_STATIC)) )
  {
    LOG_SQLITE (plugin, 
		GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->put_record))
      LOG_SQLITE (plugin, 
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;

  }
  n = sqlite3_step (plugin->put_record);
  if (SQLITE_OK != sqlite3_reset (plugin->put_record))
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  switch (n)
  {
  case SQLITE_DONE:
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite", "Record stored\n");
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
 * Store a Merkle tree node in the datastore.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone
 * @param loc location in the B-tree
 * @param ploc parent's location in the B-tree (must have depth = loc.depth + 1), NULL for root
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
  struct Plugin *plugin = cls;
  int n;

  if ( (loc->revision != ploc->revision) ||
       (loc->depth + 1 != ploc->depth) ||
       (0 == num_entries))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ((SQLITE_OK != sqlite3_bind_blob (plugin->put_node, 1, zone, sizeof (GNUNET_HashCode), SQLITE_STATIC)) ||
      (SQLITE_OK != sqlite3_bind_int (plugin->put_node, 2, loc->revision)) ||
      (SQLITE_OK != sqlite3_bind_int (plugin->put_node, 3, loc->depth)) ||
      (SQLITE_OK != sqlite3_bind_int64 (plugin->put_node, 4, loc->offset)) ||
      (SQLITE_OK != sqlite3_bind_int64 (plugin->put_node, 5, ploc->offset)) ||
      (SQLITE_OK != sqlite3_bind_blob (plugin->put_node, 6, entries, num_entries * sizeof (GNUNET_HashCode), SQLITE_STATIC)) )
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->put_node))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;

  }
  n = sqlite3_step (plugin->put_node);
  if (SQLITE_OK != sqlite3_reset (plugin->put_node))
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  switch (n)
  {
  case SQLITE_DONE:
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite", "Node stored\n");
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
  struct Plugin *plugin = cls;
  unsigned int ret;
  struct GNUNET_TIME_Absolute expiration;
  uint32_t record_type;
  enum GNUNET_NAMESTORE_RecordFlags flags;
  size_t data_size;
  const void *data;
  struct GNUNET_NAMESTORE_SignatureLocation loc;
  const char *name;

  if ((SQLITE_OK != sqlite3_bind_blob (plugin->iterate_records, 1, zone, sizeof (GNUNET_HashCode), SQLITE_STATIC)) ||
      (SQLITE_OK != sqlite3_bind_blob (plugin->iterate_records, 2, name_hash, sizeof (GNUNET_HashCode), SQLITE_STATIC)) )
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->iterate_records))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;

  }
  ret = 0;
  while (SQLITE_ROW == (ret = sqlite3_step (plugin->iterate_records)))
  {
    ret++;
    if (NULL == iter)
      continue; /* FIXME: just counting can be done more cheaply... */
    loc.revision = sqlite3_column_int (plugin->iterate_records, 1);
    name = (const char*) sqlite3_column_text (plugin->iterate_records, 2);
    record_type = sqlite3_column_int (plugin->iterate_records, 3);
    loc.depth = sqlite3_column_int (plugin->iterate_records, 4);
    loc.offset = sqlite3_column_int64 (plugin->iterate_records, 5);
    expiration.abs_value = (uint64_t) sqlite3_column_int64 (plugin->iterate_records, 6);
    flags = (enum GNUNET_NAMESTORE_RecordFlags) sqlite3_column_int (plugin->iterate_records, 7);
    data = sqlite3_column_blob (plugin->iterate_records, 8);
    data_size = sqlite3_column_bytes (plugin->iterate_records, 8);
    iter (iter_cls, zone,
	  &loc, name, record_type,
	  expiration, flags, data_size, data);
  }
  if (SQLITE_DONE != ret)
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite_step");
  sqlite3_finalize (plugin->iterate_records);
  return ret;
}

 
/**
 * Get a particular node from the signature tree.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone
 * @param loc location of the node in the signature tree
 * @param cb function to call with the result
 * @param cb_cls closure for cont
 * @return GNUNET_OK on success, GNUNET_NO if no node was found
 */
static int
namestore_sqlite_get_node (void *cls, 
			   const GNUNET_HashCode *zone,
			   const struct GNUNET_NAMESTORE_SignatureLocation *loc,
			   GNUNET_NAMESTORE_NodeCallback cb, void *cb_cls)
{
  struct Plugin *plugin = cls;
  int ret;
  size_t hashcodes_size;
  const GNUNET_HashCode *hashcodes;
  struct GNUNET_NAMESTORE_SignatureLocation ploc;
  struct GNUNET_NAMESTORE_SignatureLocation rloc;

  GNUNET_assert (NULL != cb);
  if ((SQLITE_OK != sqlite3_bind_blob (plugin->get_node, 1, zone, sizeof (GNUNET_HashCode), SQLITE_STATIC)) ||
      (SQLITE_OK != sqlite3_bind_int (plugin->get_node, 2, loc->revision)) ||
      (SQLITE_OK != sqlite3_bind_int (plugin->get_node, 3, loc->depth)) ||
      (SQLITE_OK != sqlite3_bind_int64 (plugin->get_node, 4, loc->offset)) )
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->get_node))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;

  }
  rloc.revision = loc->revision;
  rloc.depth = loc->depth;
  ploc.revision = loc->revision;
  ploc.depth = loc->depth + 1;
  ret = GNUNET_NO;
  if (SQLITE_ROW == (ret = sqlite3_step (plugin->get_node)))    
  {
    ploc.offset = sqlite3_column_int64 (plugin->get_node, 1);
    rloc.offset = sqlite3_column_int64 (plugin->get_node, 2);
    hashcodes = sqlite3_column_blob (plugin->get_node, 3);
    hashcodes_size = sqlite3_column_bytes (plugin->get_node, 3);    
    if (0 != (hashcodes_size % sizeof (GNUNET_HashCode)))
    {
      GNUNET_break (0);
      /* FIXME: delete bogus record? */
    } 
    else
    {
      ret = GNUNET_OK;
      cb (cb_cls,
	  zone,
	  &rloc,
	  &ploc,
	  hashcodes_size / sizeof (GNUNET_HashCode),
	  hashcodes);
    }
  }
  if (SQLITE_DONE != ret)
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite_step");
  sqlite3_finalize (plugin->get_node);
  return ret;
}


/**
 * Get the current signature for a zone.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone
 * @param cb function to call with the result
 * @param cb_cls closure for cont
 * @return GNUNET_OK on success, GNUNET_NO if no node was found
 */
static int
namestore_sqlite_get_signature (void *cls, 
				const GNUNET_HashCode *zone,
				GNUNET_NAMESTORE_SignatureCallback cb, void *cb_cls)
{
  struct Plugin *plugin = cls;
  int ret;
  const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key;
  struct GNUNET_NAMESTORE_SignatureLocation top_loc;
  const struct GNUNET_CRYPTO_RsaSignature *zone_sig;
  struct GNUNET_TIME_Absolute zone_time;
  const GNUNET_HashCode *top_hash;

  GNUNET_assert (NULL != cb);
  if ((SQLITE_OK != sqlite3_bind_blob (plugin->get_signature, 1, zone, sizeof (GNUNET_HashCode), SQLITE_STATIC)))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->get_signature))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  ret = GNUNET_NO;
  if (SQLITE_ROW == (ret = sqlite3_step (plugin->get_signature)))    
  {
    top_loc.offset = 0;
    top_loc.revision = sqlite3_column_int (plugin->get_signature, 1);
    zone_time.abs_value = sqlite3_column_int64 (plugin->get_signature, 2);
    top_hash = sqlite3_column_blob (plugin->get_signature, 3);
    top_loc.depth = sqlite3_column_int (plugin->get_signature, 4);
    zone_key = sqlite3_column_blob (plugin->get_signature, 5);
    zone_sig = sqlite3_column_blob (plugin->get_signature, 6);

    if ((sizeof (GNUNET_HashCode) != sqlite3_column_bytes (plugin->get_signature, 3)) ||
	(sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) != sqlite3_column_bytes (plugin->get_signature, 5)) ||
	(sizeof (struct GNUNET_CRYPTO_RsaSignature) != sqlite3_column_bytes (plugin->get_signature, 6)))
    {
      GNUNET_break (0);
      /* FIXME: delete bogus record & full zone (!?) */
    } 
    else
    {
      ret = GNUNET_OK;
      cb (cb_cls,
	  zone_key,
	  &top_loc,
	  zone_sig,
	  zone_time,
	  top_hash);
    }
  }
  if (SQLITE_DONE != ret)
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite_step");
  sqlite3_finalize (plugin->get_signature);
  return ret;
}


/**
 * Run a SQL statement that takes only a 'zone' as the argument
 * and returns nothing (deletes records).
 *
 * @param plugin our plugin
 * @param zone zone argument to pass
 * @param stmt prepared statement to run
 */
static void
run_delete_statement (struct Plugin *plugin,
		      const GNUNET_HashCode *zone,
		      sqlite3_stmt *stmt)
{
  int n;

  if (SQLITE_OK != sqlite3_bind_blob (plugin->delete_zone_records, 1, &zone, sizeof (GNUNET_HashCode), SQLITE_STATIC))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->delete_zone_records))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return;
  }
  n = sqlite3_step (plugin->put_signature);
  if (SQLITE_OK != sqlite3_reset (plugin->delete_zone_records))
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_reset");
  switch (n)
  {
  case SQLITE_DONE:
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite", "Zone records deleted\n");
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
  struct Plugin *plugin = cls;
  
  run_delete_statement (plugin, zone, plugin->delete_zone_records);
  run_delete_statement (plugin, zone, plugin->delete_zone_nodes);
  run_delete_statement (plugin, zone, plugin->delete_zone_signatures);
}


/**
 * Context for 'delete_old_zone_information'.
 */
struct DeleteContext
{
  /**
   * Plugin handle.
   */
  struct Plugin *plugin;

  /**
   * Hash of the public key of the zone (to avoid having to
   * recalculate it).
   */
  const GNUNET_HashCode *zone;

  /**
   * Revision to compare against.
   */
  uint32_t revision;
  
};


/**
 * Function called on the current signature in the database for
 * a zone.  If the revision given in the closure is more recent,
 * delete all information about the zone.  Otherwise, only delete
 * the signature.
 * 
 * @param cls a 'struct DeleteContext' with a revision to compare against
 * @param zone_key public key of the zone
 * @param loc location of the root in the B-tree (depth, revision)
 * @param top_sig signature signing the zone
 * @param zone_time time the signature was created
 * @param root_hash top level hash that is being signed
 */
static void
delete_old_zone_information (void *cls,
			     const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
			     const struct GNUNET_NAMESTORE_SignatureLocation *loc,
			     const struct GNUNET_CRYPTO_RsaSignature *top_sig,
			     struct GNUNET_TIME_Absolute zone_time,
			     const GNUNET_HashCode *root_hash)
{
  struct DeleteContext *dc = cls;

  run_delete_statement (dc->plugin, dc->zone, dc->plugin->delete_zone_signatures);    
  if (loc->revision == dc->revision)
    return;
  run_delete_statement (dc->plugin, dc->zone, dc->plugin->delete_zone_records);
  run_delete_statement (dc->plugin, dc->zone, dc->plugin->delete_zone_nodes);
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
  struct Plugin *plugin = cls;
  int n;
  GNUNET_HashCode zone;
  struct DeleteContext dc;

  GNUNET_CRYPTO_hash (zone_key,
		      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
		      &zone);
  /* get "old" signature, if older revision, delete all existing
     records/nodes for the zone, if same revision, delete only the signature */
  dc.plugin = plugin;
  dc.zone = &zone;
  dc.revision = loc->revision;
  (void) namestore_sqlite_get_signature (plugin,
					 &zone,
					 &delete_old_zone_information,
					 &dc);
  if ((SQLITE_OK != sqlite3_bind_blob (plugin->put_signature, 1, &zone, sizeof (GNUNET_HashCode), SQLITE_STATIC)) ||
      (SQLITE_OK != sqlite3_bind_int (plugin->put_signature, 2, loc->revision)) ||
      (SQLITE_OK != sqlite3_bind_int64 (plugin->put_signature, 3, zone_time.abs_value)) ||
      (SQLITE_OK != sqlite3_bind_blob (plugin->put_signature, 4, root_hash, sizeof (GNUNET_HashCode), SQLITE_STATIC)) ||
      (SQLITE_OK != sqlite3_bind_int (plugin->put_signature, 5, loc->depth)) ||
      (SQLITE_OK != sqlite3_bind_blob (plugin->put_signature, 6, zone_key, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), SQLITE_STATIC))||
      (SQLITE_OK != sqlite3_bind_blob (plugin->put_signature, 7, top_sig, sizeof (struct GNUNET_CRYPTO_RsaSignature), SQLITE_STATIC)) )
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->put_signature))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;

  }
  n = sqlite3_step (plugin->put_signature);
  if (SQLITE_OK != sqlite3_reset (plugin->put_signature))
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  switch (n)
  {
  case SQLITE_DONE:
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite", "Signature stored\n");
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
