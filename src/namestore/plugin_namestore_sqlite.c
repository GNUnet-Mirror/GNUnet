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
  sqlite3_stmt *put_records;

  /**
   * Precompiled SQL for remove record
   */
  sqlite3_stmt *remove_records;

  /**
   * Precompiled SQL for iterate over all records.
   */
  sqlite3_stmt *iterate_all;

  /**
   * Precompiled SQL for iterate records with same name.
   */
  sqlite3_stmt *iterate_by_name;

  /**
   * Precompiled SQL for iterate records with same zone.
   */
  sqlite3_stmt *iterate_by_zone;

  /**
   * Precompiled SQL for iterate records with same name and zone.
   */
  sqlite3_stmt *iterate_records;

  /**
   * Precompiled SQL for delete zone
   */
  sqlite3_stmt *delete_zone;

};


/**
 * Internal format of a record in the BLOB in the database.
 */
struct DbRecord
{

  /**
   * Expiration time for the DNS record.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * Number of bytes in 'data', network byte order.
   */
  uint32_t data_size;

  /**
   * Type of the GNS/DNS record, network byte order.
   */
  uint32_t record_type;

  /**
   * Flags for the record, network byte order.
   */
  uint32_t flags;
  
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
	sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS ir_zone_name_rv ON ns090records (zone_hash,record_name_hash,rvalue)",
		      NULL, NULL, NULL)) ||
       (SQLITE_OK !=
	sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS ir_zone_rv ON ns090records (zone_hash,rvalue)",
		      NULL, NULL, NULL)) ||
       (SQLITE_OK !=
	sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS ir_zone ON ns090records (zone_hash)",
		      NULL, NULL, NULL)) ||
       (SQLITE_OK !=
	sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS ir_name_rv ON ns090records (record_name_hash,rvalue)",
		      NULL, NULL, NULL)) ||
       (SQLITE_OK !=
	sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS ir_rv ON ns090records (rvalue)",
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
         sqlite3_exec (plugin->dbh, "PRAGMA encoding=\"UTF-8\"", NULL,
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
        " zone_key BLOB NOT NULL DEFAULT ''," 
        " zone_hash BLOB NOT NULL DEFAULT ''," 
	" record_count INT NOT NULL DEFAULT 0,"
        " record_data BLOB NOT NULL DEFAULT '',"
        " block_expiration_time INT8 NOT NULL DEFAULT 0," 
        " signature BLOB NOT NULL DEFAULT '',"
        " record_name TEXT NOT NULL DEFAULT ''," 
        " record_name_hash BLOB NOT NULL DEFAULT ''," 
	" rvalue INT8 NOT NULL DEFAULT ''"
	")", 
	NULL, NULL, NULL) != SQLITE_OK))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite3_exec");
    sqlite3_finalize (stmt);
    return GNUNET_SYSERR;
  }
  sqlite3_finalize (stmt);

  create_indices (plugin->dbh);

#define ALL "zone_key, record_name, record_count, record_data, block_expiration_time, signature"
  if ((sq_prepare
       (plugin->dbh,
        "INSERT INTO ns090records (" ALL ", zone_hash, record_name_hash, rvalue) VALUES "
	"(?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &plugin->put_records) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "DELETE FROM ns090records WHERE zone_hash=? AND record_name_hash=?",
        &plugin->remove_records) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT " ALL
	" FROM ns090records WHERE zone_hash=? AND record_name_hash=? ORDER BY rvalue LIMIT 1 OFFSET ?",
        &plugin->iterate_records) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT " ALL
	" FROM ns090records WHERE zone_hash=? ORDER BY rvalue  LIMIT 1 OFFSET ?",
        &plugin->iterate_by_zone) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT " ALL 
	" FROM ns090records WHERE record_name_hash=? ORDER BY rvalue LIMIT 1 OFFSET ?",
        &plugin->iterate_by_name) != SQLITE_OK) ||
      (sq_prepare
	(plugin->dbh,
        "SELECT " ALL
	" FROM ns090records ORDER BY rvalue LIMIT 1 OFFSET ?",
        &plugin->iterate_all) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "DELETE FROM ns090records WHERE zone_hash=?",
        &plugin->delete_zone) != SQLITE_OK) )
  {
    LOG_SQLITE (plugin,GNUNET_ERROR_TYPE_ERROR, "precompiling");
    return GNUNET_SYSERR;
  }
#undef ALL
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

  if (NULL != plugin->put_records)
    sqlite3_finalize (plugin->put_records);
  if (NULL != plugin->remove_records)
    sqlite3_finalize (plugin->remove_records);
  if (NULL != plugin->iterate_records)
    sqlite3_finalize (plugin->iterate_records);
  if (NULL != plugin->iterate_records)
    sqlite3_finalize (plugin->iterate_by_zone);
  if (NULL != plugin->iterate_records)
    sqlite3_finalize (plugin->iterate_by_name);
  if (NULL != plugin->iterate_records)
    sqlite3_finalize (plugin->iterate_all);
  if (NULL != plugin->delete_zone)
    sqlite3_finalize (plugin->delete_zone);
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
 * Removes any existing record in the given zone with the same name.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of the public key of the zone
 * @param name name to remove (at most 255 characters long)
 * @return GNUNET_OK on success
 */
static int 
namestore_sqlite_remove_records (void *cls, 
				 const GNUNET_HashCode *zone,
				 const char *name)
{
  struct Plugin *plugin = cls;
  GNUNET_HashCode nh;
  size_t name_len;
  int n;

  name_len = strlen (name);
  GNUNET_CRYPTO_hash (name, name_len, &nh);

  if ((SQLITE_OK != sqlite3_bind_blob (plugin->remove_records, 1, zone, sizeof (GNUNET_HashCode), SQLITE_STATIC)) ||
      (SQLITE_OK != sqlite3_bind_blob (plugin->remove_records, 2, &nh, sizeof (GNUNET_HashCode), SQLITE_STATIC)))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (plugin->remove_records))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  n = sqlite3_step (plugin->remove_records);
  if (SQLITE_OK != sqlite3_reset (plugin->remove_records))
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_reset");
  switch (n)
  {
  case SQLITE_DONE:
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite", "Record removed\n");
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
 * Store a record in the datastore.  Removes any existing record in the
 * same zone with the same name.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone_key public key of the zone
 * @param expire when does the corresponding block in the DHT expire (until
 *               when should we never do a DHT lookup for the same name again)?
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature of the record block, NULL if signature is unavailable (i.e. 
 *        because the user queried for a particular record type only)
 * @return GNUNET_OK on success, else GNUNET_SYSERR
 */
static int 
namestore_sqlite_put_records (void *cls, 
			      const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
			      struct GNUNET_TIME_Absolute expire,
			      const char *name,
			      unsigned int rd_count,
			      const struct GNUNET_NAMESTORE_RecordData *rd,
			      const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct Plugin *plugin = cls;
  int n;
  GNUNET_HashCode zone;
  GNUNET_HashCode nh;
  size_t name_len;
  uint64_t rvalue;
  size_t data_size;
  size_t off;
  unsigned int i;

  GNUNET_CRYPTO_hash (zone_key, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), &zone);
  (void) namestore_sqlite_remove_records (plugin, &zone, name);
  name_len = strlen (name);
  GNUNET_CRYPTO_hash (name, name_len, &nh);
  rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX);
  data_size = rd_count * sizeof (struct DbRecord);
  for (i=0;i<rd_count;i++)  
    data_size += rd[i].data_size;
  if (data_size > 64 * 65536)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  {
    char data[data_size];
    struct DbRecord *rec;
    
    rec = (struct DbRecord *) data;
    off = rd_count * sizeof (struct DbRecord);
    for (i=0;i<rd_count;i++)  
    {
      rec[i].expiration = GNUNET_TIME_absolute_hton (rd[i].expiration);
      rec[i].data_size = htonl ((uint32_t) rd[i].data_size);
      rec[i].record_type = htonl (rd[i].record_type);
      rec[i].flags = htonl (rd[i].flags);
      memcpy (&data[off],
	      rd[i].data,
	      rd[i].data_size);
      off += rd[i].data_size;
    }
    if ((SQLITE_OK != sqlite3_bind_blob (plugin->put_records, 1, zone_key, sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded), SQLITE_STATIC)) ||
	(SQLITE_OK != sqlite3_bind_text (plugin->put_records, 2, name, -1, SQLITE_STATIC)) ||
	(SQLITE_OK != sqlite3_bind_int (plugin->put_records, 3, rd_count)) ||
	(SQLITE_OK != sqlite3_bind_blob (plugin->put_records, 4, data, data_size, SQLITE_STATIC)) ||
	(SQLITE_OK != sqlite3_bind_int64 (plugin->put_records, 5, expire.abs_value)) ||
	(SQLITE_OK != sqlite3_bind_blob (plugin->put_records, 6, signature, sizeof (struct GNUNET_CRYPTO_RsaSignature), SQLITE_STATIC)) ||
	(SQLITE_OK != sqlite3_bind_blob (plugin->put_records, 7, &zone, sizeof (GNUNET_HashCode), SQLITE_STATIC)) ||
	(SQLITE_OK != sqlite3_bind_blob (plugin->put_records, 8, &nh, sizeof (GNUNET_HashCode), SQLITE_STATIC)) ||
	(SQLITE_OK != sqlite3_bind_int64 (plugin->put_records, 9, rvalue)) )
    {
      LOG_SQLITE (plugin, 
		  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_bind_XXXX");
      if (SQLITE_OK != sqlite3_reset (plugin->put_records))
	LOG_SQLITE (plugin, 
		    GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		    "sqlite3_reset");
      return GNUNET_SYSERR;
      
    }
    n = sqlite3_step (plugin->put_records);
    if (SQLITE_OK != sqlite3_reset (plugin->put_records))
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_reset");
  }
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
 * Iterate over the results for a particular key and zone in the
 * datastore.  Will return at most one result to the iterator.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone, NULL to iterate over all zones
 * @param name_hash hash of name, NULL to iterate over all records of the zone
 * @param offset offset in the list of all matching records
 * @param iter function to call with the result
 * @param iter_cls closure for iter
 * @return GNUNET_OK on success, GNUNET_NO if there were no results, GNUNET_SYSERR on error
 */
static int 
namestore_sqlite_iterate_records (void *cls, 
				  const GNUNET_HashCode *zone,
				  const GNUNET_HashCode *name_hash,
				  uint64_t offset,
				  GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  unsigned int boff;
  int ret;
  int sret;

  if (NULL == zone)
    if (NULL == name_hash)
      stmt = plugin->iterate_all;
    else
      stmt = plugin->iterate_by_name;
  else
    if (NULL == name_hash)
      stmt = plugin->iterate_by_zone;
    else
      stmt = plugin->iterate_records;

  boff = 0;
  if ( (NULL != zone) &&
       (SQLITE_OK != sqlite3_bind_blob (stmt, ++boff, 
					zone, sizeof (GNUNET_HashCode), 
					SQLITE_STATIC)) )
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin,
		  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_reset");
    return GNUNET_SYSERR;
  }      
  if ( (NULL != name_hash) &&
       (SQLITE_OK != sqlite3_bind_blob (stmt, ++boff, 
					name_hash, sizeof (GNUNET_HashCode), 
					SQLITE_STATIC)) )
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin,
		  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_reset");
    return GNUNET_SYSERR;
  }      

  if (SQLITE_OK != sqlite3_bind_int64 (stmt, ++boff, 
				       offset)) 
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  ret = GNUNET_NO;
  if (SQLITE_ROW == (sret = sqlite3_step (stmt)))
  {
    unsigned int record_count;
    size_t data_size;
    const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key;
    const struct GNUNET_CRYPTO_RsaSignature *sig;
    struct GNUNET_TIME_Absolute expiration;
    const char *data;
    const char *name;
      
    ret = GNUNET_YES;
    zone_key =  sqlite3_column_blob (stmt, 0);
    name = (const char*) sqlite3_column_text (stmt, 1);
    record_count = sqlite3_column_int (stmt, 2);
    data_size = sqlite3_column_bytes (stmt, 3);
    data = sqlite3_column_blob (stmt, 3);
    expiration.abs_value = (uint64_t) sqlite3_column_int64 (stmt, 4);
    sig = sqlite3_column_blob (stmt, 5);

    if ( (sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) != sqlite3_column_bytes (stmt, 0)) ||
	 (sizeof (struct GNUNET_CRYPTO_RsaSignature) != sqlite3_column_bytes (stmt, 5)) ||
	 (sizeof (struct DbRecord) * record_count > data_size) )
    {
      GNUNET_break (0);
      ret = GNUNET_SYSERR;
    }
    else
    {
      const struct DbRecord *db = (const struct DbRecord*) data;
      struct GNUNET_NAMESTORE_RecordData rd[record_count];
      unsigned int i;
      size_t off;

      off = record_count * sizeof (struct DbRecord);
      for (i=0;i<record_count;i++)
      {
	if (off + ntohl (db[i].data_size) > data_size)
	{
	  GNUNET_break (0);
	  ret = GNUNET_SYSERR;
	  record_count = i;
	  break;
	}
	rd[i].expiration = GNUNET_TIME_absolute_ntoh (db[i].expiration);
	rd[i].data_size = ntohl (db[i].data_size);
	rd[i].data = &data[off];
	rd[i].record_type = ntohl (db[i].record_type);
	rd[i].flags = ntohl (db[i].flags);
	off += rd[i].data_size;
      }     
      iter (iter_cls, zone_key, expiration, name, 
	    record_count, rd, sig);
    }
  }
  else
  {
    if (SQLITE_DONE != sret)
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite_step");
    iter (iter_cls, NULL, GNUNET_TIME_UNIT_ZERO_ABS, NULL, 0, NULL, NULL);
  }
  if (SQLITE_OK != sqlite3_reset (stmt))
    LOG_SQLITE (plugin,
		GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_reset");
  return ret;
}


/**
 * Delete an entire zone (all records).  Not used in normal operation.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone zone to delete
 */
static void 
namestore_sqlite_delete_zone (void *cls,
			      const GNUNET_HashCode *zone)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt = plugin->delete_zone;
  int n;

  if (SQLITE_OK != sqlite3_bind_blob (stmt, 1, zone, sizeof (GNUNET_HashCode), SQLITE_STATIC))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return;
  }
  n = sqlite3_step (stmt);
  if (SQLITE_OK != sqlite3_reset (stmt))
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_reset");
  switch (n)
  {
  case SQLITE_DONE:
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite", "Values deleted\n");
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
  api->put_records = &namestore_sqlite_put_records;
  api->remove_records = &namestore_sqlite_remove_records;
  api->iterate_records = &namestore_sqlite_iterate_records;
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
