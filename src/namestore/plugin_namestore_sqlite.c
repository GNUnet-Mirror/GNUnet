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
  * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  * Boston, MA 02110-1301, USA.
  */

/**
 * @file namestore/plugin_namestore_sqlite.c
 * @brief sqlite-based namestore backend
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_namestore_plugin.h"
#include "gnunet_namestore_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "namestore.h"
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
   * Precompiled SQL to store records.
   */
  sqlite3_stmt *store_records;

  /**
   * Precompiled SQL to deltete existing records.
   */
  sqlite3_stmt *delete_records;

  /**
   * Precompiled SQL for iterate records within a zone.
   */
  sqlite3_stmt *iterate_zone;

  /**
   * Precompiled SQL for iterate all records within all zones.
   */
  sqlite3_stmt *iterate_all_zones;

  /**
   * Precompiled SQL to for reverse lookup based on PKEY.
   */
  sqlite3_stmt *zone_to_name;

  /**
   * Precompiled SQL to lookup records based on label.
   */
  sqlite3_stmt *lookup_label;
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
	sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS ir_pkey_reverse ON ns097records (zone_private_key,pkey)",
		      NULL, NULL, NULL)) ||
       (SQLITE_OK !=
	sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS ir_pkey_iter ON ns097records (zone_private_key,rvalue)",
		      NULL, NULL, NULL)) ||
       (SQLITE_OK !=
	sqlite3_exec (dbh, "CREATE INDEX IF NOT EXISTS it_iter ON ns097records (rvalue)",
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
#define CHECK(a) if (! (a)) { GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "%s\n", e); sqlite3_free(e); }
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
      GNUNET_CONFIGURATION_get_value_filename (plugin->cfg, "namestore-sqlite",
                                               "FILENAME", &afsdir))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "namestore-sqlite", "FILENAME");
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


  /* Create table */
  CHECK (SQLITE_OK ==
         sq_prepare (plugin->dbh,
                     "SELECT 1 FROM sqlite_master WHERE tbl_name = 'ns097records'",
                     &stmt));
  if ((sqlite3_step (stmt) == SQLITE_DONE) &&
      (sqlite3_exec
       (plugin->dbh,
        "CREATE TABLE ns097records ("
        " zone_private_key BLOB NOT NULL DEFAULT '',"
        " pkey BLOB,"
	" rvalue INT8 NOT NULL DEFAULT '',"
	" record_count INT NOT NULL DEFAULT 0,"
        " record_data BLOB NOT NULL DEFAULT '',"
        " label TEXT NOT NULL DEFAULT ''"
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
        "INSERT INTO ns097records (zone_private_key, pkey, rvalue, record_count, record_data, label)"
	" VALUES (?, ?, ?, ?, ?, ?)",
        &plugin->store_records) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "DELETE FROM ns097records WHERE zone_private_key=? AND label=?",
        &plugin->delete_records) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
        "SELECT record_count,record_data,label"
	" FROM ns097records WHERE zone_private_key=? AND pkey=?",
        &plugin->zone_to_name) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
	"SELECT record_count,record_data,label"
	" FROM ns097records WHERE zone_private_key=? ORDER BY rvalue LIMIT 1 OFFSET ?",
	&plugin->iterate_zone) != SQLITE_OK) ||
      (sq_prepare
       (plugin->dbh,
	"SELECT record_count,record_data,label,zone_private_key"
	" FROM ns097records ORDER BY rvalue LIMIT 1 OFFSET ?",
	&plugin->iterate_all_zones) != SQLITE_OK)  ||
      (sq_prepare
       (plugin->dbh,
        "SELECT record_count,record_data,label,zone_private_key"
        " FROM ns097records WHERE zone_private_key=? AND label=?",
        &plugin->lookup_label) != SQLITE_OK)
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

  if (NULL != plugin->store_records)
    sqlite3_finalize (plugin->store_records);
  if (NULL != plugin->delete_records)
    sqlite3_finalize (plugin->delete_records);
  if (NULL != plugin->iterate_zone)
    sqlite3_finalize (plugin->iterate_zone);
  if (NULL != plugin->iterate_all_zones)
    sqlite3_finalize (plugin->iterate_all_zones);
  if (NULL != plugin->zone_to_name)
    sqlite3_finalize (plugin->zone_to_name);
  if (NULL != plugin->zone_to_name)
    sqlite3_finalize (plugin->lookup_label);
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
 * Store a record in the datastore.  Removes any existing record in the
 * same zone with the same name.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone_key private key of the zone
 * @param label name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
namestore_sqlite_store_records (void *cls,
				const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
				const char *label,
				unsigned int rd_count,
				const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Plugin *plugin = cls;
  int n;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  uint64_t rvalue;
  size_t data_size;
  unsigned int i;

  memset (&pkey, 0, sizeof (pkey));
  for (i=0;i<rd_count;i++)
    if (GNUNET_GNSRECORD_TYPE_PKEY == rd[i].record_type)
    {
      GNUNET_break (sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) == rd[i].data_size);
      memcpy (&pkey,
              rd[i].data,
              rd[i].data_size);
      break;
    }
  rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX);
  data_size = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
  if (data_size > 64 * 65536)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  {
    char data[data_size];

    if (data_size != GNUNET_GNSRECORD_records_serialize (rd_count, rd,
							 data_size, data))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    /* First delete 'old' records */
    if ((SQLITE_OK != sqlite3_bind_blob (plugin->delete_records, 1,
					 zone_key, sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey), SQLITE_STATIC)) ||
	(SQLITE_OK != sqlite3_bind_text (plugin->delete_records, 2, label, -1, SQLITE_STATIC)))
    {
      LOG_SQLITE (plugin,
		  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_bind_XXXX");
      if (SQLITE_OK != sqlite3_reset (plugin->delete_records))
	LOG_SQLITE (plugin,
		    GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		    "sqlite3_reset");
      return GNUNET_SYSERR;

    }
    n = sqlite3_step (plugin->delete_records);
    if (SQLITE_OK != sqlite3_reset (plugin->delete_records))
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_reset");

    if (0 != rd_count)
    {
      if ((SQLITE_OK != sqlite3_bind_blob (plugin->store_records, 1,
					   zone_key, sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey), SQLITE_STATIC)) ||
	  (SQLITE_OK != sqlite3_bind_blob (plugin->store_records, 2,
					   &pkey, sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey), SQLITE_STATIC)) ||
	  (SQLITE_OK != sqlite3_bind_int64 (plugin->store_records, 3, rvalue)) ||
	  (SQLITE_OK != sqlite3_bind_int (plugin->store_records, 4, rd_count)) ||
	  (SQLITE_OK != sqlite3_bind_blob (plugin->store_records, 5, data, data_size, SQLITE_STATIC)) ||
	  (SQLITE_OK != sqlite3_bind_text (plugin->store_records, 6, label, -1, SQLITE_STATIC)))
      {
	LOG_SQLITE (plugin,
		    GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		    "sqlite3_bind_XXXX");
	if (SQLITE_OK != sqlite3_reset (plugin->store_records))
	  LOG_SQLITE (plugin,
		      GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		      "sqlite3_reset");
	return GNUNET_SYSERR;
      }
      n = sqlite3_step (plugin->store_records);
      if (SQLITE_OK != sqlite3_reset (plugin->store_records))
	LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		    "sqlite3_reset");
    }
  }
  switch (n)
  {
  case SQLITE_DONE:
    if (0 != rd_count)
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite", "Record stored\n");
    else
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "sqlite", "Record deleted\n");
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
 * The given 'sqlite' statement has been prepared to be run.
 * It will return a record which should be given to the iterator.
 * Runs the statement and parses the returned record.
 *
 * @param plugin plugin context
 * @param stmt to run (and then clean up)
 * @param zone_key private key of the zone
 * @param iter iterator to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
 */
static int
get_record_and_call_iterator (struct Plugin *plugin,
			      sqlite3_stmt *stmt,
			      const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
			      GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
  unsigned int record_count;
  size_t data_size;
  const char *data;
  const char *label;
  int ret;
  int sret;

  ret = GNUNET_NO;
  if (SQLITE_ROW == (sret = sqlite3_step (stmt)))
  {
    record_count = sqlite3_column_int (stmt, 0);
    data_size = sqlite3_column_bytes (stmt, 1);
    data = sqlite3_column_blob (stmt, 1);
    label = (const char*) sqlite3_column_text (stmt, 2);
    if (NULL == zone_key)
    {
      /* must be "iterate_all_zones", got one extra return value */
      if (sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey) !=
	  sqlite3_column_bytes (stmt, 3))
      {
	GNUNET_break (0);
	ret = GNUNET_SYSERR;
      }
      else
      {
	zone_key = sqlite3_column_blob (stmt, 3);
      }
    }
    if (record_count > 64 * 1024)
    {
      /* sanity check, don't stack allocate far too much just
	 because database might contain a large value here */
      GNUNET_break (0);
      ret = GNUNET_SYSERR;
    }
    else
    {
      struct GNUNET_GNSRECORD_Data rd[record_count];

      if (GNUNET_OK !=
	  GNUNET_GNSRECORD_records_deserialize (data_size, data,
						record_count, rd))
      {
	GNUNET_break (0);
	ret = GNUNET_SYSERR;
      }
      else if (NULL != zone_key)
      {
      	if (NULL != iter)
      		iter (iter_cls, zone_key, label, record_count, rd);
	ret = GNUNET_YES;
      }
    }
  }
  else
  {
    if (SQLITE_DONE != sret)
      LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR, "sqlite_step");
  }
  if (SQLITE_OK != sqlite3_reset (stmt))
    LOG_SQLITE (plugin,
		GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_reset");
  return ret;
}

/**
 * Lookup records in the datastore for which we are the authority.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone private key of the zone
 * @param label name of the record in the zone
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
namestore_sqlite_lookup_records (void *cls,
    const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone, const char *label,
    GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  int err;

  if (NULL == zone)
  {
    return GNUNET_SYSERR;
  }
  else
  {
    stmt = plugin->lookup_label;
    err = ( (SQLITE_OK != sqlite3_bind_blob (stmt, 1,
                                             zone, sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey),
                                             SQLITE_STATIC)) ||
            (SQLITE_OK != sqlite3_bind_text (stmt, 2,
                                              label, -1, SQLITE_STATIC)) );
  }
  if (err)
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  return get_record_and_call_iterator (plugin, stmt, zone, iter, iter_cls);
}


/**
 * Iterate over the results for a particular key and zone in the
 * datastore.  Will return at most one result to the iterator.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone, NULL to iterate over all zones
 * @param offset offset in the list of all matching records
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
 */
static int
namestore_sqlite_iterate_records (void *cls,
				  const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
				  uint64_t offset,
				  GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  int err;

  if (NULL == zone)
  {
    stmt = plugin->iterate_all_zones;
    err = (SQLITE_OK != sqlite3_bind_int64 (stmt, 1,
					    offset));
  }
  else
  {
    stmt = plugin->iterate_zone;
    err = ( (SQLITE_OK != sqlite3_bind_blob (stmt, 1,
					     zone, sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey),
					     SQLITE_STATIC)) ||
	    (SQLITE_OK != sqlite3_bind_int64 (stmt, 2,
					      offset)) );
  }
  if (err)
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		"sqlite3_bind_XXXX");
    if (SQLITE_OK != sqlite3_reset (stmt))
      LOG_SQLITE (plugin,
		  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
		  "sqlite3_reset");
    return GNUNET_SYSERR;
  }
  return get_record_and_call_iterator (plugin, stmt, zone, iter, iter_cls);
}


/**
 * Look for an existing PKEY delegation record for a given public key.
 * Returns at most one result to the iterator.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone private key of the zone to look up in, never NULL
 * @param value_zone public key of the target zone (value), never NULL
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
 */
static int
namestore_sqlite_zone_to_name (void *cls,
			       const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
			       const struct GNUNET_CRYPTO_EcdsaPublicKey *value_zone,
			       GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;

  stmt = plugin->zone_to_name;
  if ( (SQLITE_OK != sqlite3_bind_blob (stmt, 1,
					zone, sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey),
					SQLITE_STATIC)) ||
       (SQLITE_OK != sqlite3_bind_blob (stmt, 2,
					value_zone, sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Performing reverse lookup for `%s'\n",
       GNUNET_GNSRECORD_z2s (value_zone));

  return get_record_and_call_iterator (plugin, stmt, zone, iter, iter_cls);
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_NAMESTORE_PluginEnvironment*"
 * @return NULL on error, otherwise the plugin context
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
  api = GNUNET_new (struct GNUNET_NAMESTORE_PluginFunctions);
  api->cls = &plugin;
  api->store_records = &namestore_sqlite_store_records;
  api->iterate_records = &namestore_sqlite_iterate_records;
  api->zone_to_name = &namestore_sqlite_zone_to_name;
  api->lookup_records = &namestore_sqlite_lookup_records;
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

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sqlite plugin is finished\n");
  return NULL;
}

/* end of plugin_namestore_sqlite.c */
