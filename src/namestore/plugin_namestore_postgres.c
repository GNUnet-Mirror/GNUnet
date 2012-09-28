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
 * @file namestore/plugin_namestore_postgres.c
 * @brief postgres-based namestore backend
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_namestore_plugin.h"
#include "gnunet_namestore_service.h"
#include "gnunet_postgres_lib.h"
#include "namestore.h"


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
#define LOG_POSTGRES(db, level, cmd) do { GNUNET_log_from (level, "namestore-postgres", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); } while(0)

#define LOG(kind,...) GNUNET_log_from (kind, "namestore-postgres", __VA_ARGS__)


/**
 * Context for all functions in this plugin.
 */
struct Plugin
{

  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Native Postgres database handle.
   */
  PGconn *dbh;

};


/**
 * Create our database indices.
 *
 * @param dbh handle to the database
 */
static void
create_indices (PGconn * dbh)
{
  /* create indices */
  if ( (GNUNET_OK !=
	GNUNET_POSTGRES_exec (dbh, "CREATE INDEX ir_zone_name_rv ON ns091records (zone_hash,record_name_hash,rvalue)")) ||
       (GNUNET_OK !=
	GNUNET_POSTGRES_exec (dbh, "CREATE INDEX ir_zone_delegation ON ns091records (zone_hash,zone_delegation)")) ||
       (GNUNET_OK !=
	GNUNET_POSTGRES_exec (dbh, "CREATE INDEX ir_zone_rv ON ns091records (zone_hash,rvalue)")) ||
       (GNUNET_OK !=
	GNUNET_POSTGRES_exec (dbh, "CREATE INDEX ir_zone ON ns091records (zone_hash)")) ||
       (GNUNET_OK !=
	GNUNET_POSTGRES_exec (dbh, "CREATE INDEX ir_name_rv ON ns091records (record_name_hash,rvalue)")) ||
       (GNUNET_OK !=
	GNUNET_POSTGRES_exec (dbh, "CREATE INDEX ir_rv ON ns091records (rvalue)")) )
    LOG (GNUNET_ERROR_TYPE_ERROR, 
	 _("Failed to create indices\n"));
}


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
  PGresult *res;

  plugin->dbh = GNUNET_POSTGRES_connect (plugin->cfg,
					 "namestore-postgres");
  if (NULL == plugin->dbh)
    return GNUNET_SYSERR;
  if (GNUNET_YES == 
      GNUNET_CONFIGURATION_get_value_yesno (plugin->cfg,
					    "namestore-postgres",
					    "TEMPORARY_TABLE"))
  {
    res =
      PQexec (plugin->dbh,
              "CREATE TEMPORARY TABLE ns091records ("
	      " zone_key BYTEA NOT NULL DEFAULT ''," 
	      " zone_delegation BYTEA NOT NULL DEFAULT ''," 
	      " zone_hash BYTEA NOT NULL DEFAULT ''," 
	      " record_count INTEGER NOT NULL DEFAULT 0,"
	      " record_data BYTEA NOT NULL DEFAULT '',"
	      " block_expiration_time BIGINT NOT NULL DEFAULT 0," 
	      " signature BYTEA NOT NULL DEFAULT '',"
	      " record_name TEXT NOT NULL DEFAULT ''," 
	      " record_name_hash BYTEA NOT NULL DEFAULT ''," 
	      " rvalue BIGINT NOT NULL DEFAULT 0"
	      ")" "WITH OIDS");
  }
  else
    res =
      PQexec (plugin->dbh,
              "CREATE TABLE ns091records ("
	      " zone_key BYTEA NOT NULL DEFAULT ''," 
	      " zone_delegation BYTEA NOT NULL DEFAULT ''," 
	      " zone_hash BYTEA NOT NULL DEFAULT ''," 
	      " record_count INTEGER NOT NULL DEFAULT 0,"
	      " record_data BYTEA NOT NULL DEFAULT '',"
	      " block_expiration_time BIGINT NOT NULL DEFAULT 0," 
	      " signature BYTEA NOT NULL DEFAULT '',"
	      " record_name TEXT NOT NULL DEFAULT ''," 
	      " record_name_hash BYTEA NOT NULL DEFAULT ''," 
	      " rvalue BIGINT NOT NULL DEFAULT 0"
	      ")" "WITH OIDS");

  if ((NULL == res) || ((PQresultStatus (res) != PGRES_COMMAND_OK) && (0 != strcmp ("42P07",    /* duplicate table */
                                                                                    PQresultErrorField
                                                                                    (res,
                                                                                     PG_DIAG_SQLSTATE)))))
  {
    (void) GNUNET_POSTGRES_check_result (plugin->dbh, res, PGRES_COMMAND_OK, "CREATE TABLE",
					 "ns091records");
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  if (PQresultStatus (res) == PGRES_COMMAND_OK)
    create_indices (plugin->dbh);
  PQclear (res);

  if ((GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"put_records",
				"INSERT INTO ns091records (zone_key, record_name, record_count, record_data, block_expiration_time, signature" 
				", zone_delegation, zone_hash, record_name_hash, rvalue) VALUES "
 				"($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)", 10)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"remove_records",
				"DELETE FROM ns091records WHERE zone_hash=$1 AND record_name_hash=$2", 2)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"iterate_records",
				"SELECT zone_key, record_name, record_count, record_data, block_expiration_time, signature" 
				" FROM ns091records WHERE zone_hash=$1 AND record_name_hash=$2 ORDER BY rvalue LIMIT 1 OFFSET $3", 3)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"iterate_by_zone",
				"SELECT zone_key, record_name, record_count, record_data, block_expiration_time, signature" 
				" FROM ns091records WHERE zone_hash=$1 ORDER BY rvalue  LIMIT 1 OFFSET $2", 2)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"iterate_by_name",
				"SELECT zone_key, record_name, record_count, record_data, block_expiration_time, signature" 
				" FROM ns091records WHERE record_name_hash=$1 ORDER BY rvalue LIMIT 1 OFFSET $2", 2)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"iterate_all",
				"SELECT zone_key, record_name, record_count, record_data, block_expiration_time, signature" 
				" FROM ns091records ORDER BY rvalue LIMIT 1 OFFSET $1", 1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"zone_to_name",
				"SELECT zone_key, record_name, record_count, record_data, block_expiration_time, signature"
				" FROM ns091records WHERE zone_hash=$1 AND zone_delegation=$2", 2)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"delete_zone",
				"DELETE FROM ns091records WHERE zone_hash=$1", 1)))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
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
namestore_postgres_remove_records (void *cls, 
				 const struct GNUNET_CRYPTO_ShortHashCode *zone,
				 const char *name)
{
  struct Plugin *plugin = cls;
  PGresult *ret;
  struct GNUNET_CRYPTO_ShortHashCode nh;
  const char *paramValues[] = {
    (const char *) zone,
    (const char *) &nh
  };
  int paramLengths[] = {
    sizeof (struct GNUNET_CRYPTO_ShortHashCode),
    sizeof (struct GNUNET_CRYPTO_ShortHashCode)
  };
  const int paramFormats[] = { 1, 1 };
  size_t name_len;

  name_len = strlen (name);
  GNUNET_CRYPTO_short_hash (name, name_len, &nh);
  ret =
      PQexecPrepared (plugin->dbh, "remove_records", 2, paramValues, paramLengths,
                      paramFormats, 1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, ret, PGRES_COMMAND_OK, "PQexecPrepared", "remove_records"))
    return GNUNET_SYSERR;
  PQclear (ret);
  return GNUNET_OK;
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
namestore_postgres_put_records (void *cls, 
				const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
				struct GNUNET_TIME_Absolute expire,
				const char *name,
				unsigned int rd_count,
				const struct GNUNET_NAMESTORE_RecordData *rd,
				const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  struct Plugin *plugin = cls;
  PGresult *ret;
  struct GNUNET_CRYPTO_ShortHashCode zone;
  struct GNUNET_CRYPTO_ShortHashCode zone_delegation;
  struct GNUNET_CRYPTO_ShortHashCode nh;
  size_t name_len;
  uint64_t rvalue;
  size_t data_size;
  unsigned int i;

  GNUNET_CRYPTO_short_hash (zone_key, 
			    sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
			    &zone);
  (void) namestore_postgres_remove_records (plugin, &zone, name);
  name_len = strlen (name);
  GNUNET_CRYPTO_short_hash (name, name_len, &nh);
  memset (&zone_delegation, 0, sizeof (zone_delegation));
  for (i=0;i<rd_count;i++)
    if (rd[i].record_type == GNUNET_NAMESTORE_TYPE_PKEY)
    {
      GNUNET_assert (sizeof (struct GNUNET_CRYPTO_ShortHashCode) == rd[i].data_size);
      memcpy (&zone_delegation,
	      rd[i].data,
	      sizeof (struct GNUNET_CRYPTO_ShortHashCode));
      break;
    }
  rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX);
  data_size = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  if (data_size > 64 * 65536)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  {
    char data[data_size];
    uint64_t expire_be = GNUNET_htonll (expire.abs_value);
    uint64_t rvalue_be = GNUNET_htonll (rvalue);
    uint32_t rd_count_be = htonl ((uint32_t) rd_count);
    const char *paramValues[] = {
      (const char *) zone_key,
      (const char *) name,
      (const char *) &rd_count_be,
      (const char *) data,
      (const char *) &expire_be,
      (const char *) signature,
      (const char *) &zone_delegation,
      (const char *) &zone,
      (const char *) &nh,
      (const char *) &rvalue_be
    };
    int paramLengths[] = {
      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
      name_len,
      sizeof (uint32_t),
      data_size,
      sizeof (uint64_t),
      sizeof (struct GNUNET_CRYPTO_RsaSignature), 
      sizeof (struct GNUNET_CRYPTO_ShortHashCode),
      sizeof (struct GNUNET_CRYPTO_ShortHashCode),
      sizeof (struct GNUNET_CRYPTO_ShortHashCode),
      sizeof (uint64_t)
    };
    const int paramFormats[] = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };

    if (data_size != GNUNET_NAMESTORE_records_serialize (rd_count, rd,
							 data_size, data))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    ret =
      PQexecPrepared (plugin->dbh, "put_records", 10, paramValues, paramLengths,
                      paramFormats, 1);
    if (GNUNET_OK !=
	GNUNET_POSTGRES_check_result (plugin->dbh, ret, PGRES_COMMAND_OK, "PQexecPrepared", "put_records"))
      return GNUNET_SYSERR;
    PQclear (ret);
  }
  return GNUNET_OK;  
}


/**
 * The given 'postgres' result was obtained from the database.
 * Parse the record and give it to the iterator.
 *
 * @param plugin plugin context
 * @param stmt_name name of the prepared statement that was executed
 * @param res result from postgres to interpret (and then clean up)
 * @param iter iterator to call with the result
 * @param iter_cls closure for 'iter'
 * @return GNUNET_OK on success, GNUNET_NO if there were no results, GNUNET_SYSERR on error
 *       'iter' will have been called unless the return value is 'GNUNET_SYSERR'
 */
static int
get_record_and_call_iterator (struct Plugin *plugin,
			      const char *stmt_name,
			      PGresult *res,
			      GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
  unsigned int record_count;
  size_t data_size;
  const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key;
  const struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_TIME_Absolute expiration;
  const char *data;
  const char *name;
  unsigned int cnt;
  size_t name_len;

  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, res, PGRES_TUPLES_OK, "PQexecPrepared",
				    stmt_name))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Ending iteration (postgres error)\n");
    return GNUNET_SYSERR;
  }

  if (0 == (cnt = PQntuples (res)))
  {
    /* no result */
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Ending iteration (no more results)\n");
    PQclear (res);
    iter (iter_cls, NULL, GNUNET_TIME_UNIT_ZERO_ABS, NULL, 0, NULL, NULL);
    return GNUNET_NO;
  }
  GNUNET_assert (1 == cnt);
  if ((6 != PQnfields (res)) || 
      (sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) != PQgetlength (res, 0, 0)) || 
      (sizeof (uint32_t) != PQfsize (res, 2)) || 
      (sizeof (uint64_t) != PQfsize (res, 4)) || 
      (sizeof (struct GNUNET_CRYPTO_RsaSignature) != PQgetlength (res, 0, 5)))
  {
    GNUNET_break (0);
    PQclear (res);
    return GNUNET_SYSERR;
  }
  zone_key = (const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *) PQgetvalue (res, 0, 0);
  name = PQgetvalue (res, 0, 1);
  name_len = PQgetlength (res, 0, 1);
  record_count = ntohl (*(uint32_t *) PQgetvalue (res, 0, 2));
  data_size = PQgetlength (res, 0, 3);
  data = PQgetvalue (res, 0, 3);
  expiration.abs_value =
    GNUNET_ntohll (*(uint64_t *) PQgetvalue (res, 0, 4));
  sig = (const struct GNUNET_CRYPTO_RsaSignature*) PQgetvalue (res, 0, 5);
  if (record_count > 64 * 1024)
  {
    /* sanity check, don't stack allocate far too much just
       because database might contain a large value here */
    GNUNET_break (0);
    PQclear (res);
    return GNUNET_SYSERR;
  }
  {
    struct GNUNET_NAMESTORE_RecordData rd[record_count];
    char buf[name_len + 1];
    
    memcpy (buf, name, name_len);
    buf[name_len] = '\0';
    if (GNUNET_OK !=
	GNUNET_NAMESTORE_records_deserialize (data_size, data,
					      record_count, rd))
    {
      GNUNET_break (0);
      PQclear (res);
      return GNUNET_SYSERR;
    }
    iter (iter_cls, zone_key, expiration, buf, 
	  record_count, rd, sig);
  }
  PQclear (res);
  return GNUNET_OK;
}
  
  
/**
 * Iterate over the results for a particular key and zone in the
 * datastore.  Will return at most one result to the iterator.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone, NULL to iterate over all zones
 * @param name name as string, NULL to iterate over all records of the zone
 * @param offset offset in the list of all matching records
 * @param iter function to call with the result
 * @param iter_cls closure for iter
 * @return GNUNET_OK on success, GNUNET_NO if there were no results, GNUNET_SYSERR on error
 *       'iter' will have been called unless the return value is 'GNUNET_SYSERR'
 */
static int 
namestore_postgres_iterate_records (void *cls, 
				  const struct GNUNET_CRYPTO_ShortHashCode *zone,
				  const char *name,
				  uint64_t offset,
				  GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  const char *stmt_name;
  struct GNUNET_CRYPTO_ShortHashCode name_hase;
  uint64_t offset_be = GNUNET_htonll (offset);
  const char *paramValues[] = {
    (const char *) zone,
    (const char *) &name_hase,
    (const char *) &offset_be,
    (const char *) zone,
    (const char *) &offset_be,
  };
  int paramLengths[] = {
    sizeof (struct GNUNET_CRYPTO_ShortHashCode),
    sizeof (struct GNUNET_CRYPTO_ShortHashCode),
    sizeof (uint64_t),
    sizeof (struct GNUNET_CRYPTO_ShortHashCode),
    sizeof (uint64_t)
  };
  const int paramFormats[] = { 1, 1, 1, 1, 1 };
  unsigned int num_params;
  unsigned int first_param;
  PGresult *res;

  if (NULL == zone)
    if (NULL == name)
    {
      stmt_name = "iterate_all";
      num_params = 1;
      first_param = 2;
    }
    else
    {
      GNUNET_CRYPTO_short_hash (name, strlen(name), &name_hase);
      stmt_name = "iterate_by_name";
      num_params = 2;
      first_param = 1;
    }
  else
    if (NULL == name)
    {
      stmt_name = "iterate_by_zone";
      num_params = 2;
      first_param = 3;
    }
    else
    {
      GNUNET_CRYPTO_short_hash (name, strlen(name), &name_hase);
      stmt_name = "iterate_records";
      num_params = 3;
      first_param = 0;
    }
  res =
      PQexecPrepared (plugin->dbh, stmt_name, num_params, 
		      &paramValues[first_param],
		      &paramLengths[first_param],
                      &paramFormats[first_param], 1);
  return get_record_and_call_iterator (plugin, stmt_name, res, iter, iter_cls);
}


/**
 * Look for an existing PKEY delegation record for a given public key.
 * Returns at most one result to the iterator.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone hash of public key of the zone to look up in, never NULL
 * @param value_zone hash of the public key of the target zone (value), never NULL
 * @param iter function to call with the result
 * @param iter_cls closure for iter
 * @return GNUNET_OK on success, GNUNET_NO if there were no results, GNUNET_SYSERR on error
 *       'iter' will have been called unless the return value is 'GNUNET_SYSERR'
 */
static int
namestore_postgres_zone_to_name (void *cls, 
			       const struct GNUNET_CRYPTO_ShortHashCode *zone,
			       const struct GNUNET_CRYPTO_ShortHashCode *value_zone,
			       GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  const char *paramValues[] = {
    (const char *) zone,
    (const char *) value_zone
  };
  int paramLengths[] = {
    sizeof (struct GNUNET_CRYPTO_ShortHashCode),
    sizeof (struct GNUNET_CRYPTO_ShortHashCode)
  };
  const int paramFormats[] = { 1, 1 };
  PGresult *res;

  res =
    PQexecPrepared (plugin->dbh, "zone_to_name", 2,
		    paramValues, paramLengths, paramFormats, 1);
  return get_record_and_call_iterator (plugin, "zone_to_name", res, iter, iter_cls);
}


/**
 * Delete an entire zone (all records).  Not used in normal operation.
 *
 * @param cls closure (internal context for the plugin)
 * @param zone zone to delete
 */
static void 
namestore_postgres_delete_zone (void *cls,
			      const struct GNUNET_CRYPTO_ShortHashCode *zone)
{
  struct Plugin *plugin = cls;
  PGresult *ret;
  const char *paramValues[] = {
    (const char *) zone,
  };
  int paramLengths[] = {
    sizeof (struct GNUNET_CRYPTO_ShortHashCode)
  };
  const int paramFormats[] = { 1 };

  ret =
      PQexecPrepared (plugin->dbh, "delete_zone", 1, paramValues, paramLengths,
                      paramFormats, 1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, ret, PGRES_COMMAND_OK, "PQexecPrepared", "delete_zone"))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Deleting zone failed!\n");		
    return;
  }
  PQclear (ret);
}


/**
 * Shutdown database connection and associate data
 * structures.
 *
 * @param plugin the plugin context (state for this module)
 */
static void
database_shutdown (struct Plugin *plugin)
{
  PQfinish (plugin->dbh);
  plugin->dbh = NULL;
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_NAMESTORE_PluginEnvironment*"
 * @return NULL on error, othrewise the plugin context
 */
void *
libgnunet_plugin_namestore_postgres_init (void *cls)
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
  api->put_records = &namestore_postgres_put_records;
  api->remove_records = &namestore_postgres_remove_records;
  api->iterate_records = &namestore_postgres_iterate_records;
  api->zone_to_name = &namestore_postgres_zone_to_name;
  api->delete_zone = &namestore_postgres_delete_zone;
  LOG (GNUNET_ERROR_TYPE_INFO, 
       _("Postgres database running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_namestore_postgres_done (void *cls)
{
  struct GNUNET_NAMESTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "postgres plugin is finished\n");
  return NULL;
}

/* end of plugin_namestore_postgres.c */
