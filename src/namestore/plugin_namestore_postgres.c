 /*
  * This file is part of GNUnet
  * (C) 2009-2013 Christian Grothoff (and other contributing authors)
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
	GNUNET_POSTGRES_exec (dbh,
                              "CREATE INDEX ir_query_hash ON ns096blocks (query,expiration_time)")) ||
       (GNUNET_OK !=
	GNUNET_POSTGRES_exec (dbh,
                              "CREATE INDEX ir_block_expiration ON ns096blocks (expiration_time)")) ||
       (GNUNET_OK !=
	GNUNET_POSTGRES_exec (dbh,
                              "CREATE INDEX ir_pkey_reverse ON ns097records (zone_private_key,pkey)")) ||
       (GNUNET_OK !=
	GNUNET_POSTGRES_exec (dbh,
                              "CREATE INDEX ir_pkey_iter ON ns097records (zone_private_key,rvalue)")) ||
       (GNUNET_OK !=
	GNUNET_POSTGRES_exec (dbh,
                              "CREATE INDEX it_iter ON ns097records (rvalue)")) )
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
              "CREATE TEMPORARY TABLE ns097records ("
	      " zone_private_key BYTEA NOT NULL DEFAULT '',"
	      " pkey BYTEA DEFAULT '',"
	      " rvalue BYTEA NOT NULL DEFAULT '',"
	      " record_count INTEGER NOT NULL DEFAULT 0,"
	      " record_data BYTEA NOT NULL DEFAULT '',"
	      " label TEXT NOT NULL DEFAULT ''"
	      ")" "WITH OIDS");
  }
  else
  {
    res =
      PQexec (plugin->dbh,
              "CREATE TABLE ns097records ("
	      " zone_private_key BYTEA NOT NULL DEFAULT '',"
	      " pkey BYTEA DEFAULT '',"
	      " rvalue BYTEA NOT NULL DEFAULT '',"
	      " record_count INTEGER NOT NULL DEFAULT 0,"
	      " record_data BYTEA NOT NULL DEFAULT '',"
	      " label TEXT NOT NULL DEFAULT ''"
	      ")" "WITH OIDS");
  }
  if ( (NULL == res) ||
       ((PQresultStatus (res) != PGRES_COMMAND_OK) &&
        (0 != strcmp ("42P07",    /* duplicate table */
                      PQresultErrorField
                      (res,
                       PG_DIAG_SQLSTATE)))))
  {
    (void) GNUNET_POSTGRES_check_result (plugin->dbh, res,
                                         PGRES_COMMAND_OK, "CREATE TABLE",
					 "ns097records");
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }


  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (plugin->cfg,
					    "namestore-postgres",
					    "TEMPORARY_TABLE"))
  {
    res =
      PQexec (plugin->dbh,
              "CREATE TEMPORARY TABLE ns096blocks ("
	      " query BYTEA NOT NULL DEFAULT '',"
	      " block BYTEA NOT NULL DEFAULT '',"
	      " expiration_time BIGINT NOT NULL DEFAULT 0"
	      ")" "WITH OIDS");
  }
  else
  {
    res =
      PQexec (plugin->dbh,
              "CREATE TABLE ns096blocks ("
	      " query BYTEA NOT NULL DEFAULT '',"
	      " block BYTEA NOT NULL DEFAULT '',"
	      " expiration_time BIGINT NOT NULL DEFAULT 0"
	      ")" "WITH OIDS");
  }
  if ( (NULL == res) ||
       ((PQresultStatus (res) != PGRES_COMMAND_OK) &&
        (0 != strcmp ("42P07",    /* duplicate table */
                      PQresultErrorField
                      (res,
                       PG_DIAG_SQLSTATE)))))
  {
    (void) GNUNET_POSTGRES_check_result (plugin->dbh, res,
                                         PGRES_COMMAND_OK, "CREATE TABLE",
					 "ns096blocks");
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  if (PQresultStatus (res) == PGRES_COMMAND_OK)
    create_indices (plugin->dbh);
  PQclear (res);

  if ((GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"cache_block",
				"INSERT INTO ns096blocks (query, block, expiration_time) VALUES "
 				"($1, $2, $3)", 3)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"expire_blocks",
				"DELETE FROM ns096blocks WHERE expiration_time<$1", 1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"delete_block",
				"DELETE FROM ns096blocks WHERE query=$1 AND expiration_time<=$2", 2)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"lookup_block",
				"SELECT block FROM ns096blocks WHERE query=$1"
				" ORDER BY expiration_time DESC LIMIT 1", 1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"store_records",
				"INSERT INTO ns097records (zone_private_key, pkey, rvalue, record_count, record_data, label) VALUES "
                                "($1, $2, $3, $4, $5, $6)", 6)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"delete_records",
				"DELETE FROM ns097records WHERE zone_private_key=$1 AND label=$2", 2)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"zone_to_name",
				"SELECT record_count,record_data,label FROM ns097records"
                                " WHERE zone_private_key=$1 AND pkey=$2", 2)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"iterate_zone",
				"SELECT record_count, record_data, label FROM ns097records"
                                " WHERE zone_private_key=$1 ORDER BY rvalue LIMIT 1 OFFSET $2", 2)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
				"iterate_all_zones",
				"SELECT record_count,record_data,label,zone_private_key"
				" FROM ns097records ORDER BY rvalue LIMIT 1 OFFSET $1", 1)))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Removes any expired block.
 *
 * @param plugin the plugin
 */
static void
namestore_postgres_expire_blocks (struct Plugin *plugin)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  struct GNUNET_TIME_AbsoluteNBO now_be = GNUNET_TIME_absolute_hton (now);
  const char *paramValues[] = {
    (const char *) &now_be
  };
  int paramLengths[] = {
    sizeof (now_be)
  };
  const int paramFormats[] = { 1 };
  PGresult *res;

  res =
    PQexecPrepared (plugin->dbh, "expire_blocks", 1,
		    paramValues, paramLengths, paramFormats, 1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    res,
                                    PGRES_COMMAND_OK,
                                    "PQexecPrepared",
                                    "expire_blocks"))
    return;
  PQclear (res);
}


/**
 * Delete older block in the datastore.
 *
 * @param the plugin
 * @param query query for the block
 * @param expiration time how old does the block have to be for deletion
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static void
delete_old_block (struct Plugin *plugin,
                  const struct GNUNET_HashCode *query,
                  struct GNUNET_TIME_AbsoluteNBO expiration_time)
{
  const char *paramValues[] = {
    (const char *) query,
    (const char *) &expiration_time
  };
  int paramLengths[] = {
    sizeof (*query),
    sizeof (expiration_time)
  };
  const int paramFormats[] = { 1, 1 };
  PGresult *res;

  res =
    PQexecPrepared (plugin->dbh, "delete_block", 2,
		    paramValues, paramLengths, paramFormats, 1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    res,
                                    PGRES_COMMAND_OK,
                                    "PQexecPrepared",
                                    "delete_block"))
    return;
  PQclear (res);
}


/**
 * Cache a block in the datastore.
 *
 * @param cls closure (internal context for the plugin)
 * @param block block to cache
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
namestore_postgres_cache_block (void *cls,
                                const struct GNUNET_NAMESTORE_Block *block)
{
  struct Plugin *plugin = cls;
  struct GNUNET_HashCode query;
  size_t block_size = ntohl (block->purpose.size) +
    sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
    sizeof (struct GNUNET_CRYPTO_EcdsaSignature);
  const char *paramValues[] = {
    (const char *) &query,
    (const char *) block,
    (const char *) &block->expiration_time
  };
  int paramLengths[] = {
    sizeof (query),
    (int) block_size,
    sizeof (block->expiration_time)
  };
  const int paramFormats[] = { 1, 1, 1 };
  PGresult *res;

  namestore_postgres_expire_blocks (plugin);
  GNUNET_CRYPTO_hash (&block->derived_key,
		      sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
		      &query);
  if (block_size > 64 * 65536)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  delete_old_block (plugin, &query, block->expiration_time);

  res =
    PQexecPrepared (plugin->dbh, "cache_block", 3,
		    paramValues, paramLengths, paramFormats, 1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    res,
                                    PGRES_COMMAND_OK,
                                    "PQexecPrepared",
                                    "cache_block"))
    return GNUNET_SYSERR;
  PQclear (res);
  return GNUNET_OK;
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
namestore_postgres_lookup_block (void *cls,
                                 const struct GNUNET_HashCode *query,
                                 GNUNET_NAMESTORE_BlockCallback iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  const char *paramValues[] = {
    (const char *) query
  };
  int paramLengths[] = {
    sizeof (*query)
  };
  const int paramFormats[] = { 1 };
  PGresult *res;
  unsigned int cnt;
  size_t bsize;
  const struct GNUNET_NAMESTORE_Block *block;

  res = PQexecPrepared (plugin->dbh,
                        "lookup_block", 1,
                        paramValues, paramLengths, paramFormats,
                        1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, res, PGRES_TUPLES_OK,
                                    "PQexecPrepared",
				    "lookup_block"))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Failing lookup (postgres error)\n");
    return GNUNET_SYSERR;
  }
  if (0 == (cnt = PQntuples (res)))
  {
    /* no result */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Ending iteration (no more results)\n");
    PQclear (res);
    return GNUNET_NO;
  }
  GNUNET_assert (1 == cnt);
  GNUNET_assert (1 != PQnfields (res));
  bsize = PQgetlength (res, 0, 0);
  block = (const struct GNUNET_NAMESTORE_Block *) PQgetvalue (res, 0, 0);
  if ( (bsize < sizeof (*block)) ||
       (bsize != ntohl (block->purpose.size) +
        sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
        sizeof (struct GNUNET_CRYPTO_EcdsaSignature)) )
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Failing lookup (corrupt block)\n");
    PQclear (res);
    return GNUNET_SYSERR;
  }
  iter (iter_cls, block);
  PQclear (res);
  return GNUNET_OK;
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
namestore_postgres_store_records (void *cls,
                                  const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
                                  const char *label,
                                  unsigned int rd_count,
                                  const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct Plugin *plugin = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  uint64_t rvalue;
  uint32_t rd_count_nbo = htonl ((uint32_t) rd_count);
  size_t data_size;
  unsigned int i;

  memset (&pkey, 0, sizeof (pkey));
  for (i=0;i<rd_count;i++)
    if (GNUNET_NAMESTORE_TYPE_PKEY == rd[i].record_type)
    {
      GNUNET_break (sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) == rd[i].data_size);
      memcpy (&pkey,
              rd[i].data,
              rd[i].data_size);
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
    const char *paramValues[] = {
      (const char *) zone_key,
      (const char *) &pkey,
      (const char *) &rvalue,
      (const char *) &rd_count_nbo,
      (const char *) data,
      label
    };
    int paramLengths[] = {
      sizeof (*zone_key),
      sizeof (pkey),
      sizeof (rvalue),
      sizeof (rd_count_nbo),
      data_size,
      strlen (label)
    };
    const int paramFormats[] = { 1, 1, 1, 1, 1, 1 };
    PGresult *res;

    if (data_size != GNUNET_NAMESTORE_records_serialize (rd_count, rd,
							 data_size, data))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    res =
      PQexecPrepared (plugin->dbh, "store_records", 6,
                      paramValues, paramLengths, paramFormats, 1);
    if (GNUNET_OK !=
        GNUNET_POSTGRES_check_result (plugin->dbh,
                                      res,
                                      PGRES_COMMAND_OK,
                                      "PQexecPrepared",
                                      "store_records"))
      return GNUNET_SYSERR;
    PQclear (res);
    return GNUNET_OK;
  }
}


/**
 * A statement has been run.  We should evaluate the result, and if possible
 * call the given @a iter with the result.
 *
 * @param plugin plugin context
 * @param res result from the statement that was run (to be cleaned up)
 * @param zone_key private key of the zone, could be NULL, in which case we should
 *        get the zone from @a res
 * @param iter iterator to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
 */
static int
get_record_and_call_iterator (struct Plugin *plugin,
                              PGresult *res,
			      const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key,
			      GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
  const char *data;
  size_t data_size;
  uint32_t record_count;
  const char *label;
  size_t label_len;
  unsigned int cnt;

  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, res, PGRES_TUPLES_OK,
                                    "PQexecPrepared",
				    "iteration"))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Failing lookup (postgres error)\n");
    return GNUNET_SYSERR;
  }
  if (0 == (cnt = PQntuples (res)))
  {
    /* no result */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Ending iteration (no more results)\n");
    PQclear (res);
    return GNUNET_NO;
  }
  GNUNET_assert (1 == cnt);
  GNUNET_assert (3 + ((NULL == zone_key) ? 1 : 0) == PQnfields (res));
  if (NULL == zone_key)
  {
    if (sizeof (struct GNUNET_CRYPTO_EcdsaPrivateKey) != PQgetlength (res, 0, 3))
    {
      GNUNET_break (0);
      PQclear (res);
      return GNUNET_SYSERR;
    }
    zone_key = (const struct GNUNET_CRYPTO_EcdsaPrivateKey *) PQgetvalue (res, 0, 3);
  }
  if (sizeof (uint32_t) != PQfsize (res, 0))
  {
    GNUNET_break (0);
    PQclear (res);
    return GNUNET_SYSERR;
  }

  record_count = ntohl (*(uint32_t *) PQgetvalue (res, 0, 0));
  data = PQgetvalue (res, 0, 1);
  data_size = PQgetlength (res, 0, 1);
  label = PQgetvalue (res, 0, 2);
  label_len = PQgetlength (res, 0, 1);
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
    char buf[label_len + 1];

    memcpy (buf, label, label_len);
    buf[label_len] = '\0';
    if (GNUNET_OK !=
	GNUNET_NAMESTORE_records_deserialize (data_size, data,
					      record_count, rd))
    {
      GNUNET_break (0);
      PQclear (res);
      return GNUNET_SYSERR;
    }
    iter (iter_cls, zone_key, buf, record_count, rd);
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
 * @param offset offset in the list of all matching records
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
 */
static int
namestore_postgres_iterate_records (void *cls,
                                    const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                                    uint64_t offset,
                                    GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  uint64_t offset_be = GNUNET_htonll (offset);

  if (NULL == zone)
  {
    const char *paramValues[] = {
      (const char *) &offset_be
    };
    int paramLengths[] = {
      sizeof (offset_be)
    };
    const int paramFormats[] = { 1 };
    PGresult *res;

    res = PQexecPrepared (plugin->dbh,
                          "iterate_all_zones", 1,
                          paramValues, paramLengths, paramFormats,
                          1);
    return get_record_and_call_iterator (plugin,
                                         res,
                                         NULL,
                                         iter, iter_cls);
  }
  else
  {
    const char *paramValues[] = {
      (const char *) zone,
      (const char *) &offset_be
    };
    int paramLengths[] = {
      sizeof (*zone),
      sizeof (offset_be)
    };
    const int paramFormats[] = { 1, 1 };
    PGresult *res;

    res = PQexecPrepared (plugin->dbh,
                          "iterate_zone", 2,
                          paramValues, paramLengths, paramFormats,
                          1);
    return get_record_and_call_iterator (plugin,
                                         res,
                                         zone,
                                         iter, iter_cls);
  }
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
namestore_postgres_zone_to_name (void *cls,
                                 const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                                 const struct GNUNET_CRYPTO_EcdsaPublicKey *value_zone,
                                 GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  const char *paramValues[] = {
    (const char *) zone,
    (const char *) value_zone
  };
  int paramLengths[] = {
    sizeof (*zone),
    sizeof (*value_zone)
  };
  const int paramFormats[] = { 1, 1 };
  PGresult *res;

  res = PQexecPrepared (plugin->dbh,
                        "zone_to_name", 2,
                        paramValues, paramLengths, paramFormats,
                        1);
  return get_record_and_call_iterator (plugin,
                                       res,
                                       zone,
                                       iter, iter_cls);
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
  api = GNUNET_new (struct GNUNET_NAMESTORE_PluginFunctions);
  api->cls = &plugin;
  api->cache_block = &namestore_postgres_cache_block;
  api->lookup_block = &namestore_postgres_lookup_block;
  api->store_records = &namestore_postgres_store_records;
  api->iterate_records = &namestore_postgres_iterate_records;
  api->zone_to_name = &namestore_postgres_zone_to_name;
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
