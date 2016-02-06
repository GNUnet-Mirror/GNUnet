/*
     This file is part of GNUnet
     Copyright (C) 2009-2016 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file datastore/plugin_datastore_postgres.c
 * @brief postgres-based datastore backend
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_datastore_plugin.h"
#include "gnunet_postgres_lib.h"
#include "gnunet_pq_lib.h"


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
#define BUSY_TIMEOUT GNUNET_TIME_UNIT_SECONDS


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
   * Native Postgres database handle.
   */
  PGconn *dbh;

};


/**
 * @brief Get a database handle
 *
 * @param plugin global context
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
init_connection (struct Plugin *plugin)
{
  PGresult *ret;

  plugin->dbh = GNUNET_POSTGRES_connect (plugin->env->cfg, "datastore-postgres");
  if (NULL == plugin->dbh)
    return GNUNET_SYSERR;

  ret =
      PQexec (plugin->dbh,
              "CREATE TABLE gn090 (" 
	      "  repl INTEGER NOT NULL DEFAULT 0,"
              "  type INTEGER NOT NULL DEFAULT 0,"
              "  prio INTEGER NOT NULL DEFAULT 0,"
              "  anonLevel INTEGER NOT NULL DEFAULT 0,"
              "  expire BIGINT NOT NULL DEFAULT 0,"
              "  rvalue BIGINT NOT NULL DEFAULT 0,"
              "  hash BYTEA NOT NULL DEFAULT '',"
              "  vhash BYTEA NOT NULL DEFAULT '',"
              "  value BYTEA NOT NULL DEFAULT '')" 
	      "WITH OIDS");
  if ( (NULL == ret) ||
       ((PQresultStatus (ret) != PGRES_COMMAND_OK) &&
        (0 != strcmp ("42P07",    /* duplicate table */
                      PQresultErrorField
                      (ret,
                       PG_DIAG_SQLSTATE)))))
  {
    (void) GNUNET_POSTGRES_check_result (plugin->dbh,
                                         ret,
                                         PGRES_COMMAND_OK,
                                         "CREATE TABLE",
                                         "gn090");
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }

  if (PQresultStatus (ret) == PGRES_COMMAND_OK)
  {
    if ((GNUNET_OK !=
         GNUNET_POSTGRES_exec (plugin->dbh, "CREATE INDEX idx_hash ON gn090 (hash)")) ||
        (GNUNET_OK !=
         GNUNET_POSTGRES_exec (plugin->dbh, "CREATE INDEX idx_hash_vhash ON gn090 (hash,vhash)")) ||
        (GNUNET_OK !=
         GNUNET_POSTGRES_exec (plugin->dbh, "CREATE INDEX idx_prio ON gn090 (prio)")) ||
        (GNUNET_OK !=
         GNUNET_POSTGRES_exec (plugin->dbh, "CREATE INDEX idx_expire ON gn090 (expire)")) ||
        (GNUNET_OK !=
         GNUNET_POSTGRES_exec (plugin->dbh,
			       "CREATE INDEX idx_prio_anon ON gn090 (prio,anonLevel)")) ||
        (GNUNET_OK !=
         GNUNET_POSTGRES_exec (plugin->dbh,
			       "CREATE INDEX idx_prio_hash_anon ON gn090 (prio,hash,anonLevel)")) ||
        (GNUNET_OK !=
         GNUNET_POSTGRES_exec (plugin->dbh, "CREATE INDEX idx_repl_rvalue ON gn090 (repl,rvalue)")) ||
        (GNUNET_OK !=
         GNUNET_POSTGRES_exec (plugin->dbh, "CREATE INDEX idx_expire_hash ON gn090 (expire,hash)")))
    {
      PQclear (ret);
      PQfinish (plugin->dbh);
      plugin->dbh = NULL;
      return GNUNET_SYSERR;
    }
  }
  PQclear (ret);

  ret =
      PQexec (plugin->dbh,
              "ALTER TABLE gn090 ALTER value SET STORAGE EXTERNAL");
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, ret, PGRES_COMMAND_OK, "ALTER TABLE", "gn090"))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  PQclear (ret);
  ret = PQexec (plugin->dbh, "ALTER TABLE gn090 ALTER hash SET STORAGE PLAIN");
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, ret, PGRES_COMMAND_OK, "ALTER TABLE", "gn090"))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  PQclear (ret);
  ret = PQexec (plugin->dbh, "ALTER TABLE gn090 ALTER vhash SET STORAGE PLAIN");
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, ret, PGRES_COMMAND_OK, "ALTER TABLE", "gn090"))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  PQclear (ret);
  if ((GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "getvt",
                   "SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "WHERE hash=$1 AND vhash=$2 AND type=$3 "
                   "ORDER BY oid ASC LIMIT 1 OFFSET $4", 4)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "gett",
                   "SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "WHERE hash=$1 AND type=$2 "
                   "ORDER BY oid ASC LIMIT 1 OFFSET $3", 3)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "getv",
                   "SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "WHERE hash=$1 AND vhash=$2 "
                   "ORDER BY oid ASC LIMIT 1 OFFSET $3", 3)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "get",
                   "SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "WHERE hash=$1 " "ORDER BY oid ASC LIMIT 1 OFFSET $2", 2)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "count_getvt",
				"SELECT count(*) FROM gn090 WHERE hash=$1 AND vhash=$2 AND type=$3", 3)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "count_gett",
				"SELECT count(*) FROM gn090 WHERE hash=$1 AND type=$2", 2)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "count_getv",
				"SELECT count(*) FROM gn090 WHERE hash=$1 AND vhash=$2", 2)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "count_get",
				"SELECT count(*) FROM gn090 WHERE hash=$1", 1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "put",
                   "INSERT INTO gn090 (repl, type, prio, anonLevel, expire, rvalue, hash, vhash, value) "
                   "VALUES ($1, $2, $3, $4, $5, RANDOM(), $6, $7, $8)", 9)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "update",
                   "UPDATE gn090 SET prio = prio + $1, expire = CASE WHEN expire < $2 THEN $2 ELSE expire END "
                   "WHERE oid = $3", 3)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "decrepl",
                   "UPDATE gn090 SET repl = GREATEST (repl - 1, 0) "
                   "WHERE oid = $1", 1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "select_non_anonymous",
                   "SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "WHERE anonLevel = 0 AND type = $1 ORDER BY oid DESC LIMIT 1 OFFSET $2",
                   1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "select_expiration_order",
                   "(SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "WHERE expire < $1 ORDER BY prio ASC LIMIT 1) " "UNION "
                   "(SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "ORDER BY prio ASC LIMIT 1) " "ORDER BY expire ASC LIMIT 1",
                   1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "select_replication_order",
                   "SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "ORDER BY repl DESC,RANDOM() LIMIT 1", 0)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "delrow", "DELETE FROM gn090 " "WHERE oid=$1", 1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "get_keys", "SELECT hash FROM gn090", 0)))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Get an estimate of how much space the database is
 * currently using.
 *
 * @param cls our `struct Plugin *`
 * @return number of bytes used on disk
 */
static void
postgres_plugin_estimate_size (void *cls, unsigned long long *estimate)
{
  struct Plugin *plugin = cls;
  unsigned long long total;
  PGresult *ret;

  if (NULL == estimate)
    return;
  ret =
      PQexecParams (plugin->dbh,
                    "SELECT SUM(LENGTH(value))+256*COUNT(*) FROM gn090", 0,
                    NULL, NULL, NULL, NULL, 1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, 
				    ret, 
				    PGRES_TUPLES_OK, 
				    "PQexecParams", 
				    "get_size"))
  {
    *estimate = 0;
    return;
  }
  if ((PQntuples (ret) != 1) || (PQnfields (ret) != 1) )
  {
    GNUNET_break (0);
    PQclear (ret);
    *estimate = 0;
    return;
  }
  if (PQgetlength (ret, 0, 0) != sizeof (unsigned long long))
  {
    GNUNET_break (0 == PQgetlength (ret, 0, 0));
    PQclear (ret);
    *estimate = 0;
    return;
  }
  total = GNUNET_ntohll (*(const unsigned long long *) PQgetvalue (ret, 0, 0));
  PQclear (ret);
  *estimate = total;
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure with the `struct Plugin`
 * @param key key for the item
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param cont continuation called with success or failure status
 * @param cont_cls continuation closure
 */
static void
postgres_plugin_put (void *cls, 
		     const struct GNUNET_HashCode *key,
		     uint32_t size,
                     const void *data, 
		     enum GNUNET_BLOCK_Type type,
                     uint32_t priority, 
		     uint32_t anonymity,
                     uint32_t replication,
                     struct GNUNET_TIME_Absolute expiration, 
		     PluginPutCont cont,
                     void *cont_cls)
{
  struct Plugin *plugin = cls;
  uint32_t utype = type;
  struct GNUNET_HashCode vhash;
  PGresult *ret;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_uint32 (&replication),
    GNUNET_PQ_query_param_uint32 (&utype),
    GNUNET_PQ_query_param_uint32 (&priority),
    GNUNET_PQ_query_param_uint32 (&anonymity),
    GNUNET_PQ_query_param_absolute_time (&expiration),
    GNUNET_PQ_query_param_auto_from_type (key),
    GNUNET_PQ_query_param_auto_from_type (&vhash),
    GNUNET_PQ_query_param_fixed_size (data, size),
    GNUNET_PQ_query_param_end
  };

  GNUNET_CRYPTO_hash (data, size, &vhash);
  ret = GNUNET_PQ_exec_prepared (plugin->dbh,
				 "put",
				 params);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, 
				    ret, 
				    PGRES_COMMAND_OK, 
				    "PQexecPrepared", "put"))
  {
    cont (cont_cls, key, size, 
	  GNUNET_SYSERR, 
	  _("Postgress exec failure"));
    return;
  }
  PQclear (ret);
  plugin->env->duc (plugin->env->cls, 
		    size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, 
		   "datastore-postgres",
                   "Stored %u bytes in database\n", 
		   (unsigned int) size);
  cont (cont_cls, key, size, GNUNET_OK, NULL);
}


/**
 * Function invoked to process the result and call the processor.
 *
 * @param plugin global plugin data
 * @param proc function to call the value (once only).
 * @param proc_cls closure for proc
 * @param res result from exec
 * @param filename filename for error messages
 * @param line line number for error messages
 */
static void
process_result (struct Plugin *plugin, 
		PluginDatumProcessor proc,
                void *proc_cls,
		PGresult * res,
		const char *filename, int line)
{
  int iret;
  uint32_t rowid;
  uint32_t utype;
  uint32_t anonymity;
  uint32_t priority;
  size_t size;
  void *data;
  struct GNUNET_TIME_Absolute expiration_time;
  struct GNUNET_HashCode key;
  struct GNUNET_PQ_ResultSpec rs[] = {
    GNUNET_PQ_result_spec_uint32 ("type", &utype),
    GNUNET_PQ_result_spec_uint32 ("prio", &priority),
    GNUNET_PQ_result_spec_uint32 ("anonLevel", &anonymity),
    GNUNET_PQ_result_spec_uint32 ("oid", &rowid),
    GNUNET_PQ_result_spec_absolute_time ("expire", &expiration_time),
    GNUNET_PQ_result_spec_auto_from_type ("hash", &key),
    GNUNET_PQ_result_spec_variable_size ("value", &data, &size),
    GNUNET_PQ_result_spec_end
  };

  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result_ (plugin->dbh, 
				     res, 
				     PGRES_TUPLES_OK, 
				     "PQexecPrepared",
				     "select",
				     filename, line))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		     "datastore-postgres",
                     "Ending iteration (postgres error)\n");
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 
	  GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }

  if (0 == PQntuples (res))
  {
    /* no result */
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, 
		     "datastore-postgres",
                     "Ending iteration (no more results)\n");
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 
	  GNUNET_TIME_UNIT_ZERO_ABS, 0);
    PQclear (res);
    return;
  }
  if (1 != PQntuples (res)) 
  {
    GNUNET_break (0);
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0,
	  GNUNET_TIME_UNIT_ZERO_ABS, 0);
    PQclear (res);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_PQ_extract_result (res,
				rs,
				0))
  {
    GNUNET_break (0);
    PQclear (res);
    GNUNET_POSTGRES_delete_by_rowid (plugin->dbh,
				     "delrow", 
				     rowid);
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 
	  GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, 
		   "datastore-postgres",
                   "Found result of size %u bytes and type %u in database\n",
                   (unsigned int) size, 
		   (unsigned int) utype);
  iret = proc (proc_cls,
	       &key,
	       size,
	       data,
	       (enum GNUNET_BLOCK_Type) utype, 
	       priority,
	       anonymity,
	       expiration_time,
	       rowid);
  PQclear (res);
  if (iret == GNUNET_NO)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Processor asked for item %u to be removed.\n", 
		(unsigned int) rowid);
    if (GNUNET_OK == 
	GNUNET_POSTGRES_delete_by_rowid (plugin->dbh, 
					 "delrow", 
					 rowid))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, 
		       "datastore-postgres",
                       "Deleting %u bytes from database\n",
                       (unsigned int) size);
      plugin->env->duc (plugin->env->cls,
                        - (size + GNUNET_DATASTORE_ENTRY_OVERHEAD));
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, 
		       "datastore-postgres",
                       "Deleted %u bytes from database\n",
		       (unsigned int) size);
    }
  }
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure with the 'struct Plugin'
 * @param offset offset of the result (modulo num-results);
 *        specific ordering does not matter for the offset
 * @param key maybe NULL (to match all entries)
 * @param vhash hash of the value, maybe NULL (to
 *        match all values that have the right key).
 *        Note that for DBlocks there is no difference
 *        betwen key and vhash, but for other blocks
 *        there may be!
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param proc function to call on the matching value;
 *        will be called once with a NULL if no value matches
 * @param proc_cls closure for iter
 */
static void
postgres_plugin_get_key (void *cls, 
			 uint64_t offset,
                         const struct GNUNET_HashCode *key,
                         const struct GNUNET_HashCode *vhash,
                         enum GNUNET_BLOCK_Type type,
			 PluginDatumProcessor proc,
                         void *proc_cls)
{
  struct Plugin *plugin = cls;
  uint32_t utype = type;
  PGresult *ret;
  uint64_t total;
  uint64_t limit_off;

  if (0 != type)
  {
    if (NULL != vhash)
    {
      struct GNUNET_PQ_QueryParam params[] = { 
	GNUNET_PQ_query_param_auto_from_type (key),
	GNUNET_PQ_query_param_auto_from_type (vhash),
	GNUNET_PQ_query_param_uint32 (&utype),
	GNUNET_PQ_query_param_end
      };
      ret = GNUNET_PQ_exec_prepared (plugin->dbh,
				     "count_getvt",
				     params);
    }
    else
    {
      struct GNUNET_PQ_QueryParam params[] = { 
	GNUNET_PQ_query_param_auto_from_type (key),
	GNUNET_PQ_query_param_uint32 (&utype),
	GNUNET_PQ_query_param_end
      };
      ret = GNUNET_PQ_exec_prepared (plugin->dbh,
				     "count_gett",
				     params);
    }
  }
  else
  {
    if (NULL != vhash)
    {
      struct GNUNET_PQ_QueryParam params[] = { 
	GNUNET_PQ_query_param_auto_from_type (key),
	GNUNET_PQ_query_param_auto_from_type (vhash),
	GNUNET_PQ_query_param_end
      };
      ret = GNUNET_PQ_exec_prepared (plugin->dbh,
				     "count_getv",
				     params);
    }
    else
    {
      struct GNUNET_PQ_QueryParam params[] = { 
	GNUNET_PQ_query_param_auto_from_type (key),
	GNUNET_PQ_query_param_end
      };
      ret = GNUNET_PQ_exec_prepared (plugin->dbh,
				     "count_get",
				     params);
    }
  }

  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, 
				    ret,
				    PGRES_TUPLES_OK, 
				    "PQexecParams", 
				    "count"))
  {
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 
	  GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  if ( (PQntuples (ret) != 1) || 
       (PQnfields (ret) != 1) ||
       (PQgetlength (ret, 0, 0) != sizeof (uint64_t)))
  {
    GNUNET_break (0);
    PQclear (ret);
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 
	  GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  total = GNUNET_ntohll (*(const uint64_t *) PQgetvalue (ret, 0, 0));
  PQclear (ret);
  if (0 == total)
  {
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, 
	  GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  limit_off = offset % total;

  if (0 != type)
  {
    if (NULL != vhash)
    {
      struct GNUNET_PQ_QueryParam params[] = { 
	GNUNET_PQ_query_param_auto_from_type (key),
	GNUNET_PQ_query_param_auto_from_type (&vhash),
	GNUNET_PQ_query_param_uint32 (&utype),
	GNUNET_PQ_query_param_uint64 (&limit_off),
	GNUNET_PQ_query_param_end
      };
      ret = GNUNET_PQ_exec_prepared (plugin->dbh,
				     "getvt",
				     params);
    }
    else
    {
      struct GNUNET_PQ_QueryParam params[] = { 
	GNUNET_PQ_query_param_auto_from_type (key),
	GNUNET_PQ_query_param_uint32 (&utype),
	GNUNET_PQ_query_param_uint64 (&limit_off),
	GNUNET_PQ_query_param_end
      };
      ret = GNUNET_PQ_exec_prepared (plugin->dbh,
				     "gett",
				     params);
    }
  }
  else
  {
    if (NULL != vhash)
    {
      struct GNUNET_PQ_QueryParam params[] = { 
	GNUNET_PQ_query_param_auto_from_type (key),
	GNUNET_PQ_query_param_auto_from_type (&vhash),
	GNUNET_PQ_query_param_uint64 (&limit_off),
	GNUNET_PQ_query_param_end
      };
      ret = GNUNET_PQ_exec_prepared (plugin->dbh,
				     "getv",
				     params);
    }
    else
    {
      struct GNUNET_PQ_QueryParam params[] = { 
	GNUNET_PQ_query_param_auto_from_type (key),
	GNUNET_PQ_query_param_uint64 (&limit_off),
	GNUNET_PQ_query_param_end
      };
      ret = GNUNET_PQ_exec_prepared (plugin->dbh,
				     "get",
				     params);
    }
  }
  process_result (plugin,
		  proc,
		  proc_cls, 
		  ret, 
		  __FILE__, __LINE__);
}


/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param cls our `struct Plugin *`
 * @param offset offset of the result (modulo num-results);
 *        specific ordering does not matter for the offset
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param proc function to call on the matching value;
 *        will be called with a NULL if no value matches
 * @param proc_cls closure for @a proc
 */
static void
postgres_plugin_get_zero_anonymity (void *cls, 
				    uint64_t offset,
                                    enum GNUNET_BLOCK_Type type,
                                    PluginDatumProcessor proc, 
				    void *proc_cls)
{
  struct Plugin *plugin = cls;
  uint32_t utype = type;
  struct GNUNET_PQ_QueryParam params[] = { 
    GNUNET_PQ_query_param_uint32 (&utype),
    GNUNET_PQ_query_param_uint64 (&offset),
    GNUNET_PQ_query_param_end
  };
  PGresult *ret;

  ret = GNUNET_PQ_exec_prepared (plugin->dbh,
				 "select_non_anonymous",
				 params);

  process_result (plugin, 
		  proc, proc_cls,
		  ret,
		  __FILE__, __LINE__);
}


/**
 * Context for #repl_iter() function.
 */
struct ReplCtx
{

  /**
   * Plugin handle.
   */
  struct Plugin *plugin;

  /**
   * Function to call for the result (or the NULL).
   */
  PluginDatumProcessor proc;

  /**
   * Closure for @e proc.
   */
  void *proc_cls;
};


/**
 * Wrapper for the iterator for 'sqlite_plugin_replication_get'.
 * Decrements the replication counter and calls the original
 * iterator.
 *
 * @param cls closure with the `struct ReplCtx *`
 * @param key key for the content
 * @param size number of bytes in @a data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 * @return #GNUNET_SYSERR to abort the iteration, 
 *         #GNUNET_OK to continue
 *         (continue on call to "next", of course),
 *         #GNUNET_NO to delete the item and continue (if supported)
 */
static int
repl_proc (void *cls,
	   const struct GNUNET_HashCode *key,
	   uint32_t size,
           const void *data,
	   enum GNUNET_BLOCK_Type type, 
	   uint32_t priority,
           uint32_t anonymity, 
	   struct GNUNET_TIME_Absolute expiration,
           uint64_t uid)
{
  struct ReplCtx *rc = cls;
  struct Plugin *plugin = rc->plugin;
  int ret;
  uint32_t oid = (uint32_t) uid;
  struct GNUNET_PQ_QueryParam params[] = { 
    GNUNET_PQ_query_param_uint32 (&oid),
    GNUNET_PQ_query_param_end
  };
  PGresult *qret;

  ret = rc->proc (rc->proc_cls, 
		  key, 
		  size, data, 
		  type,
		  priority, 
		  anonymity,
		  expiration, uid);
  if (NULL == key)
    return ret;
  qret = GNUNET_PQ_exec_prepared (plugin->dbh,
				  "decrepl",
				  params);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, 
				    qret, 
				    PGRES_COMMAND_OK, 
				    "PQexecPrepared",
				    "decrepl"))
    return GNUNET_SYSERR;
  PQclear (qret);
  return ret;
}


/**
 * Get a random item for replication.  Returns a single, not expired,
 * random item from those with the highest replication counters.  The
 * item's replication counter is decremented by one IF it was positive
 * before.  Call @a proc with all values ZERO or NULL if the datastore
 * is empty.
 *
 * @param cls closure with the `struct Plugin`
 * @param proc function to call the value (once only).
 * @param proc_cls closure for @a proc
 */
static void
postgres_plugin_get_replication (void *cls, 
				 PluginDatumProcessor proc,
                                 void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct ReplCtx rc;
  PGresult *ret;

  rc.plugin = plugin;
  rc.proc = proc;
  rc.proc_cls = proc_cls;
  ret = PQexecPrepared (plugin->dbh, 
			"select_replication_order", 0, NULL, NULL,
			NULL, 1);
  process_result (plugin, 
		  &repl_proc, 
		  &rc, 
		  ret, 
		  __FILE__, __LINE__);
}


/**
 * Get a random item for expiration.  Call @a proc with all values
 * ZERO or NULL if the datastore is empty.
 *
 * @param cls closure with the `struct Plugin`
 * @param proc function to call the value (once only).
 * @param proc_cls closure for @a proc
 */
static void
postgres_plugin_get_expiration (void *cls, 
				PluginDatumProcessor proc,
                                void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_PQ_QueryParam params[] = { 
    GNUNET_PQ_query_param_absolute_time (&now),
    GNUNET_PQ_query_param_end
  };
  PGresult *ret;

  now = GNUNET_TIME_absolute_get ();
  ret = GNUNET_PQ_exec_prepared (plugin->dbh,
				 "select_expiration_order",
				 params);
  process_result (plugin,
		  proc, proc_cls,
		  ret,
		  __FILE__, __LINE__);
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
 * @param cls our `struct Plugin *`
 * @param uid unique identifier of the datum
 * @param delta by how much should the priority
 *     change?  If priority + delta < 0 the
 *     priority should be set to 0 (never go
 *     negative).
 * @param expire new expiration time should be the
 *     MAX of any existing expiration time and
 *     this value
 * @param cont continuation called with success or failure status
 * @param cons_cls continuation closure
 */
static void
postgres_plugin_update (void *cls, 
			uint64_t uid, 
			int delta,
                        struct GNUNET_TIME_Absolute expire,
                        PluginUpdateCont cont,
			void *cont_cls)
{
  struct Plugin *plugin = cls;
  uint32_t idelta = delta;
  uint32_t oid = (uint32_t) uid;
  struct GNUNET_PQ_QueryParam params[] = { 
    GNUNET_PQ_query_param_uint32 (&idelta),
    GNUNET_PQ_query_param_absolute_time (&expire),
    GNUNET_PQ_query_param_uint32 (&oid),
    GNUNET_PQ_query_param_end
  };
  PGresult *ret;

  ret = GNUNET_PQ_exec_prepared (plugin->dbh,
				 "update",
				 params);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
				    ret, 
				    PGRES_COMMAND_OK, 
				    "PQexecPrepared", 
				    "update"))
  {
    cont (cont_cls, 
	  GNUNET_SYSERR, 
	  NULL);
    return;
  }
  PQclear (ret);
  cont (cont_cls, 
	GNUNET_OK, 
	NULL);
}



/**
 * Get all of the keys in the datastore.
 *
 * @param cls closure with the `struct Plugin *`
 * @param proc function to call on each key
 * @param proc_cls closure for @a proc
 */
static void
postgres_plugin_get_keys (void *cls,
			  PluginKeyProcessor proc,
			  void *proc_cls)
{
  struct Plugin *plugin = cls;
  int ret;
  int i;
  struct GNUNET_HashCode key;
  PGresult * res;

  res = PQexecPrepared (plugin->dbh, 
			"get_keys", 
			0, NULL, NULL, NULL, 1);
  ret = PQntuples (res);
  for (i=0;i<ret;i++)
  {
    if (sizeof (struct GNUNET_HashCode) != 
	PQgetlength (res, i, 0))
    {
      memcpy (&key, 
	      PQgetvalue (res, i, 0), 
	      sizeof (struct GNUNET_HashCode));
      proc (proc_cls, &key, 1);
    }
  }
  PQclear (res);
  proc (proc_cls, NULL, 0);
}



/**
 * Drop database.
 *
 * @param cls closure with the `struct Plugin *`
 */
static void
postgres_plugin_drop (void *cls)
{
  struct Plugin *plugin = cls;

  if (GNUNET_OK != 
      GNUNET_POSTGRES_exec (plugin->dbh, "DROP TABLE gn090"))
    GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, 
		     "postgres", 
		     _("Failed to drop table from database.\n"));
}


/**
 * Entry point for the plugin.
 *
 * @param cls the `struct GNUNET_DATASTORE_PluginEnvironment*`
 * @return our `struct Plugin *`
 */
void *
libgnunet_plugin_datastore_postgres_init (void *cls)
{
  struct GNUNET_DATASTORE_PluginEnvironment *env = cls;
  struct GNUNET_DATASTORE_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_new (struct Plugin);
  plugin->env = env;
  if (GNUNET_OK != init_connection (plugin))
  {
    GNUNET_free (plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_DATASTORE_PluginFunctions);
  api->cls = plugin;
  api->estimate_size = &postgres_plugin_estimate_size;
  api->put = &postgres_plugin_put;
  api->update = &postgres_plugin_update;
  api->get_key = &postgres_plugin_get_key;
  api->get_replication = &postgres_plugin_get_replication;
  api->get_expiration = &postgres_plugin_get_expiration;
  api->get_zero_anonymity = &postgres_plugin_get_zero_anonymity;
  api->get_keys = &postgres_plugin_get_keys;
  api->drop = &postgres_plugin_drop;
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "datastore-postgres",
                   _("Postgres database running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls our `struct Plugin *`
 * @return always NULL
 */
void *
libgnunet_plugin_datastore_postgres_done (void *cls)
{
  struct GNUNET_DATASTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  PQfinish (plugin->dbh);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_datastore_postgres.c */
