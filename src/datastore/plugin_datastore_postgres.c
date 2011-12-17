/*
     This file is part of GNUnet
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file datastore/plugin_datastore_postgres.c
 * @brief postgres-based datastore backend
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_datastore_plugin.h"
#include <postgresql/libpq-fe.h>

#define DEBUG_POSTGRES GNUNET_EXTRA_LOGGING

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
 * Check if the result obtained from Postgres has
 * the desired status code.  If not, log an error, clear the
 * result and return GNUNET_SYSERR.
 *
 * @param plugin global context
 * @param ret result to check
 * @param expected_status expected return value
 * @param command name of SQL command that was run
 * @param args arguments to SQL command
 * @param line line number for error reporting
 * @return GNUNET_OK if the result is acceptable
 */
static int
check_result (struct Plugin *plugin, PGresult * ret, int expected_status,
              const char *command, const char *args, int line)
{
  if (ret == NULL)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                     "datastore-postgres",
                     "Postgres failed to allocate result for `%s:%s' at %d\n",
                     command, args, line);
    return GNUNET_SYSERR;
  }
  if (PQresultStatus (ret) != expected_status)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                     "datastore-postgres",
                     _("`%s:%s' failed at %s:%d with error: %s"), command, args,
                     __FILE__, line, PQerrorMessage (plugin->dbh));
    PQclear (ret);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

/**
 * Run simple SQL statement (without results).
 *
 * @param plugin global context
 * @param sql statement to run
 * @param line code line for error reporting
 */
static int
pq_exec (struct Plugin *plugin, const char *sql, int line)
{
  PGresult *ret;

  ret = PQexec (plugin->dbh, sql);
  if (GNUNET_OK !=
      check_result (plugin, ret, PGRES_COMMAND_OK, "PQexec", sql, line))
    return GNUNET_SYSERR;
  PQclear (ret);
  return GNUNET_OK;
}

/**
 * Prepare SQL statement.
 *
 * @param plugin global context
 * @param name name for the prepared SQL statement
 * @param sql SQL code to prepare
 * @param nparams number of parameters in sql
 * @param line code line for error reporting
 * @return GNUNET_OK on success
 */
static int
pq_prepare (struct Plugin *plugin, const char *name, const char *sql,
            int nparams, int line)
{
  PGresult *ret;

  ret = PQprepare (plugin->dbh, name, sql, nparams, NULL);
  if (GNUNET_OK !=
      check_result (plugin, ret, PGRES_COMMAND_OK, "PQprepare", sql, line))
    return GNUNET_SYSERR;
  PQclear (ret);
  return GNUNET_OK;
}

/**
 * @brief Get a database handle
 *
 * @param plugin global context
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
init_connection (struct Plugin *plugin)
{
  char *conninfo;
  PGresult *ret;

  /* Open database and precompile statements */
  conninfo = NULL;
  (void) GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg,
                                                "datastore-postgres", "CONFIG",
                                                &conninfo);
  plugin->dbh = PQconnectdb (conninfo == NULL ? "" : conninfo);
  if (NULL == plugin->dbh)
  {
    /* FIXME: warn about out-of-memory? */
    GNUNET_free_non_null (conninfo);
    return GNUNET_SYSERR;
  }
  if (PQstatus (plugin->dbh) != CONNECTION_OK)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "datastore-postgres",
                     _
                     ("Unable to initialize Postgres with configuration `%s': %s"),
                     conninfo, PQerrorMessage (plugin->dbh));
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    GNUNET_free_non_null (conninfo);
    return GNUNET_SYSERR;
  }
  GNUNET_free_non_null (conninfo);
  ret =
      PQexec (plugin->dbh,
              "CREATE TABLE gn090 (" "  repl INTEGER NOT NULL DEFAULT 0,"
              "  type INTEGER NOT NULL DEFAULT 0,"
              "  prio INTEGER NOT NULL DEFAULT 0,"
              "  anonLevel INTEGER NOT NULL DEFAULT 0,"
              "  expire BIGINT NOT NULL DEFAULT 0,"
              "  rvalue BIGINT NOT NULL DEFAULT 0,"
              "  hash BYTEA NOT NULL DEFAULT '',"
              "  vhash BYTEA NOT NULL DEFAULT '',"
              "  value BYTEA NOT NULL DEFAULT '')" "WITH OIDS");
  if ((ret == NULL) || ((PQresultStatus (ret) != PGRES_COMMAND_OK) && (0 != strcmp ("42P07",    /* duplicate table */
                                                                                    PQresultErrorField
                                                                                    (ret,
                                                                                     PG_DIAG_SQLSTATE)))))
  {
    (void) check_result (plugin, ret, PGRES_COMMAND_OK, "CREATE TABLE", "gn090",
                         __LINE__);
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  if (PQresultStatus (ret) == PGRES_COMMAND_OK)
  {
    if ((GNUNET_OK !=
         pq_exec (plugin, "CREATE INDEX idx_hash ON gn090 (hash)", __LINE__)) ||
        (GNUNET_OK !=
         pq_exec (plugin, "CREATE INDEX idx_hash_vhash ON gn090 (hash,vhash)",
                  __LINE__)) ||
        (GNUNET_OK !=
         pq_exec (plugin, "CREATE INDEX idx_prio ON gn090 (prio)", __LINE__)) ||
        (GNUNET_OK !=
         pq_exec (plugin, "CREATE INDEX idx_expire ON gn090 (expire)",
                  __LINE__)) ||
        (GNUNET_OK !=
         pq_exec (plugin,
                  "CREATE INDEX idx_prio_anon ON gn090 (prio,anonLevel)",
                  __LINE__)) ||
        (GNUNET_OK !=
         pq_exec (plugin,
                  "CREATE INDEX idx_prio_hash_anon ON gn090 (prio,hash,anonLevel)",
                  __LINE__)) ||
        (GNUNET_OK !=
         pq_exec (plugin, "CREATE INDEX idx_repl_rvalue ON gn090 (repl,rvalue)",
                  __LINE__)) ||
        (GNUNET_OK !=
         pq_exec (plugin, "CREATE INDEX idx_expire_hash ON gn090 (expire,hash)",
                  __LINE__)))
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
      check_result (plugin, ret, PGRES_COMMAND_OK, "ALTER TABLE", "gn090",
                    __LINE__))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  PQclear (ret);
  ret = PQexec (plugin->dbh, "ALTER TABLE gn090 ALTER hash SET STORAGE PLAIN");
  if (GNUNET_OK !=
      check_result (plugin, ret, PGRES_COMMAND_OK, "ALTER TABLE", "gn090",
                    __LINE__))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  PQclear (ret);
  ret = PQexec (plugin->dbh, "ALTER TABLE gn090 ALTER vhash SET STORAGE PLAIN");
  if (GNUNET_OK !=
      check_result (plugin, ret, PGRES_COMMAND_OK, "ALTER TABLE", "gn090",
                    __LINE__))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  PQclear (ret);
  if ((GNUNET_OK !=
       pq_prepare (plugin, "getvt",
                   "SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "WHERE hash=$1 AND vhash=$2 AND type=$3 "
                   "ORDER BY oid ASC LIMIT 1 OFFSET $4", 4, __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare (plugin, "gett",
                   "SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "WHERE hash=$1 AND type=$2 "
                   "ORDER BY oid ASC LIMIT 1 OFFSET $3", 3, __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare (plugin, "getv",
                   "SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "WHERE hash=$1 AND vhash=$2 "
                   "ORDER BY oid ASC LIMIT 1 OFFSET $3", 3, __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare (plugin, "get",
                   "SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "WHERE hash=$1 " "ORDER BY oid ASC LIMIT 1 OFFSET $2", 2,
                   __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare (plugin, "put",
                   "INSERT INTO gn090 (repl, type, prio, anonLevel, expire, rvalue, hash, vhash, value) "
                   "VALUES ($1, $2, $3, $4, $5, RANDOM(), $6, $7, $8)", 9,
                   __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare (plugin, "update",
                   "UPDATE gn090 SET prio = prio + $1, expire = CASE WHEN expire < $2 THEN $2 ELSE expire END "
                   "WHERE oid = $3", 3, __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare (plugin, "decrepl",
                   "UPDATE gn090 SET repl = GREATEST (repl - 1, 0) "
                   "WHERE oid = $1", 1, __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare (plugin, "select_non_anonymous",
                   "SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "WHERE anonLevel = 0 AND type = $1 ORDER BY oid DESC LIMIT 1 OFFSET $2",
                   1, __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare (plugin, "select_expiration_order",
                   "(SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "WHERE expire < $1 ORDER BY prio ASC LIMIT 1) " "UNION "
                   "(SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "ORDER BY prio ASC LIMIT 1) " "ORDER BY expire ASC LIMIT 1",
                   1, __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare (plugin, "select_replication_order",
                   "SELECT type, prio, anonLevel, expire, hash, value, oid FROM gn090 "
                   "ORDER BY repl DESC,RANDOM() LIMIT 1", 0, __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare (plugin, "delrow", "DELETE FROM gn090 " "WHERE oid=$1", 1,
                   __LINE__)) ||
      (GNUNET_OK !=
       pq_prepare (plugin, "get_keys", "SELECT hash FROM gn090", 0,
                   __LINE__)))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Delete the row identified by the given rowid (qid
 * in postgres).
 *
 * @param plugin global context
 * @param rowid which row to delete
 * @return GNUNET_OK on success
 */
static int
delete_by_rowid (struct Plugin *plugin, unsigned int rowid)
{
  uint32_t browid;
  const char *paramValues[] = { (const char *) &browid };
  int paramLengths[] = { sizeof (browid) };
  const int paramFormats[] = { 1 };
  PGresult *ret;

  browid = htonl (rowid);
  ret =
      PQexecPrepared (plugin->dbh, "delrow", 1, paramValues, paramLengths,
                      paramFormats, 1);
  if (GNUNET_OK !=
      check_result (plugin, ret, PGRES_COMMAND_OK, "PQexecPrepared", "delrow",
                    __LINE__))
  {
    return GNUNET_SYSERR;
  }
  PQclear (ret);
  return GNUNET_OK;
}


/**
 * Get an estimate of how much space the database is
 * currently using.
 *
 * @param cls our "struct Plugin*"
 * @return number of bytes used on disk
 */
static unsigned long long
postgres_plugin_estimate_size (void *cls)
{
  struct Plugin *plugin = cls;
  unsigned long long total;
  PGresult *ret;

  ret =
      PQexecParams (plugin->dbh,
                    "SELECT SUM(LENGTH(value))+256*COUNT(*) FROM gn090", 0,
                    NULL, NULL, NULL, NULL, 1);
  if (GNUNET_OK !=
      check_result (plugin, ret, PGRES_TUPLES_OK, "PQexecParams", "get_size",
                    __LINE__))
  {
    return 0;
  }
  if ((PQntuples (ret) != 1) || (PQnfields (ret) != 1) ||
      (PQgetlength (ret, 0, 0) != sizeof (unsigned long long)))
  {
    GNUNET_break (0);
    PQclear (ret);
    return 0;
  }
  total = GNUNET_ntohll (*(const unsigned long long *) PQgetvalue (ret, 0, 0));
  PQclear (ret);
  return total;
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
 * @param msg set to error message
 * @return GNUNET_OK on success
 */
static int
postgres_plugin_put (void *cls, const GNUNET_HashCode * key, uint32_t size,
                     const void *data, enum GNUNET_BLOCK_Type type,
                     uint32_t priority, uint32_t anonymity,
                     uint32_t replication,
                     struct GNUNET_TIME_Absolute expiration, char **msg)
{
  struct Plugin *plugin = cls;
  GNUNET_HashCode vhash;
  PGresult *ret;
  uint32_t btype = htonl (type);
  uint32_t bprio = htonl (priority);
  uint32_t banon = htonl (anonymity);
  uint32_t brepl = htonl (replication);
  uint64_t bexpi = GNUNET_TIME_absolute_hton (expiration).abs_value__;

  const char *paramValues[] = {
    (const char *) &brepl,
    (const char *) &btype,
    (const char *) &bprio,
    (const char *) &banon,
    (const char *) &bexpi,
    (const char *) key,
    (const char *) &vhash,
    (const char *) data
  };
  int paramLengths[] = {
    sizeof (brepl),
    sizeof (btype),
    sizeof (bprio),
    sizeof (banon),
    sizeof (bexpi),
    sizeof (GNUNET_HashCode),
    sizeof (GNUNET_HashCode),
    size
  };
  const int paramFormats[] = { 1, 1, 1, 1, 1, 1, 1, 1 };

  GNUNET_CRYPTO_hash (data, size, &vhash);
  ret =
      PQexecPrepared (plugin->dbh, "put", 8, paramValues, paramLengths,
                      paramFormats, 1);
  if (GNUNET_OK !=
      check_result (plugin, ret, PGRES_COMMAND_OK, "PQexecPrepared", "put",
                    __LINE__))
    return GNUNET_SYSERR;
  PQclear (ret);
  plugin->env->duc (plugin->env->cls, size + GNUNET_DATASTORE_ENTRY_OVERHEAD);
#if DEBUG_POSTGRES
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "datastore-postgres",
                   "Stored %u bytes in database\n", (unsigned int) size);
#endif
  return GNUNET_OK;
}


/**
 * Function invoked to process the result and call
 * the processor.
 *
 * @param plugin global plugin data
 * @param proc function to call the value (once only).
 * @param proc_cls closure for proc
 * @param res result from exec
 * @param line line number for error messages
 */
static void
process_result (struct Plugin *plugin, PluginDatumProcessor proc,
                void *proc_cls, PGresult * res, int line)
{
  int iret;
  enum GNUNET_BLOCK_Type type;
  uint32_t anonymity;
  uint32_t priority;
  uint32_t size;
  unsigned int rowid;
  struct GNUNET_TIME_Absolute expiration_time;
  GNUNET_HashCode key;

  if (GNUNET_OK !=
      check_result (plugin, res, PGRES_TUPLES_OK, "PQexecPrepared", "select",
                    line))
  {
#if DEBUG_POSTGRES
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "datastore-postgres",
                     "Ending iteration (postgres error)\n");
#endif
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }

  if (0 == PQntuples (res))
  {
    /* no result */
#if DEBUG_POSTGRES
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "datastore-postgres",
                     "Ending iteration (no more results)\n");
#endif
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    PQclear (res);
    return;
  }
  if ((1 != PQntuples (res)) || (7 != PQnfields (res)) ||
      (sizeof (uint32_t) != PQfsize (res, 0)) ||
      (sizeof (uint32_t) != PQfsize (res, 6)))
  {
    GNUNET_break (0);
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    PQclear (res);
    return;
  }
  rowid = ntohl (*(uint32_t *) PQgetvalue (res, 0, 6));
  if ((sizeof (uint32_t) != PQfsize (res, 0)) ||
      (sizeof (uint32_t) != PQfsize (res, 1)) ||
      (sizeof (uint32_t) != PQfsize (res, 2)) ||
      (sizeof (uint64_t) != PQfsize (res, 3)) ||
      (sizeof (GNUNET_HashCode) != PQgetlength (res, 0, 4)))
  {
    GNUNET_break (0);
    PQclear (res);
    delete_by_rowid (plugin, rowid);
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }

  type = ntohl (*(uint32_t *) PQgetvalue (res, 0, 0));
  priority = ntohl (*(uint32_t *) PQgetvalue (res, 0, 1));
  anonymity = ntohl (*(uint32_t *) PQgetvalue (res, 0, 2));
  expiration_time.abs_value =
      GNUNET_ntohll (*(uint64_t *) PQgetvalue (res, 0, 3));
  memcpy (&key, PQgetvalue (res, 0, 4), sizeof (GNUNET_HashCode));
  size = PQgetlength (res, 0, 5);
#if DEBUG_POSTGRES
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "datastore-postgres",
                   "Found result of size %u bytes and type %u in database\n",
                   (unsigned int) size, (unsigned int) type);
#endif
  iret =
      proc (proc_cls, &key, size, PQgetvalue (res, 0, 5),
            (enum GNUNET_BLOCK_Type) type, priority, anonymity, expiration_time,
            rowid);
  PQclear (res);
  if (iret == GNUNET_NO)
  {
#if DEBUG_POSTGRES
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Processor asked for item %u to be removed.\n", rowid);
#endif
    if (GNUNET_OK == delete_by_rowid (plugin, rowid))
    {
#if DEBUG_POSTGRES
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "datastore-postgres",
                       "Deleting %u bytes from database\n",
                       (unsigned int) size);
#endif
      plugin->env->duc (plugin->env->cls,
                        -(size + GNUNET_DATASTORE_ENTRY_OVERHEAD));
#if DEBUG_POSTGRES
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "datastore-postgres",
                       "Deleted %u bytes from database\n", (unsigned int) size);
#endif
    }
  }
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure
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
postgres_plugin_get_key (void *cls, uint64_t offset,
                         const GNUNET_HashCode * key,
                         const GNUNET_HashCode * vhash,
                         enum GNUNET_BLOCK_Type type, PluginDatumProcessor proc,
                         void *proc_cls)
{
  struct Plugin *plugin = cls;
  const int paramFormats[] = { 1, 1, 1, 1, 1 };
  int paramLengths[4];
  const char *paramValues[4];
  int nparams;
  const char *pname;
  PGresult *ret;
  uint64_t total;
  uint64_t blimit_off;
  uint32_t btype;

  GNUNET_assert (key != NULL);
  paramValues[0] = (const char *) key;
  paramLengths[0] = sizeof (GNUNET_HashCode);
  btype = htonl (type);
  if (type != 0)
  {
    if (vhash != NULL)
    {
      paramValues[1] = (const char *) vhash;
      paramLengths[1] = sizeof (GNUNET_HashCode);
      paramValues[2] = (const char *) &btype;
      paramLengths[2] = sizeof (btype);
      paramValues[3] = (const char *) &blimit_off;
      paramLengths[3] = sizeof (blimit_off);
      nparams = 4;
      pname = "getvt";
      ret =
          PQexecParams (plugin->dbh,
                        "SELECT count(*) FROM gn090 WHERE hash=$1 AND vhash=$2 AND type=$3",
                        3, NULL, paramValues, paramLengths, paramFormats, 1);
    }
    else
    {
      paramValues[1] = (const char *) &btype;
      paramLengths[1] = sizeof (btype);
      paramValues[2] = (const char *) &blimit_off;
      paramLengths[2] = sizeof (blimit_off);
      nparams = 3;
      pname = "gett";
      ret =
          PQexecParams (plugin->dbh,
                        "SELECT count(*) FROM gn090 WHERE hash=$1 AND type=$2",
                        2, NULL, paramValues, paramLengths, paramFormats, 1);
    }
  }
  else
  {
    if (vhash != NULL)
    {
      paramValues[1] = (const char *) vhash;
      paramLengths[1] = sizeof (GNUNET_HashCode);
      paramValues[2] = (const char *) &blimit_off;
      paramLengths[2] = sizeof (blimit_off);
      nparams = 3;
      pname = "getv";
      ret =
          PQexecParams (plugin->dbh,
                        "SELECT count(*) FROM gn090 WHERE hash=$1 AND vhash=$2",
                        2, NULL, paramValues, paramLengths, paramFormats, 1);
    }
    else
    {
      paramValues[1] = (const char *) &blimit_off;
      paramLengths[1] = sizeof (blimit_off);
      nparams = 2;
      pname = "get";
      ret =
          PQexecParams (plugin->dbh, "SELECT count(*) FROM gn090 WHERE hash=$1",
                        1, NULL, paramValues, paramLengths, paramFormats, 1);
    }
  }
  if (GNUNET_OK !=
      check_result (plugin, ret, PGRES_TUPLES_OK, "PQexecParams", pname,
                    __LINE__))
  {
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  if ((PQntuples (ret) != 1) || (PQnfields (ret) != 1) ||
      (PQgetlength (ret, 0, 0) != sizeof (unsigned long long)))
  {
    GNUNET_break (0);
    PQclear (ret);
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  total = GNUNET_ntohll (*(const unsigned long long *) PQgetvalue (ret, 0, 0));
  PQclear (ret);
  if (total == 0)
  {
    proc (proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS, 0);
    return;
  }
  blimit_off = GNUNET_htonll (offset % total);
  ret =
      PQexecPrepared (plugin->dbh, pname, nparams, paramValues, paramLengths,
                      paramFormats, 1);
  process_result (plugin, proc, proc_cls, ret, __LINE__);
}


/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param cls our "struct Plugin*"
 * @param offset offset of the result (modulo num-results);
 *        specific ordering does not matter for the offset
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param proc function to call on the matching value;
 *        will be called with a NULL if no value matches
 * @param proc_cls closure for proc
 */
static void
postgres_plugin_get_zero_anonymity (void *cls, uint64_t offset,
                                    enum GNUNET_BLOCK_Type type,
                                    PluginDatumProcessor proc, void *proc_cls)
{
  struct Plugin *plugin = cls;
  uint32_t btype;
  uint64_t boff;
  const int paramFormats[] = { 1, 1 };
  int paramLengths[] = { sizeof (btype), sizeof (boff) };
  const char *paramValues[] = { (const char *) &btype, (const char *) &boff };
  PGresult *ret;

  btype = htonl ((uint32_t) type);
  boff = GNUNET_htonll (offset);
  ret =
      PQexecPrepared (plugin->dbh, "select_non_anonymous", 2, paramValues,
                      paramLengths, paramFormats, 1);
  process_result (plugin, proc, proc_cls, ret, __LINE__);
}


/**
 * Context for 'repl_iter' function.
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
   * Closure for proc.
   */
  void *proc_cls;
};


/**
 * Wrapper for the iterator for 'sqlite_plugin_replication_get'.
 * Decrements the replication counter and calls the original
 * iterator.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 *
 * @return GNUNET_SYSERR to abort the iteration, GNUNET_OK to continue
 *         (continue on call to "next", of course),
 *         GNUNET_NO to delete the item and continue (if supported)
 */
static int
repl_proc (void *cls, const GNUNET_HashCode * key, uint32_t size,
           const void *data, enum GNUNET_BLOCK_Type type, uint32_t priority,
           uint32_t anonymity, struct GNUNET_TIME_Absolute expiration,
           uint64_t uid)
{
  struct ReplCtx *rc = cls;
  struct Plugin *plugin = rc->plugin;
  int ret;
  PGresult *qret;
  uint32_t boid;

  ret =
      rc->proc (rc->proc_cls, key, size, data, type, priority, anonymity,
                expiration, uid);
  if (NULL != key)
  {
    boid = htonl ((uint32_t) uid);
    const char *paramValues[] = {
      (const char *) &boid,
    };
    int paramLengths[] = {
      sizeof (boid),
    };
    const int paramFormats[] = { 1 };
    qret =
        PQexecPrepared (plugin->dbh, "decrepl", 1, paramValues, paramLengths,
                        paramFormats, 1);
    if (GNUNET_OK !=
        check_result (plugin, qret, PGRES_COMMAND_OK, "PQexecPrepared",
                      "decrepl", __LINE__))
      return GNUNET_SYSERR;
    PQclear (qret);
  }
  return ret;
}


/**
 * Get a random item for replication.  Returns a single, not expired, random item
 * from those with the highest replication counters.  The item's
 * replication counter is decremented by one IF it was positive before.
 * Call 'proc' with all values ZERO or NULL if the datastore is empty.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for proc
 */
static void
postgres_plugin_get_replication (void *cls, PluginDatumProcessor proc,
                                 void *proc_cls)
{
  struct Plugin *plugin = cls;
  struct ReplCtx rc;
  PGresult *ret;

  rc.plugin = plugin;
  rc.proc = proc;
  rc.proc_cls = proc_cls;
  ret =
      PQexecPrepared (plugin->dbh, "select_replication_order", 0, NULL, NULL,
                      NULL, 1);
  process_result (plugin, &repl_proc, &rc, ret, __LINE__);
}


/**
 * Get a random item for expiration.
 * Call 'proc' with all values ZERO or NULL if the datastore is empty.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for proc
 */
static void
postgres_plugin_get_expiration (void *cls, PluginDatumProcessor proc,
                                void *proc_cls)
{
  struct Plugin *plugin = cls;
  uint64_t btime;
  const int paramFormats[] = { 1 };
  int paramLengths[] = { sizeof (btime) };
  const char *paramValues[] = { (const char *) &btime };
  PGresult *ret;

  btime = GNUNET_htonll (GNUNET_TIME_absolute_get ().abs_value);
  ret =
      PQexecPrepared (plugin->dbh, "select_expiration_order", 1, paramValues,
                      paramLengths, paramFormats, 1);
  process_result (plugin, proc, proc_cls, ret, __LINE__);
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
 * @param cls our "struct Plugin*"
 * @param uid unique identifier of the datum
 * @param delta by how much should the priority
 *     change?  If priority + delta < 0 the
 *     priority should be set to 0 (never go
 *     negative).
 * @param expire new expiration time should be the
 *     MAX of any existing expiration time and
 *     this value
 * @param msg set to error message
 * @return GNUNET_OK on success
 */
static int
postgres_plugin_update (void *cls, uint64_t uid, int delta,
                        struct GNUNET_TIME_Absolute expire, char **msg)
{
  struct Plugin *plugin = cls;
  PGresult *ret;
  int32_t bdelta = (int32_t) htonl ((uint32_t) delta);
  uint32_t boid = htonl ((uint32_t) uid);
  uint64_t bexpire = GNUNET_TIME_absolute_hton (expire).abs_value__;

  const char *paramValues[] = {
    (const char *) &bdelta,
    (const char *) &bexpire,
    (const char *) &boid,
  };
  int paramLengths[] = {
    sizeof (bdelta),
    sizeof (bexpire),
    sizeof (boid),
  };
  const int paramFormats[] = { 1, 1, 1 };

  ret =
      PQexecPrepared (plugin->dbh, "update", 3, paramValues, paramLengths,
                      paramFormats, 1);
  if (GNUNET_OK !=
      check_result (plugin, ret, PGRES_COMMAND_OK, "PQexecPrepared", "update",
                    __LINE__))
    return GNUNET_SYSERR;
  PQclear (ret);
  return GNUNET_OK;
}



/**
 * Get all of the keys in the datastore.
 *
 * @param cls closure
 * @param proc function to call on each key
 * @param proc_cls closure for proc
 */
static void
postgres_plugin_get_keys (void *cls,
			  PluginKeyProcessor proc,
			  void *proc_cls)
{
  struct Plugin *plugin = cls;
  int ret;
  int i;
  GNUNET_HashCode key;
  PGresult * res;

  res = PQexecPrepared (plugin->dbh, "get_keys", 0, NULL, NULL, NULL, 1);
  ret = PQntuples (res);
  for (i=0;i<ret;i++)
  {
    if (sizeof (GNUNET_HashCode) != PQgetlength (res, i, 0))
    {
      memcpy (&key, PQgetvalue (res, i, 0), sizeof (GNUNET_HashCode));
      proc (proc_cls, &key, 1);    
    }
  }
  PQclear (res);
}



/**
 * Drop database.
 */
static void
postgres_plugin_drop (void *cls)
{
  struct Plugin *plugin = cls;

  pq_exec (plugin, "DROP TABLE gn090", __LINE__);
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_DATASTORE_PluginEnvironment*"
 * @return our "struct Plugin*"
 */
void *
libgnunet_plugin_datastore_postgres_init (void *cls)
{
  struct GNUNET_DATASTORE_PluginEnvironment *env = cls;
  struct GNUNET_DATASTORE_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  if (GNUNET_OK != init_connection (plugin))
  {
    GNUNET_free (plugin);
    return NULL;
  }
  api = GNUNET_malloc (sizeof (struct GNUNET_DATASTORE_PluginFunctions));
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
 * @param cls our "struct Plugin*"
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
