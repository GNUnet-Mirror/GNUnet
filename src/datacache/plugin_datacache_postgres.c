/*
     This file is part of GNUnet
     (C) 2006, 2009, 2010, 2012 Christian Grothoff (and other contributing authors)

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
 * @file datacache/plugin_datacache_postgres.c
 * @brief postgres for an implementation of a database backend for the datacache
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_postgres_lib.h"
#include "gnunet_datacache_plugin.h"
#include <postgresql/libpq-fe.h>

#define LOG(kind,...) GNUNET_log_from (kind, "datacache-postgres", __VA_ARGS__)

/**
 * Per-entry overhead estimate
 */
#define OVERHEAD (sizeof(GNUNET_HashCode) + 24)

/**
 * Context for all functions in this plugin.
 */
struct Plugin
{
  /**
   * Our execution environment.
   */
  struct GNUNET_DATACACHE_PluginEnvironment *env;

  /**
   * Native Postgres database handle.
   */
  PGconn *dbh;

};


/**
 * @brief Get a database handle
 *
 * @param plugin global context
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
init_connection (struct Plugin *plugin)
{
  PGresult *ret;

  plugin->dbh = GNUNET_POSTGRES_connect (plugin->env->cfg,
					 "datacache-postgres");
  if (NULL == plugin->dbh)
    return GNUNET_SYSERR;
  ret =
      PQexec (plugin->dbh,
              "CREATE TEMPORARY TABLE gn090dc ("
              "  type INTEGER NOT NULL DEFAULT 0,"
              "  discard_time BIGINT NOT NULL DEFAULT 0,"
              "  key BYTEA NOT NULL DEFAULT '',"
              "  value BYTEA NOT NULL DEFAULT '')" "WITH OIDS");
  if ((ret == NULL) || ((PQresultStatus (ret) != PGRES_COMMAND_OK) && (0 != strcmp ("42P07",    /* duplicate table */
                                                                                    PQresultErrorField
                                                                                    (ret,
                                                                                     PG_DIAG_SQLSTATE)))))
  {
    (void) GNUNET_POSTGRES_check_result (plugin->dbh, ret, PGRES_COMMAND_OK, "CREATE TABLE",
					 "gn090dc");
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  if (PQresultStatus (ret) == PGRES_COMMAND_OK)
  {
    if ((GNUNET_OK !=
         GNUNET_POSTGRES_exec (plugin->dbh, "CREATE INDEX idx_key ON gn090dc (key)")) ||
        (GNUNET_OK !=
         GNUNET_POSTGRES_exec (plugin->dbh, "CREATE INDEX idx_dt ON gn090dc (discard_time)")))
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
              "ALTER TABLE gn090dc ALTER value SET STORAGE EXTERNAL");
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, ret, PGRES_COMMAND_OK, "ALTER TABLE", "gn090dc"))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  PQclear (ret);
  ret = PQexec (plugin->dbh, "ALTER TABLE gn090dc ALTER key SET STORAGE PLAIN");
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, ret, PGRES_COMMAND_OK, "ALTER TABLE", "gn090dc"))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  PQclear (ret);
  if ((GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "getkt",
                   "SELECT discard_time,type,value FROM gn090dc "
                   "WHERE key=$1 AND type=$2 ", 2)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "getk",
                   "SELECT discard_time,type,value FROM gn090dc "
                   "WHERE key=$1", 1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "getm",
                   "SELECT length(value),oid,key FROM gn090dc "
                   "ORDER BY discard_time ASC LIMIT 1", 0)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "delrow", "DELETE FROM gn090dc WHERE oid=$1", 1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh, "put",
                   "INSERT INTO gn090dc (type, discard_time, key, value) "
                   "VALUES ($1, $2, $3, $4)", 4)))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure (our "struct Plugin")
 * @param key key to store data under
 * @param size number of bytes in data
 * @param data data to store
 * @param type type of the value
 * @param discard_time when to discard the value in any case
 * @return 0 on error, number of bytes used otherwise
 */
static size_t
postgres_plugin_put (void *cls, const GNUNET_HashCode * key, size_t size,
                     const char *data, enum GNUNET_BLOCK_Type type,
                     struct GNUNET_TIME_Absolute discard_time)
{
  struct Plugin *plugin = cls;
  PGresult *ret;
  uint32_t btype = htonl (type);
  uint64_t bexpi = GNUNET_TIME_absolute_hton (discard_time).abs_value__;

  const char *paramValues[] = {
    (const char *) &btype,
    (const char *) &bexpi,
    (const char *) key,
    (const char *) data
  };
  int paramLengths[] = {
    sizeof (btype),
    sizeof (bexpi),
    sizeof (GNUNET_HashCode),
    size
  };
  const int paramFormats[] = { 1, 1, 1, 1 };

  ret =
      PQexecPrepared (plugin->dbh, "put", 4, paramValues, paramLengths,
                      paramFormats, 1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, ret, PGRES_COMMAND_OK, "PQexecPrepared", "put"))
    return GNUNET_SYSERR;
  PQclear (ret);
  return size + OVERHEAD;
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure (our "struct Plugin")
 * @param key
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for iter
 * @return the number of results found
 */
static unsigned int
postgres_plugin_get (void *cls, const GNUNET_HashCode * key,
                     enum GNUNET_BLOCK_Type type,
                     GNUNET_DATACACHE_Iterator iter, void *iter_cls)
{
  struct Plugin *plugin = cls;
  uint32_t btype = htonl (type);

  const char *paramValues[] = {
    (const char *) key,
    (const char *) &btype,
  };
  int paramLengths[] = {
    sizeof (GNUNET_HashCode),
    sizeof (btype),
  };
  const int paramFormats[] = { 1, 1 };
  struct GNUNET_TIME_Absolute expiration_time;
  uint32_t size;
  unsigned int cnt;
  unsigned int i;
  PGresult *res;

  res =
      PQexecPrepared (plugin->dbh, (type == 0) ? "getk" : "getkt",
                      (type == 0) ? 1 : 2, paramValues, paramLengths,
                      paramFormats, 1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, res, PGRES_TUPLES_OK, "PQexecPrepared",
				    (type == 0) ? "getk" : "getkt"))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Ending iteration (postgres error)\n");
    return 0;
  }

  if (0 == (cnt = PQntuples (res)))
  {
    /* no result */
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Ending iteration (no more results)\n");
    PQclear (res);
    return 0;
  }
  if (iter == NULL)
  {
    PQclear (res);
    return cnt;
  }
  if ((3 != PQnfields (res)) || (sizeof (uint64_t) != PQfsize (res, 0)) ||
      (sizeof (uint32_t) != PQfsize (res, 1)))
  {
    GNUNET_break (0);
    PQclear (res);
    return 0;
  }
  for (i = 0; i < cnt; i++)
  {
    expiration_time.abs_value =
        GNUNET_ntohll (*(uint64_t *) PQgetvalue (res, i, 0));
    type = ntohl (*(uint32_t *) PQgetvalue (res, i, 1));
    size = PQgetlength (res, i, 2);
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Found result of size %u bytes and type %u in database\n",
	 (unsigned int) size, (unsigned int) type);
    if (GNUNET_SYSERR ==
        iter (iter_cls, expiration_time, key, size, PQgetvalue (res, i, 2),
              (enum GNUNET_BLOCK_Type) type))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, 
	   "Ending iteration (client error)\n");
      PQclear (res);
      return cnt;
    }
  }
  PQclear (res);
  return cnt;
}


/**
 * Delete the entry with the lowest expiration value
 * from the datacache right now.
 *
 * @param cls closure (our "struct Plugin")
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
postgres_plugin_del (void *cls)
{
  struct Plugin *plugin = cls;
  uint32_t size;
  uint32_t oid;
  GNUNET_HashCode key;
  PGresult *res;

  res = PQexecPrepared (plugin->dbh, "getm", 0, NULL, NULL, NULL, 1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, res, PGRES_TUPLES_OK, "PQexecPrepared", "getm"))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Ending iteration (postgres error)\n");
    return 0;
  }
  if (0 == PQntuples (res))
  {
    /* no result */
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Ending iteration (no more results)\n");
    PQclear (res);
    return GNUNET_SYSERR;
  }
  if ((3 != PQnfields (res)) || (sizeof (size) != PQfsize (res, 0)) ||
      (sizeof (oid) != PQfsize (res, 1)) ||
      (sizeof (GNUNET_HashCode) != PQgetlength (res, 0, 2)))
  {
    GNUNET_break (0);
    PQclear (res);
    return 0;
  }
  size = ntohl (*(uint32_t *) PQgetvalue (res, 0, 0));
  oid = ntohl (*(uint32_t *) PQgetvalue (res, 0, 1));
  memcpy (&key, PQgetvalue (res, 0, 2), sizeof (GNUNET_HashCode));
  PQclear (res);
  if (GNUNET_OK != GNUNET_POSTGRES_delete_by_rowid (plugin->dbh, "delrow", oid))
    return GNUNET_SYSERR;
  plugin->env->delete_notify (plugin->env->cls, &key, size + OVERHEAD);
  return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 *
 * @param cls closure (the "struct GNUNET_DATACACHE_PluginEnvironmnet")
 * @return the plugin's closure (our "struct Plugin")
 */
void *
libgnunet_plugin_datacache_postgres_init (void *cls)
{
  struct GNUNET_DATACACHE_PluginEnvironment *env = cls;
  struct GNUNET_DATACACHE_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;

  if (GNUNET_OK != init_connection (plugin))
  {
    GNUNET_free (plugin);
    return NULL;
  }

  api = GNUNET_malloc (sizeof (struct GNUNET_DATACACHE_PluginFunctions));
  api->cls = plugin;
  api->get = &postgres_plugin_get;
  api->put = &postgres_plugin_put;
  api->del = &postgres_plugin_del;
  LOG (GNUNET_ERROR_TYPE_INFO, 
       _("Postgres datacache running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls closure (our "struct Plugin")
 * @return NULL
 */
void *
libgnunet_plugin_datacache_postgres_done (void *cls)
{
  struct GNUNET_DATACACHE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  PQfinish (plugin->dbh);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}



/* end of plugin_datacache_postgres.c */
