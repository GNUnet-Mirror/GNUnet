/*
     This file is part of GNUnet
     Copyright (C) 2006, 2009, 2010, 2012, 2015 GNUnet e.V.

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
 * @file datacache/plugin_datacache_postgres.c
 * @brief postgres for an implementation of a database backend for the datacache
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_postgres_lib.h"
#include "gnunet_datacache_plugin.h"

#define LOG(kind,...) GNUNET_log_from (kind, "datacache-postgres", __VA_ARGS__)

/**
 * Per-entry overhead estimate
 */
#define OVERHEAD (sizeof(struct GNUNET_HashCode) + 24)

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

  /**
   * Number of key-value pairs in the database.
   */
  unsigned int num_items;
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

  plugin->dbh = GNUNET_POSTGRES_connect (plugin->env->cfg,
					 "datacache-postgres");
  if (NULL == plugin->dbh)
    return GNUNET_SYSERR;
  ret =
      PQexec (plugin->dbh,
              "CREATE TEMPORARY TABLE IF NOT EXISTS gn090dc ("
              "  type INTEGER NOT NULL DEFAULT 0,"
              "  discard_time BIGINT NOT NULL DEFAULT 0,"
              "  key BYTEA NOT NULL DEFAULT '',"
              "  value BYTEA NOT NULL DEFAULT '',"
              "  path BYTEA DEFAULT '')"
	      "WITH OIDS");
  if ( (ret == NULL) ||
       ((PQresultStatus (ret) != PGRES_COMMAND_OK) &&
	(0 != strcmp ("42P07",    /* duplicate table */
		      PQresultErrorField
		      (ret,
		       PG_DIAG_SQLSTATE)))))
  {
    (void) GNUNET_POSTGRES_check_result (plugin->dbh, ret,
					 PGRES_COMMAND_OK,
                                         "CREATE TABLE",
					 "gn090dc");
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  if (PQresultStatus (ret) == PGRES_COMMAND_OK)
  {
    if ((GNUNET_OK !=
         GNUNET_POSTGRES_exec (plugin->dbh,
                               "CREATE INDEX IF NOT EXISTS idx_key ON gn090dc (key)")) ||
        (GNUNET_OK !=
         GNUNET_POSTGRES_exec (plugin->dbh,
                               "CREATE INDEX IF NOT EXISTS idx_dt ON gn090dc (discard_time)")))
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
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    ret,
                                    PGRES_COMMAND_OK,
                                    "ALTER TABLE",
                                    "gn090dc"))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  PQclear (ret);
  ret = PQexec (plugin->dbh,
                "ALTER TABLE gn090dc ALTER key SET STORAGE PLAIN");
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    ret,
                                    PGRES_COMMAND_OK,
                                    "ALTER TABLE",
                                    "gn090dc"))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }
  PQclear (ret);
  if ((GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
                                "getkt",
                                "SELECT discard_time,type,value,path FROM gn090dc "
                                "WHERE key=$1 AND type=$2 ", 2)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
                                "getk",
                                "SELECT discard_time,type,value,path FROM gn090dc "
                                "WHERE key=$1", 1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
                                "getm",
                                "SELECT length(value),oid,key FROM gn090dc "
                                "ORDER BY discard_time ASC LIMIT 1", 0)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
                                "get_random",
                                "SELECT discard_time,type,value,path,key FROM gn090dc "
                                "ORDER BY key ASC LIMIT 1 OFFSET $1", 1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
                                "get_closest",
                                "SELECT discard_time,type,value,path,key FROM gn090dc "
                                "WHERE key>=$1 ORDER BY key ASC LIMIT $2", 1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
                                "delrow",
                                "DELETE FROM gn090dc WHERE oid=$1", 1)) ||
      (GNUNET_OK !=
       GNUNET_POSTGRES_prepare (plugin->dbh,
                                "put",
                                "INSERT INTO gn090dc (type, discard_time, key, value, path) "
                                "VALUES ($1, $2, $3, $4, $5)", 5)))
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
 * @param cls closure (our `struct Plugin`)
 * @param key key to store @a data under
 * @param size number of bytes in @a data
 * @param data data to store
 * @param type type of the value
 * @param discard_time when to discard the value in any case
 * @param path_info_len number of entries in @a path_info
 * @param path_info a path through the network
 * @return 0 if duplicate, -1 on error, number of bytes used otherwise
 */
static ssize_t
postgres_plugin_put (void *cls,
                     const struct GNUNET_HashCode *key,
                     size_t size,
                     const char *data,
                     enum GNUNET_BLOCK_Type type,
                     struct GNUNET_TIME_Absolute discard_time,
		     unsigned int path_info_len,
		     const struct GNUNET_PeerIdentity *path_info)
{
  struct Plugin *plugin = cls;
  PGresult *ret;
  uint32_t btype = htonl (type);
  uint64_t bexpi = GNUNET_TIME_absolute_hton (discard_time).abs_value_us__;

  const char *paramValues[] = {
    (const char *) &btype,
    (const char *) &bexpi,
    (const char *) key,
    (const char *) data,
    (const char *) path_info
  };
  int paramLengths[] = {
    sizeof (btype),
    sizeof (bexpi),
    sizeof (struct GNUNET_HashCode),
    size,
    path_info_len * sizeof (struct GNUNET_PeerIdentity)
  };
  const int paramFormats[] = { 1, 1, 1, 1, 1 };

  ret =
      PQexecPrepared (plugin->dbh, "put", 5, paramValues, paramLengths,
                      paramFormats, 1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh, ret,
				    PGRES_COMMAND_OK, "PQexecPrepared", "put"))
    return -1;
  plugin->num_items++;
  PQclear (ret);
  return size + OVERHEAD;
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure (our `struct Plugin`)
 * @param key key to look for
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found
 */
static unsigned int
postgres_plugin_get (void *cls,
                     const struct GNUNET_HashCode *key,
                     enum GNUNET_BLOCK_Type type,
                     GNUNET_DATACACHE_Iterator iter,
                     void *iter_cls)
{
  struct Plugin *plugin = cls;
  uint32_t btype = htonl (type);

  const char *paramValues[] = {
    (const char *) key,
    (const char *) &btype
  };
  int paramLengths[] = {
    sizeof (struct GNUNET_HashCode),
    sizeof (btype)
  };
  const int paramFormats[] = { 1, 1 };
  struct GNUNET_TIME_Absolute expiration_time;
  uint32_t size;
  unsigned int cnt;
  unsigned int i;
  unsigned int path_len;
  const struct GNUNET_PeerIdentity *path;
  PGresult *res;

  res =
      PQexecPrepared (plugin->dbh, (type == 0) ? "getk" : "getkt",
                      (type == 0) ? 1 : 2, paramValues, paramLengths,
                      paramFormats, 1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    res,
                                    PGRES_TUPLES_OK,
                                    "PQexecPrepared",
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
  if ( (4 != PQnfields (res)) ||
       (sizeof (uint64_t) != PQfsize (res, 0)) ||
       (sizeof (uint32_t) != PQfsize (res, 1)))
  {
    GNUNET_break (0);
    PQclear (res);
    return 0;
  }
  for (i = 0; i < cnt; i++)
  {
    expiration_time.abs_value_us =
        GNUNET_ntohll (*(uint64_t *) PQgetvalue (res, i, 0));
    type = ntohl (*(uint32_t *) PQgetvalue (res, i, 1));
    size = PQgetlength (res, i, 2);
    path_len = PQgetlength (res, i, 3);
    if (0 != (path_len % sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break (0);
      path_len = 0;
    }
    path_len %= sizeof (struct GNUNET_PeerIdentity);
    path = (const struct GNUNET_PeerIdentity *) PQgetvalue (res, i, 3);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Found result of size %u bytes and type %u in database\n",
	 (unsigned int) size, (unsigned int) type);
    if (GNUNET_SYSERR ==
        iter (iter_cls, key, size, PQgetvalue (res, i, 2),
              (enum GNUNET_BLOCK_Type) type,
	      expiration_time,
	      path_len,
	      path))
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
 * @param cls closure (our `struct Plugin`)
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
postgres_plugin_del (void *cls)
{
  struct Plugin *plugin = cls;
  uint32_t size;
  uint32_t oid;
  struct GNUNET_HashCode key;
  PGresult *res;

  res = PQexecPrepared (plugin->dbh,
                        "getm",
                        0, NULL, NULL, NULL, 1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    res,
                                    PGRES_TUPLES_OK,
                                    "PQexecPrepared",
                                    "getm"))
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
      (sizeof (struct GNUNET_HashCode) != PQgetlength (res, 0, 2)))
  {
    GNUNET_break (0);
    PQclear (res);
    return 0;
  }
  size = ntohl (*(uint32_t *) PQgetvalue (res, 0, 0));
  oid = ntohl (*(uint32_t *) PQgetvalue (res, 0, 1));
  GNUNET_memcpy (&key, PQgetvalue (res, 0, 2), sizeof (struct GNUNET_HashCode));
  PQclear (res);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_delete_by_rowid (plugin->dbh,
                                       "delrow",
                                       oid))
    return GNUNET_SYSERR;
  plugin->num_items--;
  plugin->env->delete_notify (plugin->env->cls,
                              &key,
                              size + OVERHEAD);
  return GNUNET_OK;
}


/**
 * Obtain a random key-value pair from the datacache.
 *
 * @param cls closure (our `struct Plugin`)
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found, zero (datacache empty) or one
 */
static unsigned int
postgres_plugin_get_random (void *cls,
                            GNUNET_DATACACHE_Iterator iter,
                            void *iter_cls)
{
  struct Plugin *plugin = cls;
  unsigned int off;
  uint32_t off_be;
  struct GNUNET_TIME_Absolute expiration_time;
  uint32_t size;
  unsigned int path_len;
  const struct GNUNET_PeerIdentity *path;
  const struct GNUNET_HashCode *key;
  unsigned int type;
  PGresult *res;
  const char *paramValues[] = {
    (const char *) &off_be
  };
  int paramLengths[] = {
    sizeof (off_be)
  };
  const int paramFormats[] = { 1 };

  if (0 == plugin->num_items)
    return 0;
  if (NULL == iter)
    return 1;
  off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                  plugin->num_items);
  off_be = htonl (off);
  res =
    PQexecPrepared (plugin->dbh, "get_random",
                    1, paramValues, paramLengths, paramFormats,
                    1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    res,
                                    PGRES_TUPLES_OK,
                                    "PQexecPrepared",
				    "get_random"))
  {
    GNUNET_break (0);
    return 0;
  }
  if (0 == PQntuples (res))
  {
    GNUNET_break (0);
    return 0;
  }
  if ( (5 != PQnfields (res)) ||
       (sizeof (uint64_t) != PQfsize (res, 0)) ||
       (sizeof (uint32_t) != PQfsize (res, 1)) ||
       (sizeof (struct GNUNET_HashCode) != PQfsize (res, 4)) )
  {
    GNUNET_break (0);
    PQclear (res);
    return 0;
  }
  expiration_time.abs_value_us =
    GNUNET_ntohll (*(uint64_t *) PQgetvalue (res, 0, 0));
  type = ntohl (*(uint32_t *) PQgetvalue (res, 0, 1));
  size = PQgetlength (res, 0, 2);
  path_len = PQgetlength (res, 0, 3);
  if (0 != (path_len % sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break (0);
    path_len = 0;
  }
  path_len %= sizeof (struct GNUNET_PeerIdentity);
  path = (const struct GNUNET_PeerIdentity *) PQgetvalue (res, 0, 3);
  key = (const struct GNUNET_HashCode *) PQgetvalue (res, 0, 4);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Found random value with key %s of size %u bytes and type %u in database\n",
       GNUNET_h2s (key),
       (unsigned int) size,
       (unsigned int) type);
  (void) iter (iter_cls,
               key,
               size,
               PQgetvalue (res, 0, 2),
               (enum GNUNET_BLOCK_Type) type,
               expiration_time,
               path_len,
               path);
  PQclear (res);
  return 1;
}


/**
 * Iterate over the results that are "close" to a particular key in
 * the datacache.  "close" is defined as numerically larger than @a
 * key (when interpreted as a circular address space), with small
 * distance.
 *
 * @param cls closure (internal context for the plugin)
 * @param key area of the keyspace to look into
 * @param num_results number of results that should be returned to @a iter
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for @a iter
 * @return the number of results found
 */
static unsigned int
postgres_plugin_get_closest (void *cls,
                             const struct GNUNET_HashCode *key,
                             unsigned int num_results,
                             GNUNET_DATACACHE_Iterator iter,
                             void *iter_cls)
{
  struct Plugin *plugin = cls;
  uint32_t nbo_limit = htonl (num_results);
  const char *paramValues[] = {
    (const char *) key,
    (const char *) &nbo_limit,
  };
  int paramLengths[] = {
    sizeof (struct GNUNET_HashCode),
    sizeof (nbo_limit)

  };
  const int paramFormats[] = { 1, 1 };
  struct GNUNET_TIME_Absolute expiration_time;
  uint32_t size;
  unsigned int type;
  unsigned int cnt;
  unsigned int i;
  unsigned int path_len;
  const struct GNUNET_PeerIdentity *path;
  PGresult *res;

  res =
      PQexecPrepared (plugin->dbh,
                      "get_closest",
                      2,
                      paramValues,
                      paramLengths,
                      paramFormats,
                      1);
  if (GNUNET_OK !=
      GNUNET_POSTGRES_check_result (plugin->dbh,
                                    res,
                                    PGRES_TUPLES_OK,
                                    "PQexecPrepared",
				    "get_closest"))
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
  if (NULL == iter)
  {
    PQclear (res);
    return cnt;
  }
  if ( (5 != PQnfields (res)) ||
       (sizeof (uint64_t) != PQfsize (res, 0)) ||
       (sizeof (uint32_t) != PQfsize (res, 1)) ||
       (sizeof (struct GNUNET_HashCode) != PQfsize (res, 4)) )
  {
    GNUNET_break (0);
    PQclear (res);
    return 0;
  }
  for (i = 0; i < cnt; i++)
  {
    expiration_time.abs_value_us =
        GNUNET_ntohll (*(uint64_t *) PQgetvalue (res, i, 0));
    type = ntohl (*(uint32_t *) PQgetvalue (res, i, 1));
    size = PQgetlength (res, i, 2);
    path_len = PQgetlength (res, i, 3);
    if (0 != (path_len % sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break (0);
      path_len = 0;
    }
    path_len %= sizeof (struct GNUNET_PeerIdentity);
    path = (const struct GNUNET_PeerIdentity *) PQgetvalue (res, i, 3);
    key = (const struct GNUNET_HashCode *) PQgetvalue (res, i, 4);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Found result of size %u bytes and type %u in database\n",
	 (unsigned int) size,
         (unsigned int) type);
    if (GNUNET_SYSERR ==
        iter (iter_cls,
              key,
              size,
              PQgetvalue (res, i, 2),
              (enum GNUNET_BLOCK_Type) type,
	      expiration_time,
	      path_len,
	      path))
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
 * Entry point for the plugin.
 *
 * @param cls closure (the `struct GNUNET_DATACACHE_PluginEnvironmnet`)
 * @return the plugin's closure (our `struct Plugin`)
 */
void *
libgnunet_plugin_datacache_postgres_init (void *cls)
{
  struct GNUNET_DATACACHE_PluginEnvironment *env = cls;
  struct GNUNET_DATACACHE_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_new (struct Plugin);
  plugin->env = env;

  if (GNUNET_OK != init_connection (plugin))
  {
    GNUNET_free (plugin);
    return NULL;
  }

  api = GNUNET_new (struct GNUNET_DATACACHE_PluginFunctions);
  api->cls = plugin;
  api->get = &postgres_plugin_get;
  api->put = &postgres_plugin_put;
  api->del = &postgres_plugin_del;
  api->get_random = &postgres_plugin_get_random;
  api->get_closest = &postgres_plugin_get_closest;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Postgres datacache running\n");
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls closure (our `struct Plugin`)
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
