/*
     This file is part of GNUnet
     Copyright (C) 2006, 2009, 2010, 2012, 2015, 2017 GNUnet e.V.

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
#include "gnunet_pq_lib.h"
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
  struct GNUNET_PQ_ExecuteStatement es[] = {
    GNUNET_PQ_make_execute ("CREATE TEMPORARY TABLE IF NOT EXISTS gn090dc ("
                            "  type INTEGER NOT NULL DEFAULT 0,"
                            "  discard_time BIGINT NOT NULL DEFAULT 0,"
                            "  key BYTEA NOT NULL DEFAULT '',"
                            "  value BYTEA NOT NULL DEFAULT '',"
                            "  path BYTEA DEFAULT '')"
                            "WITH OIDS"),
    GNUNET_PQ_make_try_execute ("CREATE INDEX IF NOT EXISTS idx_key ON gn090dc (key)"),
    GNUNET_PQ_make_try_execute ("CREATE INDEX IF NOT EXISTS idx_dt ON gn090dc (discard_time)"),
    GNUNET_PQ_make_execute ("ALTER TABLE gn090dc ALTER value SET STORAGE EXTERNAL"),
    GNUNET_PQ_make_execute ("ALTER TABLE gn090dc ALTER key SET STORAGE PLAIN"),
    GNUNET_PQ_EXECUTE_STATEMENT_END
  };
  struct GNUNET_PQ_PreparedStatement ps[] = {
    GNUNET_PQ_make_prepare ("getkt",
                            "SELECT discard_time,type,value,path FROM gn090dc "
                            "WHERE key=$1 AND type=$2",
                            2),
    GNUNET_PQ_make_prepare ("getk",
                            "SELECT discard_time,type,value,path FROM gn090dc "
                            "WHERE key=$1",
                            1),
    GNUNET_PQ_make_prepare ("getm",
                            "SELECT length(value) AS len,oid,key FROM gn090dc "
                            "ORDER BY discard_time ASC LIMIT 1",
                            0),
    GNUNET_PQ_make_prepare ("get_random",
                            "SELECT discard_time,type,value,path,key FROM gn090dc "
                            "ORDER BY key ASC LIMIT 1 OFFSET $1",
                            1),
    GNUNET_PQ_make_prepare ("get_closest",
                            "SELECT discard_time,type,value,path,key FROM gn090dc "
                            "WHERE key>=$1 ORDER BY key ASC LIMIT $2",
                            1),
    GNUNET_PQ_make_prepare ("delrow",
                            "DELETE FROM gn090dc WHERE oid=$1",
                            1),
    GNUNET_PQ_make_prepare ("put",
                            "INSERT INTO gn090dc (type, discard_time, key, value, path) "
                            "VALUES ($1, $2, $3, $4, $5)",
                            5),
    GNUNET_PQ_PREPARED_STATEMENT_END
  };

  plugin->dbh = GNUNET_PQ_connect_with_cfg (plugin->env->cfg,
                                            "datacache-postgres");
  if (NULL == plugin->dbh)
    return GNUNET_SYSERR;
  if (GNUNET_OK !=
      GNUNET_PQ_exec_statements (plugin->dbh,
                                 es))
  {
    PQfinish (plugin->dbh);
    plugin->dbh = NULL;
    return GNUNET_SYSERR;
  }

  if (GNUNET_OK !=
      GNUNET_PQ_prepare_statements (plugin->dbh,
                                    ps))
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
 * @param data_size number of bytes in @a data
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
                     size_t data_size,
                     const char *data,
                     enum GNUNET_BLOCK_Type type,
                     struct GNUNET_TIME_Absolute discard_time,
		     unsigned int path_info_len,
		     const struct GNUNET_PeerIdentity *path_info)
{
  struct Plugin *plugin = cls;
  uint32_t type32 = (uint32_t) type;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_uint32 (&type32),
    GNUNET_PQ_query_param_absolute_time (&discard_time),
    GNUNET_PQ_query_param_auto_from_type (key),
    GNUNET_PQ_query_param_fixed_size (data, data_size),
    GNUNET_PQ_query_param_fixed_size (path_info,
                                      path_info_len * sizeof (struct GNUNET_PeerIdentity)),
    GNUNET_PQ_query_param_end
  };
  enum GNUNET_PQ_QueryStatus ret;

  ret = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                            "put",
                                            params);
  if (0 > ret)
    return -1;
  plugin->num_items++;
  return data_size + OVERHEAD;
}


/**
 * Closure for #handle_results.
 */
struct HandleResultContext
{

  /**
   * Function to call on each result, may be NULL.
   */
  GNUNET_DATACACHE_Iterator iter;

  /**
   * Closure for @e iter.
   */
  void *iter_cls;

  /**
   * Key used.
   */
  const struct GNUNET_HashCode *key;
};


/**
 * Function to be called with the results of a SELECT statement
 * that has returned @a num_results results.  Parse the result
 * and call the callback given in @a cls
 *
 * @param cls closure of type `struct HandleResultContext`
 * @param result the postgres result
 * @param num_result the number of results in @a result
 */
static void
handle_results (void *cls,
                PGresult *result,
                unsigned int num_results)
{
  struct HandleResultContext *hrc = cls;

  for (unsigned int i=0;i<num_results;i++)
  {
    struct GNUNET_TIME_Absolute expiration_time;
    uint32_t type;
    void *data;
    size_t data_size;
    struct GNUNET_PeerIdentity *path;
    size_t path_len;
    struct GNUNET_PQ_ResultSpec rs[] = {
      GNUNET_PQ_result_spec_absolute_time ("discard_time",
                                           &expiration_time),
      GNUNET_PQ_result_spec_uint32 ("type",
                                    &type),
      GNUNET_PQ_result_spec_variable_size ("value",
                                           &data,
                                           &data_size),
      GNUNET_PQ_result_spec_variable_size ("path",
                                           (void **) &path,
                                           &path_len),
      GNUNET_PQ_result_spec_end
    };

    if (GNUNET_YES !=
        GNUNET_PQ_extract_result (result,
                                  rs,
                                  i))
    {
      GNUNET_break (0);
      return;
    }
    if (0 != (path_len % sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break (0);
      path_len = 0;
    }
    path_len %= sizeof (struct GNUNET_PeerIdentity);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Found result of size %u bytes and type %u in database\n",
	 (unsigned int) data_size,
         (unsigned int) type);
    if ( (NULL != hrc->iter) &&
         (GNUNET_SYSERR ==
          hrc->iter (hrc->iter_cls,
                     hrc->key,
                     data_size,
                     data,
                     (enum GNUNET_BLOCK_Type) type,
                     expiration_time,
                     path_len,
                     path)) )
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Ending iteration (client error)\n");
      GNUNET_PQ_cleanup_result (rs);
      return;
    }
    GNUNET_PQ_cleanup_result (rs);
  }
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
  uint32_t type32 = (uint32_t) type;
  struct GNUNET_PQ_QueryParam paramk[] = {
    GNUNET_PQ_query_param_auto_from_type (key),
    GNUNET_PQ_query_param_end
  };
  struct GNUNET_PQ_QueryParam paramkt[] = {
    GNUNET_PQ_query_param_auto_from_type (key),
    GNUNET_PQ_query_param_uint32 (&type32),
    GNUNET_PQ_query_param_end
  };
  enum GNUNET_PQ_QueryStatus res;
  struct HandleResultContext hr_ctx;

  hr_ctx.iter = iter;
  hr_ctx.iter_cls = iter_cls;
  hr_ctx.key = key;
  res = GNUNET_PQ_eval_prepared_multi_select (plugin->dbh,
                                              (0 == type) ? "getk" : "getkt",
                                              (0 == type) ? paramk : paramkt,
                                              &handle_results,
                                              &hr_ctx);
  if (res < 0)
    return 0;
  return res;
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
  struct GNUNET_PQ_QueryParam pempty[] = {
    GNUNET_PQ_query_param_end
  };
  uint32_t size;
  uint32_t oid;
  struct GNUNET_HashCode key;
  struct GNUNET_PQ_ResultSpec rs[] = {
    GNUNET_PQ_result_spec_uint32 ("len",
                                  &size),
    GNUNET_PQ_result_spec_uint32 ("oid",
                                  &oid),
    GNUNET_PQ_result_spec_auto_from_type ("key",
                                          &key),
    GNUNET_PQ_result_spec_end
  };
  enum GNUNET_PQ_QueryStatus res;
  struct GNUNET_PQ_QueryParam dparam[] = {
    GNUNET_PQ_query_param_uint32 (&oid),
    GNUNET_PQ_query_param_end
  };

  res = GNUNET_PQ_eval_prepared_singleton_select (plugin->dbh,
                                                  "getm",
                                                  pempty,
                                                  rs);
  if (0 > res)
    return GNUNET_SYSERR;
  if (GNUNET_PQ_STATUS_SUCCESS_NO_RESULTS == res)
  {
    /* no result */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Ending iteration (no more results)\n");
    return 0;
  }
  res = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                            "delrow",
                                            dparam);
  if (0 > res)
  {
    GNUNET_PQ_cleanup_result (rs);
    return GNUNET_SYSERR;
  }
  plugin->num_items--;
  plugin->env->delete_notify (plugin->env->cls,
                              &key,
                              size + OVERHEAD);
  GNUNET_PQ_cleanup_result (rs);
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
  uint32_t off;
  struct GNUNET_TIME_Absolute expiration_time;
  size_t data_size;
  void *data;
  size_t path_len;
  struct GNUNET_PeerIdentity *path;
  struct GNUNET_HashCode key;
  uint32_t type;
  enum GNUNET_PQ_QueryStatus res;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_uint32 (&off),
    GNUNET_PQ_query_param_end
  };
  struct GNUNET_PQ_ResultSpec rs[] = {
    GNUNET_PQ_result_spec_absolute_time ("discard_time",
                                         &expiration_time),
    GNUNET_PQ_result_spec_uint32 ("type",
                                  &type),
    GNUNET_PQ_result_spec_variable_size ("value",
                                         &data,
                                         &data_size),
    GNUNET_PQ_result_spec_variable_size ("path",
                                         (void **) &path,
                                         &path_len),
    GNUNET_PQ_result_spec_auto_from_type ("key",
                                          &key),
    GNUNET_PQ_result_spec_end
  };

  if (0 == plugin->num_items)
    return 0;
  if (NULL == iter)
    return 1;
  off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                  plugin->num_items);
  res = GNUNET_PQ_eval_prepared_singleton_select (plugin->dbh,
                                                  "get_random",
                                                  params,
                                                  rs);
  if (0 > res)
  {
    GNUNET_break (0);
    return 0;
  }
  if (GNUNET_PQ_STATUS_SUCCESS_NO_RESULTS == res)
  {
    GNUNET_break (0);
    return 0;
  }
  if (0 != (path_len % sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break (0);
    path_len = 0;
  }
  path_len %= sizeof (struct GNUNET_PeerIdentity);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Found random value with key %s of size %u bytes and type %u in database\n",
       GNUNET_h2s (&key),
       (unsigned int) data_size,
       (unsigned int) type);
  (void) iter (iter_cls,
               &key,
               data_size,
               data,
               (enum GNUNET_BLOCK_Type) type,
               expiration_time,
               path_len,
               path);
  GNUNET_PQ_cleanup_result (rs);
  return 1;
}


/**
 * Closure for #extract_result_cb.
 */
struct ExtractResultContext
{
  /**
   * Function to call for each result found.
   */
  GNUNET_DATACACHE_Iterator iter;

  /**
   * Closure for @e iter.
   */
  void *iter_cls;

};


/**
 * Function to be called with the results of a SELECT statement
 * that has returned @a num_results results.  Calls the `iter`
 * from @a cls for each result.
 *
 * @param cls closure with the `struct ExtractResultContext`
 * @param result the postgres result
 * @param num_result the number of results in @a result
 */
static void
extract_result_cb (void *cls,
                   PGresult *result,
                   unsigned int num_results)
{
  struct ExtractResultContext *erc = cls;

  if (NULL == erc->iter)
    return;
  for (unsigned int i=0;i<num_results;i++)
  {
    struct GNUNET_TIME_Absolute expiration_time;
    uint32_t type;
    void *data;
    size_t data_size;
    struct GNUNET_PeerIdentity *path;
    size_t path_len;
    struct GNUNET_HashCode key;
    struct GNUNET_PQ_ResultSpec rs[] = {
      GNUNET_PQ_result_spec_absolute_time ("",
                                           &expiration_time),
      GNUNET_PQ_result_spec_uint32 ("type",
                                    &type),
      GNUNET_PQ_result_spec_variable_size ("value",
                                           &data,
                                           &data_size),
      GNUNET_PQ_result_spec_variable_size ("path",
                                           (void **) &path,
                                           &path_len),
      GNUNET_PQ_result_spec_auto_from_type ("key",
                                            &key),
      GNUNET_PQ_result_spec_end
    };

    if (0 != (path_len % sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break (0);
      path_len = 0;
    }
    path_len %= sizeof (struct GNUNET_PeerIdentity);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Found result of size %u bytes and type %u in database\n",
	 (unsigned int) data_size,
         (unsigned int) type);
    if (GNUNET_SYSERR ==
        erc->iter (erc->iter_cls,
                   &key,
                   data_size,
                   data,
                   (enum GNUNET_BLOCK_Type) type,
                   expiration_time,
                   path_len,
                   path))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Ending iteration (client error)\n");
      GNUNET_PQ_cleanup_result (rs);
      break;
    }
    GNUNET_PQ_cleanup_result (rs);
  }
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
  uint32_t num_results32 = (uint32_t) num_results;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (key),
    GNUNET_PQ_query_param_uint32 (&num_results32),
    GNUNET_PQ_query_param_end
  };
  enum GNUNET_PQ_QueryStatus res;
  struct ExtractResultContext erc;

  erc.iter = iter;
  erc.iter_cls = iter_cls;
  res = GNUNET_PQ_eval_prepared_multi_select (plugin->dbh,
                                              "get_closest",
                                              params,
                                              &extract_result_cb,
                                              &erc);
  if (0 > res)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Ending iteration (postgres error)\n");
    return 0;
  }
  if (GNUNET_PQ_STATUS_SUCCESS_NO_RESULTS == res)
  {
    /* no result */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Ending iteration (no more results)\n");
    return 0;
  }
  return res;
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
