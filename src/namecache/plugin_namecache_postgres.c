 /*
  * This file is part of GNUnet
  * Copyright (C) 2009-2013, 2016, 2017 GNUnet e.V.
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
 * @file namecache/plugin_namecache_postgres.c
 * @brief postgres-based namecache backend
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_namecache_plugin.h"
#include "gnunet_namecache_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_postgres_lib.h"
#include "gnunet_pq_lib.h"
#include "namecache.h"


#define LOG(kind,...) GNUNET_log_from (kind, "namecache-postgres", __VA_ARGS__)


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
  struct GNUNET_PQ_ExecuteStatement es_temporary =
    GNUNET_PQ_make_execute ("CREATE TEMPORARY TABLE IF NOT EXISTS ns096blocks ("
                            " query BYTEA NOT NULL DEFAULT '',"
                            " block BYTEA NOT NULL DEFAULT '',"
                            " expiration_time BIGINT NOT NULL DEFAULT 0"
                            ")"
                            "WITH OIDS");
  struct GNUNET_PQ_ExecuteStatement es_default =
    GNUNET_PQ_make_execute ("CREATE TABLE IF NOT EXISTS ns096blocks ("
                            " query BYTEA NOT NULL DEFAULT '',"
                            " block BYTEA NOT NULL DEFAULT '',"
                            " expiration_time BIGINT NOT NULL DEFAULT 0"
                            ")"
                            "WITH OIDS");
  const struct GNUNET_PQ_ExecuteStatement *cr;

  plugin->dbh = GNUNET_PQ_connect_with_cfg (plugin->cfg,
                                            "namecache-postgres");
  if (NULL == plugin->dbh)
    return GNUNET_SYSERR;
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (plugin->cfg,
					    "namecache-postgres",
					    "TEMPORARY_TABLE"))
  {
    cr = &es_temporary;
  }
  else
  {
    cr = &es_default;
  }

  {
    struct GNUNET_PQ_ExecuteStatement es[] = {
      *cr,
      GNUNET_PQ_make_try_execute ("CREATE INDEX ir_query_hash ON ns096blocks (query,expiration_time)"),
      GNUNET_PQ_make_try_execute ("CREATE INDEX ir_block_expiration ON ns096blocks (expiration_time)"),
      GNUNET_PQ_EXECUTE_STATEMENT_END
    };

    if (GNUNET_OK !=
        GNUNET_PQ_exec_statements (plugin->dbh,
                                   es))
    {
      PQfinish (plugin->dbh);
      plugin->dbh = NULL;
      return GNUNET_SYSERR;
    }
  }

  {
    struct GNUNET_PQ_PreparedStatement ps[] = {
      GNUNET_PQ_make_prepare ("cache_block",
                              "INSERT INTO ns096blocks (query, block, expiration_time) VALUES "
                              "($1, $2, $3)", 3),
      GNUNET_PQ_make_prepare ("expire_blocks",
                              "DELETE FROM ns096blocks WHERE expiration_time<$1", 1),
      GNUNET_PQ_make_prepare ("delete_block",
                              "DELETE FROM ns096blocks WHERE query=$1 AND expiration_time<=$2", 2),
      GNUNET_PQ_make_prepare ("lookup_block",
                              "SELECT block FROM ns096blocks WHERE query=$1"
                              " ORDER BY expiration_time DESC LIMIT 1", 1),
      GNUNET_PQ_PREPARED_STATEMENT_END
    };

    if (GNUNET_OK !=
        GNUNET_PQ_prepare_statements (plugin->dbh,
                                      ps))
    {
      PQfinish (plugin->dbh);
      plugin->dbh = NULL;
      return GNUNET_SYSERR;
    }
  }

  return GNUNET_OK;
}


/**
 * Removes any expired block.
 *
 * @param plugin the plugin
 */
static void
namecache_postgres_expire_blocks (struct Plugin *plugin)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_absolute_time (&now),
    GNUNET_PQ_query_param_end
  };
  enum GNUNET_PQ_QueryStatus res;

  res = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                            "expire_blocks",
                                            params);
  GNUNET_break (GNUNET_PQ_STATUS_HARD_ERROR != res);
}


/**
 * Delete older block in the datastore.
 *
 * @param plugin the plugin
 * @param query query for the block
 * @param expiration_time how old does the block have to be for deletion
 */
static void
delete_old_block (struct Plugin *plugin,
                  const struct GNUNET_HashCode *query,
                  struct GNUNET_TIME_AbsoluteNBO expiration_time)
{
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (query),
    GNUNET_PQ_query_param_absolute_time_nbo (&expiration_time),
    GNUNET_PQ_query_param_end
  };
  enum GNUNET_PQ_QueryStatus res;

  res = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                            "delete_block",
                                            params);
  GNUNET_break (GNUNET_PQ_STATUS_HARD_ERROR != res);
}


/**
 * Cache a block in the datastore.
 *
 * @param cls closure (internal context for the plugin)
 * @param block block to cache
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
namecache_postgres_cache_block (void *cls,
                                const struct GNUNET_GNSRECORD_Block *block)
{
  struct Plugin *plugin = cls;
  struct GNUNET_HashCode query;
  size_t block_size = ntohl (block->purpose.size) +
    sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
    sizeof (struct GNUNET_CRYPTO_EcdsaSignature);
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (&query),
    GNUNET_PQ_query_param_fixed_size (block, block_size),
    GNUNET_PQ_query_param_absolute_time_nbo (&block->expiration_time),
    GNUNET_PQ_query_param_end
  };
  enum GNUNET_PQ_QueryStatus res;

  namecache_postgres_expire_blocks (plugin);
  GNUNET_CRYPTO_hash (&block->derived_key,
		      sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
		      &query);
  if (block_size > 64 * 65536)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  delete_old_block (plugin,
                    &query,
                    block->expiration_time);

  res = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                            "cache_block",
                                            params);
  if (0 > res)
    return GNUNET_SYSERR;
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
namecache_postgres_lookup_block (void *cls,
                                 const struct GNUNET_HashCode *query,
                                 GNUNET_NAMECACHE_BlockCallback iter,
                                 void *iter_cls)
{
  struct Plugin *plugin = cls;
  size_t bsize;
  struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (query),
    GNUNET_PQ_query_param_end
  };
  struct GNUNET_PQ_ResultSpec rs[] = {
    GNUNET_PQ_result_spec_variable_size ("block",
                                         (void **) &block,
                                         &bsize),
    GNUNET_PQ_result_spec_end
  };
  enum GNUNET_PQ_QueryStatus res;

  res = GNUNET_PQ_eval_prepared_singleton_select (plugin->dbh,
                                                  "lookup_block",
                                                  params,
                                                  rs);
  if (0 > res)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 "Failing lookup block in namecache (postgres error)\n");
    return GNUNET_SYSERR;
  }
  if (GNUNET_PQ_STATUS_SUCCESS_NO_RESULTS == res)
  {
    /* no result */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Ending iteration (no more results)\n");
    return GNUNET_NO;
  }
  if ( (bsize < sizeof (*block)) ||
       (bsize != ntohl (block->purpose.size) +
        sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
        sizeof (struct GNUNET_CRYPTO_EcdsaSignature)) )
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Failing lookup (corrupt block)\n");
    GNUNET_PQ_cleanup_result (rs);
    return GNUNET_SYSERR;
  }
  iter (iter_cls,
        block);
  GNUNET_PQ_cleanup_result (rs);
  return GNUNET_OK;
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
 * @param cls the `struct GNUNET_NAMECACHE_PluginEnvironment *`
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_namecache_postgres_init (void *cls)
{
  static struct Plugin plugin;
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_NAMECACHE_PluginFunctions *api;

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.cfg = cfg;
  if (GNUNET_OK != database_setup (&plugin))
  {
    database_shutdown (&plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_NAMECACHE_PluginFunctions);
  api->cls = &plugin;
  api->cache_block = &namecache_postgres_cache_block;
  api->lookup_block = &namecache_postgres_lookup_block;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Postgres namecache plugin running\n");
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_namecache_postgres_done (void *cls)
{
  struct GNUNET_NAMECACHE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Postgres namecache plugin is finished\n");
  return NULL;
}

/* end of plugin_namecache_postgres.c */
