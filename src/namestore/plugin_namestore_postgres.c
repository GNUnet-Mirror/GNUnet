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
 * @file namestore/plugin_namestore_postgres.c
 * @brief postgres-based namestore backend
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_namestore_plugin.h"
#include "gnunet_namestore_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_postgres_lib.h"
#include "gnunet_pq_lib.h"
#include "namestore.h"


#define LOG(kind,...) GNUNET_log_from (kind, "namestore-postgres", __VA_ARGS__)


/**
 * Context for all functions in this plugin.
 */
struct Plugin
{

  /**
   * Our configuration.
   */
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
    GNUNET_PQ_make_execute ("CREATE TEMPORARY TABLE IF NOT EXISTS ns097records ("
                            " zone_private_key BYTEA NOT NULL DEFAULT '',"
                            " pkey BYTEA DEFAULT '',"
                            " rvalue BYTEA NOT NULL DEFAULT '',"
                            " record_count INTEGER NOT NULL DEFAULT 0,"
                            " record_data BYTEA NOT NULL DEFAULT '',"
                            " label TEXT NOT NULL DEFAULT ''"
                            ")"
                            "WITH OIDS");
  struct GNUNET_PQ_ExecuteStatement es_default =
    GNUNET_PQ_make_execute ("CREATE TABLE IF NOT EXISTS ns097records ("
                            " zone_private_key BYTEA NOT NULL DEFAULT '',"
                            " pkey BYTEA DEFAULT '',"
                            " rvalue BYTEA NOT NULL DEFAULT '',"
                            " record_count INTEGER NOT NULL DEFAULT 0,"
                            " record_data BYTEA NOT NULL DEFAULT '',"
                            " label TEXT NOT NULL DEFAULT ''"
                            ")"
                            "WITH OIDS");
  const struct GNUNET_PQ_ExecuteStatement *cr;

  plugin->dbh = GNUNET_PQ_connect_with_cfg (plugin->cfg,
                                            "namestore-postgres");
  if (NULL == plugin->dbh)
    return GNUNET_SYSERR;
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (plugin->cfg,
					    "namestore-postgres",
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
      GNUNET_PQ_make_try_execute ("CREATE INDEX IF NOT EXISTS ir_pkey_reverse "
                                  "ON ns097records (zone_private_key,pkey)"),
      GNUNET_PQ_make_try_execute ("CREATE INDEX IF NOT EXISTS ir_pkey_iter "
                                  "ON ns097records (zone_private_key,rvalue)"),
      GNUNET_PQ_make_try_execute ("CREATE INDEX IF NOT EXISTS it_iter "
                                  "ON ns097records (rvalue)"),
      GNUNET_PQ_make_try_execute ("CREATE INDEX IF NOT EXISTS ir_label "
                                  "ON ns097records (label)"),
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
      GNUNET_PQ_make_prepare ("store_records",
                              "INSERT INTO ns097records (zone_private_key, pkey, rvalue, record_count, record_data, label) VALUES "
                              "($1, $2, $3, $4, $5, $6)", 6),
      GNUNET_PQ_make_prepare ("delete_records",
                              "DELETE FROM ns097records "
                              "WHERE zone_private_key=$1 AND label=$2", 2),
      GNUNET_PQ_make_prepare ("zone_to_name",
                              "SELECT record_count,record_data,label FROM ns097records"
                              " WHERE zone_private_key=$1 AND pkey=$2", 2),
      GNUNET_PQ_make_prepare ("iterate_zone",
                              "SELECT record_count,record_data,label FROM ns097records "
                              "WHERE zone_private_key=$1 ORDER BY rvalue LIMIT 1 OFFSET $2", 2),
      GNUNET_PQ_make_prepare ("iterate_all_zones",
                              "SELECT record_count,record_data,label,zone_private_key"
                              " FROM ns097records ORDER BY rvalue LIMIT 1 OFFSET $1", 1),
      GNUNET_PQ_make_prepare ("lookup_label",
                              "SELECT record_count,record_data,label "
                              "FROM ns097records WHERE zone_private_key=$1 AND label=$2", 2),
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
                                  const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Plugin *plugin = cls;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  uint64_t rvalue;
  uint32_t rd_count32 = (uint32_t) rd_count;
  size_t data_size;

  memset (&pkey, 0, sizeof (pkey));
  for (unsigned int i=0;i<rd_count;i++)
    if (GNUNET_GNSRECORD_TYPE_PKEY == rd[i].record_type)
    {
      GNUNET_break (sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) == rd[i].data_size);
      GNUNET_memcpy (&pkey,
                     rd[i].data,
                     rd[i].data_size);
      break;
    }
  rvalue = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                     UINT64_MAX);
  data_size = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
  if (data_size > 64 * 65536)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  {
    char data[data_size];
    struct GNUNET_PQ_QueryParam params[] = {
      GNUNET_PQ_query_param_auto_from_type (zone_key),
      GNUNET_PQ_query_param_auto_from_type (&pkey),
      GNUNET_PQ_query_param_uint64 (&rvalue),
      GNUNET_PQ_query_param_uint32 (&rd_count32),
      GNUNET_PQ_query_param_fixed_size (data, data_size),
      GNUNET_PQ_query_param_string (label),
      GNUNET_PQ_query_param_end
    };
    enum GNUNET_PQ_QueryStatus res;

    if (data_size !=
        GNUNET_GNSRECORD_records_serialize (rd_count, rd,
                                            data_size, data))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }

    res = GNUNET_PQ_eval_prepared_non_select (plugin->dbh,
                                              "store_records",
                                              params);
    if (GNUNET_PQ_STATUS_SUCCESS_NO_RESULTS != res)
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Closure for #parse_result_call_iterator.
 */
struct ParserContext
{
  /**
   * Function to call for each result.
   */
  GNUNET_NAMESTORE_RecordIterator iter;

  /**
   * Closure for @e iter.
   */
  void *iter_cls;

  /**
   * Zone key, NULL if part of record.
   */
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone_key;
};


/**
 * A statement has been run.  We should evaluate the result, and if possible
 * call the @a iter in @a cls with the result.
 *
 * @param cls closure of type `struct ParserContext *`
 * @param result the postgres result
 * @param num_result the number of results in @a result
 */
static void
parse_result_call_iterator (void *cls,
                            PGresult *res,
                            unsigned int num_results)
{
  struct ParserContext *pc = cls;

  for (unsigned int i=0;i<num_results;i++)
  {
    void *data;
    size_t data_size;
    uint32_t record_count;
    char *label;
    struct GNUNET_CRYPTO_EcdsaPrivateKey zk;
    struct GNUNET_PQ_ResultSpec rs_with_zone[] = {
      GNUNET_PQ_result_spec_uint32 ("record_count", &record_count),
      GNUNET_PQ_result_spec_variable_size ("record_data", &data, &data_size),
      GNUNET_PQ_result_spec_string ("label", &label),
      GNUNET_PQ_result_spec_auto_from_type ("zone_private_key", &zk),
      GNUNET_PQ_result_spec_end
    };
    struct GNUNET_PQ_ResultSpec rs_without_zone[] = {
      GNUNET_PQ_result_spec_uint32 ("record_count", &record_count),
      GNUNET_PQ_result_spec_variable_size ("record_data", &data, &data_size),
      GNUNET_PQ_result_spec_string ("label", &label),
      GNUNET_PQ_result_spec_end
    };
    struct GNUNET_PQ_ResultSpec *rs;

    rs = (NULL == pc->zone_key) ? rs_with_zone : rs_without_zone;
    if (GNUNET_YES !=
        GNUNET_PQ_extract_result (res,
                                  rs,
                                  i))
    {
      GNUNET_break (0);
      return;
    }

    if (record_count > 64 * 1024)
    {
      /* sanity check, don't stack allocate far too much just
         because database might contain a large value here */
      GNUNET_break (0);
      GNUNET_PQ_cleanup_result (rs);
      return;
    }

    {
      struct GNUNET_GNSRECORD_Data rd[record_count];

      if (GNUNET_OK !=
          GNUNET_GNSRECORD_records_deserialize (data_size,
                                                data,
                                                record_count,
                                                rd))
      {
        GNUNET_break (0);
        GNUNET_PQ_cleanup_result (rs);
        return;
      }
      pc->iter (pc->iter_cls,
                (NULL == pc->zone_key) ? &zk : pc->zone_key,
                label,
                record_count,
                rd);
    }
    GNUNET_PQ_cleanup_result (rs);
  }
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
namestore_postgres_lookup_records (void *cls,
                                   const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                                   const char *label,
                                   GNUNET_NAMESTORE_RecordIterator iter,
                                   void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (zone),
    GNUNET_PQ_query_param_string (label),
    GNUNET_PQ_query_param_end
  };
  struct ParserContext pc;
  enum GNUNET_PQ_QueryStatus res;

  pc.iter = iter;
  pc.iter_cls = iter_cls;
  pc.zone_key = NULL;
  res = GNUNET_PQ_eval_prepared_multi_select (plugin->dbh,
                                              "lookup_label",
                                              params,
                                              &parse_result_call_iterator,
                                              &pc);
  if (res < 0)
    return GNUNET_SYSERR;
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
                                    GNUNET_NAMESTORE_RecordIterator iter,
                                    void *iter_cls)
{
  struct Plugin *plugin = cls;
  enum GNUNET_PQ_QueryStatus res;
  struct ParserContext pc;

  pc.iter = iter;
  pc.iter_cls = iter_cls;
  pc.zone_key = zone;
  if (NULL == zone)
  {
    struct GNUNET_PQ_QueryParam params_without_zone[] = {
      GNUNET_PQ_query_param_uint64 (&offset),
      GNUNET_PQ_query_param_end
    };

    res = GNUNET_PQ_eval_prepared_multi_select (plugin->dbh,
                                                "iterate_all_zones",
                                                params_without_zone,
                                                &parse_result_call_iterator,
                                                &pc);
  }
  else
  {
    struct GNUNET_PQ_QueryParam params_with_zone[] = {
      GNUNET_PQ_query_param_auto_from_type (zone),
      GNUNET_PQ_query_param_uint64 (&offset),
      GNUNET_PQ_query_param_end
    };

    res = GNUNET_PQ_eval_prepared_multi_select (plugin->dbh,
                                                "iterate_zone",
                                                params_with_zone,
                                                &parse_result_call_iterator,
                                                &pc);
  }
  if (res < 0)
    return GNUNET_SYSERR;
  return GNUNET_OK;
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
  struct GNUNET_PQ_QueryParam params[] = {
    GNUNET_PQ_query_param_auto_from_type (zone),
    GNUNET_PQ_query_param_auto_from_type (value_zone),
    GNUNET_PQ_query_param_end
  };
  enum GNUNET_PQ_QueryStatus res;
  struct ParserContext pc;

  pc.iter = iter;
  pc.iter_cls = iter_cls;
  pc.zone_key = zone;

  res = GNUNET_PQ_eval_prepared_multi_select (plugin->dbh,
                                              "zone_to_name",
                                              params,
                                              &parse_result_call_iterator,
                                              &pc);
  if (res < 0)
    return GNUNET_SYSERR;
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
 * @param cls the `struct GNUNET_NAMESTORE_PluginEnvironment*`
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
  api->store_records = &namestore_postgres_store_records;
  api->iterate_records = &namestore_postgres_iterate_records;
  api->zone_to_name = &namestore_postgres_zone_to_name;
  api->lookup_records = &namestore_postgres_lookup_records;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Postgres namestore plugin running\n");
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
       "Postgres namestore plugin is finished\n");
  return NULL;
}

/* end of plugin_namestore_postgres.c */
