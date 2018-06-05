 /*
  * This file is part of GNUnet
  * Copyright (C) 2009-2017 GNUnet e.V.
  *
  * GNUnet is free software: you can redistribute it and/or modify it
  * under the terms of the GNU General Public License as published
  * by the Free Software Foundation, either version 3 of the License,
  * or (at your option) any later version.
  *
  * GNUnet is distributed in the hope that it will be useful, but
  * WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  * Affero General Public License for more details.
  */

/**
 * @file identity-provider/plugin_identity_provider_sqlite.c
 * @brief sqlite-based idp backend
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_identity_provider_service.h"
#include "gnunet_identity_provider_plugin.h"
#include "gnunet_identity_attribute_lib.h"
#include "gnunet_sq_lib.h"
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
#define LOG_SQLITE(db, level, cmd) do { GNUNET_log_from (level, "identity-provider", _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, sqlite3_errmsg(db->dbh)); } while(0)

#define LOG(kind,...) GNUNET_log_from (kind, "identity-provider-sqlite", __VA_ARGS__)


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
   * Precompiled SQL to store ticket.
   */
  sqlite3_stmt *store_ticket;

  /**
   * Precompiled SQL to delete existing ticket.
   */
  sqlite3_stmt *delete_ticket;

  /**
   * Precompiled SQL to iterate tickets.
   */
  sqlite3_stmt *iterate_tickets;

  /**
   * Precompiled SQL to get ticket attributes.
   */
  sqlite3_stmt *get_ticket_attrs;
  
  /**
   * Precompiled SQL to iterate tickets by audience.
   */
  sqlite3_stmt *iterate_tickets_by_audience;
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
sq_prepare (sqlite3 *dbh,
            const char *zSql,
            sqlite3_stmt **ppStmt)
{
  char *dummy;
  int result;

  result =
      sqlite3_prepare_v2 (dbh,
                          zSql,
                          strlen (zSql),
                          ppStmt,
                          (const char **) &dummy);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Prepared `%s' / %p: %d\n",
       zSql,
       *ppStmt,
       result);
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
	sqlite3_exec (dbh,
                      "CREATE INDEX IF NOT EXISTS identity_reverse ON identity001tickets (identity,audience)",
		      NULL, NULL, NULL)) ||
       (SQLITE_OK !=
	sqlite3_exec (dbh,
                      "CREATE INDEX IF NOT EXISTS it_iter ON identity001tickets (rnd)",
		      NULL, NULL, NULL)) )
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 "Failed to create indices: %s\n",
         sqlite3_errmsg (dbh));
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
      GNUNET_CONFIGURATION_get_value_filename (plugin->cfg,
                                               "identity-provider-sqlite",
                                               "FILENAME",
                                               &afsdir))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "identity-provider-sqlite",
                               "FILENAME");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_DISK_file_test (afsdir))
  {
    if (GNUNET_OK !=
        GNUNET_DISK_directory_create_for_file (afsdir))
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
         sqlite3_exec (plugin->dbh,
                       "PRAGMA temp_store=MEMORY", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA synchronous=NORMAL", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA legacy_file_format=OFF", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA auto_vacuum=INCREMENTAL", NULL,
                       NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA encoding=\"UTF-8\"", NULL,
                       NULL, ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA locking_mode=EXCLUSIVE", NULL, NULL,
                       ENULL));
  CHECK (SQLITE_OK ==
         sqlite3_exec (plugin->dbh,
                       "PRAGMA page_size=4092", NULL, NULL,
                       ENULL));

  CHECK (SQLITE_OK ==
         sqlite3_busy_timeout (plugin->dbh,
                               BUSY_TIMEOUT_MS));


  /* Create table */
  CHECK (SQLITE_OK ==
         sq_prepare (plugin->dbh,
                     "SELECT 1 FROM sqlite_master WHERE tbl_name = 'identity001tickets'",
                     &stmt));
  if ((sqlite3_step (stmt) == SQLITE_DONE) &&
      (sqlite3_exec
       (plugin->dbh,
        "CREATE TABLE identity001tickets ("
        " identity BLOB NOT NULL DEFAULT '',"
        " audience BLOB NOT NULL DEFAULT '',"
	      " rnd INT8 NOT NULL DEFAULT '',"
        " attributes BLOB NOT NULL DEFAULT ''"
	")",
	NULL, NULL, NULL) != SQLITE_OK))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR,
                "sqlite3_exec");
    sqlite3_finalize (stmt);
    return GNUNET_SYSERR;
  }
  sqlite3_finalize (stmt);

  create_indices (plugin->dbh);

  if ( (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "INSERT INTO identity001tickets (identity, audience, rnd, attributes)"
                    " VALUES (?, ?, ?, ?)",
                    &plugin->store_ticket)) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "DELETE FROM identity001tickets WHERE identity=? AND rnd=?",
                    &plugin->delete_ticket)) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT identity,audience,rnd,attributes"
                    " FROM identity001tickets WHERE identity=? AND rnd=?",
                    &plugin->get_ticket_attrs)) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT identity,audience,rnd,attributes"
                    " FROM identity001tickets WHERE identity=?"
                    " ORDER BY rnd LIMIT 1 OFFSET ?",
                    &plugin->iterate_tickets)) ||
       (SQLITE_OK !=
        sq_prepare (plugin->dbh,
                    "SELECT identity,audience,rnd,attributes"
                    " FROM identity001tickets WHERE audience=?"
                    " ORDER BY rnd LIMIT 1 OFFSET ?",
                    &plugin->iterate_tickets_by_audience)) ) 
  {
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR,
                "precompiling");
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

  if (NULL != plugin->store_ticket)
    sqlite3_finalize (plugin->store_ticket);
  if (NULL != plugin->delete_ticket)
    sqlite3_finalize (plugin->delete_ticket);
  if (NULL != plugin->iterate_tickets)
    sqlite3_finalize (plugin->iterate_tickets);
  if (NULL != plugin->iterate_tickets_by_audience)
    sqlite3_finalize (plugin->iterate_tickets_by_audience);
  if (NULL != plugin->get_ticket_attrs)
    sqlite3_finalize (plugin->get_ticket_attrs);
  result = sqlite3_close (plugin->dbh);
  if (result == SQLITE_BUSY)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 _("Tried to close sqlite without finalizing all prepared statements.\n"));
    stmt = sqlite3_next_stmt (plugin->dbh,
                              NULL);
    while (NULL != stmt)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "sqlite",
                       "Closing statement %p\n",
                       stmt);
      result = sqlite3_finalize (stmt);
      if (result != SQLITE_OK)
        GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
                         "sqlite",
                         "Failed to close statement %p: %d\n",
                         stmt,
                         result);
      stmt = sqlite3_next_stmt (plugin->dbh,
                                NULL);
    }
    result = sqlite3_close (plugin->dbh);
  }
  if (SQLITE_OK != result)
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR,
                "sqlite3_close");

  GNUNET_free_non_null (plugin->fn);
}


/**
 * Store a ticket in the database.
 *
 * @param cls closure (internal context for the plugin)
 * @param ticket the ticket to persist
 * @param attrs the attributes associated with the ticket
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
identity_provider_sqlite_store_ticket (void *cls,
                                       const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket,
                                       const struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *attrs)
{
  struct Plugin *plugin = cls;
  size_t attrs_len;
  char *attrs_ser;
  int n;

  { 
    /* First delete duplicates */
    struct GNUNET_SQ_QueryParam dparams[] = {
      GNUNET_SQ_query_param_auto_from_type (&ticket->identity),
      GNUNET_SQ_query_param_uint64 (&ticket->rnd),
      GNUNET_SQ_query_param_end
    };
    if (GNUNET_OK !=
        GNUNET_SQ_bind (plugin->delete_ticket,
                        dparams))
    {
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_bind_XXXX");
      GNUNET_SQ_reset (plugin->dbh,
                       plugin->delete_ticket);
      return GNUNET_SYSERR;
    }
    n = sqlite3_step (plugin->delete_ticket);
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->delete_ticket);
    
    attrs_len = GNUNET_IDENTITY_ATTRIBUTE_list_serialize_get_size (attrs);
    attrs_ser = GNUNET_malloc (attrs_len);
    GNUNET_IDENTITY_ATTRIBUTE_list_serialize (attrs,
                              attrs_ser);
    struct GNUNET_SQ_QueryParam sparams[] = {
      GNUNET_SQ_query_param_auto_from_type (&ticket->identity),
      GNUNET_SQ_query_param_auto_from_type (&ticket->audience),
      GNUNET_SQ_query_param_uint64 (&ticket->rnd),
      GNUNET_SQ_query_param_fixed_size (attrs_ser, attrs_len),
      GNUNET_SQ_query_param_end
    };

    if (GNUNET_OK !=
        GNUNET_SQ_bind (plugin->store_ticket,
                        sparams))
    {
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_bind_XXXX");
      GNUNET_SQ_reset (plugin->dbh,
                       plugin->store_ticket);
      return GNUNET_SYSERR;
    }
    n = sqlite3_step (plugin->store_ticket);
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->store_ticket);
    GNUNET_free (attrs_ser);
  }
  switch (n)
  {
    case SQLITE_DONE:
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "sqlite",
                       "Ticket stored\n");
      return GNUNET_OK;
    case SQLITE_BUSY:
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_step");
      return GNUNET_NO;
    default:
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_step");
      return GNUNET_SYSERR;
  }
}


/**
 * Store a ticket in the database.
 *
 * @param cls closure (internal context for the plugin)
 * @param ticket the ticket to delete
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
identity_provider_sqlite_delete_ticket (void *cls,
                                        const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket)
{
  struct Plugin *plugin = cls;
  int n;

  {  
    struct GNUNET_SQ_QueryParam sparams[] = {
      GNUNET_SQ_query_param_auto_from_type (&ticket->identity),
      GNUNET_SQ_query_param_uint64 (&ticket->rnd),
      GNUNET_SQ_query_param_end
    };

    if (GNUNET_OK !=
        GNUNET_SQ_bind (plugin->delete_ticket,
                        sparams))
    {
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_bind_XXXX");
      GNUNET_SQ_reset (plugin->dbh,
                       plugin->store_ticket);
      return GNUNET_SYSERR;
    }
    n = sqlite3_step (plugin->delete_ticket);
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->delete_ticket);
  }
  switch (n)
  {
    case SQLITE_DONE:
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "sqlite",
                       "Ticket deleted\n");
      return GNUNET_OK;
    case SQLITE_BUSY:
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                  "sqlite3_step");
      return GNUNET_NO;
    default:
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
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
 * @param iter iterator to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
 */
static int
get_ticket_and_call_iterator (struct Plugin *plugin,
                              sqlite3_stmt *stmt,
                              GNUNET_IDENTITY_PROVIDER_TicketIterator iter,
                              void *iter_cls)
{
  struct GNUNET_IDENTITY_PROVIDER_Ticket ticket;
  struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *attrs;
  int ret;
  int sret;
  size_t attrs_len;
  char *attrs_ser;

  ret = GNUNET_NO;
  if (SQLITE_ROW == (sret = sqlite3_step (stmt)))
  {
    struct GNUNET_SQ_ResultSpec rs[] = {
      GNUNET_SQ_result_spec_auto_from_type (&ticket.identity),
      GNUNET_SQ_result_spec_auto_from_type (&ticket.audience),
      GNUNET_SQ_result_spec_uint64 (&ticket.rnd),
      GNUNET_SQ_result_spec_variable_size ((void**)&attrs_ser,
                                           &attrs_len),
      GNUNET_SQ_result_spec_end

    };
    ret = GNUNET_SQ_extract_result (stmt,
                                    rs);
    if (GNUNET_OK != ret)
    {
      GNUNET_break (0);
      ret = GNUNET_SYSERR;
    }
    else
    {
      attrs = GNUNET_IDENTITY_ATTRIBUTE_list_deserialize (attrs_ser,
                                          attrs_len);
      if (NULL != iter)
        iter (iter_cls,
              &ticket,
              attrs);
      GNUNET_IDENTITY_ATTRIBUTE_list_destroy (attrs);
      ret = GNUNET_YES;
    }
    GNUNET_SQ_cleanup_result (rs);
  }
  else
  {
    if (SQLITE_DONE != sret)
      LOG_SQLITE (plugin,
                  GNUNET_ERROR_TYPE_ERROR,
                  "sqlite_step");
  }
  GNUNET_SQ_reset (plugin->dbh,
                   stmt);
  return ret;
}


/**
 * Lookup tickets in the datastore.
 *
 * @param cls closure (internal context for the plugin)
 * @param ticket the ticket to retrieve attributes for
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
static int
identity_provider_sqlite_ticket_get_attrs (void *cls,
                                           const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket,
                                           GNUNET_IDENTITY_PROVIDER_TicketIterator iter,
                                           void *iter_cls)
{
  struct Plugin *plugin = cls;
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_auto_from_type (&ticket->identity),
    GNUNET_SQ_query_param_uint64 (&ticket->rnd),
    GNUNET_SQ_query_param_end
  };

  if (GNUNET_OK !=
      GNUNET_SQ_bind (plugin->get_ticket_attrs,
                      params))
  {
    LOG_SQLITE (plugin, GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    GNUNET_SQ_reset (plugin->dbh,
                     plugin->get_ticket_attrs);
    return GNUNET_SYSERR;
  }
  return get_ticket_and_call_iterator (plugin,
                                       plugin->get_ticket_attrs,
                                       iter,
                                       iter_cls);
}


/**
 * Iterate over the results for a particular key and zone in the
 * datastore.  Will return at most one result to the iterator.
 *
 * @param cls closure (internal context for the plugin)
 * @param identity the issuing identity or audience (depending on audience switch)
 * @param audience GNUNET_YES if identity is audience
 * @param offset offset in the list of all matching records
 * @param iter function to call with the result
 * @param iter_cls closure for @a iter
 * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
 */
static int
identity_provider_sqlite_iterate_tickets (void *cls,
                                          const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
                                          int audience,
                                          uint64_t offset,
                                          GNUNET_IDENTITY_PROVIDER_TicketIterator iter,
                                          void *iter_cls)
{
  struct Plugin *plugin = cls;
  sqlite3_stmt *stmt;
  int err;

  if (NULL == identity)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  struct GNUNET_SQ_QueryParam params[] = {
    GNUNET_SQ_query_param_auto_from_type (identity),
    GNUNET_SQ_query_param_uint64 (&offset),
    GNUNET_SQ_query_param_end
  };
  if (GNUNET_YES == audience)
  {
    stmt = plugin->iterate_tickets_by_audience;
    err = GNUNET_SQ_bind (stmt,
                          params);
  }
  else
  {
    stmt = plugin->iterate_tickets;
    err = GNUNET_SQ_bind (stmt,
                          params);
  }
  if (GNUNET_OK != err)
  {
    LOG_SQLITE (plugin,
                GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                "sqlite3_bind_XXXX");
    GNUNET_SQ_reset (plugin->dbh,
                     stmt);
    return GNUNET_SYSERR;
  }
  return get_ticket_and_call_iterator (plugin,
                                       stmt,
                                       iter,
                                       iter_cls);
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_IDENTITY_PROVIDER_PluginEnvironment*"
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_identity_provider_sqlite_init (void *cls)
{
  static struct Plugin plugin;
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_IDENTITY_PROVIDER_PluginFunctions *api;

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.cfg = cfg;
  if (GNUNET_OK != database_setup (&plugin))
  {
    database_shutdown (&plugin);
    return NULL;
  }
  api = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_PluginFunctions);
  api->cls = &plugin;
  api->store_ticket = &identity_provider_sqlite_store_ticket;
  api->delete_ticket = &identity_provider_sqlite_delete_ticket;
  api->iterate_tickets = &identity_provider_sqlite_iterate_tickets;
  api->get_ticket_attributes = &identity_provider_sqlite_ticket_get_attrs;
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
libgnunet_plugin_identity_provider_sqlite_done (void *cls)
{
  struct GNUNET_IDENTITY_PROVIDER_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  database_shutdown (plugin);
  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sqlite plugin is finished\n");
  return NULL;
}

/* end of plugin_identity_provider_sqlite.c */
