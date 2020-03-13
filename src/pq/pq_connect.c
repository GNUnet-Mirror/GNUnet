/*
   This file is part of GNUnet
   Copyright (C) 2017, 2019, 2020 GNUnet e.V.

   GNUnet is free software: you can redistribute it and/or modify it
   under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License,
   or (at your option) any later version.

   GNUnet is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file pq/pq_connect.c
 * @brief functions to connect to libpq (PostGres)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "pq.h"


/**
 * Function called by libpq whenever it wants to log something.
 * We already log whenever we care, so this function does nothing
 * and merely exists to silence the libpq logging.
 *
 * @param arg the SQL connection that was used
 * @param res information about some libpq event
 */
static void
pq_notice_receiver_cb (void *arg,
                       const PGresult *res)
{
  /* do nothing, intentionally */
  (void) arg;
  (void) res;
}


/**
 * Function called by libpq whenever it wants to log something.
 * We log those using the GNUnet logger.
 *
 * @param arg the SQL connection that was used
 * @param message information about some libpq event
 */
static void
pq_notice_processor_cb (void *arg,
                        const char *message)
{
  (void) arg;
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                   "pq",
                   "%s",
                   message);
}


/**
 * Create a connection to the Postgres database using @a config_str for the
 * configuration.  Initialize logging via GNUnet's log routines and disable
 * Postgres's logger.  Also ensures that the statements in @a load_path and @a
 * es are executed whenever we (re)connect to the database, and that the
 * prepared statements in @a ps are "ready".  If statements in @es fail that
 * were created with #GNUNET_PQ_make_execute(), then the entire operation
 * fails.
 *
 * In @a load_path, a list of "$XXXX.sql" files is expected where $XXXX
 * must be a sequence of contiguous integer values starting at 0000.
 * These files are then loaded in sequence using "psql $config_str" before
 * running statements from @e es.  The directory is inspected again on
 * reconnect.
 *
 * @param config_str configuration to use
 * @param load_path path to directory with SQL transactions to run, can be NULL
 * @param es #GNUNET_PQ_PREPARED_STATEMENT_END-terminated
 *            array of statements to execute upon EACH connection, can be NULL
 * @param ps array of prepared statements to prepare, can be NULL
 * @return NULL on error
 */
struct GNUNET_PQ_Context *
GNUNET_PQ_connect (const char *config_str,
                   const char *load_path,
                   const struct GNUNET_PQ_ExecuteStatement *es,
                   const struct GNUNET_PQ_PreparedStatement *ps)
{
  struct GNUNET_PQ_Context *db;
  unsigned int elen = 0;
  unsigned int plen = 0;

  if (NULL != es)
    while (NULL != es[elen].sql)
      elen++;
  if (NULL != ps)
    while (NULL != ps[plen].name)
      plen++;

  db = GNUNET_new (struct GNUNET_PQ_Context);
  db->config_str = GNUNET_strdup (config_str);
  if (NULL != load_path)
    db->load_path = GNUNET_strdup (load_path);
  if (0 != elen)
  {
    db->es = GNUNET_new_array (elen + 1,
                               struct GNUNET_PQ_ExecuteStatement);
    memcpy (db->es,
            es,
            elen * sizeof (struct GNUNET_PQ_ExecuteStatement));
  }
  if (0 != plen)
  {
    db->ps = GNUNET_new_array (plen + 1,
                               struct GNUNET_PQ_PreparedStatement);
    memcpy (db->ps,
            ps,
            plen * sizeof (struct GNUNET_PQ_PreparedStatement));
  }
  GNUNET_PQ_reconnect (db);
  if (NULL == db->conn)
  {
    GNUNET_free_non_null (db->load_path);
    GNUNET_free (db->config_str);
    GNUNET_free (db);
    return NULL;
  }
  return db;
}


/**
 * Apply patch number @a from path @a load_path.
 *
 * @param db database context to use
 * @param load_path where to find the SQL code to run
 * @param i patch number to append to the @a load_path
 * @return #GNUNET_OK on success, #GNUNET_NO if patch @a i does not exist, #GNUNET_SYSERR on error
 */
static int
apply_patch (struct GNUNET_PQ_Context *db,
             const char *load_path,
             unsigned int i)
{
  struct GNUNET_OS_Process *psql;
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long code;
  size_t slen = strlen (load_path) + 10;
  char buf[slen];

  GNUNET_snprintf (buf,
                   sizeof (buf),
                   "%s%04u.sql",
                   load_path,
                   i);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Applying SQL file `%s' on database %s\n",
              buf,
              db->config_str);
  psql = GNUNET_OS_start_process (GNUNET_NO,
                                  GNUNET_OS_INHERIT_STD_NONE,
                                  NULL,
                                  NULL,
                                  NULL,
                                  "psql",
                                  "psql",
                                  db->config_str,
                                  "-f",
                                  buf,
                                  "-q",
                                  NULL);
  if (NULL == psql)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "exec",
                              "psql");
    return GNUNET_SYSERR;
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_OS_process_wait_status (psql,
                                                &type,
                                                &code));
  GNUNET_OS_process_destroy (psql);
  if ( (GNUNET_OS_PROCESS_EXITED != type) ||
       (0 != code) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not run PSQL on file %s: %d",
                buf,
                (int) code);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Within the @a db context, run all the SQL files
 * from the @a load_path from 0000-9999.sql (as long
 * as the files exist contiguously).
 *
 * @param db database context to use
 * @param load_path where to find the XXXX.sql files
 * @return #GNUNET_OK on success
 */
int
GNUNET_PQ_run_sql (struct GNUNET_PQ_Context *db,
                   const char *load_path)
{
  const char *load_path_suffix;
  size_t slen = strlen (load_path) + 10;

  load_path_suffix = strrchr (load_path, '/');
  if (NULL == load_path_suffix)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  load_path_suffix++; /* skip '/' */
  for (unsigned int i = 1; i<10000; i++)
  {
    enum GNUNET_DB_QueryStatus qs;
    {
      char buf[slen];

      /* First, check patch actually exists */
      GNUNET_snprintf (buf,
                       sizeof (buf),
                       "%s%04u.sql",
                       load_path,
                       i);
      if (GNUNET_YES !=
          GNUNET_DISK_file_test (buf))
        return GNUNET_OK;   /* We are done */
    }

    /* Second, check with DB versioning schema if this patch was already applied,
       if so, skip it. */
    {
      char patch_name[slen];

      GNUNET_snprintf (patch_name,
                       sizeof (patch_name),
                       "%s%04u",
                       load_path_suffix,
                       i);
      {
        char *applied_by;
        struct GNUNET_PQ_QueryParam params[] = {
          GNUNET_PQ_query_param_string (patch_name),
          GNUNET_PQ_query_param_end
        };
        struct GNUNET_PQ_ResultSpec rs[] = {
          GNUNET_PQ_result_spec_string ("applied_by",
                                        &applied_by),
          GNUNET_PQ_result_spec_end
        };

        qs = GNUNET_PQ_eval_prepared_singleton_select (db,
                                                       "gnunet_pq_check_patch",
                                                       params,
                                                       rs);
        if (GNUNET_DB_STATUS_SUCCESS_ONE_RESULT == qs)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Database version %s already applied by %s, skipping\n",
                      patch_name,
                      applied_by);
          GNUNET_PQ_cleanup_result (rs);
        }
        if (GNUNET_DB_STATUS_HARD_ERROR == qs)
        {
          GNUNET_break (0);
          return GNUNET_SYSERR;
        }
      }
    }
    if (GNUNET_DB_STATUS_SUCCESS_ONE_RESULT == qs)
      continue; /* patch already applied, skip it */

    /* patch not yet applied, run it! */
    {
      int ret;

      ret = apply_patch (db,
                         load_path,
                         i);
      if (GNUNET_NO == ret)
        break;
      if (GNUNET_SYSERR == ret)
        return GNUNET_SYSERR;
    }
  }
  return GNUNET_OK;
}


/**
 * Reinitialize the database @a db if the connection is down.
 *
 * @param db database connection to reinitialize
 */
void
GNUNET_PQ_reconnect_if_down (struct GNUNET_PQ_Context *db)
{
  if (CONNECTION_BAD != PQstatus (db->conn))
    return;
  GNUNET_PQ_reconnect (db);
}


/**
 * Reinitialize the database @a db.
 *
 * @param db database connection to reinitialize
 */
void
GNUNET_PQ_reconnect (struct GNUNET_PQ_Context *db)
{
  if (NULL != db->conn)
    PQfinish (db->conn);
  db->conn = PQconnectdb (db->config_str);
  if ( (NULL == db->conn) ||
       (CONNECTION_OK != PQstatus (db->conn)) )
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                     "pq",
                     "Database connection to '%s' failed: %s\n",
                     db->config_str,
                     (NULL != db->conn) ?
                     PQerrorMessage (db->conn)
                     : "PQconnectdb returned NULL");
    if (NULL != db->conn)
    {
      PQfinish (db->conn);
      db->conn = NULL;
    }
    return;
  }
  PQsetNoticeReceiver (db->conn,
                       &pq_notice_receiver_cb,
                       db);
  PQsetNoticeProcessor (db->conn,
                        &pq_notice_processor_cb,
                        db);
  if (NULL != db->load_path)
  {
    PGresult *res;

    res = PQprepare (db->conn,
                     "gnunet_pq_check_patch",
                     "SELECT"
                     " applied_by"
                     " FROM _v.patches"
                     " WHERE patch_name = $1"
                     " LIMIT 1",
                     1,
                     NULL);
    if (PGRES_COMMAND_OK != PQresultStatus (res))
    {
      int ret;

      PQclear (res);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Failed to prepare statement to check patch level. Likely versioning schema does not exist yet, loading patch level 0000!\n");
      ret = apply_patch (db,
                         db->load_path,
                         0);
      if (GNUNET_NO == ret)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Failed to find SQL file to load database versioning logic\n");
        PQfinish (db->conn);
        db->conn = NULL;
        return;
      }
      if (GNUNET_SYSERR == ret)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Failed to run SQL logic to setup database versioning logic\n");
        PQfinish (db->conn);
        db->conn = NULL;
        return;
      }
      /* try again to prepare our statement! */
      res = PQprepare (db->conn,
                       "gnunet_pq_check_patch",
                       "SELECT"
                       " applied_by"
                       " FROM _v.patches"
                       " WHERE patch_name = $1"
                       " LIMIT 1",
                       1,
                       NULL);
      if (PGRES_COMMAND_OK != PQresultStatus (res))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "Failed to run SQL logic to setup database versioning logic: %s/%s\n",
                    PQresultErrorMessage (res),
                    PQerrorMessage (db->conn));
        PQclear (res);
        PQfinish (db->conn);
        db->conn = NULL;
        return;
      }
    }
    PQclear (res);

    if (GNUNET_SYSERR ==
        GNUNET_PQ_run_sql (db,
                           db->load_path))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to load SQL statements from `%s'\n",
                  db->load_path);
      PQfinish (db->conn);
      db->conn = NULL;
      return;
    }
  }
  if ( (NULL != db->es) &&
       (GNUNET_OK !=
        GNUNET_PQ_exec_statements (db,
                                   db->es)) )
  {
    PQfinish (db->conn);
    db->conn = NULL;
    return;
  }
  if ( (NULL != db->ps) &&
       (GNUNET_OK !=
        GNUNET_PQ_prepare_statements (db,
                                      db->ps)) )
  {
    PQfinish (db->conn);
    db->conn = NULL;
    return;
  }
}


/**
 * Connect to a postgres database using the configuration
 * option "CONFIG" in @a section.  Also ensures that the
 * statements in @a es are executed whenever we (re)connect to the
 * database, and that the prepared statements in @a ps are "ready".
 *
 * The caller does not have to ensure that @a es and @a ps remain allocated
 * and initialized in memory until #GNUNET_PQ_disconnect() is called, as a copy will be made.
 *
 * @param cfg configuration
 * @param section configuration section to use to get Postgres configuration options
 * @param load_path_suffix suffix to append to the SQL_DIR in the configuration
 * @param es #GNUNET_PQ_PREPARED_STATEMENT_END-terminated
 *            array of statements to execute upon EACH connection, can be NULL
 * @param ps array of prepared statements to prepare, can be NULL
 * @return the postgres handle, NULL on error
 */
struct GNUNET_PQ_Context *
GNUNET_PQ_connect_with_cfg (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *section,
                            const char *load_path_suffix,
                            const struct GNUNET_PQ_ExecuteStatement *es,
                            const struct GNUNET_PQ_PreparedStatement *ps)
{
  struct GNUNET_PQ_Context *db;
  char *conninfo;
  char *load_path;
  char *sp;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             section,
                                             "CONFIG",
                                             &conninfo))
    conninfo = NULL;
  load_path = NULL;
  sp = NULL;
  if ( (NULL != load_path_suffix) &&
       (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                 section,
                                                 "SQL_DIR",
                                                 &sp)) )
    GNUNET_asprintf (&load_path,
                     "%s%s",
                     sp,
                     load_path_suffix);
  db = GNUNET_PQ_connect (conninfo == NULL ? "" : conninfo,
                          load_path,
                          es,
                          ps);
  GNUNET_free_non_null (load_path);
  GNUNET_free_non_null (sp);
  GNUNET_free_non_null (conninfo);
  return db;
}


/**
 * Disconnect from the database, destroying the prepared statements
 * and releasing other associated resources.
 *
 * @param db database handle to disconnect (will be free'd)
 */
void
GNUNET_PQ_disconnect (struct GNUNET_PQ_Context *db)
{
  GNUNET_free_non_null (db->es);
  GNUNET_free_non_null (db->ps);
  GNUNET_free_non_null (db->load_path);
  GNUNET_free_non_null (db->config_str);
  PQfinish (db->conn);
  GNUNET_free (db);
}


/* end of pq/pq_connect.c */
