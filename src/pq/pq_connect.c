/*
   This file is part of GNUnet
   Copyright (C) 2017, 2019 GNUnet e.V.

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
 * Create a connection to the Postgres database using @a config_str
 * for the configuration.  Initialize logging via GNUnet's log
 * routines and disable Postgres's logger.  Also ensures that the
 * statements in @a es are executed whenever we (re)connect to the
 * database, and that the prepared statements in @a ps are "ready".
 * If statements in @es fail that were created with
 * #GNUNET_PQ_make_execute(), then the entire operation fails.
 *
 * The caller MUST ensure that @a es and @a ps remain allocated and
 * initialized in memory until #GNUNET_PQ_disconnect() is called,
 * as they may be needed repeatedly and no copy will be made.
 *
 * @param config_str configuration to use
 * @param es #GNUNET_PQ_PREPARED_STATEMENT_END-terminated
 *            array of statements to execute upon EACH connection, can be NULL
 * @param ps array of prepared statements to prepare, can be NULL
 * @return NULL on error
 */
struct GNUNET_PQ_Context *
GNUNET_PQ_connect (const char *config_str,
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
    GNUNET_free (db->config_str);
    GNUNET_free (db);
    return NULL;
  }
  return db;
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
  if ((NULL == db->conn) ||
      (CONNECTION_OK != PQstatus (db->conn)))
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
 * The caller MUST ensure that @a es and @a ps remain allocated and
 * initialized in memory until #GNUNET_PQ_disconnect() is called,
 * as they may be needed repeatedly and no copy will be made.
 *
 * @param cfg configuration
 * @param section configuration section to use to get Postgres configuration options
 * @param es #GNUNET_PQ_PREPARED_STATEMENT_END-terminated
 *            array of statements to execute upon EACH connection, can be NULL
 * @param ps array of prepared statements to prepare, can be NULL
 * @return the postgres handle, NULL on error
 */
struct GNUNET_PQ_Context *
GNUNET_PQ_connect_with_cfg (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *section,
                            const struct GNUNET_PQ_ExecuteStatement *es,
                            const struct GNUNET_PQ_PreparedStatement *ps)
{
  struct GNUNET_PQ_Context *db;
  char *conninfo;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             section,
                                             "CONFIG",
                                             &conninfo))
    conninfo = NULL;
  db = GNUNET_PQ_connect (conninfo == NULL ? "" : conninfo,
                          es,
                          ps);
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
  PQfinish (db->conn);
  GNUNET_free (db);
}


/* end of pq/pq_connect.c */
