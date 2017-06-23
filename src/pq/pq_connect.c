/*
  This file is part of GNUnet
  Copyright (C) 2017 GNUnet e.V.

  GNUnet is free software; you can redistribute it and/or modify it under the
  terms of the GNU General Public License as published by the Free Software
  Foundation; either version 3, or (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along with
  GNUnet; see the file COPYING.  If not, If not, see <http://www.gnu.org/licenses/>
*/
/**
 * @file pq/pq_connect.c
 * @brief functions to connect to libpq (PostGres)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_pq_lib.h"


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
}


/**
 * Function called by libpq whenever it wants to log something.
 * We log those using the Taler logger.
 *
 * @param arg the SQL connection that was used
 * @param message information about some libpq event
 */
static void
pq_notice_processor_cb (void *arg,
                        const char *message)
{
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                   "pq",
                   "%s",
                   message);
}


/**
 * Create a connection to the Postgres database using @a config_str
 * for the configuration.  Initialize logging via GNUnet's log
 * routines and disable Postgres's logger.
 *
 * @param config_str configuration to use
 * @return NULL on error
 */
PGconn *
GNUNET_PQ_connect (const char *config_str)
{
  PGconn *conn;

  conn = PQconnectdb (config_str);
  if ( (NULL == conn) ||
       (CONNECTION_OK !=
        PQstatus (conn)) )
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                     "pq",
                     "Database connection to '%s' failed: %s\n",
                     config_str,
                     (NULL != conn) ?
                     PQerrorMessage (conn)
                     : "PQconnectdb returned NULL");
    if (NULL != conn)
      PQfinish (conn);
    return NULL;
  }
  PQsetNoticeReceiver (conn,
                       &pq_notice_receiver_cb,
                       conn);
  PQsetNoticeProcessor (conn,
                        &pq_notice_processor_cb,
                        conn);
  return conn;
}


/**
 * Connect to a postgres database using the configuration
 * option "CONFIG" in @a section.
 *
 * @param cfg configuration
 * @param section configuration section to use to get Postgres configuration options
 * @return the postgres handle, NULL on error
 */
PGconn *
GNUNET_PQ_connect_with_cfg (const struct GNUNET_CONFIGURATION_Handle * cfg,
                            const char *section)
{
  PGconn *dbh;
  char *conninfo;

  /* Open database and precompile statements */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
					     section,
					     "CONFIG",
					     &conninfo))
    conninfo = NULL;
  dbh = GNUNET_PQ_connect (conninfo == NULL ? "" : conninfo);
  GNUNET_free_non_null (conninfo);
  return dbh;
}


/* end of pq/pq_connect.c */
