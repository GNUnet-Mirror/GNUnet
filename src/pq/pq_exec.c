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
 * @file pq/pq_exec.c
 * @brief functions to execute plain SQL statements (PostGres)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_pq_lib.h"


/**
 * Create a `struct GNUNET_PQ_ExecuteStatement` where errors are fatal.
 *
 * @param sql actual SQL statement
 * @return initialized struct
 */
struct GNUNET_PQ_ExecuteStatement
GNUNET_PQ_make_execute (const char *sql)
{
  struct GNUNET_PQ_ExecuteStatement es = {
    .sql = sql,
    .ignore_errors = GNUNET_NO
  };

  return es;
}


/**
 * Create a `struct GNUNET_PQ_ExecuteStatement` where errors should
 * be tolerated.
 *
 * @param sql actual SQL statement
 * @return initialized struct
 */
struct GNUNET_PQ_ExecuteStatement
GNUNET_PQ_make_try_execute (const char *sql)
{
  struct GNUNET_PQ_ExecuteStatement es = {
    .sql = sql,
    .ignore_errors = GNUNET_YES
  };

  return es;
}


/**
 * Request execution of an array of statements @a es from Postgres.
 *
 * @param connection connection to execute the statements over
 * @param es #GNUNET_PQ_PREPARED_STATEMENT_END-terminated array of prepared
 *            statements.
 * @return #GNUNET_OK on success (modulo statements where errors can be ignored)
 *         #GNUNET_SYSERR on error
 */
int
GNUNET_PQ_exec_statements (PGconn *connection,
                           const struct GNUNET_PQ_ExecuteStatement *es)
{
  for (unsigned int i=0; NULL != es[i].sql; i++)
  {
    PGresult *result;

    result = PQexec (connection,
                     es[i].sql);

    if ( (GNUNET_NO == es[i].ignore_errors) &&
         (PGRES_COMMAND_OK != PQresultStatus (result)) )
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "pq",
                       "Failed to execute `%s': %s/%s/%s/%s/%s",
                       es[i].sql,
                       PQresultErrorField (result,
                                           PG_DIAG_MESSAGE_PRIMARY),
                       PQresultErrorField (result,
                                           PG_DIAG_MESSAGE_DETAIL),
                       PQresultErrorMessage (result),
                       PQresStatus (PQresultStatus (result)),
                       PQerrorMessage (connection));
      PQclear (result);
      return GNUNET_SYSERR;
    }
    PQclear (result);
  }
  return GNUNET_OK;
}


/* end of pq/pq_exec.c */
