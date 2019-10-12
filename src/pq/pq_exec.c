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
 * @file pq/pq_exec.c
 * @brief functions to execute plain SQL statements (PostGres)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "pq.h"


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
 * @param db database to execute the statements with
 * @param es #GNUNET_PQ_PREPARED_STATEMENT_END-terminated array of prepared
 *            statements.
 * @return #GNUNET_OK on success (modulo statements where errors can be ignored)
 *         #GNUNET_SYSERR on error
 */
int
GNUNET_PQ_exec_statements (struct GNUNET_PQ_Context *db,
                           const struct GNUNET_PQ_ExecuteStatement *es)
{
  for (unsigned int i = 0; NULL != es[i].sql; i++)
  {
    PGresult *result;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Running statement `%s' on %p\n",
                es[i].sql,
                db);
    result = PQexec (db->conn,
                     es[i].sql);
    if ((GNUNET_NO == es[i].ignore_errors) &&
        (PGRES_COMMAND_OK != PQresultStatus (result)))
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
                       PQerrorMessage (db->conn));
      PQclear (result);
      return GNUNET_SYSERR;
    }
    PQclear (result);
  }
  return GNUNET_OK;
}


/* end of pq/pq_exec.c */
