/*
   This file is part of GNUnet
   Copyright (C) 2018 GNUnet e.V.

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
 * @file sq/sq_exec.c
 * @brief helper functions for executing SQL statements
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_sq_lib.h"


/**
 * Create a `struct GNUNET_SQ_ExecuteStatement` where errors are fatal.
 *
 * @param sql actual SQL statement
 * @return initialized struct
 */
struct GNUNET_SQ_ExecuteStatement
GNUNET_SQ_make_execute (const char *sql)
{
  struct GNUNET_SQ_ExecuteStatement es = {
    .sql = sql,
    .ignore_errors = GNUNET_NO
  };

  return es;
}


/**
 * Create a `struct GNUNET_SQ_ExecuteStatement` where errors should
 * be tolerated.
 *
 * @param sql actual SQL statement
 * @return initialized struct
 */
struct GNUNET_SQ_ExecuteStatement
GNUNET_SQ_make_try_execute (const char *sql)
{
  struct GNUNET_SQ_ExecuteStatement es = {
    .sql = sql,
    .ignore_errors = GNUNET_YES
  };

  return es;
}


/**
 * Request execution of an array of statements @a es from Postgres.
 *
 * @param dbh database to execute the statements over
 * @param es #GNUNET_PQ_PREPARED_STATEMENT_END-terminated array of prepared
 *            statements.
 * @return #GNUNET_OK on success (modulo statements where errors can be ignored)
 *         #GNUNET_SYSERR on error
 */
int
GNUNET_SQ_exec_statements (sqlite3 *dbh,
                           const struct GNUNET_SQ_ExecuteStatement *es)
{
  for (unsigned int i = 0; NULL != es[i].sql; i++)
  {
    char *emsg = NULL;

    if (SQLITE_OK !=
        sqlite3_exec (dbh,
                      es[i].sql,
                      NULL,
                      NULL,
                      &emsg))
    {
      if (es[i].ignore_errors)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Failed to run SQL `%s': %s\n",
                    es[i].sql,
                    emsg);
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Failed to run SQL `%s': %s\n",
                    es[i].sql,
                    emsg);
        sqlite3_free (emsg);
        return GNUNET_SYSERR;
      }
      sqlite3_free (emsg);
    }
  }
  return GNUNET_OK;
}


/* end of sq_exec */
