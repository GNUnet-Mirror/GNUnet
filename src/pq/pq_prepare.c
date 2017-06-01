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
 * @file pq/pq_prepare.c
 * @brief functions to connect to libpq (PostGres)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_pq_lib.h"


/**
 * Create a `struct GNUNET_PQ_PreparedStatement`.
 *
 * @param name name of the statement
 * @param sql actual SQL statement
 * @param num_args number of arguments in the statement
 * @return initialized struct
 */
struct GNUNET_PQ_PreparedStatement
GNUNET_PQ_make_prepare (const char *name,
                        const char *sql,
                        unsigned int num_args)
{
  struct GNUNET_PQ_PreparedStatement ps = {
    .name = name,
    .sql = sql,
    .num_arguments = num_args
  };

  return ps;
}


/**
 * Request creation of prepared statements @a ps from Postgres.
 *
 * @param connection connection to prepare the statements for
 * @param ps #GNUNET_PQ_PREPARED_STATEMENT_END-terminated array of prepared
 *            statements.
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on error
 */
int
GNUNET_PQ_prepare_statements (PGconn *connection,
                              const struct GNUNET_PQ_PreparedStatement *ps)
{
  for (unsigned int i=0;NULL != ps[i].name;i++)
  {
    PGresult *ret;

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     "pq",
                     "Preparing SQL statement `%s' as `%s'\n",
                     ps[i].sql,
                     ps[i].name);
    ret = PQprepare (connection,
                     ps[i].name,
                     ps[i].sql,
                     ps[i].num_arguments,
                     NULL);
    if (PGRES_COMMAND_OK != PQresultStatus (ret))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                       "pq",
                       _("PQprepare (`%s' as `%s') failed with error: %s\n"),
                       ps[i].sql,
                       ps[i].name,
                       PQerrorMessage (connection));
      PQclear (ret);
      return GNUNET_SYSERR;
    }
  }
  return GNUNET_OK;
}


/* end of pq/pq_prepare.c */
