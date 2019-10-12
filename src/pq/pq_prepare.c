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
 * @file pq/pq_prepare.c
 * @brief functions to connect to libpq (PostGres)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "pq.h"


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
 * @param db database to prepare the statements for
 * @param ps #GNUNET_PQ_PREPARED_STATEMENT_END-terminated array of prepared
 *            statements.
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on error
 */
int
GNUNET_PQ_prepare_statements (struct GNUNET_PQ_Context *db,
                              const struct GNUNET_PQ_PreparedStatement *ps)
{
  if (db->ps != ps)
  {
    /* add 'ps' to list db->ps of prepared statements to run on reconnect! */
    unsigned int olen = 0; /* length of existing 'db->ps' array */
    unsigned int nlen = 0; /* length of 'ps' array */
    struct GNUNET_PQ_PreparedStatement *rps; /* combined array */

    if (NULL != db->ps)
      while (NULL != db->ps[olen].name)
        olen++;
    while (NULL != ps[nlen].name)
      nlen++;
    rps = GNUNET_new_array (olen + nlen + 1,
                            struct GNUNET_PQ_PreparedStatement);
    if (NULL != db->ps)
      memcpy (rps,
              db->ps,
              olen * sizeof (struct GNUNET_PQ_PreparedStatement));
    memcpy (&rps[olen],
            ps,
            nlen * sizeof (struct GNUNET_PQ_PreparedStatement));
    GNUNET_free_non_null (db->ps);
    db->ps = rps;
  }

  /* actually prepare statements */
  for (unsigned int i = 0; NULL != ps[i].name; i++)
  {
    PGresult *ret;

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     "pq",
                     "Preparing SQL statement `%s' as `%s'\n",
                     ps[i].sql,
                     ps[i].name);
    ret = PQprepare (db->conn,
                     ps[i].name,
                     ps[i].sql,
                     ps[i].num_arguments,
                     NULL);
    if (PGRES_COMMAND_OK != PQresultStatus (ret))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                       "pq",
                       _ ("PQprepare (`%s' as `%s') failed with error: %s\n"),
                       ps[i].sql,
                       ps[i].name,
                       PQerrorMessage (db->conn));
      PQclear (ret);
      return GNUNET_SYSERR;
    }
    PQclear (ret);
  }
  return GNUNET_OK;
}


/* end of pq/pq_prepare.c */
