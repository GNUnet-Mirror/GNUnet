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
 * @file sq/sq_prepare.c
 * @brief helper functions for executing SQL statements
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_sq_lib.h"


/**
 * Create a `struct GNUNET_SQ_PrepareStatement`
 *
 * @param sql actual SQL statement
 * @param pstmt where to store the handle
 * @return initialized struct
 */
struct GNUNET_SQ_PrepareStatement
GNUNET_SQ_make_prepare (const char *sql,
                        sqlite3_stmt **pstmt)
{
  struct GNUNET_SQ_PrepareStatement ps = {
    .sql = sql,
    .pstmt = pstmt
  };

  return ps;
}



/**
 * Prepare all statements given in the (NULL,NULL)-terminated
 * array at @a ps
 *
 * @param dbh database to use
 * @param ps array of statements to prepare
 * @return #GNUNET_OK on success
 */
int
GNUNET_SQ_prepare (sqlite3 *dbh,
                   const struct GNUNET_SQ_PrepareStatement *ps)
{
  for (unsigned int i=0;NULL != ps[i].sql;i++)
  {
    const char *epos = NULL;
    int ret;

    if (SQLITE_OK !=
        (ret = sqlite3_prepare_v2 (dbh,
                                   ps[i].sql,
                                   strlen (ps[i].sql),
                                   ps[i].pstmt,
                                   &epos)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to prepare SQL `%s': error %d at %s\n",
                  ps[i].sql,
                  ret,
                  epos);
      return GNUNET_SYSERR;
    }
  }
  return GNUNET_OK;
}

/* end of sq_prepare.c */
