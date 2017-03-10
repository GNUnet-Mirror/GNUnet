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
 * @file sq/sq.c
 * @brief helper functions for Sqlite3 DB interactions
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_sq_lib.h"


/**
 * Execute a prepared statement.
 *
 * @param db_conn database connection
 * @param params parameters to the statement
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_SQ_bind (sqlite3_stmt *stmt,
                const struct GNUNET_SQ_QueryParam *params)
{
  unsigned int j;

  j = 1;
  for (unsigned int i=0;NULL != params[i].conv; i++)
  {
    if (GNUNET_OK !=
        params[i].conv (params[i].conv_cls,
                        params[i].data,
                        params[i].size,
                        stmt,
                        j))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
                       "sq",
                       _("Failure to bind %u-th SQL parameter\n"),
                       i);
      if (SQLITE_OK !=
          sqlite3_reset (stmt))
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
                         "sq",
                         _("Failure in sqlite3_reset (!)\n"));
        return GNUNET_SYSERR;
      }
    }
    GNUNET_assert (0 != params[i].num_params);
    j += params[i].num_params;
  }
  return GNUNET_OK;
}


/**
 * Extract results from a query result according to the given specification.
 *
 * @param result result to process
 * @param[in,out] rs result specification to extract for
 * @return
 *   #GNUNET_OK if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */
int
GNUNET_SQ_extract_result (sqlite3_stmt *result,
			  struct GNUNET_SQ_ResultSpec *rs)
{
  unsigned int j = 0;

  for (unsigned int i=0;NULL != rs[i].conv; i++)
  {
    if (NULL == rs[i].result_size)
      rs[i].result_size = &rs[i].dst_size;
    if (GNUNET_OK !=
        rs[i].conv (rs[i].cls,
                    result,
                    j,
                    rs[i].result_size,
                    rs[i].dst))
      return GNUNET_SYSERR;
    GNUNET_assert (0 != rs[i].num_params);
    j += rs[i].num_params;
  }
  return GNUNET_OK;
}


/**
 * Free all memory that was allocated in @a rs during
 * #GNUNET_SQ_extract_result().
 *
 * @param rs reult specification to clean up
 */
void
GNUNET_SQ_cleanup_result (struct GNUNET_SQ_ResultSpec *rs)
{
  for (unsigned int i=0;NULL != rs[i].conv; i++)
    if (NULL != rs[i].cleaner)
      rs[i].cleaner (rs[i].cls);
}

/* end of sq.c */
