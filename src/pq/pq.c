/*
  This file is part of GNUnet
  Copyright (C) 2014, 2015, 2016 GNUnet e.V.

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
 * @file pq/pq.c
 * @brief helper functions for libpq (PostGres) interactions
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 * @author Florian Dold
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gnunet/gnunet_util_lib.h>
#include "gnunet_pq_lib.h"


/**
 * Execute a prepared statement.
 *
 * @param db_conn database connection
 * @param name name of the prepared statement
 * @param params parameters to the statement
 * @return postgres result
 */
PGresult *
GNUNET_PQ_exec_prepared (PGconn *db_conn,
			 const char *name,
			 const struct GNUNET_PQ_QueryParam *params)
{
  unsigned int len;
  unsigned int i;

  /* count the number of parameters */
  len = 0;
  for (i=0;0 != params[i].num_params;i++)
    len += params[i].num_params;

  /* new scope to allow stack allocation without alloca */
  {
    /* Scratch buffer for temporary storage */
    void *scratch[len];
    /* Parameter array we are building for the query */
    void *param_values[len];
    int param_lengths[len];
    int param_formats[len];
    unsigned int off;
    /* How many entries in the scratch buffer are in use? */
    unsigned int soff;
    PGresult *res;
    int ret;

    off = 0;
    soff = 0;
    for (i=0;0 != params[i].num_params;i++)
    {
      const struct GNUNET_PQ_QueryParam *x = &params[i];

      ret = x->conv (x->conv_cls,
		     x->data,
		     x->size,
		     &param_values[off],
		     &param_lengths[off],
		     &param_formats[off],
		     x->num_params,
		     &scratch[soff],
		     len - soff);
      if (ret < 0)
      {
	for (off = 0; off < soff; off++)
	  GNUNET_free (scratch[off]);
	return NULL;
      }
      soff += ret;
      off += x->num_params;
    }
    GNUNET_assert (off == len);
    res = PQexecPrepared (db_conn,
                          name,
                          len,
                          (const char **) param_values,
                          param_lengths,
                          param_formats,
                          1);
    for (off = 0; off < soff; off++)
      GNUNET_free (scratch[off]);
    return res;
  }
}


/**
 * Free all memory that was allocated in @a rs during
 * #GNUNET_PQ_extract_result().
 *
 * @param rs reult specification to clean up
 */
void
GNUNET_PQ_cleanup_result (struct GNUNET_PQ_ResultSpec *rs)
{
  unsigned int i;

  for (i=0; NULL != rs[i].conv; i++)
    if (NULL != rs[i].cleaner)
      rs[i].cleaner (rs[i].cls,
		     rs[i].dst);
}


/**
 * Extract results from a query result according to the given
 * specification.  If colums are NULL, the destination is not
 * modified, and #GNUNET_NO is returned.
 *
 * @param result result to process
 * @param[in,out] rs result specification to extract for
 * @param row row from the result to extract
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_NO if at least one result was NULL
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */
int
GNUNET_PQ_extract_result (PGresult *result,
			  struct GNUNET_PQ_ResultSpec *rs,
			  int row)
{
  unsigned int i;
  int had_null = GNUNET_NO;
  int ret;

  for (i=0; NULL != rs[i].conv; i++)
  {
    struct GNUNET_PQ_ResultSpec *spec;

    spec = &rs[i];
    ret = spec->conv (spec->cls,
		      result,
		      row,
		      spec->fname,
		      &spec->dst_size,
		      spec->dst);
    if (GNUNET_SYSERR == ret)
      return GNUNET_SYSERR;
    if (GNUNET_NO == ret)
    {
      had_null = GNUNET_YES;
      continue;
    }
    if (NULL != spec->result_size)
      *spec->result_size = spec->dst_size;
  }
  if (GNUNET_YES == had_null)
    return GNUNET_NO;
  return GNUNET_OK;
}


/* end of pq/pq.c */
