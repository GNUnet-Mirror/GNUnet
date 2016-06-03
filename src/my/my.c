/*
     This file is part of GNUnet
     Copyright (C) 2016 Inria & GNUnet e.V.

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file my/my.c
 * @brief library to help with access to a MySQL database
 * @author Christophe Genevey
 * @author Christian Grothoff
 */
#include "platform.h"
#include <mysql/mysql.h>
#include "gnunet_my_lib.h"

#define STRING_SIZE 50

/**
 * Run a prepared SELECT statement.
 *
 * @param mc mysql context
 * @param sh handle to SELECT statment
 * @param params parameters to the statement
 * @return 
      #GNUNET_YES if we can prepare all statement
      #GNUNET_SYSERR if we can't prepare all statement
 */

int
GNUNET_MY_exec_prepared (struct GNUNET_MYSQL_Context *mc,
                         struct GNUNET_MYSQL_StatementHandle *sh,
                         const struct GNUNET_MY_QueryParam *params)
{
  const struct GNUNET_MY_QueryParam *p;
  unsigned int num;
  unsigned int i;
  MYSQL_STMT *stmt;

  num = 0;
  for (i=0;NULL != params[i].conv;i++)
    num += params[i].num_params;
  {
    MYSQL_BIND qbind[num];
    unsigned int off;

    memset(qbind, 0, sizeof(qbind));
    off = 0;
    for (i=0;NULL != (p = &params[i])->conv;i++)
    {
      if (GNUNET_OK !=
          p->conv (p->conv_cls,
                   p,
                   &qbind[off]))
      {
        return GNUNET_SYSERR;
      }
      off += p->num_params;
    }
    stmt = GNUNET_MYSQL_statement_get_stmt (mc, sh);
    if (mysql_stmt_bind_param (stmt,
                               qbind))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "mysql",
                       _("`%s' failed at %s:%d with error: %s\n"),
                       "mysql_stmt_bind_param", __FILE__, __LINE__,
                       mysql_stmt_error (stmt));
      GNUNET_MYSQL_statements_invalidate (mc);
      return GNUNET_SYSERR;
    }

  }
  if (mysql_stmt_execute (stmt))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "mysql",
                     _("`%s' failed at %s:%d with error: %s\n"),
                     "mysql_stmt_execute", __FILE__, __LINE__,
                     mysql_stmt_error (stmt));
    GNUNET_MYSQL_statements_invalidate (mc);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


/**
 * Extract results from a query result according
 * to the given specification. If colums are NULL,
 * the destination is not modified, and #GNUNET_NO is returned4
 *
 *
 * @param result
 * @param row, the row from the result to extract
 * @param result specificatio to extract for
 * @return
    #GNUNET_YES if all results could be extracted
    #GNUNET_NO if at least one result was NULL
    #GNUNET_SYSERR if a result was invalid
*/
int
GNUNET_MY_extract_result (struct GNUNET_MYSQL_StatementHandle *sh,
                          struct GNUNET_MY_QueryParam *qp,
                          struct GNUNET_MY_ResultSpec *rs,
                          int row)
{
  MYSQL_BIND *result;

  int num_fields;  
  MYSQL_FIELD *fields;
  MYSQL_RES *res;

  unsigned int i;
  unsigned int j;
  int had_null = GNUNET_NO;
  int ret;
  
  result = NULL;
  MYSQL_STMT *stmt;

  stmt = GNUNET_MYSQL_statement_get_stmt (NULL /* FIXME */, sh);
  if (NULL == stmt)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "mysql",
                    ("`%s' failed at %s:%d with error: %s\n"),
                       "mysql_stmt_bind_result", __FILE__, __LINE__,
                       mysql_stmt_error (stmt));
    return GNUNET_SYSERR;
  }


  num_fields = mysql_stmt_field_count (stmt);
  res = mysql_stmt_result_metadata (stmt);
  fields = mysql_fetch_fields (res);

  int int_data[num_fields];
  long int long_data[num_fields];
  short short_data[num_fields];
  char str_data[STRING_SIZE];
  int error[num_fields];

  result = (MYSQL_BIND *)malloc (sizeof (MYSQL_BIND)*num_fields);
  if(!result)
  {
    fprintf(stderr, "Error to allocate output buffers\n");
    return GNUNET_SYSERR;
  }

  memset(result, 0, sizeof (MYSQL_BIND) * num_fields);

/** INITIALISER LE MYSQL_BIND ****/

  for(i = 0 ; i< num_fields ;i++)
  {
    result[i].buffer_type = fields[i].type; 
    result[i].is_null = 0;  
    result[i].error = &error[i];

    switch (fields[i].type)
    {
      case MYSQL_TYPE_LONG:
        result[i].buffer = &(int_data[i]);
        result[i].buffer_length = sizeof (int_data);
        break;

      case MYSQL_TYPE_LONGLONG:
        result[i].buffer = &(long_data[i]);
        result[i].buffer_length = sizeof (long_data);
        break;

      case MYSQL_TYPE_STRING:
        result[i].buffer = (char *)str_data;
        result[i].buffer_length = sizeof (str_data);
        break;

      case MYSQL_TYPE_SHORT:
        result[i].buffer = &(short_data[i]);
        result[i].buffer_length = sizeof (short_data);
        break;

      default:
        fprintf(stderr, "Failed : wrong type : %d!\n", fields[i].type);
    } 
  }

  if (mysql_stmt_bind_result(stmt, result))
  {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "mysql",
                       _("`%s' failed at %s:%d with error: %s\n"),
                       "mysql_stmt_bind_result", __FILE__, __LINE__,
                       mysql_stmt_error (stmt));
      return GNUNET_SYSERR;
  }

  /*** FAILED HERE ***/
  if (mysql_stmt_fetch (stmt))
  {
    for(j = 0 ; j < num_fields ;j++)
    {
      fprintf(stderr, "Error Bind [%d] : %d\n", j, error[j]);
    }

    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "mysql",
                       _("`%s' failed at %s:%d with error: %s\n"),
                       "mysql_stmt_fetch", __FILE__, __LINE__,
                       mysql_stmt_error (stmt));
    return GNUNET_SYSERR;
  }

/*
  while (1)
  {
    mysql_stmt_fetch (stmt);

    for (i = 0 ; NULL != rs[i].conv ; i++)
    {
      struct GNUNET_MY_ResultSpec *spec;

      spec = &rs[i];
      ret = spec->conv (spec->conv_cls,
                        spec,
                        result);

      if (GNUNET_SYSERR == ret)
      {
        return GNUNET_SYSERR;
      }

      if (NULL != spec->result_size)
        *spec->result_size = spec->dst_size;
    }
  }

  if (GNUNET_YES == had_null)
    return GNUNET_NO;
*/

  free (result);
  return GNUNET_OK;
}

/* end of my.c */
