/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file monkey/edb_api.c
 * @brief Monkey API for accessing the Expression Database (edb)
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_monkey_edb.h"
#include <sqlite3.h>


/**
 * Context for Database connection and Expressions
 */
struct GNUNET_MONKEY_EDB_Context
{
  /**
   *  Database connection 
   */
  sqlite3 *db_handle;
};


/**
 * Establish a connection to the Expression Database
 *
 * @param db_file_name path the Expression Database file
 * @return context to use for Accessing the Expression Database, NULL on error
 */
struct GNUNET_MONKEY_EDB_Context *
GNUNET_MONKEY_EDB_connect (const char *db_file_name)
{
  int err;
  struct GNUNET_MONKEY_EDB_Context *ctxt =
    GNUNET_malloc (sizeof (struct GNUNET_MONKEY_EDB_Context));

  err = sqlite3_open (db_file_name, &ctxt->db_handle);
  if (err)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Cannot open Expression Database. `%s'\n",
		  sqlite3_errmsg (ctxt->db_handle));
      return NULL;
    }
  return ctxt;
}


/**
 * Disconnect from Database, and cleanup resources
 *
 * @param context context containing the Expression Database handle
 * @return GNUNET_OK on success, GNUNET_NO on failure
 */
int
GNUNET_MONKEY_EDB_disconnect (struct GNUNET_MONKEY_EDB_Context *cntxt)
{
  sqlite3_close (cntxt->db_handle);
  GNUNET_free (cntxt);
  return GNUNET_OK;
}


/**
 * Return the line number of the end-of-scope for the expression indicated by start_line_no
 *
 * @param cntxt context containing the Expression Database handle
 * @param file_name path to the file in which the expression in question exists
 * @param start_line_no expression's line
 * @param iter callback function, iterator for values returned from the Database
 * @param iter_cls closure for the expression iterator, will contain the scope-end line number
 * @return GNUNET_OK on success, GNUNET_NO on failure
 */
int
GNUNET_MONKEY_EDB_get_expression_scope_end(struct GNUNET_MONKEY_EDB_Context *cntxt,
				  const char *file_name, int start_line_no,
				  GNUNET_MONKEY_ExpressionIterator iter,
				  void *iter_cls)
{
	int err;
	char *errMsg;
	char *query;

	if (asprintf(&query, "select end_lineno from Expression where file_name LIKE \'%%/%s\' and start_lineno = %d", file_name, start_line_no) == -1) {
	  GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Memory allocation problem occurred during creating database query!\n");
		return GNUNET_NO;
	}

	err = sqlite3_exec(cntxt->db_handle, query, iter, iter_cls, &errMsg);
	if (err) {
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Error occurred while executing Database query. `%s'",
		  errMsg);
		return GNUNET_NO;
	}
	return GNUNET_OK;
}


/**
 * Run an SQLite query to retrieve those expressions that are previous to
 * given expression and are in the same scope of the given expression
 * 
 * @param cntxt context containing the Expression Database handle
 * @param file_name path to the file in which the expression in question exists
 * @param start_line_no expression beginning line
 * @param end_line_no line number for the expression's scope end
 * @param iter callback function, iterator for expressions returned from the Database
 * @param iter_cls closure for the expression iterator
 * @return GNUNET_OK success, GNUNET_NO failure
 */
int
GNUNET_MONKEY_EDB_get_expressions (struct GNUNET_MONKEY_EDB_Context *cntxt,
				   const char *file_name, int start_line_no,
				   int end_line_no,
				   GNUNET_MONKEY_ExpressionIterator iter,
				   void *iter_cls)
{
  int err;
  char *errMsg;
  char *query;
  if (asprintf
      (&query,
       "select expr_syntax, start_lineno from Expression where file_name LIKE \'%%/%s\' and start_lineno <= %d and end_lineno = %d",
       file_name, start_line_no, end_line_no) == -1)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Memory allocation problem occurred!\n");
      return GNUNET_NO;
    }

  err = sqlite3_exec (cntxt->db_handle, query, iter, iter_cls, &errMsg);
  if (err)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Error occurred while executing Database query. `%s'",
		  errMsg);
      return GNUNET_NO;
    }
  return GNUNET_OK;
}


int
GNUNET_MONKEY_EDB_get_sub_expressions (struct GNUNET_MONKEY_EDB_Context *cntxt,
				   const char *file_name, int start_line_no,
				   int end_line_no,
				   GNUNET_MONKEY_ExpressionIterator iter,
				   void *iter_cls)
{
  int err;
  char *errMsg;
  char *query;
  if (asprintf
      (&query,
       "select expr_syntax, start_lineno from Expression where file_name LIKE \'%%/%s\' and start_lineno = %d and end_lineno = %d",
       file_name, start_line_no, end_line_no) == -1)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Memory allocation problem occurred!\n");
      return GNUNET_NO;
    }

  err = sqlite3_exec (cntxt->db_handle, query, iter, iter_cls, &errMsg);
  if (err)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Error occurred while executing Database query. `%s'",
		  errMsg);
      return GNUNET_NO;
    }
  return GNUNET_OK;
}

