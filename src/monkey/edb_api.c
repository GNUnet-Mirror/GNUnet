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
	/* TODO: Implementation */
	return NULL;
}


/**
 * Disconnect from Database, and cleanup resources
 *
 * @param cfg configuration to use (used to know the path of the .db file).
 * @param service service that *this* process is implementing/providing, can be NULL
 * @return GNUNET_OK on success, GNUNET_NO on failure
 */
int
GNUNET_MONKEY_EDB_disconnect (struct GNUNET_MONKEY_EDB_Context *context)
{
	/* TODO: Implementation */
	return GNUNET_OK;
}


/**
 * Update the context with a list of expressions. 
 * The list is the initializations of sub-expressions 
 * of the expression pointed to by start_line_no and end_line_no
 * 
 * @param context the returned expessions will be available in it. 
 * expression_list_head, and expression_list_tail must be null, 
 * otherwise GNUNET_NO will be returned 
 * @param file_name path to the file in which the expression in question exists
 * @param start_line_no expression beginning line
 * @param end_line_no expression end line
 * @param iter callback function, iterator for expressions returned from the Database
 * @param iter_cls closure for the expression iterator
 * @return GNUNET_OK success, GNUNET_NO failure
 */
int
GNUNET_MONKEY_EDB_get_expressions (struct GNUNET_MONKEY_EDB_Context *context,
				   const char *file_name, int start_line_no,
				   int end_line_no,
				   GNUNET_MONKEY_ExpressionIterator iter, void *iter_cls)
{
	/* TODO: Implementation */
	return GNUNET_OK;
}
