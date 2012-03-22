/*
     This file is part of GNUnet
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_mysql_lib.h
 * @brief library to help with access to a MySQL database
 * @author Christian Grothoff
 */
#ifndef GNUNET_MYSQL_LIB_H
#define GNUNET_MYSQL_LIB_H

#include "gnunet_util_lib.h"
#include <mysql/mysql.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Mysql context.
 */
struct GNUNET_MYSQL_Context;


/**
 * Handle for a prepared statement.
 */
struct GNUNET_MYSQL_StatementHandle;


/**
 * Type of a callback that will be called for each
 * data set returned from MySQL.
 *
 * @param cls user-defined argument
 * @param num_values number of elements in values
 * @param values values returned by MySQL
 * @return GNUNET_OK to continue iterating, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_MYSQL_DataProcessor) (void *cls, unsigned int num_values,
					   MYSQL_BIND * values);


/**
 * Create a mysql context.
 *
 * @param cfg configuration
 * @param section configuration section to use to get MySQL configuration options
 * @return the mysql context
 */
struct GNUNET_MYSQL_Context *
GNUNET_MYSQL_context_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
			     const char *section);


/**
 * Destroy a mysql context.  Also frees all associated prepared statements.
 * 
 * @param mc context to destroy
 */
void
GNUNET_MYSQL_context_destroy (struct GNUNET_MYSQL_Context *mc);


/**
 * Close database connection and all prepared statements (we got a DB
 * error).  The connection will automatically be re-opened and
 * statements will be re-prepared if they are needed again later.
 *
 * @param mc mysql context
 */
void
GNUNET_MYSQL_statements_invalidate (struct GNUNET_MYSQL_Context *mc);


/**
 * Get internal handle for a prepared statement.  This function should rarely
 * be used, and if, with caution!  On failures during the interaction with
 * the handle, you must call 'GNUNET_MYSQL_statements_invalidate'!
 *
 * @param mc mysql context
 * @param sh prepared statement to introspect
 * @return MySQL statement handle, NULL on error
 */
MYSQL_STMT *
GNUNET_MYSQL_statement_get_stmt (struct GNUNET_MYSQL_Context *mc,
				 struct GNUNET_MYSQL_StatementHandle *sh);


/**
 * Prepare a statement.  Prepared statements are automatically discarded
 * when the MySQL context is destroyed.
 *
 * @param mc mysql context
 * @param query query text
 * @return prepared statement, NULL on error
 */
struct GNUNET_MYSQL_StatementHandle *
GNUNET_MYSQL_statement_prepare (struct GNUNET_MYSQL_Context *mc,
				const char *query);


/**
 * Run a SQL statement.
 *
 * @param mc mysql context
 * @param sql SQL statement to run
 * @return GNUNET_OK on success
 *         GNUNET_SYSERR if there was a problem
 */
int
GNUNET_MYSQL_statement_run (struct GNUNET_MYSQL_Context *mc,
			    const char *sql);


/**
 * Run a prepared SELECT statement.
 *
 * @param mc mysql context
 * @param sh handle to SELECT statment
 * @param result_size number of elements in results array
 * @param results pointer to already initialized MYSQL_BIND
 *        array (of sufficient size) for passing results
 * @param processor function to call on each result
 * @param processor_cls extra argument to processor
 * @param ... pairs and triplets of "MYSQL_TYPE_XXX" keys and their respective
 *        values (size + buffer-reference for pointers); terminated
 *        with "-1"
 * @return GNUNET_SYSERR on error, otherwise
 *         the number of successfully affected (or queried) rows
 */
int
GNUNET_MYSQL_statement_run_prepared_select (struct GNUNET_MYSQL_Context *mc,
					    struct GNUNET_MYSQL_StatementHandle *sh,
					    unsigned int result_size, MYSQL_BIND * results,
					    GNUNET_MYSQL_DataProcessor processor,
					    void *processor_cls, ...);


/**
 * Run a prepared SELECT statement.
 *
 * @param mc mysql context
 * @param s statement to run
 * @param result_size number of elements in results array
 * @param results pointer to already initialized MYSQL_BIND
 *        array (of sufficient size) for passing results
 * @param processor function to call on each result
 * @param processor_cls extra argument to processor
 * @param ap pairs and triplets of "MYSQL_TYPE_XXX" keys and their respective
 *        values (size + buffer-reference for pointers); terminated
 *        with "-1"
 * @return GNUNET_SYSERR on error, otherwise
 *         the number of successfully affected (or queried) rows
 */
int
GNUNET_MYSQL_statement_run_prepared_select_va (struct GNUNET_MYSQL_Context *mc,
					       struct GNUNET_MYSQL_StatementHandle *s,
					       unsigned int result_size,
					       MYSQL_BIND * results,
					       GNUNET_MYSQL_DataProcessor processor,
					       void *processor_cls,
					       va_list ap);


/**
 * Run a prepared statement that does NOT produce results.
 *
 * @param mc mysql context
 * @param sh handle to statment
 * @param insert_id NULL or address where to store the row ID of whatever
 *        was inserted (only for INSERT statements!)
 * @param ... pairs and triplets of "MYSQL_TYPE_XXX" keys and their respective
 *        values (size + buffer-reference for pointers); terminated
 *        with "-1"
 * @return GNUNET_SYSERR on error, otherwise
 *         the number of successfully affected rows
 */
int
GNUNET_MYSQL_statement_run_prepared (struct GNUNET_MYSQL_Context *mc,
				     struct GNUNET_MYSQL_StatementHandle *sh,
				     unsigned long long *insert_id, ...);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_mysql_lib.h */
#endif
