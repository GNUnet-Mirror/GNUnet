/*
      This file is part of GNUnet
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
 * @file monkey/gnunet_monkey_edb.h
 * @brief Monkey API for accessing the Expression Database (edb)
 */

#ifndef GNUNET_MONKEY_EDB_H
#define GNUNET_MONKEY_EDB_H

#ifdef __cplusplus
extern "C"
{
#if 0				/* keep Emacsens' auto-indent happy */
}
#endif
#endif


struct GNUNET_MONKEY_EDB_Context;

/**
 * Establish a connection to the Expression Database
 *
 * @param db_file_name path the Expression Database file
 * @return context to use for Accessing the Expression Database, NULL on error
 */
struct GNUNET_MONKEY_EDB_Context *GNUNET_MONKEY_EDB_connect (const char
							     *db_file_name);


/**
 * Disconnect from Database, and cleanup resources
 *
 * @param context context
 * @return GNUNET_OK on success, GNUNET_NO on failure
 */
int GNUNET_MONKEY_EDB_disconnect (struct GNUNET_MONKEY_EDB_Context *cntxt);


typedef int (*GNUNET_MONKEY_ExpressionIterator) (void *, int, char **,
						 char **);



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
				  void *iter_cls);


/**
 * Run an SQLite query to retrieve those expressions that are previous to
 * given expression and are in the same scope of the given expression
 * For example, consider the following code snippet:
 *
 * {
 *   struct Something whole; // line no.1 
 *   struct SomethingElse part; // line no.2
 *   whole.part = &part; // line no.3
 *   whole.part->member = 1; // line no.4
 * }
 *
 * If the expression supplied to the function is that of line no.4 "whole.part->member = 1;"
 * The returned list of expressions will be: whole.part (line no.4), whole.part->member (line no.4),
 * whole (line no.3), whole.part (line no.3), &part (line no.3), whole.part = &part (line no.3)
 *
 * @param cntxt context containing the Expression Database handle.
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
				   void *iter_cls);


int
GNUNET_MONKEY_EDB_get_sub_expressions (struct GNUNET_MONKEY_EDB_Context *cntxt,
				   const char *file_name, int start_line_no,
				   int end_line_no,
				   GNUNET_MONKEY_ExpressionIterator iter,
				   void *iter_cls);



#if 0				/* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
