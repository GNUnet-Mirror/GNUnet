/*
     This file is part of GNUnet
     Copyright (C) 2012 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * Helper library to access a MySQL database
 *
 * @defgroup mysql  MySQL library
 * Helper library to access a MySQL database.
 * @{
 */
#ifndef GNUNET_MY_LIB_H
#define GNUNET_MY_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_mysql_lib.h"
#include <mysql/mysql.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif



/**
 * Information we pass to #GNUNET_MY_exec_prepared() to
 * initialize the arguments of the prepared statement.
 */
struct GNUNET_MY_QueryParam;


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param pq data about the query
 * @param qbind array of parameters to initialize
 * @return -1 on error
 */
typedef int
(*GNUNET_MY_QueryConverter)(void *cls,
			    const struct GNUNET_MY_QueryParam *qp,
                            MYSQL_BIND *qbind);



/**
 * Information we pass to #GNUNET_MY_exec_prepared() to
 * initialize the arguments of the prepared statement.
 */
struct GNUNET_MY_QueryParam
{

  /**
   * Function to call for the type conversion.
   */
  GNUNET_MY_QueryConverter conv;

  /**
   * Closure for @e conv.
   */
  void *conv_cls;

  /**
   * Number of arguments the @a conv converter expects to initialize.
   */
  unsigned int num_params;

  /**
   * Information to pass to @e conv.
   */
  const void *data;

  /**
   * Information to pass to @e conv.  Size of @a data.
   */
  unsigned long data_len;

};


/**
 * End of result parameter specification.
 *
 * @return array last entry for the result specification to use
 */
#define GNUNET_MY_query_param_end { NULL, NULL, 0, NULL, 0 }



/**
 * Generate query parameter for a buffer @a ptr of
 * @a ptr_size bytes.
 *
 * @param ptr pointer to the query parameter to pass
 * @oaran ptr_size number of bytes in @a ptr
 */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_fixed_size (const void *ptr,
				  size_t ptr_size);


/**
 * Run a prepared SELECT statement.
 *
 * @param mc mysql context
 * @param sh handle to SELECT statment
 * @param params parameters to the statement
 * @return TBD
 */
int
GNUNET_MY_exec_prepared (struct GNUNET_MYSQL_Context *mc,
                         struct GNUNET_MYSQL_StatementHandle *sh,
                         const struct GNUNET_MY_QueryParam *params);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
