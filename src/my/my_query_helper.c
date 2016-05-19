/*
     This file is part of GNUnet
     Copyright (C) 2016 GNUnet e.V.

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
 * @file my/my_query_helper.c
 * @brief library to help with access to a MySQL database
 * @author Christian Grothoff
 */
#include "platform.h"
#include <mysql/mysql.h>
#include "gnunet_my_lib.h"


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param pq data about the query
 * @param qbind array of parameters to initialize
 * @return -1 on error
 */
static int
pq_conv_fixed_size (void *cls,
                    const struct GNUNET_MY_QueryParam *qp,
                    MYSQL_BIND *qbind)
{
  GNUNET_assert (1 == qp->num_params);
  qbind->buffer = (void *) qp->data;
  qbind->buffer_length = qp->data_len;
  qbind->length = (unsigned long *) &qp->data_len;
  return 0;
}


/**
 * Generate query parameter for a buffer @a ptr of
 * @a ptr_size bytes.
 *
 * @param ptr pointer to the query parameter to pass
 * @oaran ptr_size number of bytes in @a ptr
 */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_fixed_size (const void *ptr,
				  size_t ptr_size)
{
  struct GNUNET_MY_QueryParam qp = {
    &pq_conv_fixed_size,
    NULL,
    1,
    ptr,
    (unsigned long) ptr_size
  };
  return qp;
}


/* end of my_query_helper.c */
