/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013, 2016 GNUnet e.V.

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
 * Functions related to accessing services

 * @defgroup client  Client library
 * Generic client-side communication with services
 *
 * @see [Documentation](https://gnunet.org/ipc)
 *
 * @{
 */

#ifndef GNUNET_CLIENT_LIB_H
#define GNUNET_CLIENT_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_mq_lib.h"


/**
 * Create a message queue to connect to a GNUnet service.
 * If handlers are specfied, receive messages from the connection.
 *
 * @param connection the client connection
 * @param handlers handlers for receiving messages, can be NULL
 * @param error_handler error handler
 * @param error_handler_cls closure for the @a error_handler
 * @return the message queue, NULL on error
 */
struct GNUNET_MQ_Handle *
GNUNET_CLIENT_connecT (const struct GNUNET_CONFIGURATION_Handle *cfg,
                       const char *service_name,
                       const struct GNUNET_MQ_MessageHandler *handlers,
                       GNUNET_MQ_ErrorHandler error_handler,
                       void *error_handler_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CLIENT_LIB_H */
#endif

/** @} */ /* end of group client */

/* end of gnunet_client_lib.h */
