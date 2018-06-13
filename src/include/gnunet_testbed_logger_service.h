/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU Affero General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.
     
      You should have received a copy of the GNU Affero General Public License
      along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 *
 * @file
 * API for submitting data to the testbed logger service
 *
 * @defgroup testbed-logger  Testbed Logger service
 * Submit data to the testbed logger service.
 * @{
 */

#ifndef GNUNET_TESTBED_LOGGER_SERVICE_H
#define GNUNET_TESTBED_LOGGER_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"

/**
 * Opaque handle for the logging service
 */
struct GNUNET_TESTBED_LOGGER_Handle;


/**
 * Connect to the testbed logger service
 *
 * @param cfg configuration to use
 * @return the handle which can be used for sending data to the service; NULL
 *           upon any error
 */
struct GNUNET_TESTBED_LOGGER_Handle *
GNUNET_TESTBED_LOGGER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Disconnect from the logger service.  Also cancels any pending send handles.
 *
 * @param h the logger handle
 */
void
GNUNET_TESTBED_LOGGER_disconnect (struct GNUNET_TESTBED_LOGGER_Handle *h);


/**
 * Functions of this type are called to notify a successful transmission of the
 * message to the logger service.
 *
 * @param cls the closure given to GNUNET_TESTBED_LOGGER_send()
 * @param size the amount of data sent
 */
typedef void
(*GNUNET_TESTBED_LOGGER_FlushCompletion) (void *cls,
                                          size_t size);


/**
 * Send data to be logged to the logger service.  The data will be buffered and
 * will be sent upon an explicit call to GNUNET_TESTBED_LOGGER_flush() or upon
 * exceeding a threshold size.
 *
 * @param h the logger handle
 * @param data the data to send;
 * @param size how many bytes of @a data to send
 */
void
GNUNET_TESTBED_LOGGER_write (struct GNUNET_TESTBED_LOGGER_Handle *h,
                             const void *data,
                             size_t size);


/**
 * Flush the buffered data to the logger service
 *
 * @param h the logger handle
 * @param cb the callback to call after the data is flushed
 * @param cb_cls the closure for @a cb
 */
void
GNUNET_TESTBED_LOGGER_flush (struct GNUNET_TESTBED_LOGGER_Handle *h,
                             GNUNET_TESTBED_LOGGER_FlushCompletion cb,
                             void *cb_cls);


/**
 * Cancel notification upon flush.  Should only be used when the flush
 * completion callback given to GNUNET_TESTBED_LOGGER_flush() is not already
 * called.
 *
 * @param h the logger handle
 */
void
GNUNET_TESTBED_LOGGER_flush_cancel (struct GNUNET_TESTBED_LOGGER_Handle *h);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif  /* GNUNET_TESTBED_LOGGER_SERVICE_H */

/** @} */  /* end of group */

/* End of gnunet_testbed_logger_service.h */
