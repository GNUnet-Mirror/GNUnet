/*
      This file is part of GNUnet
      (C) 2009, 2010 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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

#ifndef GNUNET_NSE_SERVICE_H_
#define GNUNET_NSE_SERVICE_H_

/**
 * @file include/gnunet_nse_service.h
 * @brief API to retrieve the current network size estimate,
 *        also to register for notifications whenever a new
 *        network size estimate is calculated.
 *
 * @author Nathan Evans
 */

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"

/**
 * Version of the network size estimation API.
 */
#define GNUNET_NSE_VERSION 0x00000000

/**
 * Interval for sending network size estimation flood requests.
 * Number is in milliseconds.
 * This needs to be a factor of the number milliseconds in
 * a day, as the base time used is midnight each day offset
 * by this amount.
 *
 * There are 86400000 milliseconds in a day.
 */
#define GNUNET_NSE_INTERVAL 3600000 /* Once per hour */

/**
 * Number of bits
 */
#define GNUNET_NSE_BITS

/**
 * Handle for the network size estimation service.
 */
struct GNUNET_NSE_Handle;


/**
 * Callback to call when network size estimate is updated.
 *
 * @param cls closure
 * @param estimate the value of the current network size estimate
 * @param std_dev standard deviation (rounded down to nearest integer)
 *                of the size estimation values seen
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
typedef int
(*GNUNET_NSE_Callback) (void *cls, double estimate, double std_dev);

/**
 * Connect to the network size estimation service.
 *
 * @param cfg the configuration to use
 * @param func funtion to call with network size estimate
 * @param func_cls closure to pass for network size estimate callback
 *
 * @return handle to use
 */
struct GNUNET_NSE_Handle *
GNUNET_NSE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    GNUNET_NSE_Callback func, void *func_cls);


/**
 * Disconnect from network size estimation service
 *
 * @param h handle to destroy
 *
 */
void
GNUNET_NSE_disconnect (struct GNUNET_NSE_Handle *h);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* GNUNET_NSE_SERVICE_H_ */
