/*
      This file is part of GNUnet
      (C) 2011 Christian Grothoff (and other contributing authors)

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
 * Handle for the network size estimation service.
 */
struct GNUNET_NSE_Handle;

/**
 * Callback to call when network size estimate is updated.
 *
 * @param cls closure
 * @param timestamp time when the estimate was received from the server (or created by the server)
 * @param logestimate the log(Base 2) value of the current network size estimate
 * @param std_dev standard deviation for the estimate
 *
 */
typedef void (*GNUNET_NSE_Callback) (void *cls,
                                     struct GNUNET_TIME_Absolute timestamp,
                                     double logestimate, double std_dev);


/**
 * Convert the logarithmic estimated returned to the 'GNUNET_NSE_Callback'
 * into an absolute estimate in terms of the number of peers in the network.
 *
 * @param loge logarithmic estimate
 * @return absolute number of peers in the network (estimated)
 */
#define GNUNET_NSE_log_estimate_to_n(loge) pow(2.0, (loge))

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
