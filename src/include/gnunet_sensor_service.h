/*
      This file is part of GNUnet
      Copyright (C)

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
 * @author Omar Tarabai
 *
 * @file
 * API to the sensor service
 *
 * @defgroup sensor  Sensor service
 *
 * @{
 */

#ifndef GNUNET_SENSOR_SERVICE_H
#define GNUNET_SENSOR_SERVICE_H

#include "gnunet_common.h"
#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Handle to the sensor service.
 */
struct GNUNET_SENSOR_Handle;

/**
 * Context for an iteration request.
 */
struct GNUNET_SENSOR_IterateContext;

/**
 * Context of a force anomaly request
 */
struct GNUNET_SENSOR_ForceAnomalyContext;

/**
 * Structure containing brief info about sensor
 */
struct SensorInfoShort
{

  /*
   * Sensor name
   */
  char *name;

  /*
   * First part of version number
   */
  uint16_t version_major;

  /*
   * Second part of version number
   */
  uint16_t version_minor;

  /*
   * Sensor description
   */
  char *description;

};

/**
 * Sensor iterate request callback.
 *
 * @param cls closure
 * @param sensor Brief sensor information
 * @param error message
 */
typedef void (*GNUNET_SENSOR_SensorIterateCB) (void *cls,
                                                const struct SensorInfoShort *
                                                sensor, const char *err_msg);


/**
 * Continuation called with a status result.
 *
 * @param cls closure
 * @param emsg error message, NULL on success
 */
typedef void (*GNUNET_SENSOR_Continuation) (void *cls, const char *emsg);


/**
 * Disconnect from the sensor service
 *
 * @param h handle to disconnect
 */
void
GNUNET_SENSOR_disconnect (struct GNUNET_SENSOR_Handle *h);


/**
 * Connect to the sensor service.
 *
 * @return NULL on error
 */
struct GNUNET_SENSOR_Handle *
GNUNET_SENSOR_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Cancel an iteration request.
 * This should be called before the iterate callback is called with a NULL value.
 *
 * @param ic context of the iterator to cancel
 */
void
GNUNET_SENSOR_iterate_cancel (struct GNUNET_SENSOR_IterateContext
                                     *ic);


/**
 * Get one or all sensors loaded by the sensor service.
 * The callback will be called with each sensor received and once with a NULL
 * value to signal end of iteration.
 *
 * @param h Handle to SENSOR service
 * @param timeout how long to wait until timing out
 * @param sensorname Name of the required sensor, NULL to get all
 * @param callback the function to call for each sensor
 * @param callback_cls closure for callback
 * @return iterator context
 */
struct GNUNET_SENSOR_IterateContext *
GNUNET_SENSOR_iterate (struct GNUNET_SENSOR_Handle *h,
                               struct GNUNET_TIME_Relative timeout,
                               const char *sensor_name,
                               GNUNET_SENSOR_SensorIterateCB callback,
                               void *callback_cls);


/**
 * Cancel a force anomaly request.
 *
 * @param fa Force anomaly context returned by GNUNET_SENSOR_force_anomaly()
 */
void
GNUNET_SENSOR_force_anomaly_cancel (struct GNUNET_SENSOR_ForceAnomalyContext
                                    *fa);


/**
 * Force an anomaly status change on a given sensor. If the sensor reporting
 * module is running, this will trigger the usual reporting logic, therefore,
 * please only use this in a test environment.
 *
 * Also, if the sensor analysis module is running, it might conflict and cause
 * undefined behaviour if it detects a real anomaly.
 *
 * @param h Service handle
 * @param sensor_name Sensor name to set the anomaly status
 * @param anomalous The desired status: #GNUNET_YES / #GNUNET_NO
 * @param cont Continuation function to be called after the request is sent
 * @param cont_cls Closure for cont
 */
struct GNUNET_SENSOR_ForceAnomalyContext *
GNUNET_SENSOR_force_anomaly (struct GNUNET_SENSOR_Handle *h, char *sensor_name,
                             int anomalous, GNUNET_SENSOR_Continuation cont,
                             void *cont_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
