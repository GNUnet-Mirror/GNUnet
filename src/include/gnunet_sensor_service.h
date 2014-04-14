/*
      This file is part of GNUnet
      (C) 

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
 * @file include/gnunet_sensor_service.h
 * @brief API to the sensor service
 * @author Omar Tarabai
 */
#ifndef GNUNET_SENSOR_SERVICE_H
#define GNUNET_SENSOR_SERVICE_H

#include "platform.h"
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
 * Type of an iterator over sensor definitions.
 *
 * @param cls closure
 * @param hello hello message for the peer (can be NULL)
 * @param error message
 */
typedef void (*GNUNET_SENSOR_SensorIteratorCB) (void *cls,
                                             const struct SensorInfoShort *sensor,
                                             const char *err_msg);

/**
 * Continuation called with a status result.
 *
 * @param cls closure
 * @param emsg error message, NULL on success
 */
typedef void (*GNUNET_SENSOR_Continuation)(void *cls,
               const char *emsg);

/**
 * Connect to the sensor service.
 *
 * @return NULL on error
 */
struct GNUNET_SENSOR_Handle *
GNUNET_SENSOR_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
