/*
      This file is part of GNUnet
      (C) 2012-2013 Christian Grothoff (and other contributing authors)

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
 * @file sensor/sensor.h
 * @brief IPC messages and private service declarations
 * @author Omar Tarabai
 */

#include "gnunet_sensor_service.h"
#include "gnunet_sensor_util_lib.h"


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Carries a summary of a sensor
 *
 */
struct SensorInfoMessage
{
  /**
   * Message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Length of sensor name (name follows the struct)
   */
  size_t name_len;

  /**
   * First part of version number
   */
  uint16_t version_major;

  /**
   * Second part of version number
   */
  uint16_t version_minor;

  /**
   * Length of sensor description (description itself follows)
   */
  size_t description_len;
};

GNUNET_NETWORK_STRUCT_END

/*
 * Stop the sensor analysis module
 */
void SENSOR_analysis_stop();

/*
 * Start the sensor analysis module
 *
 * @param c our service configuration
 * @param sensors_mhm multihashmap of loaded sensors
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_analysis_start(const struct GNUNET_CONFIGURATION_Handle *c,
    struct GNUNET_CONTAINER_MultiHashMap *sensors_mhm);

/**
 * Stop sensor reporting module
 */
void SENSOR_reporting_stop();

/**
 * Start the sensor reporting module
 *
 * @param c our service configuration
 * @param sensors multihashmap of loaded sensors
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_reporting_start(const struct GNUNET_CONFIGURATION_Handle *c,
    struct GNUNET_CONTAINER_MultiHashMap *sensors);

/**
 * Stop the sensor update module
 */
void
SENSOR_update_stop ();

/**
 * Start the sensor update module
 *
 * @param c our service configuration
 * @param sensors multihashmap of loaded sensors
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_update_start (const struct GNUNET_CONFIGURATION_Handle *c,
                     struct GNUNET_CONTAINER_MultiHashMap *sensors);

