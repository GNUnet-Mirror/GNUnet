/*
      This file is part of GNUnet
      Copyright (C) 2012-2013 Christian Grothoff (and other contributing authors)

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
   * Length of sensor name. Allocated at position 0 after this struct.
   */
  uint16_t name_len;

  /**
   * First part of version number
   */
  uint16_t version_major;

  /**
   * Second part of version number
   */
  uint16_t version_minor;

  /**
   * Length of sensor description. Allocated at position 1 after this struct.
   */
  uint16_t description_len;
};

/**
 * A message sent to the sensor service to force an anomaly status on a sensor.
 */
struct ForceAnomalyMessage
{

  /**
   * Message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Hash of the sensor name
   */
  struct GNUNET_HashCode sensor_name_hash;

  /**
   * New status
   */
  uint16_t anomalous;

};

GNUNET_NETWORK_STRUCT_END
/**
 * Stop the sensor analysis module
 */
    void
SENSOR_analysis_stop ();


/**
 * Start the sensor analysis module
 *
 * @param c our service configuration
 * @param sensors multihashmap of loaded sensors
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_analysis_start (const struct GNUNET_CONFIGURATION_Handle *c,
                       struct GNUNET_CONTAINER_MultiHashMap *s);


/**
 * Stop sensor anomaly reporting module
 */
void
SENSOR_reporting_stop ();

/**
 * Used by the analysis module to tell the reporting module about a change in
 * the anomaly status of a sensor.
 *
 * @param sensor Related sensor
 * @param anomalous The new sensor anomalous status
 */
void
SENSOR_reporting_anomaly_update (struct GNUNET_SENSOR_SensorInfo *sensor,
                                 int anomalous);


/**
 * Start the sensor anomaly reporting module
 *
 * @param c our service configuration
 * @param s multihashmap of loaded sensors
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_reporting_start (const struct GNUNET_CONFIGURATION_Handle *c,
                        struct GNUNET_CONTAINER_MultiHashMap *s);


/**
 * Stop the sensor update module
 */
void
SENSOR_update_stop ();


/**
 * Start the sensor update module
 *
 * @param c our service configuration
 * @param s multihashmap of loaded sensors
 * @param cb callback to reset service components when we have new updates
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_update_start (const struct GNUNET_CONFIGURATION_Handle *c,
                     struct GNUNET_CONTAINER_MultiHashMap *s, void (*cb) ());


/**
 * Stop the sensor monitoring module
 */
void
SENSOR_monitoring_stop ();


/**
 * Start the sensor monitoring module
 *
 * @param c our service configuration
 * @param sensors multihashmap of loaded sensors
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_monitoring_start (const struct GNUNET_CONFIGURATION_Handle *c,
                         struct GNUNET_CONTAINER_MultiHashMap *s);
