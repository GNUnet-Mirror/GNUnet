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
 * Structure containing sensor definition
 */
struct SensorInfo
{

  /**
   * The configuration handle
   * carrying sensor information
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /*
   * Sensor name
   */
  char *name;

  /*
   * Path to definition file
   */
  char *def_file;

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

  /*
   * Sensor currently enabled
   */
  int enabled;

  /*
   * Category under which the sensor falls (e.g. tcp, datastore)
   */
  char *category;

  /*
   * When does the sensor become active
   */
  struct GNUNET_TIME_Absolute *start_time;

  /*
   * When does the sensor expire
   */
  struct GNUNET_TIME_Absolute *end_time;

  /*
   * Time interval to collect sensor information (e.g. every 1 min)
   */
  struct GNUNET_TIME_Relative interval;

  /*
   * Lifetime of an information sample after which it is deleted from storage
   * If not supplied, will default to the interval value
   */
  struct GNUNET_TIME_Relative lifetime;

  /*
   * A set of required peer capabilities for the sensor to collect meaningful information (e.g. ipv6)
   */
  char *capabilities;

  /*
   * Either "gnunet-statistics" or external "process"
   */
  char *source;

  /*
   * Name of the GNUnet service that is the source for the gnunet-statistics entry
   */
  char *gnunet_stat_service;

  /*
   * Name of the gnunet-statistics entry
   */
  char *gnunet_stat_name;

  /**
   * Handle to statistics get request (OR GNUNET_SCHEDULER_NO_TASK)
   */
  struct GNUNET_STATISTICS_GetHandle *gnunet_stat_get_handle;

  /*
   * Name of the external process to be executed
   */
  char *ext_process;

  /*
   * Arguments to be passed to the external process
   */
  char *ext_args;

  /*
   * Handle to the external process
   */
  struct GNUNET_OS_CommandHandle *ext_cmd;

  /*
   * Did we already receive a value
   * from the currently running external
   * proccess ? #GNUNET_YES / #GNUNET_NO
   */
  int ext_cmd_value_received;

  /*
   * The output datatype to be expected
   */
  char *expected_datatype;

  /*
   * Peer-identity of peer running collection point
   */
  struct GNUNET_PeerIdentity *collection_point;

  /*
   * Time interval to send sensor information to collection point (e.g. every 30 mins)
   */
  struct GNUNET_TIME_Relative collection_interval;

  /*
   * Flag specifying if value is to be communicated to the p2p network
   */
  int p2p_report;

  /*
   * Time interval to communicate value to the p2p network
   */
  struct GNUNET_TIME_Relative p2p_interval;

  /*
   * Execution task (OR GNUNET_SCHEDULER_NO_TASK)
   */
  GNUNET_SCHEDULER_TaskIdentifier execution_task;

  /*
   * Is the sensor being executed
   */
  int running;

};

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

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Used to communicate sensor readings to
 * collection points (SENSORDASHBAORD service)
 */
struct GNUNET_SENSOR_Reading
{

  /**
   * Size of the sensor name value, allocated
   * at position 0 after this struct
   */
  size_t sensorname_size;

  /**
   * First part of sensor version number
   */
  uint16_t sensorversion_major;

  /**
   * Second part of sensor version number
   */
  uint16_t sensorversion_minor;

  /**
   * Timestamp of recorded reading
   */
  uint64_t timestamp;

  /**
   * Size of reading value, allocation
   * at poistion 1 after this struct
   */
  size_t value_size;

};
GNUNET_NETWORK_STRUCT_END

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

/**
 * Disconnect from the sensor service
 *
 * @param h handle to disconnect
 */
void
GNUNET_SENSOR_disconnect(struct GNUNET_SENSOR_Handle *h);

/**
 * Client asking to iterate all available sensors
 *
 * @param h Handle to SENSOR service
 * @param timeout how long to wait until timing out
 * @param sensorname information on one sensor only, can be NULL to get all
 * @param sensorname_len length of the sensorname parameter
 * @param callback the method to call for each sensor
 * @param callback_cls closure for callback
 * @return iterator context
 */
struct GNUNET_SENSOR_SensorIteratorContext *
GNUNET_SENSOR_iterate_sensors (struct GNUNET_SENSOR_Handle *h,
    struct GNUNET_TIME_Relative timeout,
    const char* sensorname, size_t sensorname_len,
    GNUNET_SENSOR_SensorIteratorCB callback, void *callback_cls);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
