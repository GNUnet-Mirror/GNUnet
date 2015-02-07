/*
     This file is part of GNUnet.
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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file sensor/gnunet-service-sensor.c
 * @brief sensor service implementation
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "sensor.h"

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Path to sensor definitions directory
 */
static char *sensor_dir;

/**
 * Hashmap of loaded sensor definitions
 */
static struct GNUNET_CONTAINER_MultiHashMap *sensors;

/**
 * Start the monitoring module ?
 */
static int start_monitoring;

/**
 * Start the analysis module ?
 */
static int start_analysis;

/**
 * Start the reporting module ?
 */
static int start_reporting;

/**
 * Start the update module ?
 */
static int start_update;


/**
 * Resets the service by stopping components, reloading sensors and starting
 * components. This is needed when we receive new sensor updates.
 */
static void
reset ();


/**
 * Stops components and destroys sensors
 */
static void
stop ()
{
  if (GNUNET_YES == start_update)
    SENSOR_update_stop ();
  if (GNUNET_YES == start_analysis)
    SENSOR_analysis_stop ();
  if (GNUNET_YES == start_reporting)
    SENSOR_reporting_stop ();
  if (GNUNET_YES == start_monitoring)
    SENSOR_monitoring_stop ();
  GNUNET_SENSOR_destroy_sensors (sensors);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  stop ();
  if (NULL != sensor_dir)
  {
    GNUNET_free (sensor_dir);
    sensor_dir = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Handle a force anomaly request from client.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_anomaly_force (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  struct ForceAnomalyMessage *anomaly_msg;
  struct GNUNET_SENSOR_SensorInfo *sensor;

  anomaly_msg = (struct ForceAnomalyMessage *) message;
  sensor =
      GNUNET_CONTAINER_multihashmap_get (sensors,
                                         &anomaly_msg->sensor_name_hash);
  if (NULL == sensor)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Force anomaly message received for a sensor we don't have.\n");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  SENSOR_reporting_anomaly_update (sensor, ntohs (anomaly_msg->anomalous));
  GNUNET_SERVER_receive_done (client, GNUNET_YES);
}


/**
 * Creates a structure with basic sensor info to be sent to a client.
 *
 * @param sensor sensor information
 * @return message ready to be sent to client
 */
static struct SensorInfoMessage *
create_sensor_info_msg (struct GNUNET_SENSOR_SensorInfo *sensor)
{
  struct SensorInfoMessage *msg;
  uint16_t len;
  size_t name_len;
  size_t desc_len;
  char *str_ptr;

  name_len = strlen (sensor->name);
  if (NULL == sensor->description)
    desc_len = 0;
  else
    desc_len = strlen (sensor->description) + 1;
  len = 0;
  len += sizeof (struct SensorInfoMessage);
  len += name_len;
  len += desc_len;
  msg = GNUNET_malloc (len);
  msg->header.size = htons (len);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SENSOR_INFO);
  msg->name_len = htons (name_len);
  msg->description_len = htons (desc_len);
  msg->version_major = htons (sensor->version_major);
  msg->version_minor = htons (sensor->version_minor);
  str_ptr = (char *) &msg[1];
  memcpy (str_ptr, sensor->name, name_len);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending sensor name (%d): %.*s\n",
              name_len, name_len, str_ptr);
  str_ptr += name_len;
  memcpy (str_ptr, sensor->description, desc_len);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending sensor description (%d): %.*s\n", desc_len, desc_len,
              str_ptr);
  return msg;
}


/**
 * Handle GET SENSOR message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_get_sensor (void *cls, struct GNUNET_SERVER_Client *client,
                   const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVER_TransmitContext *tc;
  char *sensorname;
  size_t sensorname_len;
  struct GNUNET_HashCode key;
  struct GNUNET_SENSOR_SensorInfo *sensorinfo;
  struct SensorInfoMessage *msg;

  sensorname = (char *) &message[1];
  sensorname_len = ntohs (message->size) - sizeof (struct GNUNET_MessageHeader);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "`%s' message received for sensor (%d) `%.*s'\n", "GET SENSOR",
              sensorname_len, sensorname_len, sensorname);
  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_CRYPTO_hash (sensorname, sensorname_len, &key);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Created key hash for requested sensor\n");
  sensorinfo =
      (struct GNUNET_SENSOR_SensorInfo *)
      GNUNET_CONTAINER_multihashmap_get (sensors, &key);
  if (NULL != sensorinfo)
  {
    msg = create_sensor_info_msg (sensorinfo);
    GNUNET_SERVER_transmit_context_append_message (tc,
                                                   (struct GNUNET_MessageHeader
                                                    *) msg);
    GNUNET_free (msg);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Requested sensor `%.*s' was not found\n", sensorname_len,
                sensorname);
  GNUNET_SERVER_transmit_context_append_data (tc, NULL, 0,
                                              GNUNET_MESSAGE_TYPE_SENSOR_END);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Iterator for sensors and adds them to transmit context
 *
 * @param cls a `struct GNUNET_SERVER_TransmitContext *`
 * @param key hash of sensor name, key to hashmap
 * @param value a `struct GNUNET_SENSOR_SensorInfo *`
 */
static int
add_sensor_to_tc (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_SERVER_TransmitContext *tc = cls;
  struct GNUNET_SENSOR_SensorInfo *sensorinfo = value;
  struct SensorInfoMessage *msg;

  msg = create_sensor_info_msg (sensorinfo);
  GNUNET_SERVER_transmit_context_append_message (tc,
                                                 (struct GNUNET_MessageHeader *)
                                                 msg);

  GNUNET_free (msg);
  return GNUNET_YES;
}


/**
 * Handle GET ALL SENSORS message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_get_all_sensors (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVER_TransmitContext *tc;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "`%s' message received.\n",
              "GET ALL SENSOR");
  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_CONTAINER_multihashmap_iterate (sensors, &add_sensor_to_tc, tc);
  GNUNET_SERVER_transmit_context_append_data (tc, NULL, 0,
                                              GNUNET_MESSAGE_TYPE_SENSOR_END);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Loads sensors and starts different service components
 */
static void
start ()
{
  sensors = GNUNET_SENSOR_load_all_sensors (sensor_dir);
  if (GNUNET_YES == start_monitoring)
    SENSOR_monitoring_start (cfg, sensors);
  if (GNUNET_YES == start_reporting)
    SENSOR_reporting_start (cfg, sensors);
  if (GNUNET_YES == start_analysis)
    SENSOR_analysis_start (cfg, sensors);
  if (GNUNET_YES == start_update)
    SENSOR_update_start (cfg, sensors, &reset);
}


/**
 * Process statistics requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_get_sensor, NULL, GNUNET_MESSAGE_TYPE_SENSOR_GET,
     0},
    {&handle_get_all_sensors, NULL, GNUNET_MESSAGE_TYPE_SENSOR_GETALL,
     sizeof (struct GNUNET_MessageHeader)},
    {
     &handle_anomaly_force, NULL, GNUNET_MESSAGE_TYPE_SENSOR_ANOMALY_FORCE,
     sizeof (struct ForceAnomalyMessage)},
    {NULL, NULL, 0, 0}
  };

  cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "sensor", "SENSOR_DIR",
                                               &sensor_dir))
  {
    sensor_dir = GNUNET_SENSOR_get_default_sensor_dir ();
  }
  start_monitoring = GNUNET_YES;
  start_analysis = GNUNET_YES;
  start_reporting = GNUNET_YES;
  start_update = GNUNET_YES;
  if (GNUNET_NO ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "sensor", "START_MONITORING"))
  {
    start_monitoring = GNUNET_NO;
  }
  if (GNUNET_NO ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "sensor", "START_REPORTING"))
  {
    start_reporting = GNUNET_NO;
  }
  if (GNUNET_NO ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "sensor", "START_ANALYSIS"))
  {
    start_analysis = GNUNET_NO;
  }
  if (GNUNET_NO ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "sensor", "START_UPDATE"))
  {
    start_update = GNUNET_NO;
  }
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  start ();
}


/**
 * Resets the service by stopping components, reloading sensors and starting
 * components. This is needed when we receive new sensor updates.
 */
static void
reset ()
{
  stop ();
  start ();
}


/**
 * The main function for the sensor service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "sensor", GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-sensor.c */
