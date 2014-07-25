/*
     This file is part of GNUnet.
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
 * @file sensor/gnunet-service-sensor.c
 * @brief sensor service implementation
 * @author Omar Tarabai
 */
#include <inttypes.h>
#include "platform.h"
#include "gnunet_util_lib.h"
#include "sensor.h"
#include "gnunet_statistics_service.h"
#include "gnunet_peerstore_service.h"

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Hashmap of loaded sensor definitions
 */
static struct GNUNET_CONTAINER_MultiHashMap *sensors;

/**
 * Handle to statistics service
 */
struct GNUNET_STATISTICS_Handle *statistics;

/**
 * Handle to peerstore service
 */
struct GNUNET_PEERSTORE_Handle *peerstore;

/**
 * Service name
 */
char *subsystem = "sensor";

/**
 * My peer id
 */
struct GNUNET_PeerIdentity peerid;

/**
 * Change the state of the sensor.
 * Write the change to file to make it persistent.
 *
 * @param sensor sensor info struct
 * @param state new enabled state: #GNUNET_YES / #GNUNET_NO
 */
static void
set_sensor_enabled (struct GNUNET_SENSOR_SensorInfo *sensor, int state)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Sensor `%s': Setting enabled to %d.\n",
             sensor->name, state);
  sensor->enabled = GNUNET_NO;
  GNUNET_assert (NULL != sensor->cfg);
  GNUNET_CONFIGURATION_set_value_string (sensor->cfg,
                                         sensor->name,
                                         "ENABLED",
                                         (GNUNET_YES == state) ? "YES" : "NO");
  GNUNET_CONFIGURATION_write (sensor->cfg, sensor->def_file);
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  SENSOR_update_stop ();
  SENSOR_reporting_stop ();
  SENSOR_analysis_stop ();
  GNUNET_SENSOR_destroy_sensors (sensors);
  if (NULL != statistics)
  {
    GNUNET_STATISTICS_destroy (statistics, GNUNET_YES);
    statistics = NULL;
  }
  if (NULL != peerstore)
  {
    GNUNET_PEERSTORE_disconnect (peerstore, GNUNET_YES);
    peerstore = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
                          struct GNUNET_SERVER_Client *client)
{
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

  name_len = strlen(sensor->name);
  if(NULL == sensor->description)
    desc_len = 0;
  else
    desc_len = strlen(sensor->description) + 1;
  len = 0;
  len += sizeof(struct SensorInfoMessage);
  len += name_len;
  len += desc_len;
  msg = GNUNET_malloc(len);
  msg->header.size = htons(len);
  msg->header.type = htons(GNUNET_MESSAGE_TYPE_SENSOR_INFO);
  msg->name_len = htons(name_len);
  msg->description_len = htons(desc_len);
  msg->version_major = htons(sensor->version_major);
  msg->version_minor = htons(sensor->version_minor);
  str_ptr = (char*) &msg[1];
  memcpy(str_ptr, sensor->name, name_len);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Sending sensor name (%d): %.*s\n",
        name_len, name_len, str_ptr);
  str_ptr += name_len;
  memcpy(str_ptr, sensor->description, desc_len);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Sending sensor description (%d): %.*s\n",
          desc_len, desc_len, str_ptr);

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
handle_get_sensor (void *cls,
                   struct GNUNET_SERVER_Client *client,
                   const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVER_TransmitContext *tc;
  char *sensorname;
  size_t sensorname_len;
  struct GNUNET_HashCode key;
  struct GNUNET_SENSOR_SensorInfo *sensorinfo;
  struct SensorInfoMessage *msg;

  sensorname = (char *)&message[1];
  sensorname_len = ntohs(message->size) - sizeof(struct GNUNET_MessageHeader);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "`%s' message received for sensor (%d) `%.*s'\n",
              "GET SENSOR", sensorname_len, sensorname_len, sensorname);
  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_CRYPTO_hash(sensorname, sensorname_len, &key);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Created key hash for requested sensor\n");
  sensorinfo = (struct GNUNET_SENSOR_SensorInfo *)GNUNET_CONTAINER_multihashmap_get(sensors, &key);
  if(NULL != sensorinfo)
  {
    msg = create_sensor_info_msg(sensorinfo);
    GNUNET_SERVER_transmit_context_append_message(tc, (struct GNUNET_MessageHeader *)msg);
    GNUNET_free(msg);
  }
  else
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Requested sensor `%.*s' was not found\n",
        sensorname_len, sensorname);
  GNUNET_SERVER_transmit_context_append_data(tc, NULL, 0, GNUNET_MESSAGE_TYPE_SENSOR_END);
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
add_sensor_to_tc (void *cls,
                  const struct GNUNET_HashCode *key,
                  void *value)
{
  struct GNUNET_SERVER_TransmitContext *tc = cls;
  struct GNUNET_SENSOR_SensorInfo *sensorinfo = value;
  struct SensorInfoMessage *msg;

  msg = create_sensor_info_msg(sensorinfo);
  GNUNET_SERVER_transmit_context_append_message(tc, (struct GNUNET_MessageHeader *)msg);

  GNUNET_free(msg);

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
  GNUNET_CONTAINER_multihashmap_iterate(sensors, &add_sensor_to_tc, tc);
  GNUNET_SERVER_transmit_context_append_data(tc, NULL, 0, GNUNET_MESSAGE_TYPE_SENSOR_END);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}

/**
 * Do a series of checks to determine if sensor should execute
 *
 * @return #GNUNET_YES / #GNUNET_NO
 */
static int
should_run_sensor(struct GNUNET_SENSOR_SensorInfo *sensorinfo)
{
  struct GNUNET_TIME_Absolute now;

  if(GNUNET_NO == sensorinfo->enabled)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Sensor `%s' is disabled, will not run\n", sensorinfo->name);
    return GNUNET_NO;
  }
  now = GNUNET_TIME_absolute_get();
  if(NULL != sensorinfo->start_time
      && now.abs_value_us < sensorinfo->start_time->abs_value_us)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Start time for sensor `%s' not reached yet, will not run\n", sensorinfo->name);
    return GNUNET_NO;
  }
  if(NULL != sensorinfo->end_time
      && now.abs_value_us >= sensorinfo->end_time->abs_value_us)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Sensor `%s' expired, disabling.\n", sensorinfo->name);
    set_sensor_enabled(sensorinfo, GNUNET_NO);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}

/**
 * Callback function to process statistic values
 *
 * @param cls `struct GNUNET_SENSOR_SensorInfo *`
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent #GNUNET_YES if the value is persistent, #GNUNET_NO if not
 * @return #GNUNET_OK to continue, #GNUNET_SYSERR to abort iteration
 */
static int
sensor_statistics_iterator (void *cls,
                            const char *ss,
                            const char *name,
                            uint64_t value,
                            int is_persistent)
{
  struct GNUNET_SENSOR_SensorInfo *sensorinfo = cls;
  double dvalue = (double)value;
  struct GNUNET_TIME_Absolute expiry;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Received a value for sensor `%s': %" PRIu64 "\n", sensorinfo->name, value);
  expiry = GNUNET_TIME_relative_to_absolute(sensorinfo->lifetime);
  GNUNET_PEERSTORE_store(peerstore,
      subsystem,
      &peerid,
      sensorinfo->name,
      &dvalue,
      sizeof(dvalue),
      expiry,
      GNUNET_PEERSTORE_STOREOPTION_MULTIPLE,
      NULL,
      NULL);
  return GNUNET_SYSERR; /* We only want one value */
}

/**
 * Continuation called after sensor gets all gnunet statistics values
 *
 * @param cls `struct GNUNET_SENSOR_SensorInfo *`
 * @param success #GNUNET_OK if statistics were
 *        successfully obtained, #GNUNET_SYSERR if not.
 */
static void
end_sensor_run_stat (void *cls, int success)
{
  struct GNUNET_SENSOR_SensorInfo *sensorinfo = cls;

  sensorinfo->gnunet_stat_get_handle = NULL;
  sensorinfo->running = GNUNET_NO;
}

/**
 * Tries to parse a received sensor value to its
 * expected datatype
 *
 * @param value the string value received, should be null terminated
 * @param sensor sensor information struct
 * @param ret pointer to parsed value
 * @return size of new parsed value, 0 for error
 */
static size_t
parse_sensor_value (const char *value,
                    struct GNUNET_SENSOR_SensorInfo *sensor,
                    void **ret)
{
  double *dval;
  char *endptr;

  *ret = NULL;
  if ('\0' == *value)
    return 0;
  if(0 == strcmp("numeric", sensor->expected_datatype))
  {
    dval = GNUNET_new(double);
    *dval = strtod(value, &endptr);
    if(value == endptr)
      return 0;
   *ret = dval;
   return sizeof(double);
  }
  if(0 == strcmp("string", sensor->expected_datatype))
  {
    *ret = GNUNET_strdup(value);
    return strlen(value) + 1;
  }
  GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
      _("Unknown value type expected by sensor, this should not happen.\n"));
  return 0;
}

/**
 * Callback for output of executed sensor process
 *
 * @param cls `struct GNUNET_SENSOR_SensorInfo *`
 * @param line line of output from a command, NULL for the end
 */
static void
sensor_process_callback (void *cls, const char *line)
{
  struct GNUNET_SENSOR_SensorInfo *sensorinfo = cls;
  void *value;
  size_t valsize;
  struct GNUNET_TIME_Absolute expiry;

  if(NULL == line)
  {
    GNUNET_OS_command_stop(sensorinfo->ext_cmd);
    sensorinfo->ext_cmd = NULL;
    sensorinfo->running = GNUNET_NO;
    sensorinfo->ext_cmd_value_received = GNUNET_NO;
    return;
  }
  if(GNUNET_YES == sensorinfo->ext_cmd_value_received)
    return; /* We only want one *valid* value */
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Received a value for sensor `%s': %s\n", sensorinfo->name, line);
  valsize = parse_sensor_value(line, sensorinfo, &value);
  if (valsize == 0) /* invalid value, FIXME: should we disable the sensor now? */
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        _("Received an invalid value for sensor `%s': %s\n"),
        sensorinfo->name, line);
  }
  else
  {
    sensorinfo->ext_cmd_value_received = GNUNET_YES;
    expiry = GNUNET_TIME_relative_to_absolute(sensorinfo->lifetime);
    GNUNET_PEERSTORE_store(peerstore,
        subsystem,
        &peerid,
        sensorinfo->name,
        value,
        valsize,
        expiry,
        GNUNET_PEERSTORE_STOREOPTION_MULTIPLE,
        NULL,
        NULL);
    GNUNET_free (value);
  }
}

/**
 * Checks if the given file is a path
 *
 * @return #GNUNET_YES / #GNUNET_NO
 */
static int
is_path(char *filename)
{
  size_t filename_len;
  int i;

  filename_len = strlen(filename);
  for(i = 0; i < filename_len; i++)
  {
    if(DIR_SEPARATOR == filename[i])
      return GNUNET_YES;
  }
  return GNUNET_NO;
}

/**
 * Actual execution of a sensor
 *
 * @param cls 'struct SensorInfo'
 * @param tc unsed
 */
static void
sensor_run (void *cls,
            const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct GNUNET_SENSOR_SensorInfo *sensorinfo = cls;
  int check_result;
  char *sensors_dir;
  char *process_path;

  sensorinfo->execution_task = GNUNET_SCHEDULER_add_delayed(sensorinfo->interval, &sensor_run, sensorinfo);
  if(GNUNET_YES == sensorinfo->running) //FIXME: should we try to kill?
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Sensor `%s' running for too long, will try again next interval\n", sensorinfo->name);
    return;
  }
  if(GNUNET_NO == should_run_sensor(sensorinfo))
    return;
  sensorinfo->running = GNUNET_YES;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Starting the execution of sensor `%s'\n", sensorinfo->name);
  if(0 == strcmp ("gnunet-statistics", sensorinfo->source))
  {
    sensorinfo->gnunet_stat_get_handle = GNUNET_STATISTICS_get(statistics,
        sensorinfo->gnunet_stat_service,
        sensorinfo->gnunet_stat_name,
        sensorinfo->interval, //try to get values only for the interval of the sensor
        &end_sensor_run_stat,
        &sensor_statistics_iterator,
        sensorinfo);
  }
  else if(0 == strcmp ("process", sensorinfo->source))
  {
    if(GNUNET_YES == is_path(sensorinfo->ext_process))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
          _("Sensor `%s': External process should not be a path, disabling sensor.\n"),
          sensorinfo->name);
      set_sensor_enabled(sensorinfo, GNUNET_NO);
      return;
    }
    //check if the process exists in $PATH
    process_path = GNUNET_strdup(sensorinfo->ext_process);
    check_result =
        GNUNET_OS_check_helper_binary(process_path, GNUNET_NO, NULL);
    if(GNUNET_SYSERR == check_result)
    {
      //search in sensor directory
      sensors_dir = GNUNET_SENSOR_get_sensor_dir ();
      GNUNET_free(process_path);
      GNUNET_asprintf(&process_path,
                      "%s%s-files%s%s",
                      sensors_dir,
                      sensorinfo->name,
                      DIR_SEPARATOR_STR,
                      sensorinfo->ext_process);
      GNUNET_free(sensors_dir);
      check_result =
        GNUNET_OS_check_helper_binary(process_path, GNUNET_NO, NULL);
    }
    if(GNUNET_SYSERR == check_result)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
          _("Sensor `%s' process `%s' problem: binary doesn't exist or not executable\n"),
          sensorinfo->name,
          sensorinfo->ext_process);
      set_sensor_enabled(sensorinfo, GNUNET_NO);
      sensorinfo->running = GNUNET_NO;
      GNUNET_free(process_path);
      return;
    }
    sensorinfo->ext_cmd_value_received = GNUNET_NO;
    sensorinfo->ext_cmd = GNUNET_OS_command_run(&sensor_process_callback,
        sensorinfo,
        GNUNET_TIME_UNIT_FOREVER_REL,
        process_path,
        sensorinfo->ext_process,
        sensorinfo->ext_args,
        NULL);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Process started for sensor `%s'\n", sensorinfo->name);
    GNUNET_free(process_path);
  }
  else
  {
    sensorinfo->running = GNUNET_NO;
    GNUNET_break(0); //shouldn't happen
  }
}

/**
 * Starts the execution of a sensor
 *
 * @param cls unused
 * @param key hash of sensor name, key to hashmap (unused)
 * @param value a `struct GNUNET_SENSOR_SensorInfo *`
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
schedule_sensor (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_SENSOR_SensorInfo *sensorinfo = value;

  if(GNUNET_NO == should_run_sensor(sensorinfo))
    return GNUNET_YES;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Scheduling sensor `%s' to run after %" PRIu64 " microseconds\n",
      sensorinfo->name, sensorinfo->interval.rel_value_us);
  if(GNUNET_SCHEDULER_NO_TASK != sensorinfo->execution_task)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
        _("Sensor `%s' execution task already set, this should not happen\n"), sensorinfo->name);
    return GNUNET_NO;
  }
  sensorinfo->execution_task = GNUNET_SCHEDULER_add_delayed(sensorinfo->interval, &sensor_run, sensorinfo);
  return GNUNET_YES;
}

/**
 * Starts the execution of all enabled sensors
 *
 */
static void
schedule_all_sensors()
{
  GNUNET_CONTAINER_multihashmap_iterate(sensors, &schedule_sensor, NULL);
}

/**
 * Process statistics requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_get_sensor, NULL, GNUNET_MESSAGE_TYPE_SENSOR_GET,
     0},
    {&handle_get_all_sensors, NULL, GNUNET_MESSAGE_TYPE_SENSOR_GETALL,
     sizeof (struct GNUNET_MessageHeader)},
    {NULL, NULL, 0, 0}
  };

  cfg = c;
  sensors = GNUNET_SENSOR_load_all_sensors ();
  schedule_all_sensors();
  SENSOR_analysis_start(c, sensors);
  SENSOR_reporting_start(c, sensors);
  SENSOR_update_start (c, sensors);
  statistics = GNUNET_STATISTICS_create("sensor", cfg);
  GNUNET_CRYPTO_get_peer_identity(cfg, &peerid);
  peerstore = GNUNET_PEERSTORE_connect(cfg);
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server, 
           &handle_client_disconnect,
           NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
        &shutdown_task,
        NULL);
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
          GNUNET_SERVICE_run (argc,
                              argv,
                              "sensor",
            GNUNET_SERVICE_OPTION_NONE,
            &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-sensor.c */
