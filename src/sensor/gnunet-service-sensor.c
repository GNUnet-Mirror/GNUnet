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
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "sensor.h"

/**
 * Structure containing sensor definition
 */
struct SensorInfo
{

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
  struct GNUNET_TIME_Relative *interval;

  /*
   * Lifetime of an information sample after which it is deleted from storage
   */
  struct GNUNET_TIME_Relative *lifetime;

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

  /*
   * Name of the external process to be executed
   */
  char *ext_process;

  /*
   * Arguments to be passed to the external process
   */
  char *ext_args;

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
  struct GNUNET_TIME_Relative *collection_interval;

  /*
   * Flag specifying if value is to be communicated to the p2p network
   */
  int p2p_report;

  /*
   * Time interval to communicate value to the p2p network
   */
  struct GNUNET_TIME_Relative *p2p_interval;

};

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Hashmap of loaded sensor definitions
 */
struct GNUNET_CONTAINER_MultiHashMap *sensors;

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
}


/**
 * A client disconnected.  Remove all of its data structure entries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
			  struct GNUNET_SERVER_Client
			  * client)
{
}

/**
 * Parses a version number string into major and minor
 *
 * @param version full version string
 * @param major pointer to parsed major value
 * @param minor pointer to parsed minor value
 * @return #GNUNET_OK if parsing went ok, #GNUNET_SYSERROR in case of error
 */
static int
version_parse(char *version, uint16_t *major, uint16_t *minor)
{
  int majorval = 0;
  int minorval = 0;

  for(; isdigit(*version); version++)
  {
    majorval *= 10;
    majorval += *version - '0';
  }
  if(*version != '.')
    return GNUNET_SYSERR;
  version++;
  for(; isdigit(*version); version++)
  {
    minorval *= 10;
    minorval += *version - '0';
  }
  if(*version != 0)
    return GNUNET_SYSERR;
  *major = majorval;
  *minor = minorval;

  return GNUNET_OK;
}

/**
 * Load sensor definition from configuration
 *
 * @param cfg configuration handle
 * @param sectionname configuration section containing definition
 */
static struct SensorInfo *
load_sensor_from_cfg(struct GNUNET_CONFIGURATION_Handle *cfg, char *sectionname)
{
  struct SensorInfo *sensor;
  char *versionstr;

  sensor = GNUNET_new(struct SensorInfo);
  //name
  sensor->name = GNUNET_strdup(sectionname);
  //version
  if(GNUNET_OK != GNUNET_CONFIGURATION_get_value_string(cfg, sectionname, "VERSION", &versionstr) ||
      NULL == versionstr)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Error reading sensor version\n"));
    GNUNET_free(sensor);
    return NULL;
  }
  if(GNUNET_OK != version_parse(versionstr, &(sensor->version_major), &(sensor->version_minor)))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Invalid sensor version number, format should be major.minor\n"));
    GNUNET_free(sensor);
    return NULL;
  }
  //description
  GNUNET_CONFIGURATION_get_value_string(cfg, sectionname, "DESCRIPTION", &sensor->description);
  //category
  if(GNUNET_OK != GNUNET_CONFIGURATION_get_value_string(cfg, sectionname, "CATEGORY", &sensor->category) ||
        NULL == sensor->category)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Error reading sensor category\n"));
    GNUNET_free(sensor);
    return NULL;
  }

  return sensor;
}

/**
 * Load sensor definition from file
 *
 * @param filename full path to file containing sensor definition
 */
static struct SensorInfo *
load_sensor_from_file(const char *filename)
{
  struct GNUNET_CONFIGURATION_Handle *sensorcfg;
  char *filebasename;
  struct SensorInfo *sensor;

  //test file
  if(GNUNET_YES != GNUNET_DISK_file_test(filename))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Failed to access sensor file: %s\n"), filename);
    return NULL;
  }
  //load file as configuration
  sensorcfg = GNUNET_CONFIGURATION_create();
  if(GNUNET_SYSERR == GNUNET_CONFIGURATION_parse(sensorcfg, filename))
  {
    GNUNET_CONFIGURATION_destroy(sensorcfg);
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Failed to load sensor definition: %s\n"), filename);
    return NULL;
  }
  //configuration section should be the same as filename
  filebasename = GNUNET_STRINGS_get_short_name(filename);
  sensor = load_sensor_from_cfg(sensorcfg, filebasename);
  sensor->def_file = GNUNET_strdup(filename);

  GNUNET_CONFIGURATION_destroy(sensorcfg);

  return sensor;
}

/**
 * Compares version numbers of two sensors
 *
 * @param s1 first sensor
 * @param s2 second sensor
 * @return 1: s1 > s2, 0: s1 == s2, -1: s1 < s2
 */
static int
sensor_version_compare(struct SensorInfo *s1, struct SensorInfo *s2)
{
  if(s1->version_major == s2->version_major)
    return (s1->version_minor < s2->version_minor) ? -1 : (s1->version_minor > s2->version_minor);
  else
    return (s1->version_major < s2->version_major) ? -1 : (s1->version_major > s2->version_major);
}

/**
 * Adds a new sensor to given hashmap.
 * If the same name exist, compares versions and update if old.
 *
 * @param sensor Sensor structure to add
 * @param map Hashmap to add to
 * @return #GNUNET_YES if added, #GNUNET_NO if not added which is not necessarily an error
 */
static int
add_sensor_to_hashmap(struct SensorInfo *sensor, struct GNUNET_CONTAINER_MultiHashMap *map)
{
  struct GNUNET_HashCode key;
  struct SensorInfo *existing;

  GNUNET_CRYPTO_hash(sensor->name, sizeof(sensor->name), &key);
  existing = GNUNET_CONTAINER_multihashmap_get(map, &key);
  if(NULL != existing) //sensor with same name already exists
  {
    if(sensor_version_compare(existing, sensor) >= 0) //same or newer version already exist
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Sensor `%s' already exists with same or newer version\n"), sensor->name);
      return GNUNET_NO;
    }
    else
    {
      GNUNET_CONTAINER_multihashmap_remove(map, &key, existing); //remove the old version
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Upgrading sensor `%s' to a newer version\n"), sensor->name);
    }
  }
  if(GNUNET_SYSERR == GNUNET_CONTAINER_multihashmap_put(map, &key, sensor, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Error adding new sensor `%s' to global hashmap, this should not happen\n"), sensor->name);
    return GNUNET_NO;
  }

  return GNUNET_YES;
}

/**
 * Iterating over files in sensors directory
 *
 * @param cls closure
 * @param filename complete filename (absolute path)
 * @return #GNUNET_OK to continue to iterate,
 *  #GNUNET_NO to stop iteration with no error,
 *  #GNUNET_SYSERR to abort iteration with error!
 */
static int
reload_sensors_dir_cb(void *cls, const char *filename)
{
  struct SensorInfo *sensor;

  sensor = load_sensor_from_file(filename);
  if(NULL == sensor)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, _("Error loading sensor from file: %s\n"), filename);
    return GNUNET_OK;
  }
  if(GNUNET_YES == add_sensor_to_hashmap(sensor, sensors))
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Sensor `%s' added to global hashmap\n"), sensor->name);
  else
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, ("Could not add sensor `%s' to global hashmap\n"), sensor->name);

  return GNUNET_OK;
}

/*
 * Get path to the directory containing the sensor definition files
 *
 * @return sensor files directory
 */
static char *
get_sensor_dir()
{
  char* datadir;
  char* sensordir;

  datadir = GNUNET_OS_installation_get_path(GNUNET_OS_IPK_DATADIR);
  GNUNET_asprintf(&sensordir, "%ssensors%s",
      datadir, DIR_SEPARATOR_STR);

  return sensordir;
}

/**
 * Reads sensor definitions from data files
 *
 */
static void
reload_sensors()
{
  char* sensordir;
  int filesfound;

  sensordir = get_sensor_dir();
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Reloading sensor definitions from directory `%s'\n"), sensordir);
  GNUNET_assert(GNUNET_YES == GNUNET_DISK_directory_test(sensordir, GNUNET_YES));

  //read all files in sensors directory
  filesfound = GNUNET_DISK_directory_scan(sensordir, &reload_sensors_dir_cb, NULL);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, _("Loaded %d/%d sensors from directory `%s'\n"),
      GNUNET_CONTAINER_multihashmap_size(sensors), filesfound, sensordir);
}

/**
 * Creates a structure with basic sensor info to be sent to a client
 *
 * @parm sensor sensor information
 * @return message ready to be sent to client
 */
static struct SensorInfoMessage *
create_sensor_info_msg(struct SensorInfo *sensor)
{
  struct SensorInfoMessage *msg;
  uint16_t len;
  size_t name_len;
  size_t desc_len;

  name_len = strlen(sensor->name);
  if(NULL == sensor->description)
    desc_len = 0;
  else
    desc_len = strlen(sensor->description);
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
  memcpy(&msg[1], sensor->name, name_len);
  memcpy((&msg[1]) + name_len, sensor->description, desc_len);

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
  struct SensorInfo *sensorinfo;
  struct SensorInfoMessage *msg;

  sensorname = (char *)&message[1];
  sensorname_len = message->size - sizeof(struct GNUNET_MessageHeader);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "`%s' message received for sensor `%.*s\n",
              "GET SENSOR", sensorname_len, sensorname);
  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_CRYPTO_hash(sensorname, sensorname_len, &key);
  sensorinfo = (struct SensorInfo *)GNUNET_CONTAINER_multihashmap_get(sensors, &key);
  msg = create_sensor_info_msg(sensorinfo);
  GNUNET_SERVER_transmit_context_append_message(tc, (struct GNUNET_MessageHeader *)msg);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);

  GNUNET_free(msg);
}

/**
 * Iterator for sensors and adds them to transmit context
 *
 * @param cls a 'struct GNUNET_SERVER_TransmitContext *'
 * @param key hash of sensor name, key to hashmap
 * @param value a 'struct SensorInfo *'
 */
int add_sensor_to_tc(void *cls,
    const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_SERVER_TransmitContext *tc = cls;
  struct SensorInfo *sensorinfo = value;
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
     sizeof (struct GNUNET_MessageHeader)},
    {&handle_get_all_sensors, NULL, GNUNET_MESSAGE_TYPE_SENSOR_GETALL,
     0},
    {NULL, NULL, 0, 0}
  };

  cfg = c;
  sensors = GNUNET_CONTAINER_multihashmap_create(10, GNUNET_NO);
  reload_sensors();
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
