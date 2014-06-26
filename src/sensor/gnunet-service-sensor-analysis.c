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
 * @file sensor/gnunet-service-sensor-analysis.c
 * @brief sensor service analysis functionality
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "sensor.h"
#include "gnunet_peerstore_service.h"

#define LOG(kind,...) GNUNET_log_from (kind, "sensor-analysis",__VA_ARGS__)

/*
 * Carries information about the analysis model
 * corresponding to one sensor
 */
struct SensorModel
{

  /*
   * Pointer to sensor info structure
   */
  struct SensorInfo *sensor;

  /*
   * Watcher of sensor values
   */
  struct GNUNET_PEERSTORE_WatchContext *wc;

};

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/*
 * Model library name
 */
static char *model_lib_name;

/*
 * Model handle
 */
static struct GNUNET_SENSOR_ModelFunctions *model;

/**
 * Hashmap of loaded sensor definitions
 */
static struct GNUNET_CONTAINER_MultiHashMap *sensors;

/*
 * Handle to peerstore service
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;

/*
 * Datatypes supported by the analysis component
 */
static const char *analysis_datatypes[] = { "uint64", "double", NULL };

/*
 * MultiHashmap of all sensor models
 */
static struct GNUNET_CONTAINER_MultiHashMap *sensor_models;

/**
 * My peer id
 */
struct GNUNET_PeerIdentity peerid;

/*
 * TODO: document
 */
static int
destroy_sensor_model (void *cls,
    const struct GNUNET_HashCode *key,
    void *value)
{
  struct SensorModel *sensor_model = value;

  if (NULL == sensor_model)
    return GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Destroying sensor model for `%s'.\n",
        sensor_model->sensor->name);
  if (NULL != sensor_model->wc)
  {
    GNUNET_PEERSTORE_watch_cancel(sensor_model->wc);
    sensor_model->wc = NULL;
  }
  return GNUNET_YES;
}

/*
 * Stop the sensor analysis module
 */
void SENSOR_analysis_stop()
{

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Stopping sensor analysis module.\n");
  if (NULL != model)
  {
    GNUNET_break (NULL == GNUNET_PLUGIN_unload (model_lib_name, model));
    GNUNET_free (model_lib_name);
    model_lib_name = NULL;
  }
  if (NULL != sensor_models)
  {
    GNUNET_CONTAINER_multihashmap_iterate(sensor_models, &destroy_sensor_model, NULL);
    GNUNET_CONTAINER_multihashmap_destroy(sensor_models);
    sensor_models = NULL;
  }
  if (NULL != peerstore)
  {
    GNUNET_PEERSTORE_disconnect(peerstore);
    peerstore = NULL;
  }
}

/*
 * TODO: document
 */
static int
sensor_watcher (void *cls,
    struct GNUNET_PEERSTORE_Record *record,
    char *emsg)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Received a sensor value, will feed to sensor model.\n");
  return GNUNET_YES;
}

/*
 * TODO: document
 */
static int
init_sensor_model (void *cls,
    const struct GNUNET_HashCode *key,
    void *value)
{
  struct SensorInfo *sensor = value;
  struct SensorModel *sensor_model;
  int is_numeric;
  int i;

  is_numeric = GNUNET_NO;
  for (i = 0; NULL != analysis_datatypes[i]; i++)
  {
    if (0 == strcmp (analysis_datatypes[i], sensor->expected_datatype))
    {
      is_numeric = GNUNET_YES;
      break;
    }
  }
  if (GNUNET_NO == is_numeric)
    return GNUNET_YES;
  sensor_model = GNUNET_new(struct SensorModel);
  sensor_model->sensor = sensor;
  sensor_model->wc = GNUNET_PEERSTORE_watch(peerstore,
          "sensor", &peerid, sensor->name,
          &sensor_watcher, sensor_model);
  GNUNET_CONTAINER_multihashmap_put(sensor_models, key,
      sensor_model, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Created sensor model for `%s'.\n", sensor->name);
  return GNUNET_YES;
}

/*
 * Start the sensor analysis module
 *
 * @param c our service configuration
 * @param sensors_mhm multihashmap of loaded sensors
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_analysis_start(const struct GNUNET_CONFIGURATION_Handle *c,
    struct GNUNET_CONTAINER_MultiHashMap *sensors_mhm)
{
  char *model_name;

  cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "sensor-analysis", "MODEL",
                                                 &model_name))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Analysis model not defined in configuration.\n"));
    return GNUNET_SYSERR;
  }
  GNUNET_asprintf (&model_lib_name, "libgnunet_plugin_sensor_model_%s", model_name);
  model = GNUNET_PLUGIN_load(model_lib_name, (void *) cfg);
  GNUNET_free(model_name);
  if(NULL == model)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Could not load analysis model `%s'.\n"), model_lib_name);
    return GNUNET_SYSERR;
  }
  sensors = sensors_mhm;
  if (NULL == sensors)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Tried to start analysis before loading sensors.\n"));
    SENSOR_analysis_stop();
    return GNUNET_SYSERR;
  }
  peerstore = GNUNET_PEERSTORE_connect(cfg);
  if (NULL == peerstore)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Could not connect to peerstore service.\n"));
    SENSOR_analysis_stop();
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_get_peer_identity(cfg, &peerid);
  sensor_models = GNUNET_CONTAINER_multihashmap_create(10, GNUNET_NO);
  GNUNET_CONTAINER_multihashmap_iterate(sensors, &init_sensor_model, NULL);

  return GNUNET_OK;
}

/* end of gnunet-service-sensor-analysis.c */
