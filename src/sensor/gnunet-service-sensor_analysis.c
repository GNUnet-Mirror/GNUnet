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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file sensor/gnunet-service-sensor_analysis.c
 * @brief sensor service analysis functionality
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "sensor.h"
#include "gnunet_peerstore_service.h"
#include "gnunet_sensor_model_plugin.h"

#define LOG(kind,...) GNUNET_log_from (kind, "sensor-analysis",__VA_ARGS__)

/**
 * Carries information about the analysis model
 * corresponding to one sensor
 */
struct SensorModel
{

  /**
   * DLL
   */
  struct SensorModel *prev;

  /**
   * DLL
   */
  struct SensorModel *next;

  /**
   * Pointer to sensor info structure
   */
  struct GNUNET_SENSOR_SensorInfo *sensor;

  /**
   * Watcher of sensor values
   */
  struct GNUNET_PEERSTORE_WatchContext *wc;

  /**
   * State of sensor. #GNUNET_YES if anomalous, #GNUNET_NO otherwise.
   */
  int anomalous;

  /**
   * Number of anomalous readings (positive) received in a row.
   */
  int positive_count;

  /**
   * Number of non-anomalous (negative) readings received in a row.
   */
  int negative_count;

  /**
   * Closure for model plugin.
   * Usually, the instance of the model created for this sensor.
   */
  void *cls;

};

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Hashmap of loaded sensors
 */
static struct GNUNET_CONTAINER_MultiHashMap *sensors;

/*
 * Model library name
 */
static char *model_lib_name;

/**
 * Model handle
 */
static struct GNUNET_SENSOR_ModelFunctions *model_api;

/**
 * Handle to peerstore service
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;

/**
 * Head of DLL of created models
 */
static struct SensorModel *models_head;

/**
 * Tail of DLL of created models
 */
static struct SensorModel *models_tail;

/**
 * My peer id
 */
static struct GNUNET_PeerIdentity peerid;

/**
 * How many subsequent values required to flip anomaly label.
 * E.g. After 3 subsequent anomaly reports, status change to anomalous.
 */
static unsigned long long confirmation_count;

/**
 * Destroy a created model
 */
static void
destroy_sensor_model (struct SensorModel *sensor_model)
{
  GNUNET_assert (NULL != sensor_model);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Destroying sensor model for `%s'.\n",
       sensor_model->sensor->name);
  if (NULL != sensor_model->wc)
  {
    GNUNET_PEERSTORE_watch_cancel (sensor_model->wc);
    sensor_model->wc = NULL;
  }
  if (NULL != sensor_model->cls)
  {
    model_api->destroy_model (sensor_model->cls);
    sensor_model->cls = NULL;
  }
  GNUNET_free (sensor_model);
  sensor_model = NULL;
}


/**
 * Stop the sensor analysis module
 */
void
SENSOR_analysis_stop ()
{
  struct SensorModel *sm;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Stopping sensor analysis module.\n");
  while (NULL != models_head)
  {
    sm = models_head;
    GNUNET_CONTAINER_DLL_remove (models_head, models_tail, sm);
    destroy_sensor_model (sm);
  }
  if (NULL != peerstore)
  {
    GNUNET_PEERSTORE_disconnect (peerstore, GNUNET_YES);
    peerstore = NULL;
  }
  if (NULL != model_api)
  {
    GNUNET_break (NULL == GNUNET_PLUGIN_unload (model_lib_name, model_api));
    GNUNET_free (model_lib_name);
    model_lib_name = NULL;
  }
}


/**
 * Sensor value watch callback
 *
 * @param cls Sensor model struct
 * @param record Received record from peerstore, should contain new sensor value
 * @param emsg Error message from peerstore if any, NULL if no errors
 * @return #GNUNET_YES
 */
static int
sensor_watcher (void *cls,
                const struct GNUNET_PEERSTORE_Record *record,
                const char *emsg)
{
  struct SensorModel *model = cls;
  double *val;
  int anomalous;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received a sensor value, will feed to sensor model.\n");
  if (sizeof (double) != record->value_size)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Received an invalid sensor value."));
    return GNUNET_YES;
  }
  val = (double *) (record->value);
  anomalous = model_api->feed_model (model->cls, *val);
  if (GNUNET_YES == anomalous)
  {
    model->positive_count++;
    model->negative_count = 0;
    if (GNUNET_NO == model->anomalous &&
        model->positive_count >= confirmation_count)
    {
      model->anomalous = GNUNET_YES;
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Anomaly state started for sensor `%s', value: %f.\n",
           model->sensor->name, val);
      SENSOR_reporting_anomaly_update (model->sensor, model->anomalous);
    }
  }
  else
  {
    model->negative_count++;
    model->positive_count = 0;
    if (GNUNET_YES == model->anomalous &&
        model->negative_count >= confirmation_count)
    {
      model->anomalous = GNUNET_NO;
      LOG (GNUNET_ERROR_TYPE_INFO,
          "Anomaly state stopped for sensor `%s', value: %f.\n",
           model->sensor->name, val);
      SENSOR_reporting_anomaly_update (model->sensor, model->anomalous);
    }
  }
  return GNUNET_YES;
}


/**
 * Iterator for defined sensors
 * Creates sensor model for numeric sensors
 *
 * @param cls unused
 * @param key unused
 * @param value a 'struct GNUNET_SENSOR_SensorInfo *' with sensor information
 * @return #GNUNET_YES to continue iterations
 */
static int
init_sensor_model (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_SENSOR_SensorInfo *sensor = value;
  struct SensorModel *sensor_model;

  if (0 != strcmp ("numeric", sensor->expected_datatype))
    return GNUNET_YES;
  sensor_model = GNUNET_new (struct SensorModel);
  sensor_model->sensor = sensor;
  sensor_model->wc =
      GNUNET_PEERSTORE_watch (peerstore, "sensor", &peerid, sensor->name,
                              &sensor_watcher, sensor_model);
  sensor_model->anomalous = GNUNET_NO;
  sensor_model->positive_count = 0;
  sensor_model->negative_count = 0;
  sensor_model->cls = model_api->create_model (model_api->cls);
  GNUNET_CONTAINER_DLL_insert (models_head, models_tail, sensor_model);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Created sensor model for `%s'.\n",
       sensor->name);
  return GNUNET_YES;
}


/**
 * Start the sensor analysis module
 *
 * @param c our service configuration
 * @param sensors multihashmap of loaded sensors
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_analysis_start (const struct GNUNET_CONFIGURATION_Handle *c,
                       struct GNUNET_CONTAINER_MultiHashMap *s)
{
  char *model_name;

  GNUNET_assert (NULL != s);
  cfg = c;
  sensors = s;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "sensor-analysis", "MODEL",
                                             &model_name))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Analysis model not defined in configuration.\n"));
    return GNUNET_SYSERR;
  }
  GNUNET_asprintf (&model_lib_name, "libgnunet_plugin_sensor_model_%s",
                   model_name);
  model_api = GNUNET_PLUGIN_load (model_lib_name, (void *) cfg);
  GNUNET_free (model_name);
  if (NULL == model_api)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Could not load analysis model `%s'.\n"),
         model_lib_name);
    return GNUNET_SYSERR;
  }
  peerstore = GNUNET_PEERSTORE_connect (cfg);
  if (NULL == peerstore)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Could not connect to peerstore service.\n"));
    SENSOR_analysis_stop ();
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "sensor-analysis",
                                             "CONFIRMATION_COUNT",
                                             &confirmation_count))
    confirmation_count = 1;
  GNUNET_CRYPTO_get_peer_identity (cfg, &peerid);
  GNUNET_CONTAINER_multihashmap_iterate (sensors, &init_sensor_model, NULL);
  return GNUNET_OK;
}

/* end of gnunet-service-sensor_analysis.c */
