/*
 * This file is part of GNUnet
 * (C) 2013 Christian Grothoff (and other contributing authors)
 *
 * GNUnet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUnet; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * @file sensor/plugin_sensor_model_gaussian.c
 * @brief Gaussian model for sensor analysis
 * @author Omar Tarabai
 */

#include "platform.h"
#include "gnunet_sensor_model_plugin.h"
#include "gnunet_sensor_service.h"
#include "sensor.h"

#define LOG(kind,...) GNUNET_log_from (kind, "sensor-model-gaussian", __VA_ARGS__)

/*
 * Plugin state information
 */
struct Plugin
{

  /*
   * Configuration handle
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /*
   * Number of initial readings to be used for training only
   */
  int training_window;

  /*
   * Number of standard deviations considered within "normal"
   */
  int confidence_interval;

};

/*
 * State of single model instance
 */
struct Model
{

  /*
   * Pointer to the plugin state
   */
  struct Plugin *plugin;

  /*
   * Number of readings so far
   */
  int n;

  /*
   * Sum of readings
   */
  long double sum;

  /*
   * Sum square of readings
   */
  long double sumsq;

};

/**
 * Update local sums of model with a new value.
 *
 * @param model Targe model
 * @param val New value
 */
static void
update_sums (struct Model *model, double val)
{
  model->sum += val;
  model->sumsq += val * val;
  model->n++;
}


/**
 * Feed a new value to a model
 *
 * @param cls closure (model state)
 * @param val value to be fed to the model
 * @return #GNUNET_YES in case of a detected outlier, #GNUNET_NO otherwise
 */
static int
sensor_gaussian_model_feed (void *cls, double val)
{
  struct Model *model = cls;
  struct Plugin *plugin = model->plugin;
  long double mean;
  long double stddev;
  long double allowed_variance;

  if (model->n < plugin->training_window)
  {
    update_sums (model, val);
    return GNUNET_NO;
  }
  if (model->n == plugin->training_window)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Gaussian model out of training period.\n");
  mean = model->sum / model->n;
  stddev =
      sqrt ((model->sumsq - 2 * mean * model->sum +
             model->n * mean * mean) / (model->n - 1));
  allowed_variance = (plugin->confidence_interval * stddev);
  if ((val < (mean - allowed_variance)) || (val > (mean + allowed_variance)))
    return GNUNET_YES;
  update_sums (model, val);
  return GNUNET_NO;
}


/**
 * Destroy a model instance
 *
 * @param cls closure (model state)
 */
static void
sensor_gaussian_model_destroy_model (void *cls)
{
  struct Model *model = cls;

  GNUNET_free (model);
}


/**
 * Create a model instance
 *
 * @param cls closure (plugin state)
 * @return model state to be used for later calls
 */
static void *
sensor_gaussian_model_create_model (void *cls)
{
  struct Plugin *plugin = cls;
  struct Model *model;

  model = GNUNET_new (struct Model);

  model->plugin = plugin;
  return model;
}


/**
 * Entry point for the plugin.
 *
 * @param cls The struct GNUNET_CONFIGURATION_Handle.
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_sensor_model_gaussian_init (void *cls)
{
  static struct Plugin plugin;
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_SENSOR_ModelFunctions *api;
  unsigned long long num;

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.cfg = cfg;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "sensor-model-gaussian",
                                             "TRAINING_WINDOW", &num))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Missing `TRAINING_WINDOW' value in configuration.\n"));
    return NULL;
  }
  plugin.training_window = (int) num;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "sensor-model-gaussian",
                                             "CONFIDENCE_INTERVAL", &num))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Missing `CONFIDENCE_INTERVAL' value in configuration.\n"));
    return NULL;
  }
  plugin.confidence_interval = (int) num;
  api = GNUNET_new (struct GNUNET_SENSOR_ModelFunctions);

  api->cls = &plugin;
  api->create_model = &sensor_gaussian_model_create_model;
  api->destroy_model = &sensor_gaussian_model_destroy_model;
  api->feed_model = &sensor_gaussian_model_feed;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Gaussian model plugin is running.\n");
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls The plugin context (as returned by "init")
 * @return Always NULL
 */
void *
libgnunet_plugin_sensor_model_gaussian_done (void *cls)
{
  struct GNUNET_SENSOR_ModelFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  plugin->cfg = NULL;
  GNUNET_free (api);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Guassian model plugin is finished\n");
  return NULL;

}

/* end of plugin_sensor_model_gaussian.c */
