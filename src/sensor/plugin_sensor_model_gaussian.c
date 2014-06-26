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

};

static void *
sensor_gaussian_model_create_model (void *cls)
{
  struct Plugin *plugin = cls;
  struct Model *model;

  model = GNUNET_new(struct Model);
  model->plugin = plugin;
  return model;
}

/*
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

  if (NULL != plugin.cfg)
    return NULL;                /* can only initialize once! */
  memset (&plugin, 0, sizeof (struct Plugin));
  plugin.cfg = cfg;
  api = GNUNET_new (struct GNUNET_SENSOR_ModelFunctions);
  api->cls = &plugin;
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Guassian model plugin is running\n");
  return api;
}

/*
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
