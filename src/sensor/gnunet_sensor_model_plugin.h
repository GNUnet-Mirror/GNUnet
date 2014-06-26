/*
     This file is part of GNUnet
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file sensor/gnunet_sensor_model_plugin.h
 * @brief plugin API for sensor analysis models
 * @author Omar Tarabai
 */
#ifndef GNUNET_SENSOR_MODEL_PLUGIN_H
#define GNUNET_SENSOR_MODEL_PLUGIN_H

#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * API for a sensor analysis model
 */
struct GNUNET_SENSOR_ModelFunctions
{

  /**
   * Closure to pass to all plugin functions.
   */
  void *cls;

  /*
   * Create a model instance
   *
   * @param cls closure (plugin state)
   * @return model state to be used for later calls
   */
  void *
  (*create_model) (void *cls);

  /*
   * Destroy a model instance
   *
   * @param cls closure (model state)
   */
  void
  (*destroy_model) (void *cls);

  /*
   * Feed a new value to a model
   *
   * @param cls closure (model state)
   * @param val value to be fed to the model
   * @return #GNUNET_YES in case of a detected outlier, #GNUNET_NO otherwise
   */
  int
  (*feed_model) (void *cls, double val);

};


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_sensor_model_plugin.h */
#endif
