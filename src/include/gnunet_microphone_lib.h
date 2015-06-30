/*
  This file is part of GNUnet
  Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_microphone_lib.h
 * @brief API to access an audio microphone; provides access to hardware microphones
 * @author Simon Dieterle
 * @author Andreas Fuchs
 * @author Christian Grothoff
 */
#ifndef GNUNET_MICROPHONE_SERVICE_H
#define GNUNET_MICROPHONE_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0				/* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"

/**
 * Process recorded audio data.
 *
 * @param cls clsoure
 * @param data_size number of bytes in @a data
 * @param data audio data to play
 */
typedef void (*GNUNET_MICROPHONE_RecordedDataCallback)(void *cls,
						       size_t data_size,
						       const void *data);

/**
 * Enable a microphone.
 *
 * @param cls clsoure
 * @param rdc function to call with recorded data
 * @param rdc_cls closure for @a dc
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
typedef int (*GNUNET_MICROPHONE_EnableCallback)(void *cls,
						GNUNET_MICROPHONE_RecordedDataCallback rdc,
						void *rdc_cls);

/**
 * Function that disables a microphone.
 *
 * @param cls clsoure
 */
typedef void (*GNUNET_MICROPHONE_DisableCallback)(void *cls);

/**
 * Function to destroy a microphone.
 *
 * @param cls clsoure
 */
typedef void (*GNUNET_MICROPHONE_DestroyCallback)(void *cls);


/**
 * A microphone is a device that can capture or otherwise produce audio data.
 */
struct GNUNET_MICROPHONE_Handle
{

  /**
   * Turn on the microphone.
   */
  GNUNET_MICROPHONE_EnableCallback enable_microphone;

  /**
   * Turn the microphone off.
   */
  GNUNET_MICROPHONE_DisableCallback disable_microphone;

  /**
   * Destroy the microphone.  Called by #GNUNET_MICROPHONE_destroy.
   */
  GNUNET_MICROPHONE_DestroyCallback destroy_microphone;

  /**
   * Closure for the callbacks.
   */
  void *cls;

};


/**
 * Create a microphone that corresponds to the microphone hardware
 * of our system.
 *
 * @param cfg configuration to use
 * @return NULL on error
 */
struct GNUNET_MICROPHONE_Handle *
GNUNET_MICROPHONE_create_from_hardware (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Destroy a microphone.
 *
 * @param microphone microphone to destroy
 */
void
GNUNET_MICROPHONE_destroy (struct GNUNET_MICROPHONE_Handle *microphone);


#if 0				/* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
/* end of gnunet_microphone_lib.h */
