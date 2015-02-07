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
  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
  Boston, MA 02111-1307, USA.
 */

/**
 * @file include/gnunet_speaker_lib.h
 * @brief API to access an audio speaker; provides access to hardware speakers
 * @author Simon Dieterle
 * @author Andreas Fuchs
 * @author Christian Grothoff
 */
#ifndef GNUNET_SPEAKER_SERVICE_H
#define GNUNET_SPEAKER_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0				/* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"

/**
 * Function that enables a speaker.
 *
 * @param cls closure
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
typedef int (*GNUNET_SPEAKER_EnableCallback)(void *cls);

/**
 * Function that disables a speaker.
 *
 * @param cls closure
 */
typedef void (*GNUNET_SPEAKER_DisableCallback)(void *cls);

/**
 * Function to destroy a speaker.
 *
 * @param cls closure
 */
typedef void (*GNUNET_SPEAKER_DestroyCallback)(void *cls);

/**
 * Function to cause a speaker to play audio data.
 *
 * @param cls closure
 * @param data_size number of bytes in @a data
 * @param data audio data to play, format is
 *        opaque to the API but should be OPUS.
 */
typedef void (*GNUNET_SPEAKER_PlayCallback)(void *cls,
					    size_t data_size,
					    const void *data);


/**
 * A speaker is a device that can play or record audio data.
 */
struct GNUNET_SPEAKER_Handle
{

  /**
   * Turn on the speaker.
   */
  GNUNET_SPEAKER_EnableCallback enable_speaker;

  /**
   * Play audio.
   */
  GNUNET_SPEAKER_PlayCallback play;

  /**
   * Turn the speaker off.
   */
  GNUNET_SPEAKER_DisableCallback disable_speaker;

  /**
   * Destroy the speaker.  Called by #GNUNET_SPEAKER_destroy.
   */
  GNUNET_SPEAKER_DestroyCallback destroy_speaker;

  /**
   * Closure for the callbacks.
   */
  void *cls;

};


/**
 * Create a speaker that corresponds to the speaker hardware
 * of our system.
 *
 * @param cfg configuration to use
 * @return NULL on error
 */
struct GNUNET_SPEAKER_Handle *
GNUNET_SPEAKER_create_from_hardware (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Destroy a speaker.
 *
 * @param speaker speaker to destroy
 */
void
GNUNET_SPEAKER_destroy (struct GNUNET_SPEAKER_Handle *speaker);


#if 0				/* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
/* end of gnunet_speaker_lib.h */
