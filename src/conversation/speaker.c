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
 * @file conversation/speaker.c
 * @brief API to access an audio speaker; provides access to hardware speakers
 * @author Simon Dieterle
 * @author Andreas Fuchs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_speaker_lib.h"
#include "conversation.h"


/**
 * Internal data structures for the speaker.
 */
struct Speaker
{
  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Handle for the playback helper
   */
  struct GNUNET_HELPER_Handle *playback_helper;

};


/**
 * Function that enables a speaker.
 *
 * @param cls closure with the `struct Speaker`
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
enable (void *cls)
{
  struct Speaker *spe = cls;
  static char *playback_helper_argv[] =
  {
    "gnunet-helper-audio-playback",
    NULL
  };

  spe->playback_helper = GNUNET_HELPER_start (GNUNET_NO,
					      "gnunet-helper-audio-playback",
					      playback_helper_argv,
					      NULL,
					      NULL, spe);
  if (NULL == spe->playback_helper)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Could not start playback audio helper.\n"));
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function that disables a speaker.
 *
 * @param cls closure with the `struct Speaker`
 */
static void
disable (void *cls)
{
  struct Speaker *spe = cls;

  if (NULL == spe->playback_helper)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_break (GNUNET_OK ==
		GNUNET_HELPER_kill (spe->playback_helper, GNUNET_NO));
  GNUNET_HELPER_destroy (spe->playback_helper);
  spe->playback_helper = NULL;
}


/**
 * Function to destroy a speaker.
 *
 * @param cls closure with the `struct Speaker`
 */
static void
destroy (void *cls)
{
  struct Speaker *spe = cls;

  if (NULL != spe->playback_helper)
    disable (spe);
}


/**
 * Function to cause a speaker to play audio data.
 *
 * @param cls clsoure with the `struct Speaker`
 * @param data_size number of bytes in @a data
 * @param data audio data to play, format is
 *        opaque to the API but should be OPUS.
 */
static void
play (void *cls,
      size_t data_size,
      const void *data)
{
  struct Speaker *spe = cls;
  char buf[sizeof (struct AudioMessage) + data_size];
  struct AudioMessage *am;

  if (NULL == spe->playback_helper)
  {
    GNUNET_break (0);
    return;
  }
  am = (struct AudioMessage *) buf;
  am->header.size = htons (sizeof (struct AudioMessage) + data_size);
  am->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO);
  memcpy (&am[1], data, data_size);
  (void) GNUNET_HELPER_send (spe->playback_helper,
			     &am->header,
			     GNUNET_NO,
			     NULL, NULL);
}


/**
 * Create a speaker that corresponds to the speaker hardware
 * of our system.
 *
 * @param cfg configuration to use
 * @return NULL on error
 */
struct GNUNET_SPEAKER_Handle *
GNUNET_SPEAKER_create_from_hardware (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_SPEAKER_Handle *speaker;
  struct Speaker *spe;

  spe = GNUNET_new (struct Speaker);
  spe->cfg = cfg;
  speaker = GNUNET_new (struct GNUNET_SPEAKER_Handle);
  speaker->cls = spe;
  speaker->enable_speaker = &enable;
  speaker->play = &play;
  speaker->disable_speaker = &disable;
  speaker->destroy_speaker = &destroy;
  return speaker;
}


/**
 * Destroy a speaker.
 *
 * @param speaker speaker to destroy
 */
void
GNUNET_SPEAKER_destroy (struct GNUNET_SPEAKER_Handle *speaker)
{
  speaker->destroy_speaker (speaker->cls);
  GNUNET_free (speaker);
}

/* end of speaker.c */
