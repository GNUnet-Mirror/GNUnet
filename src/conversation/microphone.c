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
 * @file conversation/microphone.c
 * @brief API to access an audio microphone; provides access to hardware microphones;
 *        actually just wraps the gnunet-helper-audio-record
 * @author Simon Dieterle
 * @author Andreas Fuchs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_microphone_lib.h"
#include "conversation.h"


/**
 * Internal data structures for the microphone.
 */
struct Microphone
{

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Handle for the record helper
   */
  struct GNUNET_HELPER_Handle *record_helper;

  /**
   * Function to call with audio data (if we are enabled).
   */
  GNUNET_MICROPHONE_RecordedDataCallback rdc;

  /**
   * Closure for @e rdc.
   */
  void *rdc_cls;

};


/**
 * Function to process the audio from the record helper
 *
 * @param cls clsoure with our `struct Microphone`
 * @param client NULL
 * @param msg the message from the helper
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
process_record_messages (void *cls,
			 void *client,
			 const struct GNUNET_MessageHeader *msg)
{
  struct Microphone *mic = cls;
  const struct AudioMessage *am;

  if (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  am = (const struct AudioMessage *) msg;
  mic->rdc (mic->rdc_cls,
	    ntohs (msg->size) - sizeof (struct AudioMessage),
	    &am[1]);
  return GNUNET_OK;
}


/**
 * Enable a microphone.
 *
 * @param cls clsoure with our `struct Microphone`
 * @param rdc function to call with recorded data
 * @param rdc_cls closure for @a dc
 */
static int
enable (void *cls,
	GNUNET_MICROPHONE_RecordedDataCallback rdc,
	void *rdc_cls)
{
  struct Microphone *mic = cls;
  static char * const record_helper_argv[] =
  {
    "gnunet-helper-audio-record",
    NULL
  };

  mic->rdc = rdc;
  mic->rdc_cls = rdc_cls;
  mic->record_helper = GNUNET_HELPER_start (GNUNET_NO,
					    "gnunet-helper-audio-record",
					    record_helper_argv,
					    &process_record_messages,
					    NULL, mic);
  if (NULL == mic->record_helper)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Could not start record audio helper\n"));
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function that disables a microphone.
 *
 * @param cls clsoure
 */
static void
disable (void *cls)
{
  struct Microphone *mic = cls;

  if (NULL == mic->record_helper)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_break (GNUNET_OK ==
		GNUNET_HELPER_kill (mic->record_helper, GNUNET_NO));
  GNUNET_HELPER_destroy (mic->record_helper);
  mic->record_helper = NULL;
}


/**
 * Function to destroy a microphone.
 *
 * @param cls clsoure
 */
static void
destroy (void *cls)
{
  struct Microphone *mic = cls;

  if (NULL != mic->record_helper)
    disable (mic);
}


/**
 * Create a microphone that corresponds to the microphone hardware
 * of our system.
 *
 * @param cfg configuration to use
 * @return NULL on error
 */
struct GNUNET_MICROPHONE_Handle *
GNUNET_MICROPHONE_create_from_hardware (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_MICROPHONE_Handle *microphone;
  struct Microphone *mic;

  mic = GNUNET_new (struct Microphone);
  mic->cfg = cfg;
  microphone = GNUNET_new (struct GNUNET_MICROPHONE_Handle);
  microphone->cls = mic;
  microphone->enable_microphone = &enable;
  microphone->disable_microphone = &disable;
  microphone->destroy_microphone = &destroy;
  return microphone;
}


/**
 * Destroy a microphone.
 *
 * @param microphone microphone to destroy
 */
void
GNUNET_MICROPHONE_destroy (struct GNUNET_MICROPHONE_Handle *microphone)
{
  microphone->destroy_microphone (microphone->cls);
  GNUNET_free (microphone);
}

/* end of microphone.c */
