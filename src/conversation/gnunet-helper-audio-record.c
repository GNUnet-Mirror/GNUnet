/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file conversation/gnunet-helper-audio-playback.c
 * @brief constants for network protocols
 * @author Siomon Dieterle
 * @author Andreas Fuchs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "conversation.h"
#include "gnunet_constants.h"
#include "gnunet_core_service.h"

#include <pulse/simple.h>
#include <pulse/error.h>
#include <pulse/rtclock.h>

#include <pulse/pulseaudio.h>
#include <opus/opus.h>
#include <opus/opus_types.h>

/**
* Specification for recording. May change in the future to spec negotiation.
*/
static pa_sample_spec sample_spec = {
  .format = PA_SAMPLE_FLOAT32LE,
  .rate = 48000,
  .channels = 1
};

/**
* Pulseaudio mainloop api
*/
static pa_mainloop_api *mainloop_api = NULL;

/**
* Pulseaudio mainloop
*/
static pa_mainloop *m = NULL;

/**
* Pulseaudio context
*/
static pa_context *context = NULL;

/**
* Pulseaudio recording stream
*/
static pa_stream *stream_in = NULL;

/**
* Pulseaudio io events
*/
static pa_io_event *stdio_event = NULL;

/**
* Message tokenizer
*/
struct MessageStreamTokenizer *stdin_mst;

/**
* OPUS encoder
*/
OpusEncoder *enc = NULL;

/**
*
*/
unsigned char *opus_data;

/**
* PCM data buffer for one OPUS frame
*/
float *pcm_buffer;

/**
 * Length of the pcm data needed for one OPUS frame 
 */
int pcm_length;

/**
* Number of samples for one frame
*/
int frame_size;

/**
* Maximum length of opus payload
*/
int max_payload_bytes = 1500;

/**
* Audio buffer
*/
static void *transmit_buffer = NULL;

/**
* Length of audio buffer
*/
static size_t transmit_buffer_length = 0;

/**
* Read index for transmit buffer
*/
static size_t transmit_buffer_index = 0;

/**
* Audio message skeleton
*/
struct AudioMessage *audio_message;



/**
* Pulseaudio shutdown task
*/
static void
quit (int ret)
{
  mainloop_api->quit (mainloop_api, ret);
  exit (ret);
}



/**
* Creates OPUS packets from PCM data
*/
static void
packetizer ()
{


  while (transmit_buffer_length >= transmit_buffer_index + pcm_length)
    {

      int ret;
      int len;

      size_t msg_size = sizeof (struct AudioMessage);

      memcpy (pcm_buffer,
	      (float *) transmit_buffer +
	      (transmit_buffer_index / sizeof (float)), pcm_length);
      len =
	opus_encode_float (enc, pcm_buffer, frame_size, opus_data,
			   max_payload_bytes);

      audio_message->length = len;
      memcpy (audio_message->audio, opus_data, len);

      if ((ret = write (1, audio_message, msg_size)) != msg_size)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("write"));
	  return;
	}

      transmit_buffer_index += pcm_length;
    }

  int new_size = transmit_buffer_length - transmit_buffer_index;

  if (0 != new_size)
    {

      transmit_buffer = pa_xrealloc (transmit_buffer, new_size);
      memcpy (transmit_buffer, transmit_buffer + transmit_buffer_index,
	      new_size);

      transmit_buffer_index = 0;
      transmit_buffer_length = new_size;
    }

}

/**
* Pulseaudio callback when new data is available.
*/
static void
stream_read_callback (pa_stream * s, size_t length, void *userdata)
{
  const void *data;
  GNUNET_assert (s);
  GNUNET_assert (length > 0);

  if (stdio_event)
    mainloop_api->io_enable (stdio_event, PA_IO_EVENT_OUTPUT);

  if (pa_stream_peek (s, (const void **) &data, &length) < 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("pa_stream_peek() failed: %s\n"),
		  pa_strerror (pa_context_errno (context)));
      quit (1);
      return;
    }

  GNUNET_assert (data);
  GNUNET_assert (length > 0);

  if (transmit_buffer)
    {
      transmit_buffer =
	pa_xrealloc (transmit_buffer, transmit_buffer_length + length);
      memcpy ((uint8_t *) transmit_buffer + transmit_buffer_length, data,
	      length);
      transmit_buffer_length += length;
    }
  else
    {
      transmit_buffer = pa_xmalloc (length);
      memcpy (transmit_buffer, data, length);
      transmit_buffer_length = length;
      transmit_buffer_index = 0;
    }

  pa_stream_drop (s);
  packetizer ();
}

/**
* Exit callback for SIGTERM and SIGINT
*/
static void
exit_signal_callback (pa_mainloop_api * m, pa_signal_event * e, int sig,
		      void *userdata)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Got signal, exiting.\n"));
  quit (1);
}

/**
* Pulseaudio stream state callback
*/
static void
stream_state_callback (pa_stream * s, void *userdata)
{
  GNUNET_assert (s);

  switch (pa_stream_get_state (s))
    {
    case PA_STREAM_CREATING:
    case PA_STREAM_TERMINATED:
      break;

    case PA_STREAM_READY:
      if (1)
	{
	  const pa_buffer_attr *a;
	  char cmt[PA_CHANNEL_MAP_SNPRINT_MAX],
	    sst[PA_SAMPLE_SPEC_SNPRINT_MAX];

	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("Stream successfully created.\n"));

	  if (!(a = pa_stream_get_buffer_attr (s)))
	    {
	      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			  _("pa_stream_get_buffer_attr() failed: %s\n"),
			  pa_strerror (pa_context_errno
				       (pa_stream_get_context (s))));

	    }
	  else
	    {
	      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
			  _("Buffer metrics: maxlength=%u, fragsize=%u\n"),
			  a->maxlength, a->fragsize);
	    }

	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("Using sample spec '%s', channel map '%s'.\n"),
		      pa_sample_spec_snprint (sst, sizeof (sst),
					      pa_stream_get_sample_spec (s)),
		      pa_channel_map_snprint (cmt, sizeof (cmt),
					      pa_stream_get_channel_map (s)));

	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("Connected to device %s (%u, %ssuspended).\n"),
		      pa_stream_get_device_name (s),
		      pa_stream_get_device_index (s),
		      pa_stream_is_suspended (s) ? "" : "not ");
	}

      break;

    case PA_STREAM_FAILED:
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Stream error: %s\n"),
		  pa_strerror (pa_context_errno (pa_stream_get_context (s))));
      quit (1);
    }
}

/**
* Pulseaudio context state callback
*/
static void
context_state_callback (pa_context * c, void *userdata)
{
  GNUNET_assert (c);

  switch (pa_context_get_state (c))
    {
    case PA_CONTEXT_CONNECTING:
    case PA_CONTEXT_AUTHORIZING:
    case PA_CONTEXT_SETTING_NAME:
      break;

    case PA_CONTEXT_READY:
      {
	int r;

	GNUNET_assert (c);
	GNUNET_assert (!stream_in);

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Connection established.\n"));

	if (!
	    (stream_in =
	     pa_stream_new (c, "GNUNET_VoIP recorder", &sample_spec, NULL)))
	  {
	    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			_("pa_stream_new() failed: %s\n"),
			pa_strerror (pa_context_errno (c)));
	    goto fail;
	  }


	pa_stream_set_state_callback (stream_in, stream_state_callback, NULL);
	pa_stream_set_read_callback (stream_in, stream_read_callback, NULL);


	if ((r = pa_stream_connect_record (stream_in, NULL, NULL, 0)) < 0)
	  {
	    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			_("pa_stream_connect_record() failed: %s\n"),
			pa_strerror (pa_context_errno (c)));
	    goto fail;
	  }

	break;
      }

    case PA_CONTEXT_TERMINATED:
      quit (0);
      break;

    case PA_CONTEXT_FAILED:
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Connection failure: %s\n"),
		  pa_strerror (pa_context_errno (c)));
      goto fail;
    }

  return;

fail:
  quit (1);

}

/**
 * Pulsaudio init
 */
void
pa_init ()
{
  int r;
  int i;

  if (!pa_sample_spec_valid (&sample_spec))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Wrong Spec\n"));
    }

  /* set up main record loop */

  if (!(m = pa_mainloop_new ()))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("pa_mainloop_new() failed.\n"));
    }

  mainloop_api = pa_mainloop_get_api (m);

  /* listen to signals */

  r = pa_signal_init (mainloop_api);
  GNUNET_assert (r == 0);
  pa_signal_new (SIGINT, exit_signal_callback, NULL);
  pa_signal_new (SIGTERM, exit_signal_callback, NULL);

  /* connect to the main pulseaudio context */

  if (!(context = pa_context_new (mainloop_api, "GNUNET VoIP")))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("pa_context_new() failed.\n"));
    }

  pa_context_set_state_callback (context, context_state_callback, NULL);

  if (pa_context_connect (context, NULL, 0, NULL) < 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("pa_context_connect() failed: %s\n"),
		  pa_strerror (pa_context_errno (context)));
    }

  if (pa_mainloop_run (m, &i) < 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("pa_mainloop_run() failed.\n"));
    }
}

/**
 * OPUS init
 */
void
opus_init ()
{
  opus_int32 sampling_rate = 48000;
  frame_size = sampling_rate / 50;
  int channels = 1;

  pcm_length = frame_size * channels * sizeof (float);

  int err;

  enc =
    opus_encoder_create (sampling_rate, channels, OPUS_APPLICATION_VOIP,
			 &err);
  pcm_buffer = (float *) pa_xmalloc (pcm_length);
  opus_data = (unsigned char *) calloc (max_payload_bytes, sizeof (char));

  audio_message = pa_xmalloc (sizeof (struct AudioMessage));

  audio_message->header.size = htons (sizeof (struct AudioMessage));
  audio_message->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO);
}

/**
 * The main function for the record helper.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *argv[])
{
  opus_init ();
  pa_init ();

  return 0;
}
