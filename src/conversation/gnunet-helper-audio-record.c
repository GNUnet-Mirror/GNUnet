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
 * @author Christian Grothoff
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

#define SAMPLING_RATE 48000


/**
 * Specification for recording. May change in the future to spec negotiation.
 */
static pa_sample_spec sample_spec = {
  .format = PA_SAMPLE_FLOAT32LE,
  .rate = SAMPLING_RATE,
  .channels = 1
};

/**
 * Pulseaudio mainloop api
 */
static pa_mainloop_api *mainloop_api;

/**
 * Pulseaudio mainloop
 */
static pa_mainloop *m;

/**
 * Pulseaudio context
 */
static pa_context *context;

/**
 * Pulseaudio recording stream
 */
static pa_stream *stream_in;

/**
 * Pulseaudio io events
 */
static pa_io_event *stdio_event;

/**
 * OPUS encoder
 */
static OpusEncoder *enc;

/**
 *
 */
static unsigned char *opus_data;

/**
 * PCM data buffer for one OPUS frame
 */
static float *pcm_buffer;

/**
 * Length of the pcm data needed for one OPUS frame 
 */
static int pcm_length;

/**
 * Number of samples for one frame
 */
static int frame_size;

/**
* Maximum length of opus payload
*/
static int max_payload_bytes = 1500;

/**
 * Audio buffer
 */
static char *transmit_buffer;

/**
 * Length of audio buffer
 */
static size_t transmit_buffer_length;

/**
 * Read index for transmit buffer
 */
static size_t transmit_buffer_index;

/**
 * Audio message skeleton
 */
static struct AudioMessage *audio_message;


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
  static unsigned long long toff;
  char *nbuf;
  size_t new_size;
  const char *ptr;
  size_t off;
  ssize_t ret;
  int len; // FIXME: int?
  size_t msg_size;  

  while (transmit_buffer_length >= transmit_buffer_index + pcm_length)
  {
    memcpy (pcm_buffer,
	    &transmit_buffer[transmit_buffer_index],
	    pcm_length);
    transmit_buffer_index += pcm_length;
    len =
      opus_encode_float (enc, pcm_buffer, frame_size, opus_data,
			 max_payload_bytes);
    if (len > UINT16_MAX - sizeof (struct AudioMessage))
    {
      GNUNET_break (0);
      len = UINT16_MAX - sizeof (struct AudioMessage);
    }
    msg_size = sizeof (struct AudioMessage) + len;
    audio_message->header.size = htons ((uint16_t) msg_size);
    memcpy (&audio_message[1], opus_data, len);

    toff += msg_size;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Sending %u bytes of audio data (total: %llu)\n",
		(unsigned int) msg_size,
		toff);
    ptr = (const char *) audio_message;
    off = 0;
    while (off < msg_size)
    {
      ret = write (1, &ptr[off], msg_size - off);
      if (0 >= ret)
      {
	if (-1 == ret)
	  GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "write");
	quit (2);
      }
      off += ret;
    }
  }

  new_size = transmit_buffer_length - transmit_buffer_index;
  if (0 != new_size)
  {
    nbuf = pa_xmalloc (new_size);
    memmove (nbuf, 
	     &transmit_buffer[transmit_buffer_index],
	     new_size);    
    pa_xfree (transmit_buffer);
    transmit_buffer = nbuf;
  }
  else
  {
    pa_xfree (transmit_buffer);
    transmit_buffer = NULL;
  }
  transmit_buffer_index = 0;
  transmit_buffer_length = new_size;  
}


/**
 * Pulseaudio callback when new data is available.
 */
static void
stream_read_callback (pa_stream * s,
		      size_t length, 
		      void *userdata)
{
  const void *data;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Got %u/%u bytes of PCM data\n",
	      length,
	      pcm_length);

  GNUNET_assert (NULL != s);
  GNUNET_assert (length > 0);
  if (stdio_event)
    mainloop_api->io_enable (stdio_event, PA_IO_EVENT_OUTPUT);

  if (pa_stream_peek (s, (const void **) &data, &length) < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("pa_stream_peek() failed: %s\n"),
		pa_strerror (pa_context_errno (context)));
    quit (1);
    return;
  }
  GNUNET_assert (NULL != data);
  GNUNET_assert (length > 0);
  if (NULL != transmit_buffer)
  {
    transmit_buffer = pa_xrealloc (transmit_buffer, 
				   transmit_buffer_length + length);
    memcpy (&transmit_buffer[transmit_buffer_length], 
	    data,
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
exit_signal_callback (pa_mainloop_api * m, 
		      pa_signal_event * e, 
		      int sig,
		      void *userdata)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      _("Got signal, exiting.\n"));
  quit (1);
}


/**
 * Pulseaudio stream state callback
 */
static void
stream_state_callback (pa_stream * s, void *userdata)
{
  GNUNET_assert (NULL != s);

  switch (pa_stream_get_state (s))
  {
  case PA_STREAM_CREATING:
  case PA_STREAM_TERMINATED:
    break;    
  case PA_STREAM_READY:
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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("Stream error: %s\n"),
		pa_strerror (pa_context_errno (pa_stream_get_context (s))));
    quit (1);
  }
}


/**
 * Pulseaudio context state callback
 */
static void
context_state_callback (pa_context * c,
			void *userdata)
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
    pa_buffer_attr na;
    
    GNUNET_assert (!stream_in);    
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
		_("Connection established.\n"));
    if (! (stream_in =
	   pa_stream_new (c, "GNUNET_VoIP recorder", &sample_spec, NULL)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("pa_stream_new() failed: %s\n"),
		  pa_strerror (pa_context_errno (c)));
      goto fail;
    }
    pa_stream_set_state_callback (stream_in, &stream_state_callback, NULL);
    pa_stream_set_read_callback (stream_in, &stream_read_callback, NULL);
    memset (&na, 0, sizeof (na));
    na.maxlength = UINT32_MAX;
    na.fragsize = pcm_length;
    if ((r = pa_stream_connect_record (stream_in, NULL, &na, 
				       PA_STREAM_EARLY_REQUESTS)) < 0)
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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Connection failure: %s\n"),
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
static void
pa_init ()
{
  int r;
  int i;

  if (!pa_sample_spec_valid (&sample_spec))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("Wrong Spec\n"));
  }
  /* set up main record loop */
  if (!(m = pa_mainloop_new ()))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("pa_mainloop_new() failed.\n"));
  }
  mainloop_api = pa_mainloop_get_api (m);

  /* listen to signals */
  r = pa_signal_init (mainloop_api);
  GNUNET_assert (r == 0);
  pa_signal_new (SIGINT, &exit_signal_callback, NULL);
  pa_signal_new (SIGTERM, &exit_signal_callback, NULL);

  /* connect to the main pulseaudio context */

  if (!(context = pa_context_new (mainloop_api, "GNUNET VoIP")))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("pa_context_new() failed.\n"));
  }  
  pa_context_set_state_callback (context, &context_state_callback, NULL);
  if (pa_context_connect (context, NULL, 0, NULL) < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("pa_context_connect() failed: %s\n"),
		pa_strerror (pa_context_errno (context)));
  }
  if (pa_mainloop_run (m, &i) < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		_("pa_mainloop_run() failed.\n"));
  }
}


/**
 * OPUS init
 */
static void
opus_init ()
{
  int channels = 1;
  int err;

  frame_size = SAMPLING_RATE / 50;
  pcm_length = frame_size * channels * sizeof (float);
  pcm_buffer = pa_xmalloc (pcm_length);
  opus_data = GNUNET_malloc (max_payload_bytes);
  enc = opus_encoder_create (SAMPLING_RATE,
			     channels, 
			     OPUS_APPLICATION_VOIP,
			     &err);
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
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_log_setup ("gnunet-helper-audio-record",
				   "DEBUG",
				   "/tmp/helper-audio-record"));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Audio source starts\n");
  audio_message = GNUNET_malloc (UINT16_MAX);
  audio_message->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO);
  opus_init ();
  pa_init ();
  return 0;
}
