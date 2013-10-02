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

#define MAXLINE 4096

/**
 * Pulseaudio specification. May change in the future.
 */
static pa_sample_spec sample_spec = {
  .format = PA_SAMPLE_FLOAT32LE,
  .rate = 48000,
  .channels = 1
};


/**
 * Pulseaudio mainloop api
 */
static pa_mainloop_api *mainloop_api;

/**
 * Pulseaudio threaded mainloop
 */
static pa_threaded_mainloop *m;

/**
 * Pulseaudio context
 */
static pa_context *context;

/**
 * Pulseaudio output stream
 */
static pa_stream *stream_out;

/**
 * Pulseaudio io events
 */
static pa_io_event *stdio_event;

/**
 * OPUS decoder
 */
static OpusDecoder *dec;

/**
 * PCM data buffer
 */
static float *pcm_buffer;

/**
 * Length of PCM buffer
 */
static int pcm_length;

/**
 * Number of samples for one frame
 */
static int frame_size;

/**
 * The sampling rate used in Pulseaudio specification
 */
static opus_int32 sampling_rate;

/**
 * Audio buffer
 */
static void *buffer;

/**
 * Length of audio buffer
 */
static size_t buffer_length;

/**
 * Read index for transmit buffer
 */
static size_t buffer_index;


/**
 * Message callback
 */
static int
stdin_receiver (void *cls, 
		void *client,
		const struct GNUNET_MessageHeader *msg)
{
  struct AudioMessage *audio;

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO:
    audio = (struct AudioMessage *) msg;
    
    int len =
      opus_decode_float (dec,
			 (const unsigned char *) &audio[1],
			 ntohs (audio->header.size) - sizeof (struct AudioMessage),
			 pcm_buffer,
			 frame_size, 0);
    // FIXME: pcm_length != len???
    if (pa_stream_write
	(stream_out, (uint8_t *) pcm_buffer, pcm_length, NULL, 0,
	 PA_SEEK_RELATIVE) < 0)
    {      
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("pa_stream_write() failed: %s\n"),
		  pa_strerror (pa_context_errno (context)));
      return GNUNET_OK;
    }    
    break;
  default:
    break;
  }
  return GNUNET_OK;
}


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
 * Write some data to the stream 
 */
static void
do_stream_write (size_t length)
{
  size_t l;
  GNUNET_assert (length);

  if (!buffer || !buffer_length)
    {
      return;
    }


  l = length;
  if (l > buffer_length)
    {
      l = buffer_length;

    }

  if (pa_stream_write
      (stream_out, (uint8_t *) buffer + buffer_index, l, NULL, 0,
       PA_SEEK_RELATIVE) < 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("pa_stream_write() failed: %s\n"),
		  pa_strerror (pa_context_errno (context)));
      quit (1);
      return;
    }

  buffer_length -= l;
  buffer_index += l;

  if (!buffer_length)
    {
      pa_xfree (buffer);
      buffer = NULL;
      buffer_index = buffer_length = 0;
    }
}


/**
 * Callback when data is there for playback
 */
static void
stream_write_callback (pa_stream * s, size_t length, void *userdata)
{

  if (stdio_event)
    {
      mainloop_api->io_enable (stdio_event, PA_IO_EVENT_INPUT);
    }


  if (!buffer)
    {
      return;
    }


  do_stream_write (length);
}


/**
 * Exit callback for SIGTERM and SIGINT
 */
static void
exit_signal_callback (pa_mainloop_api * m, pa_signal_event * e, int sig,
		      void *userdata)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("gnunet-helper-audio-playback - Got signal, exiting\n"));
  quit (1);
}


/**
 * Pulseaudio stream state callback
 */
static void
context_state_callback (pa_context * c, void *userdata)
{
  int p;
  GNUNET_assert (c);

  switch (pa_context_get_state (c))
    {
    case PA_CONTEXT_CONNECTING:
    case PA_CONTEXT_AUTHORIZING:
    case PA_CONTEXT_SETTING_NAME:
      break;

    case PA_CONTEXT_READY:
      {
	GNUNET_assert (c);
	GNUNET_assert (!stream_out);

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Connection established.\n"));


	if (!
	    (stream_out =
	     pa_stream_new (c, "GNUNET VoIP playback", &sample_spec, NULL)))
	  {
	    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			_("pa_stream_new() failed: %s\n"),
			pa_strerror (pa_context_errno (c)));
	    goto fail;
	  }

	pa_stream_set_write_callback (stream_out, stream_write_callback,
				      NULL);

	if ((p =
	     pa_stream_connect_playback (stream_out, NULL, NULL, 0, NULL,
					 NULL)) < 0)
	  {
	    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			_("pa_stream_connect_playback() failed: %s\n"),
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
 * Pulseaudio initialization
 */
static void
pa_init ()
{
  int r;

  if (!pa_sample_spec_valid (&sample_spec))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Wrong Spec\n"));
    }

  /* set up threaded playback mainloop */

  if (!(m = pa_threaded_mainloop_new ()))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("pa_mainloop_new() failed.\n"));
    }

  mainloop_api = pa_threaded_mainloop_get_api (m);


  /* listen to signals */

  r = pa_signal_init (mainloop_api);
  GNUNET_assert (r == 0);
  pa_signal_new (SIGINT, exit_signal_callback, NULL);
  pa_signal_new (SIGTERM, exit_signal_callback, NULL);


  /* connect to the main pulseaudio context */

  if (!(context = pa_context_new (mainloop_api, "GNUnet VoIP")))
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

  if (pa_threaded_mainloop_start (m) < 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("pa_mainloop_run() failed.\n"));
    }
}


/**
 * OPUS initialization
 */
static void
opus_init ()
{
  int err;
  int channels = 1;
  sampling_rate = 48000;
  frame_size = sampling_rate / 50;
  pcm_length = frame_size * channels * sizeof (float);

  dec = opus_decoder_create (sampling_rate, channels, &err);
  pcm_buffer = (float *) pa_xmalloc (frame_size * channels * sizeof (float));
}


/**
 * The main function for the playback helper.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *argv[])
{
  char readbuf[MAXLINE];
  struct GNUNET_SERVER_MessageStreamTokenizer *stdin_mst;

  fprintf (stderr, "HERE!\n");
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_log_setup ("gnunet-helper-audio-playback",
				   "WARNING",
				   NULL));
  stdin_mst = GNUNET_SERVER_mst_create (&stdin_receiver, NULL);
  opus_init ();
  pa_init ();
  while (1)
  {
    ssize_t ret = read (0, readbuf, sizeof (readbuf));   
    if (0 > ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Read error from STDIN: %s\n"), 
		  strerror (errno));
      break;
    }    
    GNUNET_SERVER_mst_receive (stdin_mst, NULL,
			       readbuf, ret,
			       GNUNET_NO, GNUNET_NO);
  }
  GNUNET_SERVER_mst_destroy (stdin_mst);
  return 0;
}
