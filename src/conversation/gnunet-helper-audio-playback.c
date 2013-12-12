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
 * @brief program to playback audio data to the speaker
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

#define MAXLINE 4096

#define SAMPLING_RATE 48000

/**
 * Pulseaudio specification. May change in the future.
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
 * Pipe we use to signal the main loop that we are ready to receive.
 */
static int ready_pipe[2];

/**
 * Message callback
 */
static int
stdin_receiver (void *cls,
		void *client,
		const struct GNUNET_MessageHeader *msg)
{
  struct AudioMessage *audio;
  int ret;

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO:
    audio = (struct AudioMessage *) msg;

    ret = opus_decode_float (dec,
			     (const unsigned char *) &audio[1],
			     ntohs (audio->header.size) - sizeof (struct AudioMessage),
			     pcm_buffer,
			     frame_size, 0);
    if (ret < 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Opus decoding failed: %d\n",
		  ret);
      return GNUNET_OK;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Decoded frame with %u bytes\n",
		ntohs (audio->header.size));
    if (pa_stream_write
	(stream_out, pcm_buffer, pcm_length, NULL, 0,
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
 * Callback when data is there for playback
 */
static void
stream_write_callback (pa_stream * s,
		       size_t length,
		       void *userdata)
{
  /* unblock 'main' */
  if (-1 != ready_pipe[1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Unblocking main loop!\n");
    write (ready_pipe[1], "r", 1);
  }
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
context_state_callback (pa_context * c,
			void *userdata)
{
  int p;

  GNUNET_assert (NULL != c);
  switch (pa_context_get_state (c))
  {
  case PA_CONTEXT_CONNECTING:
  case PA_CONTEXT_AUTHORIZING:
  case PA_CONTEXT_SETTING_NAME:
    break;
  case PA_CONTEXT_READY:
  {
    GNUNET_assert (!stream_out);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Connection established.\n"));
    if (!(stream_out =
	  pa_stream_new (c, "GNUNET VoIP playback", &sample_spec, NULL)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("pa_stream_new() failed: %s\n"),
		  pa_strerror (pa_context_errno (c)));
      goto fail;
    }
    pa_stream_set_write_callback (stream_out,
				  &stream_write_callback,
				  NULL);
    if ((p =
	 pa_stream_connect_playback (stream_out, NULL,
				     NULL,
				     PA_STREAM_ADJUST_LATENCY | PA_STREAM_INTERPOLATE_TIMING | PA_STREAM_AUTO_TIMING_UPDATE,
				     NULL,  NULL)) < 0)
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
 * Pulseaudio initialization
 */
static void
pa_init ()
{
  int r;

  if (!pa_sample_spec_valid (&sample_spec))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Wrong Spec\n"));
  }
  /* set up threaded playback mainloop */
  if (!(m = pa_threaded_mainloop_new ()))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("pa_mainloop_new() failed.\n"));
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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("pa_context_new() failed.\n"));
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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("pa_mainloop_run() failed.\n"));
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

  frame_size = SAMPLING_RATE / 50;
  pcm_length = frame_size * channels * sizeof (float);

  dec = opus_decoder_create (SAMPLING_RATE, channels, &err);
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
  static unsigned long long toff;

  char readbuf[MAXLINE];
  struct GNUNET_SERVER_MessageStreamTokenizer *stdin_mst;
  char c;
  ssize_t ret;

  GNUNET_assert (GNUNET_OK ==
		 GNUNET_log_setup ("gnunet-helper-audio-playback",
				   "WARNING",
				   NULL));
  if (0 != pipe (ready_pipe))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "pipe");
    return 1;
  }
  stdin_mst = GNUNET_SERVER_mst_create (&stdin_receiver, NULL);
  opus_init ();
  pa_init ();
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Waiting for PulseAudio to be ready.\n");
  GNUNET_assert (1 == read (ready_pipe[0], &c, 1));
  close (ready_pipe[0]);
  close (ready_pipe[1]);
  ready_pipe[0] = -1;
  ready_pipe[1] = -1;
  while (1)
  {
    ret = read (0, readbuf, sizeof (readbuf));
    toff += ret;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Received %d bytes of audio data (total: %llu)\n",
		(int) ret,
		toff);
    if (0 > ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Read error from STDIN: %s\n"),
		  strerror (errno));
      break;
    }
    if (0 == ret)
      break;
    GNUNET_SERVER_mst_receive (stdin_mst, NULL,
			       readbuf, ret,
			       GNUNET_NO, GNUNET_NO);
  }
  GNUNET_SERVER_mst_destroy (stdin_mst);
  return 0;
}
