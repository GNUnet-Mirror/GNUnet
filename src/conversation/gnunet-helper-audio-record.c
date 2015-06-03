/*
     This file is part of GNUnet.
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
 * @file conversation/gnunet-helper-audio-record.c
 * @brief program to record audio data from the microphone
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
#include <ogg/ogg.h>

#define DEBUG_RECORD_PURE_OGG 1

/**
 * Sampling rate
 */
#define SAMPLING_RATE 48000

/**
 * How many ms of audio to buffer before encoding them.
 * Possible values:
 * 60, 40, 20, 10, 5, 2.5
 */
#define FRAME_SIZE_MS 40

/**
 * How many samples to buffer before encoding them.
 */
#define FRAME_SIZE (SAMPLING_RATE / 1000 * FRAME_SIZE_MS)

/**
 * Pages are commited when their size goes over this value.
 * Note that in practice we flush pages VERY often (every frame),
 * which means that pages NEVER really get to be this big.
 * With one-packet-per-page, pages are roughly 100-300 bytes each.
 *
 * This value is chosen to make MAX_PAYLOAD_BYTES=1024 fit
 * into a single page.
 */
#define PAGE_WATERLINE 800

/**
 * Maximum length of opus payload
 */
#define MAX_PAYLOAD_BYTES 1024

/**
 * Number of channels
 */
#define CHANNELS 1

/**
 * Configures the encoder's expected packet loss percentage.
 *
 * Higher values will trigger progressively more loss resistant behavior
 * in the encoder at the expense of quality at a given bitrate
 * in the lossless case, but greater quality under loss.
 */
#define CONV_OPUS_PACKET_LOSS_PERCENTAGE 1

/**
 * Configures the encoder's computational complexity.
 *
 * The supported range is 0-10 inclusive with 10 representing
 * the highest complexity.
 */
#define CONV_OPUS_ENCODING_COMPLEXITY 10

/**
 * Configures the encoder's use of inband forward error correction (FEC).
 *
 * Note: This is only applicable to the LPC layer.
 */
#define CONV_OPUS_INBAND_FEC 1

/**
 * Configures the type of signal being encoded.
 *
 * This is a hint which helps the encoder's mode selection.
 *
 * Possible values:
 * OPUS_AUTO - (default) Encoder detects the type automatically.
 * OPUS_SIGNAL_VOICE - Bias thresholds towards choosing LPC or Hybrid modes.
 * OPUS_SIGNAL_MUSIC - Bias thresholds towards choosing MDCT modes.
 */
#define CONV_OPUS_SIGNAL OPUS_SIGNAL_VOICE

/**
 * Coding mode.
 *
 * Possible values:
 * OPUS_APPLICATION_VOIP - gives best quality at a given bitrate for voice
 * signals. It enhances the input signal by high-pass filtering and
 * emphasizing formants and harmonics. Optionally it includes in-band forward
 * error correction to protect against packet loss. Use this mode for typical
 * VoIP applications. Because of the enhancement, even at high bitrates
 * the output may sound different from the input.
 * OPUS_APPLICATION_AUDIO - gives best quality at a given bitrate for most
 * non-voice signals like music. Use this mode for music and mixed
 * (music/voice) content, broadcast, and applications requiring less than
 * 15 ms of coding delay.
 * OPUS_APPLICATION_RESTRICTED_LOWDELAY - configures low-delay mode that
 * disables the speech-optimized mode in exchange for slightly reduced delay.
 * This mode can only be set on an newly initialized or freshly reset encoder
 * because it changes the codec delay.
 */
#define CONV_OPUS_APP_TYPE OPUS_APPLICATION_VOIP

/**
 * Specification for recording. May change in the future to spec negotiation.
 */
static pa_sample_spec sample_spec = {
  .format = PA_SAMPLE_FLOAT32LE,
  .rate = SAMPLING_RATE,
  .channels = CHANNELS
};

GNUNET_NETWORK_STRUCT_BEGIN

/* OggOpus spec says the numbers must be in little-endian order */
struct OpusHeadPacket
{
  uint8_t magic[8];
  uint8_t version;
  uint8_t channels;
  uint16_t preskip GNUNET_PACKED;
  uint32_t sampling_rate GNUNET_PACKED;
  uint16_t gain GNUNET_PACKED;
  uint8_t channel_mapping;
};

struct OpusCommentsPacket
{
  uint8_t magic[8];
  uint32_t vendor_length;
  /* followed by:
     char vendor[vendor_length];
     uint32_t string_count;
     followed by @a string_count pairs of:
       uint32_t string_length;
       char string[string_length];
   */
};

GNUNET_NETWORK_STRUCT_END

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
 * Buffer for encoded data
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
 * Ogg muxer state
 */
static ogg_stream_state os;

/**
 * Ogg packet id
 */
static int32_t packet_id;

/**
 * Ogg granule for current packet
 */
static int64_t enc_granulepos;

#ifdef DEBUG_RECORD_PURE_OGG
/**
 * 1 to not to write GNUnet message headers,
 * producing pure playable ogg output
 */
static int dump_pure_ogg;
#endif

/**
 * Pulseaudio shutdown task
 */
static void
quit (int ret)
{
  mainloop_api->quit (mainloop_api, ret);
  exit (ret);
}


static void
write_data (const char *ptr, size_t msg_size)
{
  ssize_t ret;
  size_t off;
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

static void
write_page (ogg_page *og)
{
  static unsigned long long toff;
  size_t msg_size;
  msg_size = sizeof (struct AudioMessage) + og->header_len + og->body_len;
  audio_message->header.size = htons ((uint16_t) msg_size);
  memcpy (&audio_message[1], og->header, og->header_len);
  memcpy (((char *) &audio_message[1]) + og->header_len, og->body, og->body_len);

  toff += msg_size;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending %u bytes of audio data (total: %llu)\n",
              (unsigned int) msg_size,
              toff);
#ifdef DEBUG_RECORD_PURE_OGG
  if (dump_pure_ogg)
    write_data ((const char *) &audio_message[1], og->header_len + og->body_len);
  else
#endif
    write_data ((const char *) audio_message, msg_size);
}

/**
 * Creates OPUS packets from PCM data
 */
static void
packetizer ()
{
  char *nbuf;
  size_t new_size;
  int32_t len;
  ogg_packet op;
  ogg_page og;

  while (transmit_buffer_length >= transmit_buffer_index + pcm_length)
  {
    memcpy (pcm_buffer,
	    &transmit_buffer[transmit_buffer_index],
	    pcm_length);
    transmit_buffer_index += pcm_length;
    len =
      opus_encode_float (enc, pcm_buffer, FRAME_SIZE, opus_data,
			 MAX_PAYLOAD_BYTES);

    if (len < 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("opus_encode_float() failed: %s. Aborting\n"),
                  opus_strerror (len));
      quit (5);
    }
    if (len > UINT16_MAX - sizeof (struct AudioMessage))
    {
      GNUNET_break (0);
      continue;
    }

    /* As per OggOpus spec, granule is calculated as if the audio
       had 48kHz sampling rate. */
    enc_granulepos += FRAME_SIZE * 48000 / SAMPLING_RATE;

    op.packet = (unsigned char *) opus_data;
    op.bytes = len;
    op.b_o_s = 0;
    op.e_o_s = 0;
    op.granulepos = enc_granulepos;
    op.packetno = packet_id++;
    ogg_stream_packetin (&os, &op);

    while (ogg_stream_flush_fill (&os, &og, PAGE_WATERLINE))
    {
      if (og.header_len + og.body_len > UINT16_MAX - sizeof (struct AudioMessage))
      {
        GNUNET_assert (0);
        continue;
      }
      write_page (&og);
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
      char cmt[PA_CHANNEL_MAP_SNPRINT_MAX];
      char sst[PA_SAMPLE_SPEC_SNPRINT_MAX];

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
				       PA_STREAM_ADJUST_LATENCY)) < 0)
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
  int err;

  pcm_length = FRAME_SIZE * CHANNELS * sizeof (float);
  pcm_buffer = pa_xmalloc (pcm_length);
  opus_data = GNUNET_malloc (MAX_PAYLOAD_BYTES);
  enc = opus_encoder_create (SAMPLING_RATE,
			     CHANNELS,
			     CONV_OPUS_APP_TYPE,
			     &err);
  opus_encoder_ctl (enc,
		    OPUS_SET_PACKET_LOSS_PERC (CONV_OPUS_PACKET_LOSS_PERCENTAGE));
  opus_encoder_ctl (enc,
		    OPUS_SET_COMPLEXITY (CONV_OPUS_ENCODING_COMPLEXITY));
  opus_encoder_ctl (enc,
		    OPUS_SET_INBAND_FEC (CONV_OPUS_INBAND_FEC));
  opus_encoder_ctl (enc,
		    OPUS_SET_SIGNAL (CONV_OPUS_SIGNAL));
}

static void
ogg_init ()
{
  int serialno;
  struct OpusHeadPacket headpacket;
  struct OpusCommentsPacket *commentspacket;
  size_t commentspacket_len;

  serialno = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, 0x7FFFFFFF);

  /*Initialize Ogg stream struct*/
  if (-1 == ogg_stream_init (&os, serialno))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("ogg_stream_init() failed.\n"));
    exit (3);
  }

  packet_id = 0;

  /*Write header*/
  {
    ogg_packet op;
    ogg_page og;
    const char *opusver;
    int vendor_length;

    memcpy (headpacket.magic, "OpusHead", 8);
    headpacket.version = 1;
    headpacket.channels = CHANNELS;
    headpacket.preskip = GNUNET_htole16 (0);
    headpacket.sampling_rate = GNUNET_htole32 (SAMPLING_RATE);
    headpacket.gain = GNUNET_htole16 (0);
    headpacket.channel_mapping = 0; /* Mono or stereo */

    op.packet = (unsigned char *) &headpacket;
    op.bytes = sizeof (headpacket);
    op.b_o_s = 1;
    op.e_o_s = 0;
    op.granulepos = 0;
    op.packetno = packet_id++;
    ogg_stream_packetin (&os, &op);

    /* Head packet must be alone on its page */
    while (ogg_stream_flush (&os, &og))
    {
      write_page (&og);
    }

    commentspacket_len = sizeof (*commentspacket);
    opusver = opus_get_version_string ();
    vendor_length = strlen (opusver);
    commentspacket_len += vendor_length;
    commentspacket_len += sizeof (uint32_t);

    commentspacket = (struct OpusCommentsPacket *) malloc (commentspacket_len);
    if (NULL == commentspacket)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to allocate %d bytes for second packet\n"),
                  commentspacket_len);
      exit (5);
    }

    memcpy (commentspacket->magic, "OpusTags", 8);
    commentspacket->vendor_length = GNUNET_htole32 (vendor_length);
    memcpy (&commentspacket[1], opusver, vendor_length);
    *(uint32_t *) &((char *) &commentspacket[1])[vendor_length] = \
        GNUNET_htole32 (0); /* no tags */

    op.packet = (unsigned char *) commentspacket;
    op.bytes = commentspacket_len;
    op.b_o_s = 0;
    op.e_o_s = 0;
    op.granulepos = 0;
    op.packetno = packet_id++;
    ogg_stream_packetin (&os, &op);

    /* Comment packets must not be mixed with audio packets on their pages */
    while (ogg_stream_flush (&os, &og))
    {
      write_page (&og);
    }

    free (commentspacket);
  }
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
				   "WARNING",
				   NULL));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Audio source starts\n");
  audio_message = GNUNET_malloc (UINT16_MAX);
  audio_message->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO);

#ifdef DEBUG_RECORD_PURE_OGG
  dump_pure_ogg = getenv ("GNUNET_RECORD_PURE_OGG") ? 1 : 0;
#endif
  ogg_init ();
  opus_init ();
  pa_init ();
  return 0;
}
