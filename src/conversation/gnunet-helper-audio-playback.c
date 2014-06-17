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
#include <ogg/ogg.h>

#define DEBUG_READ_PURE_OGG 1
#define DEBUG_DUMP_DECODED_OGG 1

#define MAXLINE 4096

#define SAMPLING_RATE 48000

#define CHANNELS 1

/* 120ms at 48000 */
#define MAX_FRAME_SIZE (960 * 6)

/**
 * Pulseaudio specification. May change in the future.
 */
static pa_sample_spec sample_spec = {
  .format = PA_SAMPLE_FLOAT32LE,
  .rate = SAMPLING_RATE,
  .channels = CHANNELS
};

#ifdef DEBUG_DUMP_DECODED_OGG
static int dump_to_stdout;
#endif

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
 * Number of samples for one frame
 */
static int frame_size;

/**
 * Pipe we use to signal the main loop that we are ready to receive.
 */
static int ready_pipe[2];

/**
 * Ogg I/O state.
 */
static ogg_sync_state oy;

/**
 * Ogg stream state.
 */
static ogg_stream_state os;

static int channels;

static int preskip;

static float gain;

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

GNUNET_NETWORK_STRUCT_END

/*Process an Opus header and setup the opus decoder based on it.
  It takes several pointers for header values which are needed
  elsewhere in the code.*/
static OpusDecoder *
process_header (ogg_packet *op)
{
  int err;
  OpusDecoder *dec;
  struct OpusHeadPacket header;

  if (op->bytes < sizeof (header))
    return NULL;
  memcpy (&header, op->packet, sizeof (header));
  header.preskip = GNUNET_le16toh (header.preskip);
  header.sampling_rate = GNUNET_le32toh (header.sampling_rate);
  header.gain = GNUNET_le16toh (header.gain);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Header: v%u, %u-ch, skip %u, %uHz, %u gain\n",
               header.version, header.channels, header.preskip, header.sampling_rate, header.gain);

  channels = header.channels;
  preskip = header.preskip;

  if (header.channel_mapping != 0)
  {
    fprintf (stderr, "This implementation does not support non-mono streams\n");
    return NULL;
  }

  dec = opus_decoder_create (SAMPLING_RATE, channels, &err);
  if (OPUS_OK != err)
  {
    fprintf (stderr, "Cannot create encoder: %s\n", opus_strerror (err));
    return NULL;
  }
  if (!dec)
  {
    fprintf (stderr, "Decoder initialization failed: %s\n", opus_strerror (err));
    return NULL;
  }

  if (0 != header.gain)
  {
    /*Gain API added in a newer libopus version, if we don't have it
      we apply the gain ourselves. We also add in a user provided
      manual gain at the same time.*/
    int gainadj = (int) header.gain;
    err = opus_decoder_ctl (dec, OPUS_SET_GAIN (gainadj));
    if(OPUS_UNIMPLEMENTED == err)
    {
      gain = pow (10.0, gainadj / 5120.0);
    }
    else if (OPUS_OK != err)
    {
      fprintf (stderr, "Error setting gain: %s\n", opus_strerror (err));
      return NULL;
    }
  }

  return dec;
}


#ifdef DEBUG_DUMP_DECODED_OGG
static size_t fwrite_le32(opus_int32 i32, FILE *file)
{
   unsigned char buf[4];
   buf[0]=(unsigned char)(i32&0xFF);
   buf[1]=(unsigned char)(i32>>8&0xFF);
   buf[2]=(unsigned char)(i32>>16&0xFF);
   buf[3]=(unsigned char)(i32>>24&0xFF);
   return fwrite(buf,4,1,file);
}

static size_t fwrite_le16(int i16, FILE *file)
{
   unsigned char buf[2];
   buf[0]=(unsigned char)(i16&0xFF);
   buf[1]=(unsigned char)(i16>>8&0xFF);
   return fwrite(buf,2,1,file);
}

static int write_wav_header()
{
   int ret;
   FILE *file = stdout;

   ret = fprintf (file, "RIFF") >= 0;
   ret &= fwrite_le32 (0x7fffffff, file);

   ret &= fprintf (file, "WAVEfmt ") >= 0;
   ret &= fwrite_le32 (16, file);
   ret &= fwrite_le16 (1, file);
   ret &= fwrite_le16 (channels, file);
   ret &= fwrite_le32 (SAMPLING_RATE, file);
   ret &= fwrite_le32 (2*channels*SAMPLING_RATE, file);
   ret &= fwrite_le16 (2*channels, file);
   ret &= fwrite_le16 (16, file);

   ret &= fprintf (file, "data") >= 0;
   ret &= fwrite_le32 (0x7fffffff, file);

   return !ret ? -1 : 16;
}

#endif

static int64_t
audio_write (int64_t maxout)
{
  int64_t sampout = 0;
  int tmp_skip;
  unsigned out_len;
  unsigned to_write;
  float *output;
#ifdef DEBUG_DUMP_DECODED_OGG
  static int wrote_wav_header;

  if (dump_to_stdout && !wrote_wav_header)
  {
    write_wav_header ();
    wrote_wav_header = 1;
  }
#endif
  maxout = 0 > maxout ? 0 : maxout;
  do
  {
    tmp_skip = (preskip > frame_size) ? (int) frame_size : preskip;
    preskip -= tmp_skip;
    output = pcm_buffer + channels * tmp_skip;
    out_len = frame_size - tmp_skip;
    if (out_len > MAX_FRAME_SIZE)
      exit (6);
    frame_size = 0;

    to_write = out_len < maxout ? out_len : (unsigned) maxout;
    if (0 < maxout)
    {
      int64_t wrote = 0;
      wrote = to_write;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Writing %u * %u * %u = %u bytes into PA\n",
                  to_write, channels, sizeof (float),
                  to_write * channels * sizeof (float));
#ifdef DEBUG_DUMP_DECODED_OGG
      if (dump_to_stdout)
      {
# define fminf(_x,_y) ((_x)<(_y)?(_x):(_y))
# define fmaxf(_x,_y) ((_x)>(_y)?(_x):(_y))
# define float2int(flt) ((int)(floor(.5+flt)))
        int i;
        int16_t *out = alloca(sizeof(short)*MAX_FRAME_SIZE*channels);
        for (i=0;i<(int)out_len*channels;i++)
          out[i]=(short)float2int(fmaxf(-32768,fminf(output[i]*32768.f,32767)));

        fwrite (out, 2 * channels, out_len<maxout?out_len:maxout, stdout);
      }
      else
#endif
      if (pa_stream_write
          (stream_out, output, to_write * channels * sizeof (float), NULL, 0,
          PA_SEEK_RELATIVE) < 0)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
  	            _("pa_stream_write() failed: %s\n"),
                    pa_strerror (pa_context_errno (context)));
      }
      sampout += wrote;
      maxout -= wrote;
    }
  } while (0 < frame_size && 0 < maxout);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Wrote %" PRId64 " samples\n",
              sampout);
  return sampout;
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


static void
ogg_demux_and_decode ()
{
  ogg_page og;
  static int stream_init;
  int64_t page_granule = 0;
  ogg_packet op;
  static int has_opus_stream;
  static int has_tags_packet;
  static int32_t opus_serialno;
  static int64_t link_out;
  static int64_t packet_count;
  int eos = 0;
  static int total_links;
  static int gran_offset;

  while (1 == ogg_sync_pageout (&oy, &og))
  {
    if (0 == stream_init)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Initialized the stream\n");
      ogg_stream_init (&os, ogg_page_serialno (&og));
      stream_init = 1;
    }
    if (ogg_page_serialno (&og) != os.serialno)
    {
      /* so all streams are read. */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Re-set serial number\n");
      ogg_stream_reset_serialno (&os, ogg_page_serialno (&og));
    }
    /*Add page to the bitstream*/
    ogg_stream_pagein (&os, &og);
    page_granule = ogg_page_granulepos (&og);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Reading page that ends at %" PRId64 "\n",
                page_granule);
    /*Extract all available packets*/
    while (1 == ogg_stream_packetout (&os, &op))
    {
      /*OggOpus streams are identified by a magic string in the initial
        stream header.*/
      if (op.b_o_s && op.bytes >= 8 && !memcmp (op.packet, "OpusHead", 8))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Got Opus Header\n");
        if (has_opus_stream && has_tags_packet)
        {
          /*If we're seeing another BOS OpusHead now it means
            the stream is chained without an EOS.
            This can easily happen if record helper is terminated unexpectedly.
           */
          has_opus_stream = 0;
          if (dec)
            opus_decoder_destroy (dec);
          dec = NULL;
          fprintf (stderr, "\nWarning: stream %" PRId64 " ended without EOS and a new stream began.\n", (int64_t) os.serialno);
        }
        if (!has_opus_stream)
        {
          if (packet_count > 0 && opus_serialno == os.serialno)
          {
            fprintf (stderr, "\nError: Apparent chaining without changing serial number (%" PRId64 "==%" PRId64 ").\n",
              (int64_t) opus_serialno, (int64_t) os.serialno);
            quit(1);
          }
          opus_serialno = os.serialno;
          has_opus_stream = 1;
          has_tags_packet = 0;
          link_out = 0;
          packet_count = 0;
          eos = 0;
          total_links++;
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Got header for stream %" PRId64 ", this is %dth link\n",
                      (int64_t) opus_serialno, total_links);
        }
        else
        {
          fprintf (stderr, "\nWarning: ignoring opus stream %" PRId64 "\n", (int64_t) os.serialno);
        }
      }
      if (!has_opus_stream || os.serialno != opus_serialno)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "breaking out\n");
        break;
      }
      /*If first packet in a logical stream, process the Opus header*/
      if (0 == packet_count)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Decoding header\n");
        dec = process_header (&op);
        if (!dec)
           quit (1);

        if (0 != ogg_stream_packetout (&os, &op) || 255 == og.header[og.header_len - 1])
        {
          /*The format specifies that the initial header and tags packets are on their
            own pages. To aid implementors in discovering that their files are wrong
            we reject them explicitly here. In some player designs files like this would
            fail even without an explicit test.*/
          fprintf (stderr, "Extra packets on initial header page. Invalid stream.\n");
          quit (1);
        }

        /*Remember how many samples at the front we were told to skip
          so that we can adjust the timestamp counting.*/
        gran_offset = preskip;

        if (!pcm_buffer)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Allocating %u * %u * %u = %u bytes of buffer space\n",
                  MAX_FRAME_SIZE, channels, sizeof (float),
                  MAX_FRAME_SIZE * channels * sizeof (float));
          pcm_buffer = pa_xmalloc (sizeof (float) * MAX_FRAME_SIZE * channels);
        }
      }
      else if (1 == packet_count)
      {
        has_tags_packet = 1;
        if (0 != ogg_stream_packetout (&os, &op) || 255 == og.header[og.header_len - 1])
        {
          fprintf (stderr, "Extra packets on initial tags page. Invalid stream.\n");
          quit (1);
        }
      }
      else
      {
        int ret;
        int64_t maxout;
        int64_t outsamp;

        /*End of stream condition*/
        if (op.e_o_s && os.serialno == opus_serialno)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Got EOS\n");
          eos = 1; /* don't care for anything except opus eos */
        }

        /*Decode Opus packet*/
        ret = opus_decode_float (dec,
			         (const unsigned char *) op.packet,
			         op.bytes,
			         pcm_buffer,
			         MAX_FRAME_SIZE, 0);

        /*If the decoder returned less than zero, we have an error.*/
        if (0 > ret)
        {
          fprintf (stderr, "Decoding error: %s\n", opus_strerror (ret));
          break;
        }
        frame_size = ret;
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Decoded %d bytes/channel (%d bytes) from %u compressed bytes\n",
                    ret, ret * channels, op.bytes);

        /*Apply header gain, if we're not using an opus library new
          enough to do this internally.*/
        if (0 != gain)
        {
          int i;
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Applying gain %f\n",
                      gain);
          for (i = 0; i < frame_size * channels; i++)
            pcm_buffer[i] *= gain;
        }

        /*This handles making sure that our output duration respects
          the final end-trim by not letting the output sample count
          get ahead of the granpos indicated value.*/
        maxout = ((page_granule - gran_offset) * SAMPLING_RATE / 48000) - link_out;
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Writing audio packet %" PRId64 ", at most %" PRId64 " samples\n",
                    packet_count, maxout);

        outsamp = audio_write (0 > maxout ? 0 : maxout);
        link_out += outsamp;
      }
      packet_count++;
    }
    if (eos)
    {
      has_opus_stream = 0;
      if (dec)
        opus_decoder_destroy (dec);
      dec = NULL;
    }
  }
}

/**
 * Message callback
 */
static int
stdin_receiver (void *cls,
		void *client,
		const struct GNUNET_MessageHeader *msg)
{
  struct AudioMessage *audio;
  char *data;
  size_t payload_len;

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO:
    audio = (struct AudioMessage *) msg;
    payload_len = ntohs (audio->header.size) - sizeof (struct AudioMessage);

    /*Get the ogg buffer for writing*/
    data = ogg_sync_buffer (&oy, payload_len);
    /*Read bitstream from input file*/
    memcpy (data, (const unsigned char *) &audio[1], payload_len);
    ogg_sync_wrote (&oy, payload_len);

    ogg_demux_and_decode ();
    break;
  default:
    break;
  }
  return GNUNET_OK;
}


/**
 * Callback when data is there for playback
 */
static void
stream_write_callback (pa_stream *s,
		       size_t length,
		       void *userdata)
{
  /* unblock 'main' */
  if (-1 != ready_pipe[1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Unblocking main loop!\n");
    (void) write (ready_pipe[1], "r", 1);
  }
}


/**
 * Exit callback for SIGTERM and SIGINT
 */
static void
exit_signal_callback (pa_mainloop_api *m,
                      pa_signal_event *e,
                      int sig,
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
context_state_callback (pa_context *c,
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
    GNUNET_assert (! stream_out);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Connection established.\n"));
    if (! (stream_out =
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


static void
ogg_init ()
{
  ogg_sync_init (&oy);
}

static void
drain_callback (pa_stream*s, int success, void *userdata)
{
  pa_threaded_mainloop_signal (m, 0);
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
#ifdef DEBUG_READ_PURE_OGG
  int read_pure_ogg = getenv ("GNUNET_READ_PURE_OGG") ? 1 : 0;
#endif

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
  ogg_init ();
  pa_init ();
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Waiting for PulseAudio to be ready.\n");
  GNUNET_assert (1 == read (ready_pipe[0], &c, 1));
  close (ready_pipe[0]);
  close (ready_pipe[1]);
  ready_pipe[0] = -1;
  ready_pipe[1] = -1;
#ifdef DEBUG_DUMP_DECODED_OGG
  dump_to_stdout = getenv ("GNUNET_DUMP_DECODED_OGG") ? 1 : 0;
#endif
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
#ifdef DEBUG_READ_PURE_OGG
    if (read_pure_ogg)
    {
      char *data = ogg_sync_buffer (&oy, ret);
      memcpy (data, readbuf, ret);
      ogg_sync_wrote (&oy, ret);
      ogg_demux_and_decode ();
    }
    else
#endif
    GNUNET_SERVER_mst_receive (stdin_mst, NULL,
			       readbuf, ret,
			       GNUNET_NO, GNUNET_NO);
  }
  GNUNET_SERVER_mst_destroy (stdin_mst);
  if (stream_out)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Locking\n");
    pa_threaded_mainloop_lock (m);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Draining\n");
    pa_operation *o = pa_stream_drain (stream_out, drain_callback, NULL);
    while (pa_operation_get_state (o) == PA_OPERATION_RUNNING)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Waiting\n");
      pa_threaded_mainloop_wait (m);
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Unreffing\n");
    pa_operation_unref (o);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Unlocking\n");
    pa_threaded_mainloop_unlock (m);
  }
  return 0;
}
