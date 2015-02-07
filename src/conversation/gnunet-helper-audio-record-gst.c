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
 * @file conversation/gnunet-helper-audio-record-gst.c
 * @brief program to record audio data from the microphone (GStreamer version)
 * @author LRN
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "conversation.h"
#include "gnunet_constants.h"
#include "gnunet_core_service.h"

#include <gst/gst.h>
#include <gst/app/gstappsink.h>
#include <gst/audio/gstaudiobasesrc.h>
#include <glib.h>

#define DEBUG_RECORD_PURE_OGG 1

/**
 * Number of channels.
 * Must be one of the following (from libopusenc documentation):
 * 1, 2
 */
#define OPUS_CHANNELS 1

/**
 * Maximal size of a single opus packet.
 */
#define MAX_PAYLOAD_SIZE (1024 / OPUS_CHANNELS)

/**
 * Size of a single frame fed to the encoder, in ms.
 * Must be one of the following (from libopus documentation):
 * 2.5, 5, 10, 20, 40 or 60
 */
#define OPUS_FRAME_SIZE 40

/**
 * Expected packet loss to prepare for, in percents.
 */
#define PACKET_LOSS_PERCENTAGE 1

/**
 * Set to 1 to enable forward error correction.
 * Set to 0 to disable.
 */
#define INBAND_FEC_MODE 1

/**
 * Max number of microseconds to buffer in audiosource.
 * Default is 200000
 */
#define BUFFER_TIME 1000 /* 1ms */

/**
 * Min number of microseconds to buffer in audiosource.
 * Default is 10000
 */
#define LATENCY_TIME 1000 /* 1ms */

/**
 * Maximum delay in multiplexing streams, in ns.
 * Setting this to 0 forces page flushing, which
 * decreases delay, but increases overhead.
 */
#define OGG_MAX_DELAY 0

/**
 * Maximum delay for sending out a page, in ns.
 * Setting this to 0 forces page flushing, which
 * decreases delay, but increases overhead.
 */
#define OGG_MAX_PAGE_DELAY 0

/**
 * Main pipeline.
 */
static GstElement *pipeline;

#ifdef DEBUG_RECORD_PURE_OGG
static int dump_pure_ogg;
#endif

static void
quit ()
{
  if (NULL != pipeline)
    gst_element_set_state (pipeline, GST_STATE_NULL);
}

static gboolean
bus_call (GstBus *bus, GstMessage *msg, gpointer data)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Bus message\n");
  switch (GST_MESSAGE_TYPE (msg))
  {
  case GST_MESSAGE_EOS:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "End of stream\n");
    quit ();
    break;

  case GST_MESSAGE_ERROR:
    {
      gchar  *debug;
      GError *error;

      gst_message_parse_error (msg, &error, &debug);
      g_free (debug);

      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error: %s\n", error->message);
      g_error_free (error);

      quit ();
      break;
    }
  default:
    break;
  }

  return TRUE;
}

void
source_child_added (GstChildProxy *child_proxy, GObject *object, gchar *name, gpointer user_data)
{
  if (GST_IS_AUDIO_BASE_SRC (object))
    g_object_set (object, "buffer-time", (gint64) BUFFER_TIME, "latency-time", (gint64) LATENCY_TIME, NULL);
}

static void
signalhandler (int s)
{
  quit ();
}


int
main (int argc, char **argv)
{
  GstElement *source, *filter, *encoder, *conv, *resampler, *sink, *oggmux;
  GstCaps *caps;
  GstBus *bus;
  guint bus_watch_id;
  struct AudioMessage audio_message;
  int abort_send = 0;

  typedef void (*SignalHandlerPointer) (int);

  SignalHandlerPointer inthandler, termhandler;
  inthandler = signal (SIGINT, signalhandler);
  termhandler = signal (SIGTERM, signalhandler);

#ifdef DEBUG_RECORD_PURE_OGG
  dump_pure_ogg = getenv ("GNUNET_RECORD_PURE_OGG") ? 1 : 0;
#endif

#ifdef WINDOWS
  setmode (1, _O_BINARY);
#endif

  /* Initialisation */
  gst_init (&argc, &argv);

  GNUNET_assert (GNUNET_OK ==
		 GNUNET_log_setup ("gnunet-helper-audio-record",
				   "WARNING",
				   NULL));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Audio source starts\n");

  audio_message.header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO);

  /* Create gstreamer elements */
  pipeline = gst_pipeline_new ("audio-recorder");
  source   = gst_element_factory_make ("autoaudiosrc",  "audiosource");
  filter   = gst_element_factory_make ("capsfilter",    "filter");
  conv     = gst_element_factory_make ("audioconvert",  "converter");
  resampler= gst_element_factory_make ("audioresample", "resampler");
  encoder  = gst_element_factory_make ("opusenc",       "opus-encoder");
  oggmux   = gst_element_factory_make ("oggmux",        "ogg-muxer");
  sink     = gst_element_factory_make ("appsink",       "audio-output");

  if (!pipeline || !filter || !source || !conv || !resampler || !encoder || !oggmux || !sink)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        "One element could not be created. Exiting.\n");
    return -1;
  }

  g_signal_connect (source, "child-added", G_CALLBACK (source_child_added), NULL);

  /* Set up the pipeline */

  caps = gst_caps_new_simple ("audio/x-raw",
    "format", G_TYPE_STRING, "S16LE",
/*    "rate", G_TYPE_INT, SAMPLING_RATE,*/
    "channels", G_TYPE_INT, OPUS_CHANNELS,
/*    "layout", G_TYPE_STRING, "interleaved",*/
     NULL);
  g_object_set (G_OBJECT (filter),
      "caps", caps,
      NULL);
  gst_caps_unref (caps);

  g_object_set (G_OBJECT (encoder),
/*      "bitrate", 64000, */
/*      "bandwidth", OPUS_BANDWIDTH_FULLBAND, */
      "inband-fec", INBAND_FEC_MODE,
      "packet-loss-percentage", PACKET_LOSS_PERCENTAGE,
      "max-payload-size", MAX_PAYLOAD_SIZE,
      "audio", FALSE, /* VoIP, not audio */
      "frame-size", OPUS_FRAME_SIZE,
      NULL);

  g_object_set (G_OBJECT (oggmux),
      "max-delay", OGG_MAX_DELAY,
      "max-page-delay", OGG_MAX_PAGE_DELAY,
      NULL);

  /* we add a message handler */
  bus = gst_pipeline_get_bus (GST_PIPELINE (pipeline));
  bus_watch_id = gst_bus_add_watch (bus, bus_call, pipeline);
  gst_object_unref (bus);

  /* we add all elements into the pipeline */
  /* audiosource | converter | resampler | opus-encoder | audio-output */
  gst_bin_add_many (GST_BIN (pipeline), source, filter, conv, resampler, encoder,
      oggmux, sink, NULL);

  /* we link the elements together */
  gst_element_link_many (source, filter, conv, resampler, encoder, oggmux, sink, NULL);

  /* Set the pipeline to "playing" state*/
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Now playing\n");
  gst_element_set_state (pipeline, GST_STATE_PLAYING);


  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Running...\n");
  /* Iterate */
  while (!abort_send)
  {
    GstSample *s;
    GstBuffer *b;
    GstMapInfo m;
    size_t len, msg_size;
    const char *ptr;
    int phase;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "pulling...\n");
    s = gst_app_sink_pull_sample (GST_APP_SINK (sink));
    if (NULL == s)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "pulled NULL\n");
      break;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "...pulled!\n");
    {
      const GstStructure *si;
      char *si_str;
      GstCaps *s_caps;
      char *caps_str;
      si = gst_sample_get_info (s);
      if (si)
      {
        si_str = gst_structure_to_string (si);
        if (si_str)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got sample %s\n", si_str);
          g_free (si_str);
        }
      }
      else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got sample with no info\n");
      s_caps = gst_sample_get_caps (s);
      if (s_caps)
      {
        caps_str = gst_caps_to_string (s_caps);
        if (caps_str)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got sample with caps %s\n", caps_str);
          g_free (caps_str);
        }
      }
      else
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got sample with no caps\n");
    }
    b = gst_sample_get_buffer (s);
    if (NULL == b || !gst_buffer_map (b, &m, GST_MAP_READ))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got NULL buffer %p or failed to map the buffer\n", b);
      gst_sample_unref (s);
      continue;
    }

    len = m.size;
    if (len > UINT16_MAX - sizeof (struct AudioMessage))
    {
      GNUNET_break (0);
      len = UINT16_MAX - sizeof (struct AudioMessage);
    }
    msg_size = sizeof (struct AudioMessage) + len;
    audio_message.header.size = htons ((uint16_t) msg_size);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "Sending %u bytes of audio data\n", (unsigned int) msg_size);
    for (phase = 0; phase < 2; phase++)
    {
      size_t offset;
      size_t to_send;
      ssize_t ret;
      if (0 == phase)
      {
#ifdef DEBUG_RECORD_PURE_OGG
        if (dump_pure_ogg)
          continue;
#endif
        ptr = (const char *) &audio_message;
        to_send = sizeof (audio_message);
      }
      else
      {
        ptr = (const char *) m.data;
        to_send = len;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
          "Sending %u bytes on phase %d\n", (unsigned int) to_send, phase);
      for (offset = 0; offset < to_send; offset += ret)
      {
        ret = write (1, &ptr[offset], to_send - offset);
        if (0 >= ret)
        {
          if (-1 == ret)
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to write %u bytes at offset %u (total %u) in phase %d: %s\n",
                (unsigned int) to_send - offset, (unsigned int) offset,
                (unsigned int) (to_send + offset), phase, strerror (errno));
          abort_send = 1;
          break;
        }
      }
      if (abort_send)
        break;
    }
    gst_buffer_unmap (b, &m);
    gst_sample_unref (s);
  }

  signal (SIGINT, inthandler);
  signal (SIGINT, termhandler);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Returned, stopping playback\n");
  quit ();

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Deleting pipeline\n");
  gst_object_unref (GST_OBJECT (pipeline));
  pipeline = NULL;
  g_source_remove (bus_watch_id);

  return 0;
}
