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
 * @file conversation/gnunet-helper-audio-playback-gst.c
 * @brief program to playback audio data to the speaker (GStreamer version)
 * @author LRN
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "conversation.h"
#include "gnunet_constants.h"
#include "gnunet_core_service.h"

#include <gst/gst.h>
#include <gst/audio/gstaudiobasesrc.h>
#include <gst/app/gstappsrc.h>
#include <glib.h>

#define DEBUG_READ_PURE_OGG 1

/**
 * How much data to read in one go
 */
#define MAXLINE 4096

/**
 * Max number of microseconds to buffer in audiosink.
 * Default is 1000
 */
#define BUFFER_TIME 1000

/**
 * Min number of microseconds to buffer in audiosink.
 * Default is 1000
 */
#define LATENCY_TIME 1000

/**
 * Tokenizer for the data we get from stdin
 */
struct GNUNET_SERVER_MessageStreamTokenizer *stdin_mst;

/**
 * Main pipeline.
 */
static GstElement *pipeline;

/**
 * Appsrc instance into which we write data for the pipeline.
 */
static GstElement *source;

static GstElement *demuxer;
static GstElement *decoder;
static GstElement *conv;
static GstElement *resampler;
static GstElement *sink;

/**
 * Set to 1 to break the reading loop
 */
static int abort_read;


static void
sink_child_added (GstChildProxy *child_proxy,
		  GObject *object, 
		  gchar *name,
		  gpointer user_data)
{
  if (GST_IS_AUDIO_BASE_SRC (object))
    g_object_set (object,
		  "buffer-time", (gint64) BUFFER_TIME, 
		  "latency-time", (gint64) LATENCY_TIME,
		  NULL);
}


static void
ogg_pad_added (GstElement *element, 
	       GstPad *pad,
	       gpointer data)
{
  GstPad *sinkpad;
  GstElement *decoder = (GstElement *) data;

  /* We can now link this pad with the opus-decoder sink pad */
  sinkpad = gst_element_get_static_pad (decoder, "sink");

  gst_pad_link (pad, sinkpad);

  gst_element_link_many (decoder, conv, resampler, sink, NULL);

  gst_object_unref (sinkpad);
}


static void
quit ()
{
  if (NULL != source)
    gst_app_src_end_of_stream (GST_APP_SRC (source));
  if (NULL != pipeline)
    gst_element_set_state (pipeline, GST_STATE_NULL);
  abort_read = 1;
}


static gboolean
bus_call (GstBus *bus, GstMessage *msg, gpointer data)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Bus message\n");
  switch (GST_MESSAGE_TYPE (msg))
  {
  case GST_MESSAGE_EOS:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"End of stream\n");
    quit ();
    break;

  case GST_MESSAGE_ERROR:
    {
      gchar  *debug;
      GError *error;
      
      gst_message_parse_error (msg, &error, &debug);
      g_free (debug);
      
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		  "Error: %s\n", 
		  error->message);
      g_error_free (error);
      
      quit ();
      break;
    }
  default:
    break;
  }

  return TRUE;
}


static void
signalhandler (int s)
{
  quit ();
}


static int
feed_buffer_to_gst (const char *audio, size_t b_len)
{
  GstBuffer *b;
  gchar *bufspace;
  GstFlowReturn flow;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Feeding %u bytes to GStreamer\n",
	      (unsigned int) b_len);

  bufspace = g_memdup (audio, b_len);
  b = gst_buffer_new_wrapped (bufspace, b_len);
  if (NULL == b)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Failed to wrap a buffer\n");
    g_free (bufspace);
    return GNUNET_SYSERR;
  }
  flow = gst_app_src_push_buffer (GST_APP_SRC (source), b);
  /* They all return GNUNET_OK, because currently player stops when
   * data stops coming. This might need to be changed for the player
   * to also stop when pipeline breaks.
   */
  switch (flow)
  {
  case GST_FLOW_OK:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Fed %u bytes to the pipeline\n",
		(unsigned int) b_len);
    break;
  case GST_FLOW_FLUSHING:
    /* buffer was dropped, because pipeline state is not PAUSED or PLAYING */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Dropped a buffer\n");
    break;
  case GST_FLOW_EOS:
    /* end of stream */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
		"EOS\n");
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		"Unexpected push result\n");
    break;
  }
  return GNUNET_OK;
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
  size_t b_len;

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO:
    audio = (struct AudioMessage *) msg;

    b_len = ntohs (audio->header.size) - sizeof (struct AudioMessage);
    feed_buffer_to_gst ((const char *) &audio[1], b_len);
    break;
  default:
    break;
  }
  return GNUNET_OK;
}


int
main (int argc, char **argv)
{
  GstBus *bus;
  guint bus_watch_id;
  uint64_t toff;

  typedef void (*SignalHandlerPointer) (int);
 
  SignalHandlerPointer inthandler, termhandler;
#ifdef DEBUG_READ_PURE_OGG
  int read_pure_ogg = getenv ("GNUNET_READ_PURE_OGG") ? 1 : 0;
#endif

  inthandler = signal (SIGINT, 
		       &signalhandler);
  termhandler = signal (SIGTERM, 
			&signalhandler);
  
#ifdef WINDOWS
  setmode (0, _O_BINARY);
#endif
  
  /* Initialisation */
  gst_init (&argc, &argv);

  GNUNET_assert (GNUNET_OK ==
		 GNUNET_log_setup ("gnunet-helper-audio-playback-gst",
				   "WARNING",
				   NULL));
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Audio sink starts\n");
  
  stdin_mst = GNUNET_SERVER_mst_create (&stdin_receiver, 
					NULL);
  
  /* Create gstreamer elements */
  pipeline = gst_pipeline_new ("audio-player");
  source   = gst_element_factory_make ("appsrc",        "audio-input");
  demuxer  = gst_element_factory_make ("oggdemux",      "ogg-demuxer");
  decoder  = gst_element_factory_make ("opusdec",       "opus-decoder");
  conv     = gst_element_factory_make ("audioconvert",  "converter");
  resampler= gst_element_factory_make ("audioresample", "resampler");
  sink     = gst_element_factory_make ("autoaudiosink", "audiosink");

  if (!pipeline || !source || !conv || !resampler || !decoder || !demuxer || !sink)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"One element could not be created. Exiting.\n");
    return -1;
  }

  g_signal_connect (sink, 
		    "child-added",
		    G_CALLBACK (sink_child_added), 
		    NULL);
  g_signal_connect (demuxer, 
		    "pad-added",
		    G_CALLBACK (ogg_pad_added), 
		    decoder);

  /* Keep a reference to it, we operate on it */
  gst_object_ref (GST_OBJECT (source));

  /* Set up the pipeline */

  /* we feed appsrc as fast as possible, it just blocks when it's full */
  g_object_set (G_OBJECT (source),
/*      "format", GST_FORMAT_TIME,*/
      "block", TRUE,
      "is-live", TRUE,
      NULL);

  g_object_set (G_OBJECT (decoder),
/*      "plc", FALSE,*/
/*      "apply-gain", TRUE,*/
      "use-inband-fec", TRUE,
      NULL);

  /* we add a message handler */
  bus = gst_pipeline_get_bus (GST_PIPELINE (pipeline));
  bus_watch_id = gst_bus_add_watch (bus, bus_call, pipeline);
  gst_object_unref (bus);

  /* we add all elements into the pipeline */
  /* audio-input | ogg-demuxer | opus-decoder | converter | resampler | audiosink */
  gst_bin_add_many (GST_BIN (pipeline), source, demuxer, decoder, conv,
      resampler, sink, NULL);

  /* we link the elements together */
  gst_element_link_many (source, demuxer, NULL);

  /* Set the pipeline to "playing" state*/
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Now playing\n");
  gst_element_set_state (pipeline, GST_STATE_PLAYING);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Running...\n");
  /* Iterate */
  toff = 0;
  while (!abort_read)
  {
    char readbuf[MAXLINE];
    int ret;

    ret = read (0, readbuf, sizeof (readbuf));
    if (0 > ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Read error from STDIN: %d %s\n"),
		  ret, strerror (errno));
      break;
    }
    toff += ret;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Received %d bytes of audio data (total: %llu)\n",
		(int) ret,
		toff);
    if (0 == ret)
      break;
#ifdef DEBUG_READ_PURE_OGG
    if (read_pure_ogg)
    {
      feed_buffer_to_gst (readbuf, ret);
    }
    else
#endif
    GNUNET_SERVER_mst_receive (stdin_mst, NULL,
			       readbuf, ret,
			       GNUNET_NO, GNUNET_NO);
  }
  GNUNET_SERVER_mst_destroy (stdin_mst);

  signal (SIGINT, inthandler);
  signal (SIGINT, termhandler);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      "Returned, stopping playback\n");
  quit ();

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      "Deleting pipeline\n");
  gst_object_unref (GST_OBJECT (source));
  source = NULL;
  gst_object_unref (GST_OBJECT (pipeline));
  pipeline = NULL;
  g_source_remove (bus_watch_id);

  return 0;
}
