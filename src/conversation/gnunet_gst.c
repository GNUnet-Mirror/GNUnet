/*
  This file is part of GNUnet.
  Copyright (C) 2016 GNUnet e.V.

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
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/
/**
 * @file conversation/gnunet_gst.c
 * @brief FIXME
 * @author Hark
 */
#include "gnunet_gst_def.h"

/**
 * Our configuration.
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

void
dump_buffer(unsigned n, const unsigned char* buf)
{
  const unsigned char *p, *end;
  unsigned i, j;

  end = buf + n;

  for (i = 0; ; i += 16) {
    p = buf + i;
    for (j = 0; j < 16; j++) {
      fprintf(stderr, "%02X ", p[j]);
      if (p + j >= end)
        goto BREAKOUT;
    }
    fprintf(stderr, " ");
    p = buf + i;
    for (j = 0; j < 16; j++) {
      fprintf(stderr, "%c", isprint(p[j]) ? p[j] :
          '.');
      if (p + j >= end)
        goto BREAKOUT;
    }
    fprintf(stderr, "\n");
  }
BREAKOUT:
  return;
}

/***
 * load gnunet configuration
 */
  void
gg_load_configuration(GNUNET_gstData * d)
{
  char *audiobackend_string;
  cfg =  GNUNET_CONFIGURATION_create();
  GNUNET_CONFIGURATION_load(cfg, "mediahelper.conf");

  char *section = "MEDIAHELPER";

  GNUNET_CONFIGURATION_get_value_string(cfg, "MEDIAHELPER", "JACK_PP_IN", &d->jack_pp_in);
  GNUNET_CONFIGURATION_get_value_string(cfg, "MEDIAHELPER", "JACK_PP_OUT", &d->jack_pp_out);

  GNUNET_CONFIGURATION_get_value_string(cfg, "MEDIAHELPER", "AUDIOBACKEND", &audiobackend_string);

 // printf("abstring: %s \n", audiobackend_string);

  if ( audiobackend_string == "AUTO" )
  {
    d->audiobackend = AUTO;
  } else if ( audiobackend_string = "JACK" )
  {
    d->audiobackend = JACK;
  } else if ( audiobackend_string = "ALSA" )
  {
    d->audiobackend = ALSA;
  } else if ( audiobackend_string = "FAKE" )
  {
    d->audiobackend = FAKE;
  } else if ( audiobackend_string = "TEST" )
  {
    d->audiobackend = TEST;
  } else
  {
    d->audiobackend = AUTO;
  }

  if (GNUNET_CONFIGURATION_get_value_yesno(cfg, "MEDIAHELPER", "REMOVESILENCE") == GNUNET_YES)
  {
    d->dropsilence = TRUE;
  } else {
    d->dropsilence = FALSE;
  }

  if (GNUNET_CONFIGURATION_get_value_yesno(cfg, "MEDIAHELPER", "NO_GN_HEADERS") == GNUNET_YES)
  {
    d->pure_ogg = TRUE;
  } else {
    d->pure_ogg = FALSE;
  }


  if (GNUNET_CONFIGURATION_get_value_yesno(cfg, "MEDIAHELPER", "USERTP") == GNUNET_YES)
  {
    d->usertp = TRUE;
  } else {
    d->usertp = FALSE;
  }

//  GNUNET_CONFIGURATION_write(cfg, "mediahelper.conf");

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
//      quit (2);
    }
    off += ret;
  }
}



extern GstFlowReturn
on_appsink_new_sample (GstElement * element, GNUNET_gstData * d)
{
  static unsigned long long toff;

  //size of message including gnunet header
  size_t msg_size;

  GstSample *s;
  GstBuffer *b;
  GstMapInfo map;
/*
  const GstStructure *si;
  char *si_str;
  GstCaps *s_caps;
  char *caps_str;
*/
  (d->audio_message)->header.size = htons ((uint16_t) msg_size);

  if (gst_app_sink_is_eos(GST_APP_SINK(element)))
    return GST_FLOW_OK;

  //pull sample from appsink
   s = gst_app_sink_pull_sample (GST_APP_SINK(element));

   if (s == NULL)
     return GST_FLOW_OK;

   if (!GST_IS_SAMPLE (s))
     return GST_FLOW_OK;

   b = gst_sample_get_buffer(s);

   GST_WARNING ("caps are %" GST_PTR_FORMAT, gst_sample_get_caps(s));



   gst_buffer_map (b, &map, GST_MAP_READ);

   size_t len;
    len = map.size;
   if (len > UINT16_MAX - sizeof (struct AudioMessage))
   {
     // this should never happen?
     printf("GSTREAMER sample too big! \n");
     exit(20);
     len = UINT16_MAX - sizeof (struct AudioMessage);
   }

   msg_size = sizeof (struct AudioMessage) + len;

  // copy the data into audio_message
  memcpy (((char *) &(d->audio_message)[1]), map.data, len);
/*
  toff += msg_size;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending %u bytes of audio data (total: %llu)\n",
              (unsigned int) msg_size,
              toff);
*/
  if (d->pure_ogg)
    // write the audio_message without the gnunet headers
    write_data ((const char *) &(d->audio_message)[1], len);
  else
    write_data ((const char *) d->audio_message, msg_size);

   gst_sample_unref(s);
  return GST_FLOW_OK;
}

/***
 * Dump a pipeline graph
 */
 extern void
pl_graph(GstElement * pipeline)
{

#ifdef IS_SPEAKER
  gst_debug_bin_to_dot_file_with_ts(GST_BIN(pipeline), GST_DEBUG_GRAPH_SHOW_ALL, "playback_helper.dot");

#endif
#ifdef IS_MIC
  gst_debug_bin_to_dot_file_with_ts(GST_BIN(pipeline), GST_DEBUG_GRAPH_SHOW_ALL, "record_helper.dot");

#endif


  //  load_configuration();
}



extern gboolean
gnunet_gst_bus_call (GstBus *bus, GstMessage *msg, gpointer data)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Bus message\n");
  switch (GST_MESSAGE_TYPE (msg))
  {
  case GST_MESSAGE_EOS:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"End of stream\n");
    exit (10);
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

      exit (10);
      break;
    }
  default:
    break;
  }

  return TRUE;
}

/* called when pipeline changes state */
  extern void
state_changed_cb (GstBus * bus, GstMessage * msg, GNUNET_gstData * d)
{
  GstState old_state, new_state, pending_state;

  gst_message_parse_state_changed (msg, &old_state, &new_state,
      &pending_state);
  switch (new_state)
  {

    case GST_STATE_READY:
//      printf("ready.... \n");
      //pl_graph(GST_ELEMENT(d->pipeline));
      break;
    case GST_STATE_PLAYING:

    //GST_LOG ("caps are %" GST_PTR_FORMAT, caps);

 //     printf("Playing.... \n");
      pl_graph(GST_ELEMENT(d->pipeline));
      break;
    case GST_STATE_VOID_PENDING:
   //   printf("void_pending.... \n");
      //pl_graph(GST_ELEMENT(d->pipeline));
      break;
    case GST_STATE_NULL:
    //  printf("null.... \n");
      //pl_graph(GST_ELEMENT(d->pipeline));
      break;

    case GST_STATE_PAUSED:
 //     printf("paused.... \n");
      //pl_graph(GST_ELEMENT(d->pipeline));
      break;
  }
}

  static void
  application_cb (GstBus * bus, GstMessage * msg, GNUNET_gstData * data)
{
 // printf("application cb");
  return;
}

  static void
  error_cb (GstBus * bus, GstMessage * msg, GNUNET_gstData * data)
{
 // printf("error cb");
  return;
}

  static void
  eos_cb (GstBus * bus, GstMessage * msg, GNUNET_gstData * data)
{
 // printf("eos cb");
  return;
}

extern void
gg_setup_gst_bus (GNUNET_gstData * d)
{
  GstBus *bus;
  bus = gst_element_get_bus (GST_ELEMENT(d->pipeline));
  gst_bus_add_signal_watch (bus);
  g_signal_connect (G_OBJECT (bus), "message::error", (GCallback) error_cb,
      d);
  g_signal_connect (G_OBJECT (bus), "message::eos", (GCallback) eos_cb,
      d);
  g_signal_connect (G_OBJECT (bus), "message::state-changed",
      (GCallback) state_changed_cb, d);
  g_signal_connect (G_OBJECT (bus), "message::application",
      (GCallback) application_cb, d);
  g_signal_connect (G_OBJECT (bus), "message::about-to-finish",
      (GCallback) application_cb, d);
  gst_object_unref (bus);

}

/*
 * take buffer from gstreamer and feed it to gnunet
 */
/*
  extern int
feed_buffer_to_gnunet (GNUNET_gstData * d)
{
  GstSample *s;
  GstBuffer *b;
  GstMapInfo m;
  size_t len, msg_size;
  const char *ptr;
  int phase;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "pulling...\n");
  s = gst_app_sink_pull_sample (GST_APP_SINK(d->appsink));
  if (NULL == s)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "pulled NULL\n");
    return OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "...pulled!\n");

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

  b = gst_sample_get_buffer (s);
  if (NULL == b || !gst_buffer_map (b, &m, GST_MAP_READ))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got NULL buffer %p or failed to map the buffer\n", b);
    gst_sample_unref (s);
    return FAIL;
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
    if (0 == phase && !d->pure_ogg)
    {
//#ifdef DEBUG_RECORD_PURE_OGG

//      if (d->pure_ogg)
//        break;

//#endif
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
     //   abort_send = 1;
        return FAIL;
      }
    }

 //   if (abort_send)
   //   break;

  }
  gst_buffer_unmap (b, &m);
  gst_sample_unref (s);
}
*/


  extern int
feed_buffer_to_gst (const char *audio, size_t b_len, GNUNET_gstData * d)
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
  if (GST_APP_SRC(d->appsrc) == NULL)
    exit(10);
  flow = gst_app_src_push_buffer (GST_APP_SRC(d->appsrc), b);
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
 * debug making elements
 */
  extern GstElement *
gst_element_factory_make_debug( gchar *factoryname, gchar *name)
{
  GstElement *element;

  element = gst_element_factory_make(factoryname,name);

  if (element == NULL) {

    printf ("\n Failed to create element - type: %s name: %s \n", factoryname, name);
    exit(10);
    return element;
  } else {
    return element;
  }
}

/*
 static gboolean
gst_element_link_many_debug(...)
{
  va_list arguments;
  gst_element_link_many(argptr);
}

#define gst_element_link_many(...) \
           gst_element_link_many_debug(__VA_ARGS__)
*/
  extern void
lf(char * msg)
{
  printf("linking elements failed: %s", msg);
  exit(10);
}

/***
 * used to set properties on autoaudiosink's chosen sink
 */
static void
autoaudiosink_child_added (GstChildProxy *child_proxy,
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

/***
 * used to set properties on autoaudiosource's chosen sink
 */
static  void
autoaudiosource_child_added (GstChildProxy *child_proxy, GObject *object, gchar *name, gpointer user_data)
{
  if (GST_IS_AUDIO_BASE_SRC (object))
    g_object_set (object, "buffer-time", (gint64) BUFFER_TIME, "latency-time", (gint64) LATENCY_TIME, NULL);
}

GstElement *
get_pipeline(GstElement *element)
{
  GstPipeline *p;

  p = gst_object_get_parent(element);

  return p;
}

  static void
decoder_ogg_pad_added (GstElement *element,
	       GstPad *pad,
	       gpointer data)
{
  GstPad *sinkpad;
  GstElement *decoder = (GstElement *) data;

  printf("==== ogg pad added callback \n");
  /* We can now link this pad with the opus-decoder sink pad */
//  pl_graph(get_pipeline(element));
  sinkpad = gst_element_get_static_pad (decoder, "sink");

  gst_pad_link (pad, sinkpad);
  gst_element_link_many(element, decoder, NULL);
  gst_object_unref (sinkpad);
}

int
gnunet_read (GNUNET_gstData * d)
{
  char readbuf[MAXLINE];
  int ret;
  printf("read \n");
  ret = read (0, readbuf, sizeof (readbuf));
  if (0 > ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
        _("Read error from STDIN: %d %s\n"),
        ret, strerror (errno));
    return FAIL;
  }
  //toff += ret;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Received %d bytes of audio data\n",
      (int) ret);
  if (0 == ret)
    return FAIL;
  //#ifdef DEBUG_READ_PURE_OGG

     if (d->pure_ogg)
     {
     feed_buffer_to_gst (readbuf, ret, d);
     }
     else
     {
  //#endif
  GNUNET_SERVER_mst_receive (d->stdin_mst, NULL,
      readbuf, ret,
      GNUNET_NO, GNUNET_NO);
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
  size_t b_len;
  printf("stdin receiver \n ");
  dump_buffer(sizeof(msg), msg);

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO:
    audio = (struct AudioMessage *) msg;

    b_len = ntohs (audio->header.size) - sizeof (struct AudioMessage);
    printf("feeding buffer to gst \n ");
    feed_buffer_to_gst ((const char *) &audio[1], b_len, cls);
    break;
  default:
    printf("No audio message: %u \n ", ntohs(msg->type));
    break;
  }
  return GNUNET_OK;
}


GstBin *
get_app(GNUNET_gstData *d, int type)
{
  GstBin *bin;
  GstPad *pad, *ghostpad;

  if ( type == SOURCE )
  {
    bin = GST_BIN(gst_bin_new("Gnunet appsrc"));


    GNUNET_assert (GNUNET_OK ==
       GNUNET_log_setup ("gnunet-helper-audio-playback",
             "WARNING",
             NULL));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
          "Audio playback starts\n");
    printf(" creating appsrc \n ");
    //d->audio_message.header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO);

// d->audio_message = GNUNET_malloc (UINT16_MAX);
 //  d->audio_message = (AudioMessage*)malloc(sizeof(struct AudioMessage));
//  d->audio_message = GNUNET_malloc(sizeof(struct AudioMessage));


 //d->audio_message.header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO);


    d->stdin_mst = GNUNET_SERVER_mst_create (&stdin_receiver, d);

    if ( d->stdin_mst == NULL)
     printf("stdin_mst = NULL");

    d->appsrc     = gst_element_factory_make ("appsrc",       "appsrc");

    gst_bin_add_many( bin, d->appsrc, NULL);
//    gst_element_link_many ( encoder, muxer, NULL);

    pad = gst_element_get_static_pad (d->appsrc, "src");
    ghostpad = gst_ghost_pad_new ("src", pad);
  }
  if ( type == SINK )
  {
    bin = GST_BIN(gst_bin_new("Gnunet appsink"));


    GNUNET_assert (GNUNET_OK ==
       GNUNET_log_setup ("gnunet-helper-audio-record",
             "WARNING",
             NULL));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
          "Audio source starts\n");

    d->appsink     = gst_element_factory_make ("appsink",       "appsink");

    // Move this out of here!
    d->audio_message = GNUNET_malloc (UINT16_MAX);
    (d->audio_message)->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO);
    g_object_set (G_OBJECT (d->appsink), "emit-signals", TRUE, "sync", TRUE, NULL);

    g_signal_connect (d->appsink, "new-sample",
          G_CALLBACK (on_appsink_new_sample), &d);

    gst_bin_add_many( bin, d->appsink, NULL);
//    gst_element_link_many ( encoder, muxer, NULL);

    pad = gst_element_get_static_pad (d->appsink, "sink");
    ghostpad = gst_ghost_pad_new ("sink", pad);
  }

  /* set the bin pads */
  gst_pad_set_active (ghostpad, TRUE);
  gst_element_add_pad (GST_ELEMENT(bin), ghostpad);

  gst_object_unref (pad);

  return bin;
}

  extern GstBin *
get_coder(GNUNET_gstData *d , int type)
{
  GstBin *bin;
  GstPad *srcpad, *sinkpad, *srcghostpad, *sinkghostpad;
  GstCaps *caps, *rtpcaps;
  GstElement *encoder, *muxer, *decoder, *demuxer, *jitterbuffer, *rtpcapsfilter;

  if ( d->usertp == TRUE )
  {
     /*
       * application/x-rtp, media=(string)audio, clock-rate=(int)48000, encoding-name=(string)OPUS, sprop-maxcapturerate=(string)48000, sprop-stereo=(string)0, payload=(int)96, encoding-params=(string)2, ssrc=(uint)630297634, timestamp-offset=(uint)678334141, seqnum-offset=(uint)16938 */
/*
    rtpcaps = gst_caps_new_simple ("application/x-rtp",
          "media", G_TYPE_STRING, "audio",
          "clock-rate", G_TYPE_INT, SAMPLING_RATE,
          "encoding-name", G_TYPE_STRING, "OPUS",
          "payload", G_TYPE_INT, 96,
          "sprop-stereo", G_TYPE_STRING, "0",
          "encoding-params", G_TYPE_STRING, "2",
          NULL);
*/
      rtpcaps = gst_caps_new_simple ("application/x-rtp",
          "media", G_TYPE_STRING, "audio",
          "clock-rate", G_TYPE_INT, SAMPLING_RATE,
          "encoding-name", G_TYPE_STRING, "OPUS",
          "payload", G_TYPE_INT, 96,
          "sprop-stereo", G_TYPE_STRING, "0",
          "encoding-params", G_TYPE_STRING, "2",
          NULL);


      rtpcapsfilter  = gst_element_factory_make ("capsfilter",    "rtpcapsfilter");

      g_object_set (G_OBJECT (rtpcapsfilter),
          "caps", rtpcaps,
          NULL);
      gst_caps_unref (rtpcaps);

  }


  if ( type == ENCODER )
  {
    bin = GST_BIN(gst_bin_new("Gnunet audioencoder"));

    encoder  = gst_element_factory_make ("opusenc",       "opus-encoder");
    if ( d->usertp == TRUE )
    {
      muxer   = gst_element_factory_make ("rtpopuspay",        "rtp-payloader");
    } else {
      muxer   = gst_element_factory_make ("oggmux",        "ogg-muxer");
    }
    g_object_set (G_OBJECT (encoder),
        /*      "bitrate", 64000, */
        /*      "bandwidth", OPUS_BANDWIDTH_FULLBAND, */
        "inband-fec", INBAND_FEC_MODE,
        "packet-loss-percentage", PACKET_LOSS_PERCENTAGE,
        "max-payload-size", MAX_PAYLOAD_SIZE,
        "audio", TRUE, /* VoIP, not audio */
        "frame-size", OPUS_FRAME_SIZE,
        NULL);

    if ( d->usertp != TRUE)
    {
      g_object_set (G_OBJECT (muxer),
          "max-delay", OGG_MAX_DELAY,
          "max-page-delay", OGG_MAX_PAGE_DELAY,
          NULL);
    }

    gst_bin_add_many( bin, encoder, muxer, NULL);
    gst_element_link_many ( encoder, muxer, NULL);
    sinkpad = gst_element_get_static_pad(encoder, "sink");
    sinkghostpad = gst_ghost_pad_new ("sink", sinkpad);

    srcpad = gst_element_get_static_pad(muxer, "src");
    srcghostpad = gst_ghost_pad_new ("src", srcpad);

  }
  if ( type == DECODER )
  {
     bin = GST_BIN(gst_bin_new("Gnunet audiodecoder"));

    // decoder
    if ( d->usertp == TRUE )
    {

      demuxer  = gst_element_factory_make ("rtpopusdepay",      "ogg-demuxer");
      jitterbuffer = gst_element_factory_make ("rtpjitterbuffer", "rtpjitterbuffer");
    } else {
      demuxer  = gst_element_factory_make ("oggdemux",      "ogg-demuxer");
    }
    decoder  = gst_element_factory_make ("opusdec",       "opus-decoder");

    if ( d->usertp == TRUE )
    {
      gst_bin_add_many( bin, rtpcapsfilter, jitterbuffer, demuxer, decoder, NULL);
      gst_element_link_many ( rtpcapsfilter, jitterbuffer, demuxer, decoder, NULL);
      sinkpad = gst_element_get_static_pad(rtpcapsfilter, "sink");


    } else {
      gst_bin_add_many( bin, demuxer, decoder, NULL);

      g_signal_connect (demuxer,
          "pad-added",
          G_CALLBACK (decoder_ogg_pad_added),
          decoder);

      sinkpad = gst_element_get_static_pad(demuxer, "sink");
    }
    sinkghostpad = gst_ghost_pad_new ("sink", sinkpad);

    srcpad = gst_element_get_static_pad(decoder, "src");
    srcghostpad = gst_ghost_pad_new ("src", srcpad);

  }

  // add pads to the bin
  gst_pad_set_active (sinkghostpad, TRUE);
  gst_element_add_pad (GST_ELEMENT(bin), sinkghostpad);

  gst_pad_set_active (srcghostpad, TRUE);
  gst_element_add_pad (GST_ELEMENT(bin), srcghostpad);


  return bin;
}
  extern GstBin *
get_audiobin(GNUNET_gstData *d , int type)
{
  GstBin *bin;
  GstElement *sink, *source, *queue, *conv, *resampler, *removesilence, *filter;
  GstPad *pad, *ghostpad;
  GstCaps *caps;
  if ( type == SINK ) {

    bin = GST_BIN(gst_bin_new("Gnunet audiosink"));

    /* Create all the elements */
    if ( d->dropsilence == TRUE )
    {
      queue = gst_element_factory_make ("queue", "queue");
      removesilence = gst_element_factory_make ("removesilence", "removesilence");
    }

    conv     = gst_element_factory_make ("audioconvert",  "converter");
    resampler= gst_element_factory_make ("audioresample", "resampler");

    if ( d->audiobackend == AUTO )
    {
      sink     = gst_element_factory_make ("autoaudiosink", "audiosink");
      g_signal_connect (sink, "child-added", G_CALLBACK (autoaudiosink_child_added), NULL);

    }

    if ( d->audiobackend == ALSA )
    {
      sink     = gst_element_factory_make ("alsaaudiosink", "audiosink");
    }

    if ( d->audiobackend == JACK )
    {
      sink     = gst_element_factory_make ("jackaudiosink", "audiosink");

      g_object_set (G_OBJECT (sink), "client-name", "gnunet", NULL);

      if (g_object_class_find_property
          (G_OBJECT_GET_CLASS (sink), "port-pattern"))
      {

//        char *portpattern = "system";

        g_object_set (G_OBJECT (sink), "port-pattern", d->jack_pp_out,
            NULL);
      }

    }

    if ( d->audiobackend == FAKE )
    {
      sink     = gst_element_factory_make ("fakesink", "audiosink");
    }

    g_object_set (sink,
        "buffer-time", (gint64) BUFFER_TIME,
        "latency-time", (gint64) LATENCY_TIME,
        NULL);

    if ( d->dropsilence == TRUE )
    {
      // Do not remove silence by default
      g_object_set( removesilence, "remove", FALSE, NULL);
      g_object_set( queue, "max-size-buffers", 12,  NULL);
      /*
         g_signal_connect (source,
         "need-data",
         G_CALLBACK(appsrc_need_data),
         NULL);

         g_signal_connect (source,
         "enough-data",
         G_CALLBACK(appsrc_enough_data),
         NULL);
         */
/*
      g_signal_connect (queue,
          "notify::current-level-bytes",
          G_CALLBACK(queue_current_level),
          NULL);

      g_signal_connect (queue,
          "underrun",
          G_CALLBACK(queue_underrun),
          NULL);

      g_signal_connect (queue,
          "running",
          G_CALLBACK(queue_running),
          NULL);

      g_signal_connect (queue,
          "overrun",
          G_CALLBACK(queue_overrun),
          NULL);

      g_signal_connect (queue,
          "pushing",
          G_CALLBACK(queue_pushing),
          NULL);
 */

    }





    gst_bin_add_many (bin ,  conv, resampler, sink, NULL);
    gst_element_link_many ( conv, resampler, sink, NULL);

    if ( d->dropsilence == TRUE )
    {
      gst_bin_add_many (bin , queue ,removesilence , NULL);

      if ( !gst_element_link_many ( queue, removesilence, conv,  NULL) )
        lf ("queue, removesilence, conv ");

      pad = gst_element_get_static_pad (queue, "sink");

    } else {

      pad = gst_element_get_static_pad(conv, "sink");

    }

    ghostpad = gst_ghost_pad_new ("sink", pad);

  } else {
    // SOURCE

    bin = GST_BIN(gst_bin_new("Gnunet audiosource"));

    //    source = gst_element_factory_make("audiotestsrc", "audiotestsrcbla");

    if (d->audiobackend == AUTO )
    {
      source     = gst_element_factory_make ("autoaudiosrc", "audiosource");
    }
    if (d->audiobackend == ALSA )
    {
      source     = gst_element_factory_make ("alsasrc", "audiosource");
    }
    if (d->audiobackend == JACK )
    {
      source     = gst_element_factory_make ("jackaudiosrc", "audiosource");
    }
    if (d->audiobackend == TEST )
    {
      source     = gst_element_factory_make ("audiotestsrc", "audiosource");
    }

    filter   = gst_element_factory_make ("capsfilter",    "filter");
    conv     = gst_element_factory_make ("audioconvert",  "converter");
    resampler= gst_element_factory_make ("audioresample", "resampler");

    if (d->audiobackend == AUTO ) {
            g_signal_connect (source, "child-added", G_CALLBACK (autoaudiosource_child_added), NULL);

    } else {
      if (GST_IS_AUDIO_BASE_SRC (source))
        g_object_set (source, "buffer-time", (gint64) BUFFER_TIME, "latency-time", (gint64) LATENCY_TIME, NULL);
      if ( d->audiobackend == JACK ) {
        g_object_set (G_OBJECT (source), "client-name", "gnunet", NULL);
        if (g_object_class_find_property
            (G_OBJECT_GET_CLASS (source), "port-pattern"))
        {

          char *portpattern = "moc";

          g_object_set (G_OBJECT (source), "port-pattern", portpattern,
              NULL);
        }
      }
    }

    caps = gst_caps_new_simple ("audio/x-raw",
        /*  "format", G_TYPE_STRING, "S16LE", */
        /*    "rate", G_TYPE_INT, SAMPLING_RATE,*/
        "channels", G_TYPE_INT, OPUS_CHANNELS,
        /*    "layout", G_TYPE_STRING, "interleaved",*/
        NULL);

    g_object_set (G_OBJECT (filter),
        "caps", caps,
        NULL);
    gst_caps_unref (caps);

    gst_bin_add_many (bin ,  source, filter, conv, resampler,  NULL);
    gst_element_link_many ( source, filter, conv, resampler, NULL);

    pad = gst_element_get_static_pad (resampler, "src");


    /* pads */
    ghostpad = gst_ghost_pad_new ("src", pad);

  }

  /* set the bin pads */
  gst_pad_set_active (ghostpad, TRUE);
  gst_element_add_pad (GST_ELEMENT(bin), ghostpad);

  gst_object_unref (pad);

  return bin;
}
