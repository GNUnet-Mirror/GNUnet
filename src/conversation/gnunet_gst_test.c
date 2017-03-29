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
 * @file conversation/gnunet_gst_test.c
 * @brief FIXME
 * @author Hark
 */

#include "gnunet_gst_def.h"
#include "gnunet_gst.h"

int
main (int argc, char *argv[])
{
  struct GNUNET_gstData *gst;
  // GstBus *bus;
  GstElement *gnunetsrc, *gnunetsink, *source, *sink, *encoder, *decoder;



  // audio_message = GNUNET_malloc (UINT16_MAX);
  //audio_message->header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO);


  //GstPipeline *pipeline;

  gst = (GNUNET_gstData*)malloc(sizeof(struct GNUNET_gstData));

  //gst->audio_message.header.type = htons (GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO);


  gg_load_configuration(gst);
/*
  gst->audiobackend = JACK;
  gst->dropsilence = TRUE;
  gst->usertp = FALSE;
  */
  /* Initialize GStreamer */
  gst_init (&argc, &argv);

  gst->pipeline = GST_PIPELINE(gst_pipeline_new ("gnunet-media-helper"));

#ifdef IS_SPEAKER
  int type = SPEAKER;
  printf("this is the speaker \n");
#endif
#ifdef IS_MIC
  int type = MICROPHONE;
  printf("this is the microphone \n");

#endif
  if ( type == SPEAKER)
  {

    gnunetsrc = GST_ELEMENT(get_app(gst, SOURCE));

    sink = GST_ELEMENT(get_audiobin(gst, SINK));
    decoder = GST_ELEMENT(get_coder(gst, DECODER));
    gst_bin_add_many( GST_BIN(gst->pipeline), gnunetsrc, decoder, sink, NULL);
    gst_element_link_many( gnunetsrc, decoder, sink , NULL);

  }
  if ( type == MICROPHONE ) {

    source = GST_ELEMENT(get_audiobin(gst, SOURCE));

    encoder = GST_ELEMENT(get_coder(gst, ENCODER));

    gnunetsink = GST_ELEMENT(get_app(gst, SINK));

    gst_bin_add_many( GST_BIN(gst->pipeline), source, encoder, gnunetsink, NULL);
    gst_element_link_many( source, encoder, gnunetsink , NULL);


  }
  /*
  gst_bin_add_many( GST_BIN(gst->pipeline), appsource, appsink, source, encoder, decoder, sink, NULL);
  gst_element_link_many( source, encoder, decoder, sink , NULL);
*/
  pl_graph(gst->pipeline);
  /* Start playing */
  gst_element_set_state (GST_ELEMENT(gst->pipeline), GST_STATE_PLAYING);

  //pl_graph(gst->pipeline);

  /* Wait until error or EOS */
  //bus = gst_element_get_bus (GST_ELEMENT(gst->pipeline));
  //bus_watch_id = gst_bus_add_watch (bus, gnunet_gst_bus_call, pipeline);

  gg_setup_gst_bus(gst);
// g_print ("Running...\n");


  // start pushing buffers
 if ( type == MICROPHONE )
 {


    GMainLoop *loop;
    loop = g_main_loop_new (NULL, FALSE);

     g_main_loop_run (loop);

/*
   while ( 1 )
     {
         GstFlowReturn flow;
         flow = on_appsink_new_sample (gst->appsink, gst);
    }
*/
    }
 if ( type == SPEAKER )
 {
   while ( 1 )
   {
//      printf("read.. \n");
      gnunet_read(gst);
   }
 }
  g_print ("Returned, stopping playback\n");

  // gst_object_unref (bus);
  gst_element_set_state (GST_ELEMENT(gst->pipeline), GST_STATE_NULL);
  gst_object_unref (gst->pipeline);

  return 0;
}
