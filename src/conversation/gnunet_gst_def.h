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
 * @file conversation/gnunet_gst_def.h
 * @brief FIXME
 * @author Hark
 */

#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <regex.h>


#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
//#include "gnunet/conversation.h" doesn't get installed
#include "conversation.h"
#include "gnunet_constants.h"
#include "gnunet_core_service.h"
#include "gnunet_common.h"

/*
#include <gst/gst.h>
#include <gst/audio/gstaudiobasesrc.h>
#include <gst/app/gstappsrc.h>
*/

/* huh
#include <glib-2.0/glib.h>

#include <gstreamer-1.0/gst/gst.h>
#include <gstreamer-1.0/gst/pbutils/pbutils.h>
#include <gstreamer-1.0/gst/video/videooverlay.h>
#include <gstreamer-1.0/gst/audio/gstaudiobasesrc.h>
#include <gstreamer-1.0/gst/app/gstappsrc.h>
*/

#include <gst/gst.h>
#include <gst/audio/gstaudiobasesrc.h>
#include <gst/app/gstappsrc.h>
#include <glib.h>
#include <gst/app/gstappsink.h>

// sockets
#include <netinet/in.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


//glib stuff
//#include <glib.h>
#include <glib-2.0/glib/gprintf.h>
#include <glib-unix.h>

// static struct AudioMessage *audio_message;



typedef struct GNUNET_gstData GNUNET_gstData;
struct GNUNET_gstData {
  //general
  GstPipeline *pipeline;

  // things
  struct AudioMessage *audio_message;
  struct GNUNET_SERVER_MessageStreamTokenizer *stdin_mst;
  GstElement *appsrc;
  GstElement *appsink;
  //settings
  int audiobackend;
  int dropsilence;
  int usertp;
  int pure_ogg;
  char *jack_pp_in;
  char *jack_pp_out;
};




#define DEBUG_READ_PURE_OGG 1
#define DEBUG_RECORD_PURE_OGG 1


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

#define SAMPLING_RATE 48000

enum {
    AUTO,
    JACK,
    ALSA,
    FAKE,
    TEST
};

enum {
    SOURCE,
    SINK
};

enum {
    ENCODER,
    DECODER
};

enum {
    FAIL,
    OK
};

enum {
    SPEAKER,
    MICROPHONE
};
