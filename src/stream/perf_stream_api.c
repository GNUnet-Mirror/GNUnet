/*
     This file is part of GNUnet.
     (C) 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @file stream/perf_stream_api.c
 * @brief performance benchmarks for stream api
 * @author Sree Harsha Totakura
 */

/****************************************************************************************/
/* Test is setup into the following major steps:   				        */
/*    1. Measurements over loopback (1 hop). i.e. we use only one peer and open	        */
/*       stream connections over loopback. Messages will go through		        */
/*       STREAM_API->MESH_API->MESH_SERVICE->MESH_API->STREAM_API.		        */
/*    2. Measurements over 2 peers (2 hops). We use testbed to create 2 peers,	        */
/*       connect them and then create stream connections. Messages will go through      */
/*       STREAM_API->MESH_API->MESH_SERVICE->CORE1.....CORE2->MESH_API->STREAM_API      */
/*    3. Measurements over 3 peers (3 hops). We use testbed to create 3 peers,	        */
/*       connect them in a line topology: peer1->peer2->peer3. Messages will go	        */
/*       through								        */
/*       STREAM_API->MESH_API->MESH_SERVICE->CORE1..CORE2..CORE3->MESH_API->STREAM_API. */
/****************************************************************************************/

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_stream_lib.h"


  
/**
 * Simple struct to keep track of progress, and print a
 * nice little percentage meter for long running tasks.
 */
struct ProgressMeter
{
  unsigned int total;

  unsigned int modnum;

  unsigned int dotnum;

  unsigned int completed;

  int print;

  char *startup_string;
};


/**
 * Steps in testing
 */
enum TestStep
{
  /**
   * Single hop loopback testing
   */
  TEST_STEP_1_HOP,

  /**
   * Testing with 2 peers
   */
  TEST_STEP_2_HOP,

  /**
   * Testing with 3 peers
   */
  TEST_STEP_3_HOP
};

/**
 * Structure for holding peer's sockets and IO Handles
 */
struct PeerData
{
  /**
   * Peer's stream socket
   */
  struct GNUNET_STREAM_Socket *socket;

  struct GNUNET_PeerIdentity self;

  /**
   * Peer's io write handle
   */
  struct GNUNET_STREAM_IOWriteHandle *io_write_handle;

  /**
   * Peer's io read handle
   */
  struct GNUNET_STREAM_IOReadHandle *io_read_handle;

  /**
   * Bytes the peer has written
   */
  unsigned int bytes_wrote;

  /**
   * Byte the peer has read
   */
  unsigned int bytes_read;
};


/**
 * Maximum size of the data which we will transfer during tests
 */
#define DATA_SIZE 65536      /* 64KB */

/**
 * Listen socket of peer2
 */
struct GNUNET_STREAM_ListenSocket *peer2_listen_socket;

/**
 * Handle to configuration during TEST_STEP_1_HOP
 */
const struct GNUNET_CONFIGURATION_Handle *config;

/**
 * Placeholder for peer data
 */
static struct PeerData peer_data[3];

/**
 * Task ID for abort task
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

/**
 * Random data block. Should generate data first
 */
static uint32_t data[DATA_SIZE / 4];     /* 64KB array */

/**
 * Payload sizes to test each major test with
 */
static uint16_t payload_size[] = 
{ 20, 500, 2000, 7000, 13000, 25000, 56000, 64000 };

/**
 * Handle for the progress meter
 */
static struct ProgressMeter *meter;

/**
 * Current step of testing
 */
static enum TestStep test_step;

/**
 * Index for choosing payload size
 */
unsigned int payload_size_index;

/**
 * Create a meter to keep track of the progress of some task.
 *
 * @param total the total number of items to complete
 * @param start_string a string to prefix the meter with (if printing)
 * @param print GNUNET_YES to print the meter, GNUNET_NO to count
 *              internally only
 *
 * @return the progress meter
 */
static struct ProgressMeter *
create_meter (unsigned int total, char *start_string, int print)
{
  struct ProgressMeter *ret;

  ret = GNUNET_malloc (sizeof (struct ProgressMeter));
  ret->print = print;
  ret->total = total;
  ret->modnum = total / 4;
  if (ret->modnum == 0)         /* Divide by zero check */
    ret->modnum = 1;
  ret->dotnum = (total / 50) + 1;
  if (start_string != NULL)
    ret->startup_string = GNUNET_strdup (start_string);
  else
    ret->startup_string = GNUNET_strdup ("");

  return ret;
}


/**
 * Update progress meter (increment by one).
 *
 * @param meter the meter to update and print info for
 *
 * @return GNUNET_YES if called the total requested,
 *         GNUNET_NO if more items expected
 */
static int
update_meter (struct ProgressMeter *meter)
{
  if (meter->print == GNUNET_YES)
  {
    if (meter->completed % meter->modnum == 0)
    {
      if (meter->completed == 0)
      {
        FPRINTF (stdout, "%sProgress: [0%%", meter->startup_string);
      }
      else
        FPRINTF (stdout, "%d%%",
                 (int) (((float) meter->completed / meter->total) * 100));
    }
    else if (meter->completed % meter->dotnum == 0)
      FPRINTF (stdout, "%s",  ".");

    if (meter->completed + 1 == meter->total)
      FPRINTF (stdout, "%d%%]\n", 100);
    fflush (stdout);
  }
  meter->completed++;

  if (meter->completed == meter->total)
    return GNUNET_YES;
  if (meter->completed > meter->total)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Progress meter overflow!!\n");
  return GNUNET_NO;
}


/**
 * Reset progress meter.
 *
 * @param meter the meter to reset
 *
 * @return GNUNET_YES if meter reset,
 *         GNUNET_SYSERR on error
 */
static int
reset_meter (struct ProgressMeter *meter)
{
  if (meter == NULL)
    return GNUNET_SYSERR;

  meter->completed = 0;
  return GNUNET_YES;
}


/**
 * Release resources for meter
 *
 * @param meter the meter to free
 */
static void
free_meter (struct ProgressMeter *meter)
{
  GNUNET_free_non_null (meter->startup_string);
  GNUNET_free (meter);
}


/**
 * Something went wrong and timed out. Kill everything and set error flag
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_break (0);
}


/**
 * Functions of this type are called upon new stream connection from other peers
 *
 * @param cls the closure from GNUNET_STREAM_listen
 * @param socket the socket representing the stream
 * @param initiator the identity of the peer who wants to establish a stream
 *            with us
 * @return GNUNET_OK to keep the socket open, GNUNET_SYSERR to close the
 *             stream (the socket will be invalid after the call)
 */
static int
stream_listen_cb (void *cls, struct GNUNET_STREAM_Socket *socket,
		  const struct GNUNET_PeerIdentity *initiator)
{
  GNUNET_break (0);
  return GNUNET_OK;
}


/**
 * Listen success callback; connects a peer to stream as client
 */
static void
stream_connect (void)
{
  GNUNET_break (0);
}


/**
 * Initialize framework and start test
 *
 * @param cls closure
 * @param cfg configuration of the peer that was started
 * @param peer identity of the peer that was created
 */
static void
run (void *cls, 
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_PeerIdentity self;

  GNUNET_TESTING_peer_get_identity (peer, &self);
  config = cfg;
  peer2_listen_socket = 
      GNUNET_STREAM_listen (config, 10, /* App port */ &stream_listen_cb, NULL,
                            GNUNET_STREAM_OPTION_SIGNAL_LISTEN_SUCCESS,
                            &stream_connect, GNUNET_STREAM_OPTION_END);
  GNUNET_assert (NULL != peer2_listen_socket);
  peer_data[1].self = self;
  peer_data[2].self = self;
  abort_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 60), &do_abort,
                                  NULL);
}


/**
 * Main function
 */
int main (int argc, char **argv)
{
  char *pmsg;
  unsigned int count;
  int ret;

  meter = create_meter ((sizeof (data) / 4), "Generating random data\n", GNUNET_YES);
  for (count=0; count < (sizeof (data) / 4); count++)
  {
    data[count] = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                            UINT32_MAX);
    update_meter (meter);
  }
  reset_meter (meter);
  free_meter (meter);
  test_step = TEST_STEP_1_HOP;
  for (payload_size_index = 0; 
       payload_size_index < (sizeof (payload_size) / sizeof (uint16_t));
       payload_size_index++)
  {
    GNUNET_asprintf (&pmsg, "Testing over loopback with payload size %hu\n",
                     payload_size[payload_size_index]);
    meter = create_meter ((sizeof (data) / 4), pmsg, GNUNET_YES);
    GNUNET_free (pmsg);
    ret = GNUNET_TESTING_peer_run ("test_stream_big", "test_stream_local.conf",
                                   &run, NULL);
    free_meter (meter);
    if (0 != ret)
      break;
  }
  test_step = TEST_STEP_2_HOP;
  for (payload_size_index = 0; 
       payload_size_index < (sizeof (payload_size) / sizeof (uint16_t));
       payload_size_index++)
  {
    /* Initialize testbed here */
  }
  test_step = TEST_STEP_3_HOP;
  for (payload_size_index = 0; 
       payload_size_index < (sizeof (payload_size) / sizeof (uint16_t));
       payload_size_index++)
  {
    /* Initialize testbed here */
  }
  return ret;
}
