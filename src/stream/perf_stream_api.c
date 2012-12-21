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

#define LOG(kind, ...)                         \
  GNUNET_log (kind, __VA_ARGS__);

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

  /**
   * Peer's io write handle
   */
  struct GNUNET_STREAM_WriteHandle *io_write_handle;

  /**
   * Peer's io read handle
   */
  struct GNUNET_STREAM_ReadHandle *io_read_handle;

  /**
   * The peer handle when we use the testbed servie
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * Handle to peer specific opearations while using testbed service
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * The identity of this peer
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Peer's shutdown handle
   */
  struct GNUNET_STREAM_ShutdownHandle *shutdown_handle;

  /**
   * Bytes the peer has written
   */
  size_t bytes_wrote;

  /**
   * Byte the peer has read
   */
  size_t bytes_read;

  /**
   * number of packets sent
   */
  unsigned int packets_wrote;

  /**
   * number of packets read
   */
  unsigned int packets_read;
};


/**
 * Enumeration of stages in this testing
 */
enum TestStage
{
  /**
   * The initial stage
   */
  INIT,
  
  /**
   * Uplink testing stage
   */
  UPLINK_OK,

  /**
   * Downlink testing stage
   */
  DOWNLINK_OK
};


/**
 * Maximum size of the data which we will transfer during tests
 */
#define DATA_SIZE 5000000      /* 5mB */

/**
 * Fixed number of packets we send in each direction during each subtest
 */
#define MAX_PACKETS 1000

/**
 * Listen socket of peer2
 */
struct GNUNET_STREAM_ListenSocket *peer2_listen_socket;

/**
 * Handle to configuration during TEST_STEP_1_HOP
 */
const struct GNUNET_CONFIGURATION_Handle *config;

/**
 * Handle for the progress meter
 */
static struct ProgressMeter *meter;

/**
 * Placeholder for peer data
 */
static struct PeerData peer_data[3];

/**
 * Handle to common operations while using testbed
 */
static struct GNUNET_TESTBED_Operation *common_op;

/**
 * Task ID for abort task
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

/**
 * Task ID for write task
 */
static GNUNET_SCHEDULER_TaskIdentifier write_task;

/**
 * Task ID for read task
 */
static GNUNET_SCHEDULER_TaskIdentifier read_task;

/**
 * Absolute time when profiling starts
 */
static struct GNUNET_TIME_Absolute prof_start_time;

/**
 * Test time taken for sending the data
 */
static struct GNUNET_TIME_Relative prof_time;

/**
 * Random data block. Should generate data first
 */
static uint32_t data[DATA_SIZE / 4];

/**
 * Payload sizes to test each major test with
 */
static uint16_t payload_size[] = 
{ 20, 500, 2000, 7000, 13000, 25000, 30000};//, 50000, 60000, 63000, 64000 };

/**
 * Current step of testing
 */
static enum TestStep test_step;

/**
 * Index for choosing payload size
 */
static unsigned int payload_size_index;

/**
 * Number of peers we want to create while using the testbed service
 */
static int num_peers;

/**
 * Flag to indicate that the other peer should reset its data read source index
 */
static int reset_read;

/**
 * Testing result of a major test
 */
static enum TestStage result;

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
 * Shutdown nicely
 */
static void
do_close (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  switch (test_step)
  {
  case TEST_STEP_1_HOP:
    if (NULL != peer_data[0].socket)
      GNUNET_STREAM_close (peer_data[0].socket);
    if (NULL != peer_data[1].socket)
      GNUNET_STREAM_close (peer_data[1].socket);
    if (NULL != peer2_listen_socket)
      GNUNET_STREAM_listen_close (peer2_listen_socket); /* Close listen socket */
    break;
  case TEST_STEP_2_HOP:
    if (NULL != peer_data[1].socket)
      GNUNET_STREAM_close (peer_data[1].socket);
    if (NULL != peer_data[0].op)
      GNUNET_TESTBED_operation_done (peer_data[0].op);
    if (NULL != peer_data[1].op)
      GNUNET_TESTBED_operation_done (peer_data[1].op);
    break;
  case TEST_STEP_3_HOP:
    GNUNET_break (0);    
  }  
  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (GNUNET_SCHEDULER_NO_TASK != write_task)
    GNUNET_SCHEDULER_cancel (write_task);
  GNUNET_SCHEDULER_shutdown (); /* Shutdown this testcase */
  if (NULL != meter)
  {
    free_meter (meter);
    meter = NULL;
  }
}


/**
 * Something went wrong and timed out. Kill everything and set error flag
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  abort_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "test: ABORT\n");
  if (GNUNET_SCHEDULER_NO_TASK != read_task)
    GNUNET_SCHEDULER_cancel (read_task);
  result = GNUNET_SYSERR;
  do_close (cls, tc);
}


/**
 * Completion callback for shutdown
 *
 * @param cls the closure from GNUNET_STREAM_shutdown call
 * @param operation the operation that was shutdown (SHUT_RD, SHUT_WR,
 *          SHUT_RDWR) 
 */
static void 
shutdown_completion (void *cls,
                     int operation)
{
  static int shutdowns;

  if (++shutdowns == 1)
  {
    peer_data[0].shutdown_handle = NULL;
    peer_data[1].shutdown_handle = GNUNET_STREAM_shutdown (peer_data[1].socket, SHUT_RDWR,
                                                           &shutdown_completion, cls);
    return;
  }  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "STREAM shutdown successful\n");
  GNUNET_SCHEDULER_add_now (&do_close, cls);
}


/**
 * Shutdown sockets gracefully
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  peer_data[0].shutdown_handle = GNUNET_STREAM_shutdown (peer_data[0].socket, SHUT_RDWR,
                                                         &shutdown_completion, cls);
}

  
/**
 * Scheduler call back; to be executed when a new stream is connected
 * Called from listen connect for peer2
 */
static void
stream_read_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Task for calling STREAM_write with a chunk of random data
 *
 * @param cls the peer data entity
 * @param tc the task context
 */
static void
stream_write_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * The write completion function; called upon writing some data to stream or
 * upon error
 *
 * @param cls the closure from GNUNET_STREAM_write/read
 * @param status the status of the stream at the time this function is called
 * @param size the number of bytes written
 */
static void 
write_completion (void *cls, enum GNUNET_STREAM_Status status, size_t size)
{
  struct PeerData *pdata = cls;
  double throughput;
  double prof_time_sec;
  unsigned int packets_wrote;

  if (GNUNET_STREAM_OK != status)
  {
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }
  GNUNET_assert (size <= DATA_SIZE);
  packets_wrote = (size + payload_size[payload_size_index] - 1)
      / payload_size[payload_size_index];
  pdata->bytes_wrote += size;
  for (;packets_wrote > 0; packets_wrote--)
  {    
    update_meter (meter);
    pdata->packets_wrote++;
  }
  if (pdata->packets_wrote < MAX_PACKETS) /* Have more data to send */
  {
    size_t write_amount;
    
    if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    {
      GNUNET_SCHEDULER_cancel (abort_task);
      abort_task = 
          GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                        (GNUNET_TIME_UNIT_SECONDS, 300), &do_abort,
                                    NULL);
    }
    write_amount = (MAX_PACKETS - pdata->packets_wrote) *
        payload_size[payload_size_index];
    if (write_amount > DATA_SIZE)
      write_amount = DATA_SIZE;
    reset_read = GNUNET_YES;
    pdata->io_write_handle = GNUNET_STREAM_write (pdata->socket, data,
                                                  write_amount,
                                                  GNUNET_TIME_UNIT_FOREVER_REL,
                                                  &write_completion, pdata);
    GNUNET_assert (NULL != pdata->io_write_handle);
  }
  else
  {
    free_meter (meter);
    meter = NULL;
    prof_time = GNUNET_TIME_absolute_get_duration (prof_start_time);
    prof_time_sec = (((double) prof_time.rel_value)/ ((double) 1000));
    throughput = ((float) pdata->bytes_wrote) / prof_time_sec;
    PRINTF ("Throughput %.2f kB/sec\n", throughput / 1000.00);
    switch (result)
    {
    case INIT:
      result = UPLINK_OK;
      GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == read_task);
      GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == write_task);
      pdata->bytes_read = 0;
      pdata->packets_read = 0;
      meter = create_meter (MAX_PACKETS, "Testing Downlink\n", GNUNET_YES);
      read_task = GNUNET_SCHEDULER_add_now (&stream_read_task, &peer_data[0]);
      write_task = GNUNET_SCHEDULER_add_now (&stream_write_task, &peer_data[1]);
      break;
    case UPLINK_OK:
      result = DOWNLINK_OK;
      GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
      break;
    case DOWNLINK_OK:
      GNUNET_assert (0);
    }
  }
}


/**
 * Task for calling STREAM_write with a chunk of random data
 *
 * @param cls the peer data entity
 * @param tc the task context
 */
static void
stream_write_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerData *pdata = cls;
  size_t write_amount;

  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
  {
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = 
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 300), &do_abort,
                                    NULL);
  }
  write_task = GNUNET_SCHEDULER_NO_TASK;
  prof_start_time = GNUNET_TIME_absolute_get ();
  pdata->bytes_wrote = 0;
  pdata->packets_wrote = 0;
  write_amount = MAX_PACKETS * payload_size[payload_size_index];
  if (write_amount > DATA_SIZE)
    write_amount = DATA_SIZE;
  reset_read = GNUNET_YES;
  pdata->io_write_handle = GNUNET_STREAM_write (pdata->socket, data,
                                                write_amount,
						GNUNET_TIME_UNIT_FOREVER_REL,
						&write_completion, pdata);
  GNUNET_assert (NULL != pdata->io_write_handle);
}


/**
 * Scheduler call back; to be executed when a new stream is connected
 * Called from listen connect for peer2
 */
static void
stream_read_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Input processor
 *
 * @param cls peer2
 * @param status the status of the stream at the time this function is called
 * @param data traffic from the other side
 * @param size the number of bytes available in data read 
 * @return number of bytes of processed from 'data' (any data remaining should be
 *         given to the next time the read processor is called).
 */
static size_t
input_processor (void *cls, enum GNUNET_STREAM_Status status,
		 const void *input_data, size_t size)
{
  struct PeerData *pdata = cls;

  if (GNUNET_STREAM_OK != status)
  {
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return 0;
  }
  GNUNET_assert (size <= DATA_SIZE);
  if (GNUNET_YES == reset_read)
  {
    pdata->bytes_read = 0;
    reset_read = GNUNET_NO;
  }
  GNUNET_assert ((pdata->bytes_read + size) <= DATA_SIZE);
  GNUNET_assert (0 == memcmp (((void *)data ) + pdata->bytes_read, 
                              input_data, size));
  pdata->bytes_read += size;
  pdata->packets_read += (size + payload_size[payload_size_index] - 1)
      / payload_size[payload_size_index];
  if (pdata->packets_read < MAX_PACKETS)
  {
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == read_task);
    read_task = GNUNET_SCHEDULER_add_now (&stream_read_task, pdata);
  }
  else 
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Reading finished successfully\n");
  }
  return size;
}

  
/**
 * Scheduler call back; to be executed when a new stream is connected
 * Called from listen connect for peer2
 */
static void
stream_read_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerData *pdata = cls;

  read_task = GNUNET_SCHEDULER_NO_TASK;
  pdata->io_read_handle =
      GNUNET_STREAM_read (pdata->socket, GNUNET_TIME_UNIT_FOREVER_REL,
			  &input_processor, pdata);
  GNUNET_assert (NULL != pdata->io_read_handle);
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
  struct PeerData *pdata = cls;

  
  if ((NULL == socket) || (NULL == initiator))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Binding error\n");
    if (GNUNET_SCHEDULER_NO_TASK != abort_task)
      GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return GNUNET_OK;
  }
  GNUNET_assert (NULL != socket);
  GNUNET_assert (pdata == &peer_data[1]);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer connected: %s\n",
	      GNUNET_i2s(initiator));
  pdata->socket = socket;
  pdata->bytes_read = 0;
  read_task = GNUNET_SCHEDULER_add_now (&stream_read_task, pdata);
  return GNUNET_OK;
}


/**
 * Function executed after stream has been established
 *
 * @param cls the closure from GNUNET_STREAM_open
 * @param socket socket to use to communicate with the other side (read/write)
 */
static void 
stream_open_cb (void *cls,
                struct GNUNET_STREAM_Socket *socket)
{
  struct PeerData *pdata = cls;

  GNUNET_assert (socket == pdata->socket);
  meter = create_meter (MAX_PACKETS, "Testing Uplink\n", GNUNET_YES);
  write_task = GNUNET_SCHEDULER_add_now (&stream_write_task, pdata);
}


/**
 * Listen success callback; connects a peer to stream as client
 */
static void
stream_connect (void)
{
  peer_data[0].socket = 
      GNUNET_STREAM_open (config, &peer_data[1].id, 10, &stream_open_cb,
			  &peer_data[0],
			  GNUNET_STREAM_OPTION_MAX_PAYLOAD_SIZE,
			  payload_size[payload_size_index],
			  GNUNET_STREAM_OPTION_END);
  GNUNET_assert (NULL != peer_data[0].socket);
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
  struct GNUNET_PeerIdentity id;

  GNUNET_TESTING_peer_get_identity (peer, &id);
  config = cfg;
  peer2_listen_socket = 
      GNUNET_STREAM_listen (config, 10, &stream_listen_cb, &peer_data[1],
			    GNUNET_STREAM_OPTION_SIGNAL_LISTEN_SUCCESS,
                            &stream_connect,
                            GNUNET_STREAM_OPTION_MAX_PAYLOAD_SIZE,
                            payload_size[payload_size_index],
                            GNUNET_STREAM_OPTION_END);
  GNUNET_assert (NULL != peer2_listen_socket);
  peer_data[0].id = id;
  peer_data[1].id = id;
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 300), &do_abort,
                                    NULL);
}


/**
 * Adapter function called to establish a connection to
 * a service.
 * 
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void * 
stream_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Adapter function called to destroy a connection to
 * a service.
 * 
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
stream_da (void *cls, void *op_result)
{
  if (&peer_data[1] == cls)
  {
    GNUNET_STREAM_listen_close (op_result);
    return;
  }
  else if (&peer_data[0] == cls)
  {
    GNUNET_STREAM_close (op_result);
    return;
  }
  GNUNET_assert (0);
}


/**
 * Listen success callback; connects a peer to stream as client. Called from
 * testbed stream_ca
 */
static void
stream_connect2 (void)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stream listen open successful\n");
  peer_data[0].op =
      GNUNET_TESTBED_service_connect (&peer_data[0], peer_data[0].peer,
				      "stream", NULL, NULL, stream_ca,
				      stream_da, &peer_data[0]);
}


/**
 * Adapter function called to establish a connection to
 * a service.
 * 
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void * 
stream_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct PeerData *pdata = cls;

  if (&peer_data[1] == pdata)
  {
    peer2_listen_socket = NULL;
    peer2_listen_socket =
	GNUNET_STREAM_listen (cfg, 10, &stream_listen_cb, &peer_data[1],
			      GNUNET_STREAM_OPTION_SIGNAL_LISTEN_SUCCESS,
			      &stream_connect2,
                              GNUNET_STREAM_OPTION_MAX_PAYLOAD_SIZE,
                              payload_size[payload_size_index],
                              GNUNET_STREAM_OPTION_END);
    GNUNET_assert (NULL != peer2_listen_socket);
    return peer2_listen_socket;
  }
  if (&peer_data[0] == pdata)
  {
    pdata->socket =
	GNUNET_STREAM_open (cfg, &peer_data[1].id, 10, &stream_open_cb,
			    &peer_data[0],
			    GNUNET_STREAM_OPTION_MAX_PAYLOAD_SIZE,
			    payload_size[payload_size_index],
			    GNUNET_STREAM_OPTION_END);
    GNUNET_assert (NULL != pdata->socket);
    return pdata->socket;
  }
  GNUNET_assert (0);
  return NULL;
}


/**
 * Callback to be called when the requested peer information is available
 *
 * @param cb_cls the closure from GNUNET_TETSBED_peer_get_information()
 * @param op the operation this callback corresponds to
 * @param pinfo the result; will be NULL if the operation has failed
 * @param emsg error message if the operation has failed; will be NULL if the
 *          operation is successfull
 */
static void 
peerinfo_cb (void *cb_cls, struct GNUNET_TESTBED_Operation *op,
	     const struct GNUNET_TESTBED_PeerInformation *pinfo,
	     const char *emsg)
{
  struct PeerData *pdata = cb_cls;

  GNUNET_assert (NULL == emsg);
  GNUNET_assert (common_op == op);
  GNUNET_assert (NULL != pdata);
  memcpy (&pdata->id, pinfo->result.id, sizeof (struct GNUNET_PeerIdentity));
  GNUNET_TESTBED_operation_done (op);
  if (pdata == &peer_data[0])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer 1 id: %s\n",
		GNUNET_i2s (&pdata->id));
    common_op = GNUNET_TESTBED_peer_get_information (peer_data[1].peer,
						     GNUNET_TESTBED_PIT_IDENTITY,
						     &peerinfo_cb, &peer_data[1]);
  }
  else if (pdata == &peer_data[1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer 2 id: %s\n",
		GNUNET_i2s (&pdata->id));
    if (TEST_STEP_2_HOP == test_step)
      peer_data[1].op = 
	  GNUNET_TESTBED_service_connect (&peer_data[1], peer_data[1].peer,
					  "stream", NULL, NULL, stream_ca,
					  stream_da, &peer_data[1]);
    else
      GNUNET_break (0);		/* FIXME: 3 hop test case here... */
  }
}


/**
 * Controller event callback
 *
 * @param cls NULL
 * @param event the controller event
 */
static void
controller_event_cb (void *cls,
                     const struct GNUNET_TESTBED_EventInformation *event)
{
  switch (event->type)
  {
  case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    if (NULL != event->details.operation_finished.emsg)
    {
      FPRINTF (stderr, "Error while expecting an operation to succeed:%s \n",
	       event->details.operation_finished.emsg);
      GNUNET_assert (0);
    }
    break;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param num_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed
 */
static void
test_master (void *cls, unsigned int num_peers_,
             struct GNUNET_TESTBED_Peer **peers)
{
  GNUNET_assert (NULL != peers);
  GNUNET_assert (NULL != peers[0]);
  GNUNET_assert (NULL != peers[1]);
  GNUNET_assert (num_peers_ == num_peers);
  peer_data[0].peer = peers[0];
  peer_data[1].peer = peers[1];
  if (2 == num_peers)
        /* Get the peer identity and configuration of peers */
    common_op =
	GNUNET_TESTBED_peer_get_information (peer_data[0].peer,
					     GNUNET_TESTBED_PIT_IDENTITY,
					     &peerinfo_cb, &peer_data[0]);
  else
    GNUNET_break (0);
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
				    (GNUNET_TIME_UNIT_SECONDS, 120), &do_abort,
				    NULL);
}


/**
 * Main function
 */
int main (int argc, char **argv)
{
  char *test_name = "perf_stream_api";
  char *cfg_file = "test_stream_local.conf";
  uint64_t event_mask;
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
  meter = NULL;
  test_step = TEST_STEP_1_HOP;
  for (payload_size_index = 0;
       payload_size_index < (sizeof (payload_size) / sizeof (uint16_t));
       payload_size_index++)
  {
    PRINTF ("\nTesting over loopback with payload size %hu\n",
  	    payload_size[payload_size_index]);
    (void) memset (peer_data, 0, sizeof (peer_data));
    result = INIT;
    reset_read = GNUNET_NO;
    ret = GNUNET_TESTING_peer_run (test_name, cfg_file, &run, NULL);
    if ((0 != ret) || (DOWNLINK_OK != result))
      goto return_fail;
  }
  test_step = TEST_STEP_2_HOP;
  num_peers = 2;
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  for (payload_size_index = 0;
       payload_size_index < (sizeof (payload_size) / sizeof (uint16_t));
       payload_size_index++)
  {
    PRINTF ("\nTesting over 1 hop with payload size %hu\n",
            payload_size[payload_size_index]);
    (void) memset (peer_data, 0, sizeof (peer_data));
    result = INIT;
    reset_read = GNUNET_NO;
    (void) GNUNET_TESTBED_test_run (test_name, cfg_file, num_peers, event_mask,
                                    &controller_event_cb, NULL, &test_master, 
                                    NULL);
    if (DOWNLINK_OK != result)
      goto return_fail;
  }
  test_step = TEST_STEP_3_HOP;
  for (payload_size_index = 0; 
       payload_size_index < (sizeof (payload_size) / sizeof (uint16_t));
       payload_size_index++)
  {
    /* Initialize testbed here */
  }
  return 0;

 return_fail:
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Test failed\n");
  return 1;
}

/* end of perf_stream_api.c */
