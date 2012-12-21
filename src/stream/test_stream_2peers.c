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
 * @file stream/test_stream_2peers.c
 * @brief Stream API testing between 2 peers using testing API
 * @author Sree Harsha Totakura
 */

#include <string.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_mesh_service.h"
#include "gnunet_stream_lib.h"
#include "gnunet_testbed_service.h"

/**
 * Number of peers; Do NOT change this
 */
#define NUM_PEERS 2

/**
 * Shorthand for Relative time in seconds
 */
#define TIME_REL_SECS(sec) \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, sec)

/**
 * Structure for holding peer's sockets and IO Handles
 */
struct PeerData
{
  /**
   * Handle to testbed peer
   */
  struct GNUNET_TESTBED_Peer *peer;

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
   * Peer's shutdown handle
   */
  struct GNUNET_STREAM_ShutdownHandle *shutdown_handle;

  /**
   * The service connect operation to stream
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Our Peer id
   */
  struct GNUNET_PeerIdentity our_id;

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
 * Different states in test setup
 */
enum SetupState
{
  /**
   * Get the identity of peer 1
   */
  PEER1_GET_IDENTITY,

  /**
   * Get the identity of peer 2
   */
  PEER2_GET_IDENTITY,
  
  /**
   * Connect to stream service of peer 1
   */
  PEER1_STREAM_CONNECT,

  /**
   * Connect to stream service of peer 2
   */
  PEER2_STREAM_CONNECT

};

/**
 * Various states during test setup
 */
static enum SetupState setup_state;

/**
 * Data context for peer 1
 */
static struct PeerData peer1;

/**
 * Data context for peer 2
 */
static struct PeerData peer2;

/**
 * Testbed operation handle
 */
static struct GNUNET_TESTBED_Operation *op;

static GNUNET_SCHEDULER_TaskIdentifier abort_task;

static char *data = "ABCD";
static int result;

static int writing_success;
static int reading_success;


/**
 * Input processor
 *
 * @param cls the closure from GNUNET_STREAM_write/read
 * @param status the status of the stream at the time this function is called
 * @param data traffic from the other side
 * @param size the number of bytes available in data read 
 * @return number of bytes of processed from 'data' (any data remaining should be
 *         given to the next time the read processor is called).
 */
static size_t
input_processor (void *cls,
                 enum GNUNET_STREAM_Status status,
                 const void *input_data,
                 size_t size);

/**
 * Task for calling STREAM_read
 *
 * @param cls the peer data entity
 * @param tc the task context
 */
static void
stream_read_task (void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerData *peer = cls;
  
  peer->io_read_handle = GNUNET_STREAM_read (peer->socket,
                                             GNUNET_TIME_relative_multiply
                                             (GNUNET_TIME_UNIT_SECONDS, 5),
                                             &input_processor,
                                             peer);
  GNUNET_assert (NULL != peer->io_read_handle);
}

/**
 * The write completion function; called upon writing some data to stream or
 * upon error
 *
 * @param cls the closure from GNUNET_STREAM_write/read
 * @param status the status of the stream at the time this function is called
 * @param size the number of bytes read or written
 */
static void 
write_completion (void *cls,
                  enum GNUNET_STREAM_Status status,
                  size_t size);


/**
 * Task for calling STREAM_write
 *
 * @param cls the peer data entity
 * @param tc the task context
 */
static void
stream_write_task (void *cls,
                   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerData *peer = cls;
  
  peer->io_write_handle = 
    GNUNET_STREAM_write (peer->socket,
                         (void *) data,
                         strlen(data) - peer->bytes_wrote,
                         GNUNET_TIME_relative_multiply
                         (GNUNET_TIME_UNIT_SECONDS, 5),
                         &write_completion,
                         peer);
 
  GNUNET_assert (NULL != peer->io_write_handle);
 }


/**
 * Close sockets and stop testing deamons nicely
 */
static void
do_close (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (NULL != peer1.socket)
    GNUNET_STREAM_close (peer1.socket);
  if (NULL != peer1.op)
    GNUNET_TESTBED_operation_done (peer1.op);
  else
    GNUNET_SCHEDULER_shutdown (); /* For shutting down testbed */
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
    peer1.shutdown_handle = NULL;
    peer2.shutdown_handle = GNUNET_STREAM_shutdown (peer2.socket, SHUT_RDWR,
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
  result = GNUNET_OK;
  peer1.shutdown_handle = GNUNET_STREAM_shutdown (peer1.socket, SHUT_RDWR,
                                                  &shutdown_completion, cls);
}


/**
 * Something went wrong and timed out. Kill everything and set error flag
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: ABORT\n");
  result = GNUNET_SYSERR;
  abort_task = 0;
  do_close (cls, tc);  
}


/**
 * The write completion function; called upon writing some data to stream or
 * upon error
 *
 * @param cls the closure from GNUNET_STREAM_write/read
 * @param status the status of the stream at the time this function is called
 * @param size the number of bytes read or written
 */
static void 
write_completion (void *cls,
                  enum GNUNET_STREAM_Status status,
                  size_t size)
{
  struct PeerData *peer=cls;

  GNUNET_assert (GNUNET_STREAM_OK == status);
  GNUNET_assert (size <= strlen (data));
  peer->bytes_wrote += size;

  if (peer->bytes_wrote < strlen(data)) /* Have more data to send */
    {
      GNUNET_SCHEDULER_add_now (&stream_write_task, peer);
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Writing completed\n");

      if (&peer2 == peer)   /* Peer1 has finished writing; should read now */
        {
          peer->bytes_read = 0;
          GNUNET_SCHEDULER_add_now (&stream_read_task, peer);
        }
      else
        {
          writing_success = GNUNET_YES;
          if (GNUNET_YES == reading_success)
            GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
        }
    }
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
  struct PeerData *peer=cls;
  
  GNUNET_assert (&peer2 == peer);
  GNUNET_assert (socket == peer2.socket);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s: Stream established from peer2\n",
              GNUNET_i2s (&peer1.our_id));
  peer->bytes_wrote = 0;
  GNUNET_SCHEDULER_add_now (&stream_write_task, peer);
}


/**
 * Input processor
 *
 * @param cls the closure from GNUNET_STREAM_write/read
 * @param status the status of the stream at the time this function is called
 * @param data traffic from the other side
 * @param size the number of bytes available in data read 
 * @return number of bytes of processed from 'data' (any data remaining should be
 *         given to the next time the read processor is called).
 */
static size_t
input_processor (void *cls,
                 enum GNUNET_STREAM_Status status,
                 const void *input_data,
                 size_t size)
{
  struct PeerData *peer;

  peer = (struct PeerData *) cls;

  if (GNUNET_STREAM_TIMEOUT == status)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Read operation timedout - reading again!\n");
      GNUNET_assert (0 == size);
      GNUNET_SCHEDULER_add_now (&stream_read_task, peer);
      return 0;
    }

  GNUNET_assert (GNUNET_STREAM_OK == status);
  GNUNET_assert (size <= strlen (data));
  GNUNET_assert (0 == strncmp ((const char *) data + peer->bytes_read, 
                               (const char *) input_data,
                               size));
  peer->bytes_read += size;
  
  if (peer->bytes_read < strlen (data))
    {
      GNUNET_SCHEDULER_add_now (&stream_read_task, peer);
    }
  else 
    {
      if (&peer1 == peer)    /* Peer2 has completed reading; should write */
        {
          peer->bytes_wrote = 0;
          GNUNET_SCHEDULER_add_now (&stream_write_task, peer);
        }
      else                      /* Peer1 has completed reading. End of tests */
        {
          reading_success = GNUNET_YES;
          if (GNUNET_YES == writing_success)
            GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
        }
    }
  return size;
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
stream_listen_cb (void *cls,
                  struct GNUNET_STREAM_Socket *socket,
                  const struct GNUNET_PeerIdentity *initiator)
{
  if ((NULL == socket) || (NULL == initiator))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Binding error\n");
    if (GNUNET_SCHEDULER_NO_TASK != abort_task)
      GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return GNUNET_OK;
  }
  GNUNET_assert (NULL != initiator);
  GNUNET_assert (socket != peer2.socket);
  GNUNET_assert (0 == memcmp (initiator, &peer2.our_id, 
                              sizeof (struct GNUNET_PeerIdentity)));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s: Peer connected: %s\n",
              GNUNET_i2s (&peer1.our_id), GNUNET_i2s (initiator));  
  peer1.socket = socket;
  peer1.bytes_read = 0;
  GNUNET_SCHEDULER_add_now (&stream_read_task, &peer1);
  return GNUNET_OK;
}


/**
 * Listen success callback; connects a peer to stream as client
 */
static void stream_connect (void);


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
  struct GNUNET_STREAM_ListenSocket *lsocket;
  struct GNUNET_STREAM_Socket *socket;

  if (&peer1 == cls)
  {
    lsocket = op_result;
    GNUNET_STREAM_listen_close (lsocket);
    if (NULL != peer2.op)
      GNUNET_TESTBED_operation_done (peer2.op);
    else
      GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (&peer2 == cls)
  {
    socket = op_result;
    GNUNET_STREAM_close (socket);
    GNUNET_SCHEDULER_shutdown (); /* Exit point of the test */
    return;
  }
  GNUNET_assert (0);
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
  struct GNUNET_STREAM_ListenSocket *lsocket;
  
  switch (setup_state)
  {
  case PEER1_STREAM_CONNECT:
    lsocket = GNUNET_STREAM_listen (cfg, 10, &stream_listen_cb, NULL,
                                    GNUNET_STREAM_OPTION_SIGNAL_LISTEN_SUCCESS,
                                    &stream_connect, GNUNET_STREAM_OPTION_END);
    return lsocket;
  case PEER2_STREAM_CONNECT:
    peer2.socket = GNUNET_STREAM_open (cfg, &peer1.our_id, 10, &stream_open_cb,
                                       &peer2, GNUNET_STREAM_OPTION_END);
    return peer2.socket;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Listen success callback; connects a peer to stream as client
 */
static void
stream_connect (void)
{ 
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stream listen open successful\n");
  peer2.op = GNUNET_TESTBED_service_connect (&peer2, peer2.peer, "stream",
					     NULL, NULL,
                                             stream_ca, stream_da, &peer2);
  setup_state = PEER2_STREAM_CONNECT;
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
peerinfo_cb (void *cb_cls, struct GNUNET_TESTBED_Operation *op_,
	     const struct GNUNET_TESTBED_PeerInformation *pinfo,
	     const char *emsg)
{
  GNUNET_assert (NULL == emsg);
  GNUNET_assert (op == op_);
  switch (setup_state)
    {
    case PEER1_GET_IDENTITY:
      memcpy (&peer1.our_id, pinfo->result.id, 
	      sizeof (struct GNUNET_PeerIdentity));
      GNUNET_TESTBED_operation_done (op);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer 1 id: %s\n", GNUNET_i2s
                  (&peer1.our_id));
      op = GNUNET_TESTBED_peer_get_information (peer2.peer,
                                                GNUNET_TESTBED_PIT_IDENTITY,
						&peerinfo_cb, NULL);
      setup_state = PEER2_GET_IDENTITY;
      break;
    case PEER2_GET_IDENTITY:
      memcpy (&peer2.our_id, pinfo->result.id,
              sizeof (struct GNUNET_PeerIdentity));
      GNUNET_TESTBED_operation_done (op);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer 2 id: %s\n", GNUNET_i2s
                  (&peer2.our_id));
      peer1.op = GNUNET_TESTBED_service_connect (&peer1, peer1.peer, "stream",
						 NULL, NULL, stream_ca,
						 stream_da, &peer1);
      setup_state = PEER1_STREAM_CONNECT;
      break;
    default:
      GNUNET_assert (0);
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
    switch (setup_state)
    {    
    case PEER1_STREAM_CONNECT:
    case PEER2_STREAM_CONNECT:
      GNUNET_assert (NULL == event->details.operation_finished.emsg);
      break;
    default:
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
test_master (void *cls, unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **peers)
{
  GNUNET_assert (NULL != peers);
  GNUNET_assert (NULL != peers[0]);
  GNUNET_assert (NULL != peers[1]);
  peer1.peer = peers[0];
  peer2.peer = peers[1];
  /* Get the peer identity and configuration of peers */
  op = GNUNET_TESTBED_peer_get_information (peer1.peer,
                                            GNUNET_TESTBED_PIT_IDENTITY,
                                            &peerinfo_cb, NULL);
  setup_state = PEER1_GET_IDENTITY;
  abort_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 40), &do_abort,
                                  NULL);
}


/**
 * Main function
 */
int main (int argc, char **argv)
{
  uint64_t event_mask;  

  result = GNUNET_NO;
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  (void) GNUNET_TESTBED_test_run ("test_stream_2peers",
                                  "test_stream_local.conf",
                                  NUM_PEERS, event_mask, &controller_event_cb,
                                  NULL,
                                  &test_master, NULL);
  if (GNUNET_SYSERR == result)
    return 1;
  return 0;
}
