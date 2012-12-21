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
 * @file stream/test_stream_local.c
 * @brief Stream API testing between local peers
 * @author Sree Harsha Totakura
 */

#include <string.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_mesh_service.h"
#include "gnunet_stream_lib.h"
#include "gnunet_testing_lib.h"

/**
 * Relative seconds shorthand
 */
#define TIME_REL_SECS(sec) \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, sec)


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
   * Peer's shutdown handle
   */
  struct GNUNET_STREAM_ShutdownHandle *shutdown_handle;

  /**
   * Bytes the peer has written
   */
  unsigned int bytes_wrote;

  /**
   * Byte the peer has read
   */
  unsigned int bytes_read;
};

static struct PeerData peer1;
static struct PeerData peer2;
static struct GNUNET_STREAM_ListenSocket *peer2_listen_socket;
static const struct GNUNET_CONFIGURATION_Handle *config;
static struct GNUNET_TESTING_Peer *self;
static struct GNUNET_PeerIdentity self_id;

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
 * Shutdown nicely
 */
static void
do_close (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (NULL != peer1.socket)
    GNUNET_STREAM_close (peer1.socket);
  if (NULL != peer2.socket)
    GNUNET_STREAM_close (peer2.socket);
  if (NULL != peer2_listen_socket)
    GNUNET_STREAM_listen_close (peer2_listen_socket);
}


/**
 * Something went wrong and timed out. Kill everything and set error flag
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: ABORT\n");
  result = GNUNET_SYSERR;
  abort_task = GNUNET_SCHEDULER_NO_TASK;
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
      if (&peer1 == peer)  /* Peer1 has finished writing; should read now */
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

  GNUNET_assert (&peer1 == peer);
  GNUNET_assert (socket == peer1.socket);
  GNUNET_assert (socket == peer->socket);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stream established from peer1\n");
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
  struct PeerData *peer = cls;

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
      if (&peer2 == peer)    /* Peer2 has completed reading; should write */
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
 * @param cls the PeerData of peer2
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
  struct PeerData *peer=cls;

  if ((NULL == socket) || (NULL == initiator))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Binding error\n");
    if (GNUNET_SCHEDULER_NO_TASK != abort_task)
      GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return GNUNET_OK;
  }
  GNUNET_assert (NULL != socket);
  GNUNET_assert (socket != peer1.socket);
  GNUNET_assert (&peer2 == peer);
  GNUNET_assert (0 == memcmp (&self_id,
                              initiator,
                              sizeof (struct GNUNET_PeerIdentity)));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer connected: %s\n", GNUNET_i2s(initiator));
  peer->socket = socket;
  peer->bytes_read = 0;
  GNUNET_SCHEDULER_add_now (&stream_read_task, &peer2);
  return GNUNET_OK;
}


/**
 * Listen success callback; connects a peer to stream as client
 */
static void
stream_connect (void)
{
  peer1.socket = GNUNET_STREAM_open (config,
                                     &self_id,
                                     10,           /* App port */
                                     &stream_open_cb,
                                     &peer1,
				     GNUNET_STREAM_OPTION_END);
  GNUNET_assert (NULL != peer1.socket);
}


/**
 * Initialize framework and start test
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  config = cfg;
  self = peer;
  GNUNET_TESTING_peer_get_identity (peer, &self_id);
  peer2_listen_socket = 
    GNUNET_STREAM_listen (config,
                          10, /* App port */
                          &stream_listen_cb,
                          &peer2,
                          GNUNET_STREAM_OPTION_SIGNAL_LISTEN_SUCCESS,
                          &stream_connect,
                          GNUNET_STREAM_OPTION_END);
  GNUNET_assert (NULL != peer2_listen_socket);
  abort_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 30), &do_abort,
                                  NULL);
}

/**
 * Main function
 */
int main (int argc, char **argv)
{
  if (0 != GNUNET_TESTING_peer_run ("test_stream_local",
				    "test_stream_local.conf",
				    &run, NULL))
    return 1;
  return (GNUNET_SYSERR == result) ? 1 : 0;
}

/* end of test_stream_local.c */
